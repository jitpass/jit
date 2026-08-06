// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/jitpass/jit/internal/pointerfile"
	"github.com/jitpass/jit/internal/vault"
)

// clisso's config (~/.clisso.yaml) holds one long-lived secret: a OneLogin
// provider's API client-secret, in plaintext — the credential that mints
// AWS sessions for every configured app. This file moves it to the vault
// and leaves a jit://vault/<path> pointer in its place (the same pointer
// grammar migrated .env files use), so the on-disk config becomes a decoy
// that still round-trips through clisso's own config writes.
//
// The pointer is deliberately the stored value, not a comment: clisso
// rewrites this file itself (`apps create`, `providers create`, `cp`), and
// viper preserves values it doesn't understand — so the pointer survives
// every rewrite, where a comment would be dropped on the first one. An
// unwrapped clisso run sends the pointer to OneLogin and fails loudly with
// an auth error, which is the correct failure: silent plaintext fallback
// is the thing being removed.
//
// Serving the real value back is the capture shim's job
// (jit clisso-capture renders the config with pointers resolved and hands
// it to clisso via -c); RenderClissoConfig below is that half.

// ClissoConfigPath returns ~/.clisso.yaml.
func ClissoConfigPath(home string) string {
	return filepath.Join(home, ".clisso.yaml")
}

// clissoVaultPathPattern is the provider-name shape that maps cleanly onto
// a vault path. Anything else is skipped with a warning rather than
// guessed at — a mangled vault path would strand the secret.
var clissoVaultPathPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// ClissoVaultPath returns the vault path a provider's client-secret is
// stored at: wrap-clisso/<provider>-client-secret.
func ClissoVaultPath(provider string) string {
	return "wrap-clisso/" + provider + "-client-secret"
}

const clissoPointerPrefix = pointerfile.ValuePrefix

// ClissoConfigMigration reports what ApplyClissoConfig moved.
type ClissoConfigMigration struct {
	ConfigPath string
	Backup     string   // encrypted backup's vault path ("" if nothing changed)
	Providers  []string // providers whose client-secret moved, in file order
	Skipped    []string // providers skipped for an unsafe name
}

// DiscoverClissoSecrets reports which providers in home's ~/.clisso.yaml
// hold a plaintext client-secret (non-empty and not already a jit://vault
// pointer). The cheap read-only half of ApplyClissoConfig, split out so
// callers can decide whether opening the vault (and its unlock prompt) is
// warranted at all — the capture shim runs a reconcile after every
// config-mutating clisso subcommand, and most of those add no secret.
func DiscoverClissoSecrets(home string) ([]string, error) {
	data, err := os.ReadFile(ClissoConfigPath(home)) // #nosec G304 -- fixed ~/.clisso.yaml under the user's home
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var found []string
	err = walkClissoSecrets(data, func(provider string, secret *yaml.Node) error {
		found = append(found, provider)
		return nil
	})
	if err != nil {
		return nil, nil // malformed YAML — nothing discoverable, clisso's own parse will complain
	}
	return found, nil
}

// ApplyClissoConfig moves every plaintext provider client-secret in
// ~/.clisso.yaml into v's vault and rewrites the file with jit://vault
// pointers in their place. The file is backed up (encrypted,
// undo-indexed) before the first change; `jit migrate undo` restores it
// byte-for-byte. Idempotent: a file already holding only pointers is left
// untouched, backup and all.
//
// The YAML is edited via a node-level round-trip, not a map re-marshal,
// so key order and comments survive — this file is rewritten repeatedly
// (by clisso and by reconciles), and a rewrite that reshuffles it every
// time would turn diffs into noise.
func ApplyClissoConfig(v *vault.Vault, home string) (ClissoConfigMigration, error) {
	res := ClissoConfigMigration{ConfigPath: ClissoConfigPath(home)}
	data, err := os.ReadFile(res.ConfigPath) // #nosec G304 -- fixed ~/.clisso.yaml under the user's home
	if err != nil {
		if os.IsNotExist(err) {
			return res, nil
		}
		return res, err
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return res, fmt.Errorf("parsing %s: %w", res.ConfigPath, err)
	}

	meta, err := newProvenance(vault.ClassWrap, res.ConfigPath)
	if err != nil {
		return res, err
	}
	err = walkClissoSecretsNode(&doc, func(provider string, secret *yaml.Node) error {
		if !clissoVaultPathPattern.MatchString(provider) {
			res.Skipped = append(res.Skipped, provider)
			return nil
		}
		if res.Backup == "" {
			backup, berr := backupSecretFile(v, res.ConfigPath)
			if berr != nil {
				return fmt.Errorf("backing up %s: %w", res.ConfigPath, berr)
			}
			res.Backup = backup
		}
		path := ClissoVaultPath(provider)
		if err := v.SetWithMeta(path, []byte(secret.Value), meta); err != nil {
			return fmt.Errorf("storing %s in vault: %w", path, err)
		}
		secret.Value = clissoPointerPrefix + path
		// A secret can look like a number or carry odd characters; the
		// pointer is a plain string and must marshal as one.
		secret.Tag = "!!str"
		res.Providers = append(res.Providers, provider)
		return nil
	})
	if err != nil {
		return res, err
	}
	if len(res.Providers) == 0 {
		return res, nil // nothing moved — leave the file's exact bytes alone
	}

	out, err := yaml.Marshal(&doc)
	if err != nil {
		return res, fmt.Errorf("re-marshaling %s: %w", res.ConfigPath, err)
	}
	if err := os.WriteFile(res.ConfigPath, out, 0o600); err != nil {
		return res, fmt.Errorf("writing %s: %w", res.ConfigPath, err)
	}
	return res, nil
}

// RenderClissoConfig resolves every jit://vault pointer in a clisso config
// against v and returns the rendered bytes — the real config the capture
// shim serves to clisso via -c, existing only in memory and a FIFO.
// resolved reports whether any pointer was found (none means the config
// was never wrapped and needs no serving). A pointer whose secret is
// missing from the vault is a hard error naming the fix: serving the
// pointer through would just move the confusing OneLogin auth failure
// one step further from its cause.
func RenderClissoConfig(v *vault.Vault, data []byte) (rendered []byte, resolved bool, err error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, false, fmt.Errorf("parsing clisso config: %w", err)
	}
	found := false
	err = walkClissoPointers(&doc, func(provider string, secret *yaml.Node) error {
		path := strings.TrimPrefix(secret.Value, clissoPointerPrefix)
		value, gerr := v.Get(path)
		if gerr != nil {
			return fmt.Errorf("provider %q points at %s but the vault has no such secret (re-run `jit wrap clisso`, or `jit vault set %s`): %w", provider, path, path, gerr)
		}
		secret.Value = string(value)
		secret.Tag = "!!str"
		found = true
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	if !found {
		return nil, false, nil
	}
	out, err := yaml.Marshal(&doc)
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}

// walkClissoSecrets parses data and visits every provider whose
// client-secret is plaintext (non-empty, not a pointer).
func walkClissoSecrets(data []byte, visit func(provider string, secret *yaml.Node) error) error {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return err
	}
	return walkClissoSecretsNode(&doc, visit)
}

// walkClissoSecretsNode visits every provider mapping's client-secret
// scalar that holds a plaintext value.
func walkClissoSecretsNode(doc *yaml.Node, visit func(provider string, secret *yaml.Node) error) error {
	return walkClissoClientSecrets(doc, func(provider string, secret *yaml.Node) error {
		if secret.Value == "" || strings.HasPrefix(secret.Value, clissoPointerPrefix) {
			return nil
		}
		return visit(provider, secret)
	})
}

// walkClissoPointers visits every provider client-secret that IS a pointer.
func walkClissoPointers(doc *yaml.Node, visit func(provider string, secret *yaml.Node) error) error {
	return walkClissoClientSecrets(doc, func(provider string, secret *yaml.Node) error {
		if !strings.HasPrefix(secret.Value, clissoPointerPrefix) {
			return nil
		}
		return visit(provider, secret)
	})
}

// walkClissoClientSecrets walks doc's providers mapping and visits each
// provider's client-secret scalar node, whatever its value. yaml.v3
// documents wrap the real root in a DocumentNode.
func walkClissoClientSecrets(doc *yaml.Node, visit func(provider string, secret *yaml.Node) error) error {
	root := doc
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		root = root.Content[0]
	}
	providers := yamlMapValue(root, "providers")
	if providers == nil || providers.Kind != yaml.MappingNode {
		return nil
	}
	// A mapping node's Content alternates key, value, key, value…
	for i := 0; i+1 < len(providers.Content); i += 2 {
		name := providers.Content[i].Value
		secret := yamlMapValue(providers.Content[i+1], "client-secret")
		if secret == nil || secret.Kind != yaml.ScalarNode {
			continue
		}
		if err := visit(name, secret); err != nil {
			return err
		}
	}
	return nil
}

// yamlMapValue returns the value node for key in a mapping node, or nil.
func yamlMapValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}
