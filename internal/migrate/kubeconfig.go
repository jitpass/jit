// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

// KubeconfigUserMigration describes what jit migrate did to one
// kubeconfig user entry.
type KubeconfigUserMigration struct {
	UserName         string
	ConfigPath       string
	Backup           string
	VaultProfileName string
	VaultProfilePath string
	Variables        []string
	AuthType         string // "token" or "client-cert"
}

// KubeconfigPath returns ~/.kube/config.
func KubeconfigPath(home string) string {
	return filepath.Join(home, ".kube", "config")
}

// DiscoverKubeconfigUsers returns every kubeconfig user with a bearer
// token, or a complete client-certificate-data + client-key-data pair,
// that ApplyKubeconfigUser can convert. A user with only one half of a
// cert/key pair is skipped — migrating half a credential would produce a
// kubeconfig that authenticates even less than the broken one it started
// from. Sorted for determinism.
func DiscoverKubeconfigUsers(home string) ([]string, error) {
	path := KubeconfigPath(home)
	doc, err := loadKubeconfig(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	users, err := kubeconfigUsers(doc)
	if err != nil {
		return nil, err
	}

	var names []string
	for _, u := range users {
		if !hasMigratableAuth(u) {
			continue
		}
		if name, _ := u["name"].(string); name != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}

// ApplyKubeconfigUser moves userName's bearer token or client-certificate
// credential out of ~/.kube/config and into v's vault, under a
// home-rooted global profile (profile.GlobalRoot) named
// "k8s-<userName>" — kubectl/client-go invoke an exec plugin from
// whatever directory the calling command happens to run in, not any
// particular jit project directory, so the profile has to resolve
// independent of cwd the same way shell-config/MCP/AWS profiles do.
//
// Replaces the user's raw token/client-certificate-data/client-key-data
// fields with an exec block (RFC.md Pillar III Tier 2, client-go's exec
// plugin protocol, client.authentication.k8s.io/v1) that invokes `jit
// k8s-exec-credential` — using jit's own resolved executable path, not a
// bare "jit", for the same PATH-reliability reason MCP migration does.
// Every other field in the kubeconfig (clusters, contexts,
// current-context, other users, preferences) is preserved, though
// re-marshaling the whole document loses exact key ordering/comments —
// the same accepted tradeoff as MCP config migration's JSON remarshal.
// ~/.kube/config is backed up first.
//
// dedup, if non-nil, makes a run migrating several users from one
// ~/.kube/config back the file up once (its pristine state) rather than
// once per user — otherwise undo restores the last, most-stripped snapshot
// and loses the earlier users' credentials. See BackupTracker (GAPS.md #65).
func ApplyKubeconfigUser(v *vault.Vault, home, userName string, dedup ...*BackupTracker) (KubeconfigUserMigration, error) {
	var tracker *BackupTracker
	if len(dedup) > 0 {
		tracker = dedup[0]
	}
	path := KubeconfigPath(home)
	doc, err := loadKubeconfig(path)
	if err != nil {
		return KubeconfigUserMigration{}, fmt.Errorf("reading %s: %w", path, err)
	}
	users, err := kubeconfigUsers(doc)
	if err != nil {
		return KubeconfigUserMigration{}, fmt.Errorf("%s: %w", path, err)
	}
	userEntry, found := findKubeconfigUser(users, userName)
	if !found {
		return KubeconfigUserMigration{}, fmt.Errorf("user %q not found in %s", userName, path)
	}
	userMap, _ := userEntry["user"].(map[string]interface{})
	if userMap == nil || !hasMigratableAuth(userEntry) {
		return KubeconfigUserMigration{}, fmt.Errorf("user %q has no migratable credentials in %s", userName, path)
	}

	vaultProfileName := "k8s-" + sanitizeProfileName(userName)
	globalRoot, err := profile.GlobalRoot()
	if err != nil {
		return KubeconfigUserMigration{}, fmt.Errorf("resolving global profile root: %w", err)
	}
	vaultProfilePath, err := profile.Path(globalRoot, vaultProfileName)
	if err != nil {
		return KubeconfigUserMigration{}, err
	}

	entries := profile.Profile{}
	switch existing, lerr := profile.LoadFile(vaultProfilePath); {
	case lerr == nil:
		for k, v2 := range existing {
			entries[k] = v2
		}
	case errors.Is(lerr, os.ErrNotExist):
		// no existing profile yet — start fresh
	default:
		return KubeconfigUserMigration{}, fmt.Errorf("loading existing profile %s: %w", vaultProfilePath, lerr)
	}

	authType, secrets := kubeconfigUserSecrets(userMap)
	varNames := make([]string, 0, len(secrets))
	for name := range secrets {
		varNames = append(varNames, name)
	}
	sort.Strings(varNames)
	for _, name := range varNames {
		secretPath := vaultProfileName + "/" + name
		if err := v.Set(secretPath, []byte(secrets[name])); err != nil {
			return KubeconfigUserMigration{}, fmt.Errorf("storing %s in vault: %w", name, err)
		}
		entries[name] = secretPath
	}

	if err := writeProfileManifest(vaultProfilePath, entries); err != nil {
		return KubeconfigUserMigration{}, fmt.Errorf("writing profile %s: %w", vaultProfilePath, err)
	}

	backupPath, err := tracker.backupOnce(v, path)
	if err != nil {
		return KubeconfigUserMigration{}, fmt.Errorf("backing up %s: %w", path, err)
	}

	jitPath, err := resolveJitExecutable()
	if err != nil {
		return KubeconfigUserMigration{}, fmt.Errorf("resolving jit's own executable path: %w", err)
	}

	delete(userMap, "token")
	delete(userMap, "client-certificate-data")
	delete(userMap, "client-key-data")
	userMap["exec"] = map[string]interface{}{
		"apiVersion":      "client.authentication.k8s.io/v1",
		"command":         jitPath,
		"args":            []interface{}{"k8s-exec-credential", "--profile", vaultProfileName},
		"interactiveMode": "Never",
	}

	out, err := yaml.Marshal(doc)
	if err != nil {
		return KubeconfigUserMigration{}, err
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return KubeconfigUserMigration{}, fmt.Errorf("writing %s: %w", path, err)
	}

	return KubeconfigUserMigration{
		UserName:         userName,
		ConfigPath:       path,
		Backup:           backupPath,
		VaultProfileName: vaultProfileName,
		VaultProfilePath: vaultProfilePath,
		Variables:        varNames,
		AuthType:         authType,
	}, nil
}

func loadKubeconfig(path string) (map[string]interface{}, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- fixed ~/.kube/config path, not external input
	if err != nil {
		return nil, err
	}
	var doc map[string]interface{}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return doc, nil
}

func kubeconfigUsers(doc map[string]interface{}) ([]map[string]interface{}, error) {
	raw, ok := doc["users"]
	if !ok {
		return nil, nil
	}
	list, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("users is not a list")
	}
	users := make([]map[string]interface{}, 0, len(list))
	for _, item := range list {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		users = append(users, m)
	}
	return users, nil
}

func findKubeconfigUser(users []map[string]interface{}, name string) (map[string]interface{}, bool) {
	for _, u := range users {
		if n, _ := u["name"].(string); n == name {
			return u, true
		}
	}
	return nil, false
}

// hasMigratableAuth reports whether userEntry's "user" block has a
// bearer token or a complete client-certificate-data + client-key-data
// pair.
func hasMigratableAuth(userEntry map[string]interface{}) bool {
	userMap, _ := userEntry["user"].(map[string]interface{})
	if userMap == nil {
		return false
	}
	if s, ok := userMap["token"].(string); ok && s != "" {
		return true
	}
	cert, _ := userMap["client-certificate-data"].(string)
	key, _ := userMap["client-key-data"].(string)
	return cert != "" && key != ""
}

// kubeconfigUserSecrets extracts userMap's migratable credential(s),
// returning which auth type was found ("token" or "client-cert") and the
// variable-name -> value pairs to store in the vault.
func kubeconfigUserSecrets(userMap map[string]interface{}) (authType string, secrets map[string]string) {
	if token, ok := userMap["token"].(string); ok && token != "" {
		return "token", map[string]string{"TOKEN": token}
	}
	cert, _ := userMap["client-certificate-data"].(string)
	key, _ := userMap["client-key-data"].(string)
	return "client-cert", map[string]string{
		"CLIENT_CERTIFICATE_DATA": cert,
		"CLIENT_KEY_DATA":         key,
	}
}
