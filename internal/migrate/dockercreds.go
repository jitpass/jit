// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

// Docker registry credential migration (same shape as Terraform's
// credentials-helper migration in terraform.go): `docker login` without a
// configured credential store writes each registry's username and
// password/token into ~/.docker/config.json's "auths" map, base64-encoded
// — encoding, not encryption. Docker's own credential-helper protocol is
// the native hook: an executable named docker-credential-<name> on $PATH,
// named as "<name>" by a per-registry `credHelpers` entry or the default
// `credsStore` key, makes docker (and everything speaking its config —
// buildx, compose, SDKs) ask jit for the credential instead of reading
// the file. Per-registry credHelpers entries win over credsStore, so
// migrating never has to replace an existing store (Docker Desktop's
// "desktop"/"osxkeychain"); jit claims the DEFAULT store only when the
// config had none at all, which is exactly the plaintext-auths case —
// and is what routes a future `docker login` to a brand-new registry into
// the vault instead of back into base64.

// dockerHelperName is the <name> in credsStore/credHelpers values and the
// docker-credential-<name> executable filename — Docker's own naming
// convention ties the two together, like Terraform's
// terraform-credentials-<name>.
const dockerHelperName = "jit"

// dockerProfilePrefix namespaces the global vault profile for a registry:
// "docker-index.docker.io-v1" for Docker Hub's canonical
// "https://index.docker.io/v1/" server address.
const dockerProfilePrefix = "docker-"

// DockerMigration describes what jit migrate did to one registry's stored
// credential in ~/.docker/config.json.
type DockerMigration struct {
	Registry         string // the auths key / server address docker uses, verbatim
	ConfigPath       string
	ConfigBackup     string
	HelperPath       string
	VaultProfileName string // "docker-<sanitized registry>"
	VaultProfilePath string
	Variables        []string
	// ClaimedDefaultStore is true when this run set credsStore to "jit"
	// because the config had no default store at all — from now on a
	// `docker login` to ANY registry lands in the vault, not in base64.
	ClaimedDefaultStore bool
}

// DockerConfigPath returns ~/.docker/config.json — where `docker login`
// stores registry credentials when no credential store is configured.
func DockerConfigPath(home string) string {
	return filepath.Join(home, ".docker", "config.json")
}

// DockerHelperPath returns where the credential-helper executable lives.
// Docker discovers helpers strictly by $PATH lookup of
// docker-credential-<name>, so the script goes in jit's own shim
// directory — the one directory jit already keeps on PATH (the same
// ~/.jit/shims wrap.ShimDir returns; a small independent copy of that
// path, this package's existing convention, rather than an import of
// internal/wrap). Deliberately a shell script, not a symlink: wrap's shim
// dispatch and listing only ever consider symlinks, so a script is
// invisible to them.
func DockerHelperPath(home string) string {
	return filepath.Join(home, ".jit", "shims", "docker-credential-"+dockerHelperName)
}

// DockerTokenUsername is the username Docker's protocol prescribes when
// the stored secret is an identity token rather than a password.
const DockerTokenUsername = "<token>"

// dockerConfig is ~/.docker/config.json's shape, decoded generically
// (json.RawMessage at both levels) so rewriting one registry's entry
// preserves every other top-level key ("aliases", "proxies", "plugins",
// ...) and any per-auth field byte-for-byte — the same "preserve
// everything you don't understand" discipline terraform.go's
// tfrcCredentials follows.
type dockerConfig struct {
	raw         map[string]json.RawMessage
	auths       map[string]json.RawMessage
	credsStore  string
	credHelpers map[string]string
}

// dockerAuthEntry is one auths entry's known fields; auth is
// base64("username:password").
type dockerAuthEntry struct {
	Auth          string `json:"auth"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	IdentityToken string `json:"identitytoken"`
}

// dockerPlainCreds is a credential pair extracted from a plaintext auths
// entry, normalized to the helper protocol's Username/Secret shape.
type dockerPlainCreds struct {
	Username string
	Secret   string
}

// errDockerConfigMalformed marks a config.json jit can't parse —
// distinguished from a read error so DiscoverDockerRegistries can skip it
// (nothing parseable means nothing safely rewritable) while still
// propagating genuine I/O failures.
var errDockerConfigMalformed = errors.New("malformed ~/.docker/config.json")

func parseDockerConfig(path string) (*dockerConfig, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- fixed ~/.docker path, not external input
	if err != nil {
		return nil, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", errDockerConfigMalformed, path, err)
	}
	cfg := &dockerConfig{raw: raw, auths: map[string]json.RawMessage{}, credHelpers: map[string]string{}}
	if authsRaw, ok := raw["auths"]; ok {
		if err := json.Unmarshal(authsRaw, &cfg.auths); err != nil {
			return nil, fmt.Errorf("%w: %s: auths: %v", errDockerConfigMalformed, path, err)
		}
	}
	if storeRaw, ok := raw["credsStore"]; ok {
		if err := json.Unmarshal(storeRaw, &cfg.credsStore); err != nil {
			return nil, fmt.Errorf("%w: %s: credsStore: %v", errDockerConfigMalformed, path, err)
		}
	}
	if helpersRaw, ok := raw["credHelpers"]; ok {
		if err := json.Unmarshal(helpersRaw, &cfg.credHelpers); err != nil {
			return nil, fmt.Errorf("%w: %s: credHelpers: %v", errDockerConfigMalformed, path, err)
		}
	}
	return cfg, nil
}

// plaintextCreds extracts registry's credential pair when its auths entry
// actually holds one on disk — the migratable case. An empty entry ({} —
// docker's own marker once a credential store holds the secret) yields
// false. The username can't contain ':' (Docker Hub and the registry
// protocol both reject it), so splitting the decoded auth on the FIRST
// colon is correct even for passwords that contain colons.
func (c *dockerConfig) plaintextCreds(registry string) (dockerPlainCreds, bool) {
	entryRaw, ok := c.auths[registry]
	if !ok {
		return dockerPlainCreds{}, false
	}
	var entry dockerAuthEntry
	if err := json.Unmarshal(entryRaw, &entry); err != nil {
		return dockerPlainCreds{}, false
	}

	username, password := entry.Username, entry.Password
	if entry.Auth != "" {
		if decoded, err := base64.StdEncoding.DecodeString(entry.Auth); err == nil {
			if u, p, found := strings.Cut(string(decoded), ":"); found {
				username, password = u, p
			}
		}
	}

	// An identity token (web-based `docker login` flows) is the secret;
	// the protocol's own convention is username "<token>".
	if entry.IdentityToken != "" {
		u := username
		if u == "" {
			u = DockerTokenUsername
		}
		return dockerPlainCreds{Username: u, Secret: entry.IdentityToken}, true
	}
	if username != "" && password != "" {
		return dockerPlainCreds{Username: username, Secret: password}, true
	}
	return dockerPlainCreds{}, false
}

// marshalMigrated re-encodes the config with registry's plaintext auths
// entry replaced by the empty marker object docker itself leaves once a
// credential store holds the secret, a credHelpers entry routing that
// registry to jit, optionally the default credsStore claimed for jit, and
// every other key untouched.
func (c *dockerConfig) marshalMigrated(registry string, claimDefaultStore bool) ([]byte, error) {
	auths := make(map[string]json.RawMessage, len(c.auths))
	for r, raw := range c.auths {
		auths[r] = raw
	}
	auths[registry] = json.RawMessage("{}")
	authsRaw, err := marshalJSONNoEscape(auths, "")
	if err != nil {
		return nil, err
	}

	helpers := make(map[string]string, len(c.credHelpers)+1)
	for r, h := range c.credHelpers {
		helpers[r] = h
	}
	helpers[registry] = dockerHelperName
	helpersRaw, err := marshalJSONNoEscape(helpers, "")
	if err != nil {
		return nil, err
	}

	out := make(map[string]json.RawMessage, len(c.raw)+2)
	for k, v := range c.raw {
		out[k] = v
	}
	out["auths"] = authsRaw
	out["credHelpers"] = helpersRaw
	if claimDefaultStore {
		storeRaw, err := marshalJSONNoEscape(dockerHelperName, "")
		if err != nil {
			return nil, err
		}
		out["credsStore"] = storeRaw
	}
	return marshalJSONNoEscape(out, "  ")
}

// dockerRegistrySanitizer collapses everything profile.Path's name
// pattern would reject into '-'.
var dockerRegistrySanitizer = regexp.MustCompile(`[^A-Za-z0-9_.-]+`)

// sanitizeDockerRegistry maps a registry server address to the stable
// name component both migration and the helper protocol derive
// independently: "https://index.docker.io/v1/" -> "index.docker.io-v1".
// Deterministic on the exact string docker uses is what matters — docker
// passes the SAME serverURL to a helper's get/store/erase that it uses as
// the auths/credHelpers key, so both sides always agree without any
// registry->profile index on disk. Returns "" when nothing survives.
func sanitizeDockerRegistry(serverURL string) string {
	s := strings.TrimPrefix(serverURL, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.Trim(s, "/")
	s = dockerRegistrySanitizer.ReplaceAllString(s, "-")
	return strings.Trim(s, "-")
}

// DockerProfileName returns the global vault profile name for a registry
// server address, or "" for an address that sanitizes to nothing (no such
// registry can ever have been migrated).
func DockerProfileName(serverURL string) string {
	s := sanitizeDockerRegistry(serverURL)
	if s == "" {
		return ""
	}
	return dockerProfilePrefix + s
}

// DiscoverDockerRegistries returns every registry in
// ~/.docker/config.json whose auths entry still holds a plaintext
// credential jit can migrate (mirroring audit.scanDockerConfig's
// detection), sorted for determinism. A missing or unparseable file
// yields nothing rather than an error — a file jit can't parse is also
// one it could never safely rewrite (same reasoning as
// DiscoverTerraformHosts). A registry whose credHelpers entry already
// names a NON-jit helper is skipped too: the plaintext there is a stale
// leftover jit must not take over from a helper the user configured
// deliberately — audit still reports it, and deleting the stale entry by
// hand (or `docker logout` + `docker login`) clears it.
func DiscoverDockerRegistries(home string) ([]string, error) {
	cfg, err := parseDockerConfig(DockerConfigPath(home))
	if err != nil {
		if os.IsNotExist(err) || errors.Is(err, errDockerConfigMalformed) {
			return nil, nil
		}
		return nil, err
	}
	var registries []string
	for registry := range cfg.auths {
		if _, ok := cfg.plaintextCreds(registry); !ok {
			continue
		}
		if h := cfg.credHelpers[registry]; h != "" && h != dockerHelperName {
			continue
		}
		if sanitizeDockerRegistry(registry) == "" {
			continue
		}
		registries = append(registries, registry)
	}
	sort.Strings(registries)
	return registries, nil
}

// upsertDockerProfile merges USERNAME/SECRET -> their vault paths into
// the registry's global profile manifest, preserving any existing
// entries — the same merge-not-overwrite discipline every other Apply*
// here follows. Returns the profile name and manifest path used.
func upsertDockerProfile(v *vault.Vault, serverURL string, creds dockerPlainCreds, meta vault.Meta) (name, manifestPath string, err error) {
	name = DockerProfileName(serverURL)
	if name == "" {
		return "", "", fmt.Errorf("registry address %q sanitizes to nothing usable as a profile name", serverURL)
	}
	globalRoot, err := profile.GlobalRoot()
	if err != nil {
		return "", "", fmt.Errorf("resolving global profile root: %w", err)
	}
	manifestPath, err = profile.Path(globalRoot, name)
	if err != nil {
		return "", "", err
	}

	entries := profile.Profile{}
	switch existing, lerr := profile.LoadFile(manifestPath); {
	case lerr == nil:
		for k, v2 := range existing {
			entries[k] = v2
		}
	case errors.Is(lerr, os.ErrNotExist):
		// no existing profile yet — start fresh
	default:
		return "", "", fmt.Errorf("loading existing profile %s: %w", manifestPath, lerr)
	}

	for varName, value := range map[string]string{"USERNAME": creds.Username, "SECRET": creds.Secret} {
		secretPath := name + "/" + varName
		if err := v.SetWithMeta(secretPath, []byte(value), meta); err != nil {
			return "", "", fmt.Errorf("storing %s in vault: %w", varName, err)
		}
		entries[varName] = secretPath
	}
	if err := writeProfileManifest(manifestPath, entries, nil); err != nil {
		return "", "", fmt.Errorf("writing profile %s: %w", manifestPath, err)
	}
	return name, manifestPath, nil
}

// ApplyDockerRegistry moves registry's credential out of
// ~/.docker/config.json and into v's vault under a home-rooted global
// profile ("docker-<registry>" — docker invokes its credential helper
// from whatever directory a command happens to run in, so the profile
// must resolve independent of cwd, same as AWS/kubeconfig/Terraform),
// writes the docker-credential-jit helper executable, routes the registry
// to jit via a credHelpers entry (claiming the default credsStore too
// when the config had none — see the file's doc comment), and rewrites
// config.json with the plaintext replaced by docker's own empty-object
// marker. Standard ordering: vault writes → profile manifest → backup →
// helper → rewrite the source file; the conflict check (a non-jit
// credHelpers entry) happens before any of it, so a run that can't
// complete never half-mutates.
//
// dedup, if non-nil, makes a run migrating several registries from one
// config.json back the shared file up once — its pristine pre-run
// state — rather than once per registry, so undo restores the original
// rather than the last, most-stripped snapshot. See BackupTracker
// (GAPS.md #65).
func ApplyDockerRegistry(v *vault.Vault, home, registry string, dedup ...*BackupTracker) (DockerMigration, error) {
	var tracker *BackupTracker
	if len(dedup) > 0 {
		tracker = dedup[0]
	}
	configPath := DockerConfigPath(home)
	cfg, err := parseDockerConfig(configPath)
	if err != nil {
		return DockerMigration{}, fmt.Errorf("reading %s: %w", configPath, err)
	}
	creds, ok := cfg.plaintextCreds(registry)
	if !ok {
		return DockerMigration{}, fmt.Errorf("registry %q not found (or has no plaintext credential) in %s", registry, configPath)
	}
	if h := cfg.credHelpers[registry]; h != "" && h != dockerHelperName {
		return DockerMigration{}, fmt.Errorf("%s already routes %q to credential helper %q, jit won't take a registry over from a helper you configured; `docker logout %s` clears the stale plaintext entry instead", configPath, registry, h, registry)
	}

	meta, err := newProvenance(vault.ClassDocker, configPath)
	if err != nil {
		return DockerMigration{}, err
	}
	profileName, manifestPath, err := upsertDockerProfile(v, registry, creds, meta)
	if err != nil {
		return DockerMigration{}, err
	}

	configBackup, err := tracker.backupOnce(v, configPath)
	if err != nil {
		return DockerMigration{}, fmt.Errorf("backing up %s: %w", configPath, err)
	}

	helperPath, err := writeDockerHelper(home)
	if err != nil {
		return DockerMigration{}, err
	}

	claimedStore := cfg.credsStore == ""
	rewritten, err := cfg.marshalMigrated(registry, claimedStore)
	if err != nil {
		return DockerMigration{}, fmt.Errorf("re-encoding %s: %w", configPath, err)
	}
	if err := os.WriteFile(configPath, append(rewritten, '\n'), 0o600); err != nil {
		return DockerMigration{}, fmt.Errorf("writing %s: %w", configPath, err)
	}

	return DockerMigration{
		Registry:            registry,
		ConfigPath:          configPath,
		ConfigBackup:        configBackup,
		HelperPath:          helperPath,
		VaultProfileName:    profileName,
		VaultProfilePath:    manifestPath,
		Variables:           []string{"SECRET", "USERNAME"},
		ClaimedDefaultStore: claimedStore,
	}, nil
}

// writeDockerHelper writes the docker-credential-jit executable — a
// two-line shell wrapper exec-ing this jit binary, since docker discovers
// helpers strictly by executable name on $PATH and jit can't rename
// itself. Same shape and rationale as writeTerraformHelper, including
// unconditional overwrite: the script is jit's own artifact, and a
// rebuilt/moved jit binary should refresh it on the next migrate rather
// than keep exec-ing a stale path.
func writeDockerHelper(home string) (string, error) {
	jitPath, err := resolveJitExecutable()
	if err != nil {
		return "", fmt.Errorf("resolving jit's own executable path: %w", err)
	}
	helperPath := DockerHelperPath(home)
	if err := os.MkdirAll(filepath.Dir(helperPath), 0o700); err != nil {
		return "", fmt.Errorf("creating %s: %w", filepath.Dir(helperPath), err)
	}
	script := fmt.Sprintf("#!/bin/sh\n# Written by jit migrate, Docker credential helper. See `jit docker-credential --help`.\nexec %s docker-credential \"$@\"\n", singleQuote(jitPath))
	if err := os.WriteFile(helperPath, []byte(script), 0o700); err != nil { // #nosec G306 -- must be executable; helper runs as this same user
		return "", fmt.Errorf("writing %s: %w", helperPath, err)
	}
	return helperPath, nil
}

// StoreDockerCredential implements the helper protocol's "store" verb
// (`docker login` after migration): the credential goes into the vault
// and the registry's global profile, exactly as ApplyDockerRegistry would
// have put it — so a re-login (or a first login to a brand-new registry,
// once jit holds the default store) keeps working through jit instead of
// landing a fresh base64 credential back in config.json.
func StoreDockerCredential(v *vault.Vault, serverURL, username, secret string) error {
	if secret == "" {
		return fmt.Errorf("empty secret for registry %q", serverURL)
	}
	if username == "" {
		username = DockerTokenUsername
	}
	// Live `docker login` after migration: no config.json to point at, so
	// class-only provenance (a fresh group, no origin), same shape a
	// re-migrated registry keeps once it already exists in the vault.
	meta, err := newProvenance(vault.ClassDocker, "")
	if err != nil {
		return err
	}
	_, _, err = upsertDockerProfile(v, serverURL, dockerPlainCreds{Username: username, Secret: secret}, meta)
	return err
}

// EraseDockerCredential implements the helper protocol's "erase" verb
// (`docker logout`): removes the registry's credential from the vault and
// its profile manifest. Idempotent — erasing a registry that was never
// stored is a no-op, matching how docker treats a logout with nothing
// saved.
func EraseDockerCredential(v *vault.Vault, serverURL string) error {
	name := DockerProfileName(serverURL)
	if name == "" {
		return nil
	}
	globalRoot, err := profile.GlobalRoot()
	if err != nil {
		return fmt.Errorf("resolving global profile root: %w", err)
	}
	manifestPath, err := profile.Path(globalRoot, name)
	if err != nil {
		return err
	}
	for _, varName := range []string{"USERNAME", "SECRET"} {
		if err := v.Remove(name + "/" + varName); err != nil && !errors.Is(err, vault.ErrNotFound) {
			return err
		}
	}
	if err := os.Remove(manifestPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
