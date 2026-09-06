// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

// Cargo registry migration (RFC.md Pillar III Tier 2, same shape as
// Terraform's credentials_helper): `cargo login` stores a plain publish
// token in ~/.cargo/credentials.toml. Cargo's stable credential-provider
// mechanism (1.74+) is the native hook: a cargo-credential-jit wrapper
// exec'ing `jit cargo-credential` (the JSON protocol over stdin/stdout),
// registered LAST in [registry] global-credential-providers so it takes
// precedence — spike/cargo-credential-provider/FINDINGS.md verified every
// protocol shape empirically, including that later entries win, that
// `cargo login`/`logout` route through the provider (so a re-login lands
// in the vault, never back in the plaintext file), and that a not-found
// answer falls back to `cargo:token` cleanly for unmigrated registries.

// cargoProfilePrefix namespaces the global vault profile for a registry:
// "cargo-crates-io", "cargo-<name>". Global-store because cargo invokes
// its provider from whatever directory a build happens to use, same
// reasoning as terraform's.
const cargoProfilePrefix = "cargo-"

// cargoCratesIOName is the registry name cargo itself reserves for
// crates.io — the `[registry]` table in credentials.toml — and the name
// the credential-provider protocol reports for it.
const cargoCratesIOName = "crates-io"

// CargoMigration describes what jit migrate did to one registry's token.
type CargoMigration struct {
	Registry          string
	CredentialsPath   string // the file the token was found in
	CredentialsBackup string
	ConfigPath        string
	ConfigBackup      string // "" when ~/.cargo/config.toml didn't exist before this run
	HelperPath        string
	VaultProfileName  string // "cargo-<registry>"
	VaultProfilePath  string
	Variables         []string
}

// CargoCredentialPaths returns the two files cargo reads a registry token
// from: credentials.toml, and the pre-1.39 bare "credentials" it still
// honors. Mirrors audit's cargoCredentialPaths (scanCargoCredentials) —
// cargo only reads the first that exists, but a stale copy in the other
// is still a plaintext credential, so migration strips both.
func CargoCredentialPaths(home string) []string {
	return []string{
		filepath.Join(home, ".cargo", "credentials.toml"),
		filepath.Join(home, ".cargo", "credentials"),
	}
}

// CargoConfigPath returns ~/.cargo/config.toml, where the
// credential-provider registration lives.
func CargoConfigPath(home string) string {
	return filepath.Join(home, ".cargo", "config.toml")
}

// CargoHelperPath returns where the wrapper executable lives. Unlike
// Terraform (which discovers helpers by name in a fixed plugin dir),
// cargo takes the provider as a path in config.toml, so the wrapper sits
// beside cargo's own files in ~/.cargo. The cargo-credential-<name>
// naming follows cargo's convention for provider executables.
func CargoHelperPath(home string) string {
	return filepath.Join(home, ".cargo", "cargo-credential-jit")
}

// cargoSectionPattern matches the two token-holding table headers
// credentials.toml uses: [registry] (crates.io) and [registries.<name>].
var cargoSectionPattern = regexp.MustCompile(`^\s*\[\s*(registry|registries\.([A-Za-z0-9_-]+))\s*\]\s*$`)

// cargoTokenLinePattern matches the `token = "..."` line within a table.
// Both TOML string forms: basic ("...") and literal ('...') — audit's
// unquote strips either, so migrate accepting only one would flag-but-
// refuse a single-quoted token (the D5 divergence this category exists to
// close).
var cargoTokenLinePattern = regexp.MustCompile(`^\s*token\s*=\s*(?:"([^"]*)"|'([^']*)')\s*$`)

// cargoRegistryToken is one registry's token and where it was found.
type cargoRegistryToken struct {
	Registry string // "crates-io" or the [registries.<name>] name
	Token    string
	Path     string // which credentials file held it
	Line     int    // 0-based line index in that file
}

// findCargoTokens parses one credentials file line-orientedly (the same
// line-oriented TOML subset audit's scanCargoCredentialFile reads via
// parseINISections) and returns every non-empty registry token in it.
func findCargoTokens(path string) ([]cargoRegistryToken, error) {
	lines, err := readLines(path)
	if err != nil {
		return nil, err
	}
	var out []cargoRegistryToken
	registry := ""
	for i, line := range lines {
		if m := cargoSectionPattern.FindStringSubmatch(line); m != nil {
			if m[2] != "" {
				registry = m[2]
			} else {
				registry = cargoCratesIOName
			}
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(line), "[") {
			registry = "" // some other table — its keys are not registry tokens
			continue
		}
		if registry == "" {
			continue
		}
		m := cargoTokenLinePattern.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		token := m[1]
		if token == "" {
			token = m[2] // the single-quoted (TOML literal string) form
		}
		if token == "" {
			continue
		}
		out = append(out, cargoRegistryToken{Registry: registry, Token: token, Path: path, Line: i})
	}
	return out, nil
}

// DiscoverCargoRegistries returns every registry name with a non-empty
// token in either cargo credentials file, sorted for determinism. A
// missing file yields nothing; cargo reads the first file that exists, so
// when both hold a token for one registry the first file's value is the
// live one and wins (findCargoTokensAll keeps that order).
func DiscoverCargoRegistries(home string) ([]string, error) {
	tokens, err := findCargoTokensAll(home)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var names []string
	for _, t := range tokens {
		if !seen[t.Registry] {
			seen[t.Registry] = true
			names = append(names, t.Registry)
		}
	}
	sort.Strings(names)
	return names, nil
}

func findCargoTokensAll(home string) ([]cargoRegistryToken, error) {
	var all []cargoRegistryToken
	for _, path := range CargoCredentialPaths(home) {
		// Lstat + IsRegular before reading, the same guard every Discover
		// here applies: a FIFO from an earlier migration must never be
		// opened for read (it would block forever with no agent writing).
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		tokens, err := findCargoTokens(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		all = append(all, tokens...)
	}
	return all, nil
}

// cargoProvidersPattern finds an existing global-credential-providers
// line in ~/.cargo/config.toml. Cargo allows a LIST of providers, but
// merging jit's entry into someone's hand-written TOML array by string
// surgery is exactly the kind of edit that can't be done provably right
// line-orientedly — so like Terraform's one-helper conflict, an existing
// configuration that isn't jit's own is a hard stop with instructions,
// never a silent rewrite.
var cargoProvidersPattern = regexp.MustCompile(`(?m)^\s*global-credential-providers\s*=\s*(.*)$`)

// checkCargoConfigConflict inspects ~/.cargo/config.toml before anything
// is mutated: returns the error to fail with if a provider list jit
// didn't write is already configured, and whether jit's own line is
// already present (a re-run — idempotent, nothing to add).
func checkCargoConfigConflict(configPath, helperPath string) (alreadyInstalled bool, err error) {
	data, err := os.ReadFile(configPath) // #nosec G304 -- fixed ~/.cargo path, not external input
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", configPath, err)
	}
	m := cargoProvidersPattern.FindSubmatch(data)
	if m == nil {
		return false, nil
	}
	if strings.Contains(string(m[1]), helperPath) {
		return true, nil
	}
	return false, fmt.Errorf("%s already configures global-credential-providers, so jit won't rewrite it; add %q as the LAST entry yourself (last wins) if you want jit to serve these tokens", configPath, helperPath)
}

// upsertCargoProfile merges TOKEN -> its vault path into the registry's
// global profile manifest, the same merge-not-overwrite discipline
// upsertTerraformProfile follows.
func upsertCargoProfile(v *vault.Vault, registry string, token []byte, meta vault.Meta) (name, manifestPath, secretPath string, err error) {
	name = cargoProfilePrefix + registry
	globalRoot, err := profile.GlobalRoot()
	if err != nil {
		return "", "", "", fmt.Errorf("resolving global profile root: %w", err)
	}
	manifestPath, err = profile.Path(globalRoot, name)
	if err != nil {
		return "", "", "", err
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
		return "", "", "", fmt.Errorf("loading existing profile %s: %w", manifestPath, lerr)
	}

	secretPath = name + "/TOKEN"
	if err := v.SetWithMeta(secretPath, token, meta); err != nil {
		return "", "", "", fmt.Errorf("storing token in vault: %w", err)
	}
	entries["TOKEN"] = secretPath
	if err := writeProfileManifest(manifestPath, entries, nil); err != nil {
		return "", "", "", fmt.Errorf("writing profile %s: %w", manifestPath, err)
	}
	return name, manifestPath, secretPath, nil
}

// ApplyCargoRegistry moves one registry's token out of cargo's
// credentials file(s) and into v's vault under a home-rooted global
// profile ("cargo-<registry>"), writes the cargo-credential-jit wrapper,
// registers it in ~/.cargo/config.toml, and strips the token line(s) from
// every credentials file that held one. Standard ordering: conflict check
// first, then vault writes -> profile manifest -> backups -> wiring ->
// rewrite the source files, so a run that can't complete never
// half-mutates.
//
// dedup, if non-nil, makes a run migrating several registries back each
// shared file up once, at its pristine pre-run state (BackupTracker,
// GAPS.md #65).
func ApplyCargoRegistry(v *vault.Vault, home, registry string, dedup ...*BackupTracker) (CargoMigration, error) {
	var tracker *BackupTracker
	if len(dedup) > 0 {
		tracker = dedup[0]
	}

	tokens, err := findCargoTokensAll(home)
	if err != nil {
		return CargoMigration{}, err
	}
	var live *cargoRegistryToken
	for i := range tokens {
		if tokens[i].Registry == registry {
			live = &tokens[i]
			break // first file wins — the copy cargo actually reads
		}
	}
	if live == nil {
		return CargoMigration{}, fmt.Errorf("registry %q not found (or has no token) in %s", registry, CargoCredentialPaths(home)[0])
	}

	configPath := CargoConfigPath(home)
	helperPath := CargoHelperPath(home)
	// The provider registration is a whitespace-split string in cargo's
	// config, so a path containing whitespace cannot be registered at all.
	// Fail loud before mutating anything rather than write a config cargo
	// would misparse.
	if strings.ContainsAny(helperPath, " \t") {
		return CargoMigration{}, fmt.Errorf("cargo's credential-provider config splits on whitespace and %q contains it; jit can't register a provider from this home directory", helperPath)
	}
	alreadyInstalled, err := checkCargoConfigConflict(configPath, helperPath)
	if err != nil {
		return CargoMigration{}, err
	}

	meta, err := newProvenance(vault.ClassCargo, live.Path)
	if err != nil {
		return CargoMigration{}, err
	}
	profileName, manifestPath, _, err := upsertCargoProfile(v, registry, []byte(live.Token), meta)
	if err != nil {
		return CargoMigration{}, err
	}

	// ~/.cargo/config.toml is shared across every registry in this run and
	// may not exist yet — same discipline as ~/.terraformrc: back it up
	// once at its pristine state if it existed; if jit creates it, record
	// it for removal on undo.
	configHandled := tracker.alreadyHandled(configPath)
	_, configStatErr := os.Stat(configPath)
	configExisted := configStatErr == nil

	// Undo linkage (BackupRecord.RestoreWith): cargo is the category where
	// restoring the credentials file ALONE is silently ineffective — jit's
	// provider registered in config.toml outranks credentials.toml (later
	// wins, spike finding 2), so cargo would keep fetching the stale vault
	// token and the "restored" file would never be read. Terraform has the
	// opposite precedence (a static credentials entry beats the helper),
	// which is why its records need no link. The link is recorded when this
	// run touches config.toml (appends the provider line, creates the file,
	// or an earlier registry in the run already handled it); a config left
	// untouched because a PREVIOUS run registered jit must not be yanked
	// back to that older backup by this run's undo.
	var credLink []string
	if !alreadyInstalled || configHandled {
		credLink = []string{configPath}
	}
	var credFiles []string
	for _, t := range tokens {
		if !slices.Contains(credFiles, t.Path) {
			credFiles = append(credFiles, t.Path)
		}
	}

	credBackup, err := tracker.backupOnceLinking(v, live.Path, credLink)
	if err != nil {
		return CargoMigration{}, fmt.Errorf("backing up %s: %w", live.Path, err)
	}

	var configBackup string
	if configExisted && !configHandled {
		configBackup, err = tracker.backupOnceLinking(v, configPath, credFiles)
		if err != nil {
			return CargoMigration{}, fmt.Errorf("backing up %s: %w", configPath, err)
		}
	}

	if err := writeCargoHelper(home); err != nil {
		return CargoMigration{}, err
	}
	if !alreadyInstalled {
		if err := appendCargoProviders(configPath, helperPath); err != nil {
			return CargoMigration{}, err
		}
	}
	if !configExisted && !configHandled {
		absConfig, err := filepath.Abs(configPath)
		if err != nil {
			return CargoMigration{}, fmt.Errorf("resolving %s: %w", configPath, err)
		}
		if err := RecordCreatedFile(v.Root, absConfig); err != nil {
			return CargoMigration{}, fmt.Errorf("recording created %s in the undo index: %w", configPath, err)
		}
		tracker.markCreated(configPath)
	}

	// Strip the registry's token line from EVERY credentials file holding
	// one — cargo reads the first file that exists, but the stale copy in
	// the other is the same plaintext credential.
	for _, t := range tokens {
		if t.Registry != registry {
			continue
		}
		if _, err := tracker.backupOnceLinking(v, t.Path, credLink); err != nil {
			return CargoMigration{}, fmt.Errorf("backing up %s: %w", t.Path, err)
		}
		if err := removeCargoTokenLine(t.Path, registry); err != nil {
			return CargoMigration{}, err
		}
	}

	return CargoMigration{
		Registry:          registry,
		CredentialsPath:   live.Path,
		CredentialsBackup: credBackup,
		ConfigPath:        configPath,
		ConfigBackup:      configBackup,
		HelperPath:        helperPath,
		VaultProfileName:  profileName,
		VaultProfilePath:  manifestPath,
		Variables:         []string{"TOKEN"},
	}, nil
}

// writeCargoHelper writes the cargo-credential-jit executable — a
// two-line shell wrapper exec-ing this jit binary, the same shape as
// terraform-credentials-jit and for the same reason: the provider is an
// executable of its own, and jit can't rename itself. Overwrites
// unconditionally so a rebuilt/moved jit refreshes it on the next
// migrate.
func writeCargoHelper(home string) error {
	jitPath, err := resolveJitExecutable()
	if err != nil {
		return fmt.Errorf("resolving jit's own executable path: %w", err)
	}
	helperPath := CargoHelperPath(home)
	if err := os.MkdirAll(filepath.Dir(helperPath), 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(helperPath), err)
	}
	script := fmt.Sprintf("#!/bin/sh\n# Written by jit migrate, cargo credential provider. See `jit cargo-credential --help`.\nexec %s cargo-credential \"$@\"\n", singleQuote(jitPath))
	if err := os.WriteFile(helperPath, []byte(script), 0o700); err != nil { // #nosec G306 -- must be executable; helper runs as this same user
		return fmt.Errorf("writing %s: %w", helperPath, err)
	}
	return nil
}

// appendCargoProviders registers jit's provider in ~/.cargo/config.toml:
// `global-credential-providers = ["cargo:token", "<helper>"]` under the
// [registry] table. cargo:token stays FIRST so an unmigrated registry's
// credentials.toml token keeps working (jit answers not-found and cargo
// falls back — spike finding 6); jit sits LAST because later entries take
// precedence (finding 2), which also routes every future `cargo login`
// into the vault instead of a plaintext file.
//
// If a [registry] table already exists the key is inserted right after
// its header; otherwise the table is appended. Callers must have already
// run checkCargoConfigConflict, so the key itself is known absent.
func appendCargoProviders(configPath, helperPath string) error {
	keyLine := fmt.Sprintf("global-credential-providers = [\"cargo:token\", %q]", helperPath)

	data, err := os.ReadFile(configPath) // #nosec G304 -- fixed ~/.cargo path, not external input
	if os.IsNotExist(err) {
		if mkErr := os.MkdirAll(filepath.Dir(configPath), 0o700); mkErr != nil {
			return fmt.Errorf("creating %s: %w", filepath.Dir(configPath), mkErr)
		}
		content := "[registry]\n" + keyLine + "\n"
		if wErr := os.WriteFile(configPath, []byte(content), 0o600); wErr != nil {
			return fmt.Errorf("writing %s: %w", configPath, wErr)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading %s: %w", configPath, err)
	}

	lines := strings.Split(string(data), "\n")
	inserted := false
	for i, line := range lines {
		if strings.TrimSpace(line) == "[registry]" {
			lines = append(lines[:i+1], append([]string{keyLine}, lines[i+1:]...)...)
			inserted = true
			break
		}
	}
	content := strings.Join(lines, "\n")
	if !inserted {
		if content != "" && !strings.HasSuffix(content, "\n") {
			content += "\n"
		}
		if content != "" {
			content += "\n"
		}
		content += "[registry]\n" + keyLine + "\n"
	}
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil { // #nosec G703 -- fixed ~/.cargo path, not external input
		return fmt.Errorf("writing %s: %w", configPath, err)
	}
	return nil
}

// removeCargoTokenLine rewrites one credentials file with the named
// registry's token line(s) removed and every other byte untouched. The
// table header stays even if now empty — harmless to cargo, and a smaller
// diff for the user to review.
func removeCargoTokenLine(path, registry string) error {
	lines, err := readLines(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	var out []string
	current := ""
	for _, line := range lines {
		if m := cargoSectionPattern.FindStringSubmatch(line); m != nil {
			if m[2] != "" {
				current = m[2]
			} else {
				current = cargoCratesIOName
			}
		} else if strings.HasPrefix(strings.TrimSpace(line), "[") {
			current = ""
		} else if current == registry && cargoTokenLinePattern.MatchString(line) {
			continue // the migrated token — the vault holds it now
		}
		out = append(out, line)
	}
	if err := os.WriteFile(path, []byte(strings.Join(out, "\n")), 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// StoreCargoToken implements the provider protocol's "login" kind
// (`cargo login` after migration): the token goes into the vault and the
// registry's global profile, so a re-login keeps working through jit
// instead of landing a fresh plaintext token in credentials.toml.
func StoreCargoToken(v *vault.Vault, registry, token string) error {
	if token == "" {
		return fmt.Errorf("empty token for registry %q", registry)
	}
	// Live `cargo login` after migration: no credentials file to point at,
	// so class-only provenance (fresh group, no origin) — same shape as
	// StoreTerraformToken.
	meta, err := newProvenance(vault.ClassCargo, "")
	if err != nil {
		return err
	}
	_, _, _, err = upsertCargoProfile(v, registry, []byte(token), meta)
	return err
}

// ForgetCargoToken implements the provider protocol's "logout" kind:
// removes the registry's token from the vault and its profile manifest.
// Idempotent, matching ForgetTerraformToken.
func ForgetCargoToken(v *vault.Vault, registry string) error {
	name := cargoProfilePrefix + registry
	globalRoot, err := profile.GlobalRoot()
	if err != nil {
		return fmt.Errorf("resolving global profile root: %w", err)
	}
	manifestPath, err := profile.Path(globalRoot, name)
	if err != nil {
		return err
	}
	if err := v.Remove(name + "/TOKEN"); err != nil && !errors.Is(err, vault.ErrNotFound) {
		return err
	}
	if err := os.Remove(manifestPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
