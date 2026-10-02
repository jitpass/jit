// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jitpass/jit/internal/atomicfile"
	"github.com/jitpass/jit/internal/sealstore"
	"github.com/jitpass/jit/internal/vault"
)

// AWS SSO logins, sealed (design/aws-sso-sealed.md). The token cache
// `aws sso login` writes to ~/.aws/sso/cache moves into the vault as one
// value; each SSO profile in ~/.aws/config is rewritten to fetch through
// `jit aws-sso --profile <name>`, which unseals the cache for one run of
// AWS's own `aws configure export-credentials`; the profiles' original
// definitions live in a config file jit owns, the one the inner run reads.

// AWSSSOStorePath is the sealed token cache's vault path (class aws).
const AWSSSOStorePath = "aws-sso/cache"

// AWSSSOLayout is the token cache relative to ~/.aws/sso: the whole cache
// directory is the secret.
var AWSSSOLayout = sealstore.Layout{Secrets: []string{"cache"}}

// AWSSSODir returns ~/.aws/sso, the directory AWSSSOLayout is relative to.
func AWSSSODir(home string) string { return filepath.Join(home, ".aws", "sso") }

// AWSSSOCacheDir returns ~/.aws/sso/cache.
func AWSSSOCacheDir(home string) string { return filepath.Join(AWSSSODir(home), "cache") }

// AWSSSOSealedConfigPath is the config file holding the original SSO
// profile definitions (D2): not secret, but the only copy once the user's
// config is rewritten, so it lives in jit's own root.
func AWSSSOSealedConfigPath(root string) string {
	return filepath.Join(root, "aws-sso", "config")
}

// awsSSORoleKeys are what make botocore's SSO credential provider claim a
// profile (spike Result 2). Removing them hands the profile to
// credential_process; sso_session (or the legacy start URL) stays, so
// `aws sso login --profile` keeps working.
var awsSSORoleKeys = []string{"sso_account_id", "sso_role_name"}

// DiscoverAWSSSOProfiles lists the SSO profiles in ~/.aws/config that use
// the token cache directly: a profile with an SSO role (account or role
// name) and an SSO login (sso_session or sso_start_url). A profile already
// rewritten has no role keys, so it is not found again. Sorted.
func DiscoverAWSSSOProfiles(home string) ([]string, error) {
	_, sections, err := parseINILines(AWSConfigPath(home))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for section, kv := range sections {
		name, ok := awsProfileFromSection(section)
		if !ok {
			continue
		}
		hasRole := kv["sso_account_id"] != "" || kv["sso_role_name"] != ""
		hasLogin := kv["sso_session"] != "" || kv["sso_start_url"] != ""
		if hasRole && hasLogin {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

// awsProfileFromSection inverts awsConfigSectionName: "default" and
// "profile <name>" are profiles; "sso-session x" and "services y" are not.
func awsProfileFromSection(section string) (string, bool) {
	if section == "default" {
		return "default", true
	}
	if name, ok := strings.CutPrefix(section, "profile "); ok && strings.TrimSpace(name) != "" {
		return strings.TrimSpace(name), true
	}
	return "", false
}

// AWSSSOMigration says what ApplyAWSSSO did.
type AWSSSOMigration struct {
	Profiles     []string // the profiles rewritten to credential_process
	ConfigPath   string
	ConfigBackup string   // vault path of ~/.aws/config's backup
	CacheFiles   []string // token cache files moved into the vault
	LoggedOut    bool     // no login was cached; the next `aws sso login` is captured
	SealedConfig string   // the jit-owned copy of the original definitions
	RoleCaches   int      // SSO role-credential files removed from ~/.aws/cli/cache
}

// ApplyAWSSSO seals the given SSO profiles (DiscoverAWSSSOProfiles). In
// order, so that a failure part-way leaves the user where they were:
//
//  1. the token cache is merged into the vault's sealed copy (a later
//     migration keeps sessions sealed earlier) and its files are backed up,
//     linked to the config's backup so undo brings them back together;
//  2. the original definitions (each profile and the sso-sessions it uses)
//     are written to the sealed config;
//  3. ~/.aws/config is backed up and each profile rewritten: role keys
//     out, credential_process in;
//  4. only then the plaintext goes: the token cache files, and the SSO
//     role credentials the CLI cached in ~/.aws/cli/cache.
func ApplyAWSSSO(v *vault.Vault, home string, profiles []string, tracker *BackupTracker) (AWSSSOMigration, error) {
	res := AWSSSOMigration{ConfigPath: AWSConfigPath(home), SealedConfig: AWSSSOSealedConfigPath(v.Root)}
	if len(profiles) == 0 {
		return res, nil
	}
	configPath := AWSConfigPath(home)
	lines, sections, err := parseINILines(configPath)
	if err != nil {
		return res, fmt.Errorf("reading %s: %w", configPath, err)
	}
	for _, p := range profiles {
		kv := sections[awsConfigSectionName(p)]
		if kv == nil || (kv["sso_account_id"] == "" && kv["sso_role_name"] == "") {
			return res, fmt.Errorf("profile %q in %s is not an SSO profile jit can seal", p, configPath)
		}
	}

	// 1. The token cache, into the vault.
	cacheFiles, err := awsSSOCacheFiles(home)
	if err != nil {
		return res, err
	}
	blob, err := mergeAWSSSOCache(v, home)
	if err != nil {
		return res, err
	}
	for _, f := range cacheFiles {
		data, err := os.ReadFile(f) // #nosec G304 -- f is a regular file under ~/.aws/sso/cache, listed by awsSSOCacheFiles
		if err != nil {
			return res, err
		}
		if _, err := storeSecretBackup(v, f, data, backupFlags{restoreWith: append(restorePartners(cacheFiles, f), configPath)}); err != nil {
			return res, err
		}
	}
	if err := StoreAWSSSOCache(v, home, blob); err != nil {
		return res, err
	}

	// 2. The original definitions, into the sealed config.
	if err := writeAWSSSOSealedConfig(v.Root, configPath, lines, sections, profiles); err != nil {
		return res, err
	}

	// 3. The user's config, backed up and rewritten.
	res.ConfigBackup, err = tracker.backupOnceLinking(v, configPath, cacheFiles)
	if err != nil {
		return res, fmt.Errorf("backing up %s: %w", configPath, err)
	}
	jitPath, err := resolveJitExecutable()
	if err != nil {
		return res, fmt.Errorf("resolving jit's own executable path: %w", err)
	}
	for _, p := range profiles {
		section := awsConfigSectionName(p)
		lines = removeINIKeys(lines, section, awsSSORoleKeys)
		command := fmt.Sprintf("%s aws-sso --profile %s", quoteIfNeeded(jitPath), quoteIfNeeded(p))
		lines = upsertINIValue(lines, section, "credential_process", command)
	}
	if err := atomicfile.WriteFileMode(configPath, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		return res, fmt.Errorf("writing %s: %w", configPath, err)
	}
	res.Profiles = profiles

	// 4. The plaintext, gone.
	for _, f := range cacheFiles {
		if err := os.Remove(f); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return res, fmt.Errorf("removing %s (it is vaulted and backed up; delete it by hand): %w", f, err)
		}
	}
	res.CacheFiles = cacheFiles
	res.LoggedOut = sealstore.Empty(blob)
	res.RoleCaches = removeSSORoleCaches(home)
	return res, nil
}

// StoreAWSSSOCache writes the sealed token cache. Used at sealing and by
// every `jit aws-sso` run whose refresh rotated the token (D4). No backup:
// per-file backups are taken at sealing only (D10).
func StoreAWSSSOCache(v *vault.Vault, home string, blob []byte) error {
	meta, err := newProvenance(vault.ClassAWS, AWSSSOCacheDir(home))
	if err != nil {
		return err
	}
	if err := v.SetWithMeta(AWSSSOStorePath, blob, meta); err != nil {
		return fmt.Errorf("storing the AWS SSO login in the vault: %w", err)
	}
	return nil
}

// AWSSSOSealed reports whether the vault holds a sealed AWS SSO cache.
func AWSSSOSealed(v *vault.Vault) (bool, error) {
	return v.Exists(AWSSSOStorePath)
}

// mergeAWSSSOCache returns the vault's sealed cache with whatever the real
// cache holds laid over it (an empty store when nothing is sealed yet).
func mergeAWSSSOCache(v *vault.Vault, home string) ([]byte, error) {
	sealed, err := AWSSSOSealed(v)
	if err != nil {
		return nil, err
	}
	if !sealed {
		return AWSSSOLayout.Pack(AWSSSODir(home))
	}
	blob, err := v.Get(AWSSSOStorePath)
	if err != nil {
		return nil, err
	}
	return AWSSSOLayout.Merge(blob, AWSSSODir(home))
}

// CaptureAWSSSOLogin moves a login `aws sso login` left in the real cache
// into the vault (D5): merged over the sealed copy, then removed from disk.
// Reports whether there was one. The caller holds the run lock.
func CaptureAWSSSOLogin(v *vault.Vault, home string) (bool, error) {
	files, err := awsSSOCacheFiles(home)
	if err != nil || len(files) == 0 {
		return false, err
	}
	blob, err := mergeAWSSSOCache(v, home)
	if err != nil {
		return false, err
	}
	if err := StoreAWSSSOCache(v, home, blob); err != nil {
		return false, err
	}
	for _, f := range files {
		if err := os.Remove(f); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return true, err
		}
	}
	return true, nil
}

// UnsealAWSSSOCache writes the sealed cache back to ~/.aws/sso/cache: for
// `jit migrate undo` and `jit uninstall --restore`, which both want the
// current login rather than the seal-day one (D10). With overwrite, a
// cache file already there (the seal-day copy an undo just restored) is
// replaced; without, it is kept. Returns the files written.
func UnsealAWSSSOCache(v *vault.Vault, home string, overwrite bool) ([]string, error) {
	blob, err := v.Get(AWSSSOStorePath)
	if err != nil {
		return nil, err
	}
	stage, err := os.MkdirTemp(v.Root, "aws-sso-unseal-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(stage) }()
	if err := AWSSSOLayout.Unpack(blob, stage); err != nil {
		return nil, err
	}
	dst := AWSSSOCacheDir(home)
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(stage, "cache"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var written []string
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		target := filepath.Join(dst, e.Name())
		if _, err := os.Lstat(target); err == nil && !overwrite {
			continue
		}
		data, err := os.ReadFile(filepath.Join(stage, "cache", e.Name())) // #nosec G304 -- under the stage dir just unpacked
		if err != nil {
			return written, err
		}
		if err := atomicfile.WriteFileMode(target, data, 0o600); err != nil {
			return written, err
		}
		written = append(written, target)
	}
	return written, nil
}

// IsAWSSSOCacheFile reports whether path is a token-cache file sealing
// moves into the vault.
func IsAWSSSOCacheFile(home, path string) bool {
	return filepath.Dir(path) == AWSSSOCacheDir(home) && strings.HasSuffix(path, ".json")
}

// awsSSOCacheFiles lists the regular *.json files in ~/.aws/sso/cache.
func awsSSOCacheFiles(home string) ([]string, error) {
	dir := AWSSSOCacheDir(home)
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.Type().IsRegular() && strings.HasSuffix(e.Name(), ".json") {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(out)
	return out, nil
}

// removeSSORoleCaches deletes the role credentials the CLI cached for SSO
// profiles (~/.aws/cli/cache/*.json with ProviderType "sso"): derived from
// the login, up to 12 h live, and never written again once the profiles go
// through credential_process. Other cached sessions (assume-role) are not
// this change's to touch. Best effort; returns how many went.
func removeSSORoleCaches(home string) int {
	dir := filepath.Join(home, ".aws", "cli", "cache")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		p := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(p) // #nosec G304 -- a file listed in the CLI's own cache dir
		if err != nil {
			continue
		}
		var doc struct {
			ProviderType string `json:"ProviderType"`
		}
		if json.Unmarshal(data, &doc) == nil && doc.ProviderType == "sso" && os.Remove(p) == nil {
			n++
		}
	}
	return n
}

// writeAWSSSOSealedConfig writes each profile's original section, and the
// sso-session sections they name, to the sealed config: replacing any
// section of the same name a previous migration wrote, keeping the rest.
func writeAWSSSOSealedConfig(root, configPath string, lines []string, sections map[string]map[string]string, profiles []string) error {
	path := AWSSSOSealedConfigPath(root)
	var sealed []string
	if data, err := os.ReadFile(path); err == nil { // #nosec G304 -- jit's own file under its root
		sealed = strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	var names []string
	seen := map[string]bool{}
	for _, p := range profiles {
		section := awsConfigSectionName(p)
		names = append(names, section)
		if s := sections[section]["sso_session"]; s != "" && !seen[s] {
			seen[s] = true
			names = append(names, "sso-session "+s)
		}
	}
	for _, name := range names {
		block := iniSectionBlock(lines, name)
		if block == nil {
			if strings.HasPrefix(name, "sso-session ") {
				return fmt.Errorf("%s names [%s], which it does not define", configPath, name)
			}
			continue
		}
		sealed = removeINISection(sealed, name)
		if len(sealed) > 0 && strings.TrimSpace(sealed[len(sealed)-1]) != "" {
			sealed = append(sealed, "")
		}
		sealed = append(sealed, block...)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return atomicfile.WriteFileMode(path, []byte(strings.Join(sealed, "\n")+"\n"), 0o600)
}

// iniSectionBlock returns section's header and its lines up to the next
// section, trailing blank lines trimmed; nil when the section is absent.
func iniSectionBlock(lines []string, section string) []string {
	var out []string
	in := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			name := strings.TrimSpace(trimmed[1 : len(trimmed)-1])
			if in {
				break
			}
			if name == section {
				in = true
				out = append(out, line)
			}
			continue
		}
		if in {
			out = append(out, line)
		}
	}
	for len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
		out = out[:len(out)-1]
	}
	return out
}

// removeINISection drops section's header and lines.
func removeINISection(lines []string, section string) []string {
	var out []string
	skip := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			skip = strings.TrimSpace(trimmed[1:len(trimmed)-1]) == section
		}
		if !skip {
			out = append(out, line)
		}
	}
	for len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
		out = out[:len(out)-1]
	}
	return out
}
