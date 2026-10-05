// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jitpass/jit/internal/atomicfile"
	"github.com/jitpass/jit/internal/sealstore"
	"github.com/jitpass/jit/internal/vault"
)

// AWS sign-in logins, sealed (design/aws-sso-sealed.md). Two caches, one
// mechanism: the IAM Identity Center tokens `aws sso login` writes to
// ~/.aws/sso/cache, and the console sessions `aws login` writes to
// ~/.aws/login/cache (spike/aws-login-process). Both move into the vault as
// one value; each profile that uses them is rewritten to fetch through
// `jit aws-sso --profile <name>`, which unseals them for one run of AWS's
// own `aws configure export-credentials`; the profiles' original
// definitions live in a config file jit owns, the one the inner run reads.

// AWSSSOStorePath is the sealed token cache's vault path (class aws).
const AWSSSOStorePath = "aws-sso/cache"

// AWSSSOLayout is the sealed store relative to ~/.aws: both sign-in caches,
// whole (sso/cache and login/cache are all those directories hold).
var AWSSSOLayout = sealstore.Layout{Secrets: []string{"sso", "login"}}

// AWSSSODir returns ~/.aws, the directory AWSSSOLayout is relative to.
func AWSSSODir(home string) string { return filepath.Join(home, ".aws") }

// AWSSSOCacheDir returns ~/.aws/sso/cache, `aws sso login`'s token cache.
func AWSSSOCacheDir(home string) string { return filepath.Join(AWSSSODir(home), "sso", "cache") }

// AWSLoginCacheDir returns ~/.aws/login/cache, `aws login`'s session cache.
func AWSLoginCacheDir(home string) string { return filepath.Join(AWSSSODir(home), "login", "cache") }

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

// awsLoginKeys are what make botocore's login provider claim a profile
// (LoginProvider.load: `login_session` present). Unlike SSO, `aws login`
// then refuses the rewritten profile, so re-login goes through
// `jit aws-sso login` (spike/aws-login-process Result 2).
var awsLoginKeys = []string{"login_session"}

// isAWSLoginProfile reports whether a profile's keys make it an `aws login`
// profile rather than an SSO one.
func isAWSLoginProfile(kv map[string]string) bool { return kv["login_session"] != "" }

// DiscoverAWSSSOProfiles lists the profiles in ~/.aws/config that use a
// sign-in cache directly: an SSO profile (an SSO role, sso_account_id or
// sso_role_name, and an SSO login, sso_session or sso_start_url), or an
// `aws login` profile (login_session). A rewritten profile has none of
// those keys, so it is not found again. Sorted.
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
		if hasRole && hasLogin || isAWSLoginProfile(kv) {
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
	Profiles []string // the profiles rewritten to credential_process
	// LoginProfiles are the `aws login` ones among them: `aws login`
	// refuses them now, and `jit aws-sso login` signs them in.
	LoginProfiles []string
	ConfigPath    string
	ConfigBackup  string   // vault path of ~/.aws/config's backup
	CacheFiles    []string // token cache files moved into the vault
	LoggedOut     bool     // no login was cached; the next `aws sso login` is captured
	SealedConfig  string   // the jit-owned copy of the original definitions
	RoleCaches    int      // SSO role-credential files removed from ~/.aws/cli/cache
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
		if kv == nil || (kv["sso_account_id"] == "" && kv["sso_role_name"] == "" && !isAWSLoginProfile(kv)) {
			return res, fmt.Errorf("profile %q in %s is not an SSO or `aws login` profile jit can seal", p, configPath)
		}
	}

	// 1. The logins, into the vault: the whole SSO token cache (its
	// files are named for sessions and start URLs, all the profiles' to
	// share), and the `aws login` session of each profile sealed here.
	// Another profile's `aws login` session stays: that profile still
	// reads it from disk.
	cacheFiles, err := awsSSOCacheFiles(home)
	if err != nil {
		return res, err
	}
	var sessions []string
	for _, p := range profiles {
		if s := sections[awsConfigSectionName(p)]["login_session"]; s != "" {
			sessions = append(sessions, s)
		}
	}
	cacheFiles = append(cacheFiles, awsLoginCacheFiles(home, sessions)...)
	blob, err := mergeAWSStore(v, home, cacheFiles)
	if err != nil {
		return res, err
	}
	for _, f := range cacheFiles {
		data, err := os.ReadFile(f) // #nosec G304 -- f is a regular file in one of the sign-in caches, listed above
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
		if isAWSLoginProfile(sections[section]) {
			res.LoginProfiles = append(res.LoginProfiles, p)
			lines = removeINIKeys(lines, section, awsLoginKeys)
			// `aws login` refuses a profile with credential_process and its
			// error says to remove it, which would unseal the session. Say
			// what to run instead, where the user will look.
			lines = insertINIComment(lines, section, fmt.Sprintf("# jit: this login is sealed in the vault; log in again with `jit aws-sso login --profile %s`", p))
		} else {
			lines = removeINIKeys(lines, section, awsSSORoleKeys)
		}
		command := fmt.Sprintf("%s aws-sso --profile %s", quoteIfNeeded(jitPath), quoteIfNeeded(p))
		lines = upsertINIValue(lines, section, "credential_process", command)
	}
	out := strings.Join(lines, "\n")
	if !strings.HasSuffix(out, "\n") {
		out += "\n" // config files end in one; parseINILines drops it
	}
	if err := writeThroughLink(configPath, []byte(out), 0o600); err != nil {
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
	meta, err := newProvenance(vault.ClassAWSSignIn, AWSSSOCacheDir(home))
	if err != nil {
		return err
	}
	if err := v.SetWithMeta(AWSSSOStorePath, blob, meta); err != nil {
		return fmt.Errorf("storing the AWS sign-in in the vault: %w", err)
	}
	// No history: a signed-out session's refresh token (an `aws login`
	// one has no server-side revoke) must not survive in it
	// (ToolStore.store's reasoning).
	if err := v.ForgetHistory(AWSSSOStorePath); err != nil {
		return err
	}
	if !blobHasAWSSSOToken(blob) {
		// Signed out: the seal-day cache backups go too, or `jit migrate
		// undo` would write the signed-out login back (ToolStore.store's
		// reasoning).
		if err := dropLoginBackups(v, func(p string) bool { return IsAWSSSOCacheFile(home, p) }); err != nil {
			return err
		}
	}
	recordLoginState(awsSSOStatePath(v.Root), blobHasAWSSSOToken(blob))
	return nil
}

func awsSSOStatePath(root string) string { return filepath.Join(root, "aws-sso", "state.json") }

// AWSSSOSignedIn reports, prompt-free, whether the vault holds an AWS SSO
// login: known is false when nothing was ever sealed.
func AWSSSOSignedIn(root string) (signedIn, known bool) {
	return readLoginState(awsSSOStatePath(root))
}

// blobHasAWSSSOToken reports whether a sealed cache holds a token file (an
// access or refresh token), as opposed to only a client registration. An
// SSO token's accessToken is a string; an `aws login` session's is an
// object of credentials beside its refreshToken.
func blobHasAWSSSOToken(blob []byte) bool {
	tr := tar.NewReader(bytes.NewReader(blob))
	for {
		hdr, err := tr.Next()
		if err != nil {
			return false
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr, 1<<20))
		if err != nil {
			return false
		}
		var tok struct {
			AccessToken  json.RawMessage `json:"accessToken"`
			RefreshToken string          `json:"refreshToken"`
		}
		if json.Unmarshal(data, &tok) != nil {
			continue
		}
		if a := strings.TrimSpace(string(tok.AccessToken)); tok.RefreshToken != "" || a != "" && a != "null" && a != `""` {
			return true
		}
	}
}

// AWSSSOSealed reports whether the vault holds a sealed AWS SSO cache.
func AWSSSOSealed(v *vault.Vault) (bool, error) {
	return v.Exists(AWSSSOStorePath)
}

// mergeAWSStore returns the vault's sealed store (an empty one when nothing
// is sealed yet) with files, each in a sign-in cache under ~/.aws, laid
// over it. Nothing else in those caches is taken in.
func mergeAWSStore(v *vault.Vault, home string, files []string) ([]byte, error) {
	var blob []byte
	sealed, err := AWSSSOSealed(v)
	if err != nil {
		return nil, err
	}
	if sealed {
		if blob, err = v.Get(AWSSSOStorePath); err != nil {
			return nil, err
		}
	}
	rels := make([]string, 0, len(files))
	for _, f := range files {
		rel, err := filepath.Rel(AWSSSODir(home), f)
		if err != nil {
			return nil, err
		}
		rels = append(rels, filepath.ToSlash(rel))
	}
	return AWSSSOLayout.MergeFiles(blob, AWSSSODir(home), rels)
}

// CaptureAWSSSOLogin moves a login `aws sso login` left in the real cache
// into the vault (D5): merged over the sealed copy, then removed from disk.
// Reports whether there was one. The caller holds the run lock.
//
// SSO only. `aws login` cannot sign in a sealed profile (it refuses one
// with credential_process), so a session in ~/.aws/login/cache belongs to
// a profile that is not sealed, and reads it from there.
func CaptureAWSSSOLogin(v *vault.Vault, home string) (bool, error) {
	all, err := awsSSOCacheFiles(home)
	if err != nil || len(all) == 0 {
		return false, err
	}
	// Only logins a sealed profile uses: a token file names its start URL,
	// and one for a start URL no sealed profile signs in to belongs to a
	// profile jit has not sealed, which reads it from here (release QA's
	// 2.4.1 list). Client registrations carry no start URL and are taken;
	// botocore registers again if a profile needs one.
	urls := sealedSSOStartURLs(v.Root)
	var files []string
	for _, f := range all {
		if u := cachedStartURL(f); u == "" || urls[u] {
			files = append(files, f)
		}
	}
	if len(files) == 0 {
		return false, nil
	}
	blob, err := mergeAWSStore(v, home, files)
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
	var written []string
	for _, cache := range []string{filepath.Join("sso", "cache"), filepath.Join("login", "cache")} {
		entries, err := os.ReadDir(filepath.Join(stage, cache))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return written, err
		}
		dst := filepath.Join(AWSSSODir(home), cache)
		if err := os.MkdirAll(dst, 0o700); err != nil {
			return written, err
		}
		for _, e := range entries {
			if !e.Type().IsRegular() {
				continue
			}
			target := filepath.Join(dst, e.Name())
			if _, err := os.Lstat(target); err == nil && !overwrite {
				continue
			}
			data, err := os.ReadFile(filepath.Join(stage, cache, e.Name())) // #nosec G304 -- under the stage dir just unpacked
			if err != nil {
				return written, err
			}
			if err := atomicfile.WriteFileMode(target, data, 0o600); err != nil {
				return written, err
			}
			written = append(written, target)
		}
	}
	return written, nil
}

// IsAWSSSOCacheFile reports whether path is a sign-in cache file sealing
// moves into the vault (either cache).
func IsAWSSSOCacheFile(home, path string) bool {
	d := filepath.Dir(path)
	return (d == AWSSSOCacheDir(home) || d == AWSLoginCacheDir(home)) && strings.HasSuffix(path, ".json")
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

// AWSLoginCacheFile is where `aws login` keeps session's tokens: the
// file is named for the SHA-256 of the session (botocore
// generate_login_cache_key), so each profile's file is known exactly.
func AWSLoginCacheFile(home, session string) string {
	sum := sha256.Sum256([]byte(session))
	return filepath.Join(AWSLoginCacheDir(home), hex.EncodeToString(sum[:])+".json")
}

// awsLoginCacheFiles lists the sessions' cache files that are there:
// regular files only, a link or anything else is no login of theirs.
func awsLoginCacheFiles(home string, sessions []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range sessions {
		p := AWSLoginCacheFile(home, s)
		if info, err := os.Lstat(p); err == nil && info.Mode().IsRegular() && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// AWSSealedLoginArgs returns the AWS CLI command that signs a sealed
// profile in again, to run against the sealed config: `aws login` for a
// console-credentials profile, `aws sso login` for an SSO one. remote is
// the flow for a machine whose browser is elsewhere (over SSH).
func AWSSealedLoginArgs(root, home, profile string, remote bool) ([]string, error) {
	_, sections, err := parseINILines(AWSSSOSealedConfigPath(root))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	kv := sections[awsConfigSectionName(profile)]
	switch {
	case kv == nil:
		if _, user, err := parseINILines(AWSConfigPath(home)); err == nil && user[awsConfigSectionName(profile)] != nil {
			return nil, fmt.Errorf("profile %q isn't sealed yet; run `jit migrate ~/.aws/config`", profile)
		}
		return nil, fmt.Errorf("no profile %q in ~/.aws/config", profile)
	case isAWSLoginProfile(kv):
		args := []string{"login", "--profile", profile}
		if remote {
			args = append(args, "--remote")
		}
		return args, nil
	default:
		args := []string{"sso", "login", "--profile", profile}
		if remote {
			args = append(args, "--use-device-code")
		}
		return args, nil
	}
}

// insertINIComment puts comment on the line after section's header, once:
// a second migration of the same profile finds it there and adds nothing.
func insertINIComment(lines []string, section, comment string) []string {
	for _, l := range lines {
		if strings.TrimSpace(l) == comment {
			return lines
		}
	}
	out := make([]string, 0, len(lines)+1)
	for _, line := range lines {
		out = append(out, line)
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") && strings.TrimSpace(t[1:len(t)-1]) == section {
			out = append(out, comment)
		}
	}
	return out
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

// AWSSSOLoginWaiting reports whether ~/.aws/sso/cache holds a login the next
// `jit aws-sso` run would capture: a token for a sealed start URL. A login an
// unsealed profile keeps there is not one.
func AWSSSOLoginWaiting(root, home string) bool {
	files, err := awsSSOCacheFiles(home)
	if err != nil {
		return false
	}
	urls := sealedSSOStartURLs(root)
	for _, f := range files {
		u := cachedStartURL(f)
		// Capture's own rule: a sealed start URL, or a token that names none.
		if u != "" && urls[u] || u == "" && fileHasSSOToken(f) {
			return true
		}
	}
	return false
}

// fileHasSSOToken reports whether a cache file holds a token rather than
// only a client registration.
func fileHasSSOToken(path string) bool {
	data, err := os.ReadFile(path) // #nosec G304 -- a file in ~/.aws/sso/cache
	if err != nil {
		return false
	}
	var tok struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
	}
	return json.Unmarshal(data, &tok) == nil && (tok.AccessToken != "" || tok.RefreshToken != "")
}

// sealedSSOStartURLs is every SSO start URL the sealed config signs in to:
// its sso-session blocks' and its legacy profiles'.
func sealedSSOStartURLs(root string) map[string]bool {
	_, sections, err := parseINILines(AWSSSOSealedConfigPath(root))
	if err != nil {
		return nil
	}
	out := map[string]bool{}
	for _, kv := range sections {
		if u := kv["sso_start_url"]; u != "" {
			out[u] = true
		}
	}
	return out
}

// cachedStartURL is the start URL an SSO cache file's token was issued
// for, "" for a file that names none (a client registration).
func cachedStartURL(path string) string {
	data, err := os.ReadFile(path) // #nosec G304 -- a file in ~/.aws/sso/cache, listed by awsSSOCacheFiles
	if err != nil {
		return ""
	}
	var tok struct {
		StartURL string `json:"startUrl"`
	}
	if json.Unmarshal(data, &tok) != nil {
		return ""
	}
	return tok.StartURL
}
