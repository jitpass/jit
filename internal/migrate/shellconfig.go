// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package migrate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jitpass/jit/internal/audit"
	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

// shellConfigFiles mirrors internal/audit/shellconfig.go's own list — kept
// as a separate small copy rather than exporting audit's unexported slice,
// matching this package's existing precedent for .env detection constants
// (see apply.go's comment on envFileNamePattern).
var shellConfigFiles = []string{
	".zshrc",
	".zprofile",
	".bashrc",
	".bash_profile",
	".profile",
}

// exportLinePattern mirrors internal/audit/shellconfig.go's own pattern.
var exportLinePattern = regexp.MustCompile(`^\s*export\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$`)

// jitShellComment marks the line jit migrate inserts above its eval call,
// so a human skimming the file understands why the export is gone.
const jitShellComment = "# jit migrate moved the plaintext secret export(s) below into the vault:"

// ShellConfigMigration describes what jit migrate did to one shell config
// file.
type ShellConfigMigration struct {
	FilePath    string
	BackupPath  string
	ProfileName string
	ProfilePath string
	Variables   []string
}

// ShellConfigPaths returns the fixed set of shell config file paths under
// home jit migrate knows how to convert (the same list DiscoverShellConfigs
// scans), whether or not each one exists. jit migrate path uses it to route
// an explicitly named ~/.zshrc (etc.) to shell-config handling instead of
// the project-file discoveries — a shell config's name matches none of the
// env/tfvars/mcp/npmrc recognizers, so without this a targeted ~/.zshrc
// would silently fall through to "nothing to migrate."
func ShellConfigPaths(home string) []string {
	paths := make([]string, len(shellConfigFiles))
	for i, name := range shellConfigFiles {
		paths[i] = filepath.Join(home, name)
	}
	return paths
}

// DiscoverShellConfigs returns every shell config file under home
// containing at least one secret-shaped `export KEY=value` line jit
// migrate can convert (RFC.md §4 category 1's own file list and pattern —
// see audit.LooksLikeSecretKey). Home-scoped rather than cwd-scoped like
// DiscoverEnvFiles: shell configs always live at a fixed set of paths
// under $HOME regardless of the caller's current directory, so checking
// them isn't the same kind of blast-radius expansion walking the whole
// home directory for arbitrary project files would be.
func DiscoverShellConfigs(home string) ([]string, error) {
	var found []string
	for _, name := range shellConfigFiles {
		path := filepath.Join(home, name)
		lines, err := readLines(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		if len(findSecretExports(lines)) > 0 {
			found = append(found, path)
		}
	}
	sort.Strings(found)
	return found, nil
}

// ApplyShellConfig moves every secret-shaped `export KEY=value` line out of
// path and into v's vault, under a profile stored in the home-rooted
// global profile store (profile.GlobalRoot) — a shell config isn't tied to
// one project directory, so the eval line this leaves behind needs to
// resolve no matter what directory a new shell happens to start in. The
// removed line(s) are replaced with a single `eval "$(jit export
// --profile <name>)"` call. Order matters for safety, same as
// ApplyEnvFile: every vault write and the profile manifest write happen
// before path itself is touched, and path is backed up before being
// rewritten — a mistake here breaks every future shell session, not just
// one file, so this gets a safety net .env migration doesn't need.
//
// Idempotent across repeated runs: a file with no secret-shaped export
// left (already migrated) simply won't be returned by
// DiscoverShellConfigs again, and a second migration adding new secrets to
// an already-migrated file merges into the same profile rather than
// clobbering entries a previous run already moved.
func ApplyShellConfig(v *vault.Vault, path string) (ShellConfigMigration, error) {
	lines, err := readLines(path)
	if err != nil {
		return ShellConfigMigration{}, fmt.Errorf("reading %s: %w", path, err)
	}

	matches := findSecretExports(lines)
	if len(matches) == 0 {
		return ShellConfigMigration{}, fmt.Errorf("%s has no secret-shaped export lines to migrate", path)
	}

	values := make(map[string]string, len(matches))
	removeIdx := make(map[int]bool, len(matches))
	for _, m := range matches {
		values[m.Key] = m.Value // last assignment wins, matching real shell semantics
		removeIdx[m.Index] = true
	}

	profileName := shellProfileName(path)
	home, err := profile.GlobalRoot()
	if err != nil {
		return ShellConfigMigration{}, fmt.Errorf("resolving global profile root: %w", err)
	}
	profilePath, err := profile.Path(home, profileName)
	if err != nil {
		return ShellConfigMigration{}, err
	}

	entries := profile.Profile{}
	switch existing, lerr := profile.LoadFile(profilePath); {
	case lerr == nil:
		for k, v2 := range existing {
			entries[k] = v2
		}
	case errors.Is(lerr, os.ErrNotExist):
		// no existing profile yet — start fresh
	default:
		return ShellConfigMigration{}, fmt.Errorf("loading existing profile %s: %w", profilePath, lerr)
	}

	varNames := make([]string, 0, len(values))
	for name := range values {
		varNames = append(varNames, name)
	}
	sort.Strings(varNames)

	meta, err := newProvenance(vault.ClassShell, path)
	if err != nil {
		return ShellConfigMigration{}, err
	}
	for _, name := range varNames {
		secretPath := profileName + "/" + name
		if err := v.SetWithMeta(secretPath, []byte(values[name]), meta); err != nil {
			return ShellConfigMigration{}, fmt.Errorf("storing %s in vault: %w", name, err)
		}
		entries[name] = secretPath
	}

	if err := writeProfileManifest(profilePath, entries, nil); err != nil {
		return ShellConfigMigration{}, fmt.Errorf("writing profile %s: %w", profilePath, err)
	}

	backupPath, err := backupSecretFile(v, path)
	if err != nil {
		return ShellConfigMigration{}, fmt.Errorf("backing up %s: %w", path, err)
	}

	rewritten := rewriteShellConfigLines(lines, removeIdx, profileName)
	if err := os.WriteFile(path, []byte(strings.Join(rewritten, "\n")), 0o600); err != nil {
		return ShellConfigMigration{}, fmt.Errorf("writing %s: %w", path, err)
	}

	return ShellConfigMigration{
		FilePath:    path,
		BackupPath:  backupPath,
		ProfileName: profileName,
		ProfilePath: profilePath,
		Variables:   varNames,
	}, nil
}

// shellSecretMatch is one secret-shaped export line found in a shell
// config, keyed by its 0-based line index so the rewrite step can remove
// exactly those lines without re-parsing.
type shellSecretMatch struct {
	Index int
	Key   string
	Value string
}

func findSecretExports(lines []string) []shellSecretMatch {
	var matches []shellSecretMatch
	for i, line := range lines {
		m := exportLinePattern.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key := m[1]
		if !audit.LooksLikeSecretKey(key) {
			continue
		}
		matches = append(matches, shellSecretMatch{Index: i, Key: key, Value: unquoteEnvValue(m[2])})
	}
	return matches
}

// hasJitExportLine reports whether lines already contains an eval call
// for profileName, so a second migration round on a file that still has
// leftover secret exports elsewhere doesn't insert a duplicate eval line.
func hasJitExportLine(lines []string, profileName string) bool {
	marker := fmt.Sprintf("jit export --profile %s", profileName)
	for _, l := range lines {
		if strings.Contains(l, marker) {
			return true
		}
	}
	return false
}

func rewriteShellConfigLines(lines []string, removeIdx map[int]bool, profileName string) []string {
	alreadyHasEval := hasJitExportLine(lines, profileName)
	out := make([]string, 0, len(lines))
	inserted := false
	for i, line := range lines {
		if removeIdx[i] {
			if !inserted && !alreadyHasEval {
				out = append(out, jitShellComment, fmt.Sprintf(`eval "$(jit export --profile %s)"`, profileName))
				inserted = true
			}
			continue
		}
		out = append(out, line)
	}
	return out
}

// shellProfileName names the profile after path's own filename (".zshrc"
// -> "zshrc"), not a single shared name across every shell config — two
// different shell files might define the same key name with different
// values, and a shared profile would let one silently clobber the other's
// vault entry.
func shellProfileName(path string) string {
	return strings.TrimPrefix(filepath.Base(path), ".")
}

// readLines reads path and splits it into lines, preserving a trailing
// blank "line" if the file ends with a newline so strings.Join(lines,
// "\n") round-trips the original byte-for-byte when nothing is removed.
func readLines(path string) ([]string, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is one of shellConfigFiles' fixed names under home, or a fixed/discovered MCP config path, never external input
	if err != nil {
		return nil, err
	}
	return strings.Split(string(data), "\n"), nil
}

// vaultPathUnsafeChars sanitizes an absolute filesystem path into
// something backupVaultPath can safely use as a vault path segment
// (vault.sanitizeSecretPath only allows letters, digits, '.', '_', '-',
// and '/' as the segment separator) — a real path can contain spaces or
// other characters that aren't valid there (e.g. macOS's own "~/Library/
// Application Support/..."), so every disallowed run of characters
// collapses to a single "_".
var vaultPathUnsafeChars = regexp.MustCompile(`[^A-Za-z0-9_.\-/]+`)

// backupSecretFile stores path's raw bytes as an ENCRYPTED vault entry
// under the dedicated "_backups/" namespace, instead of backupFile's
// plaintext sibling file — every category that migrates a file holding
// a REAL secret uses this for its pre-rewrite backup (GAPS.md #33).
// Recoverable later exactly like any other secret: `jit vault get
// <the returned path>`.
//
// A real, reported problem: `.env`'s own backup, added for GAPS.md #32
// specifically to close a real recovery gap, immediately created a new
// one — the plaintext `<file>.jit-bak-<ts>` it wrote was itself an
// unencrypted copy of the exact secret jit migrate exists to get OFF
// disk, sitting right next to the live mount indefinitely (never
// cleaned up — "repeated migrations just accumulate more of them" was
// backupFile's own documented behavior), capturable by Time Machine/
// iCloud/any backup or indexing tool. `internal/migrate` already
// rejects that exact exposure for a near-identical case
// (pointerfile.go's rejected just-in-time scheme) — this brought the
// backup mechanism itself in line with that already-stated position,
// for every category, not just .env.
//
// "_backups/" can never collide with a real profile: every real profile
// name in this package is derived from a directory or server name (see
// deriveProfileName, shellProfileName, etc.), never starting with an
// underscore. backupVaultPath's own sanitize+timestamp keeps this
// collision-free and non-overwriting the same way backupFile's sibling
// file naming did.
func backupSecretFile(v *vault.Vault, path string) (string, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- same fixed/discovered path as readLines above
	if err != nil {
		return "", err
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolving %s: %w", path, err)
	}

	// Never overwrite an existing backup entry: the timestamp is
	// second-granular, so two backups of the same file within one second
	// (a migrate immediately followed by `jit migrate undo`'s own
	// pre-restore snapshot, or repeated Apply* calls in a test) would
	// otherwise land on the identical vault path and the later Set would
	// silently destroy the earlier backup's bytes — the one copy the undo
	// path exists to preserve. Bumping the timestamp forward keeps every
	// backup, at worst dating one a second or two later than reality.
	ts := time.Now().Unix()
	vaultPath := backupVaultPath(absPath, ts)
	for {
		exists, exErr := v.Exists(vaultPath)
		if exErr != nil {
			return "", exErr
		}
		if !exists {
			break
		}
		ts++
		vaultPath = backupVaultPath(absPath, ts)
	}

	if err := v.Set(vaultPath, data); err != nil {
		return "", fmt.Errorf("storing backup of %s in vault: %w", path, err)
	}
	// Index it for `jit migrate undo` (undo.go): backupVaultPath's
	// sanitization is lossy, so without this record the original path
	// can't be recovered from the vault path alone.
	if err := appendBackupRecord(v.Root, BackupRecord{OriginalPath: absPath, VaultPath: vaultPath, UnixTS: ts}); err != nil {
		return "", fmt.Errorf("recording backup of %s in the undo index: %w", path, err)
	}
	return vaultPath, nil
}

// backupVaultPath derives backupSecretFile's vault path for absPath —
// kept human-recognizable (the sanitized absolute path is still legible)
// rather than an opaque hash, so `jit vault list` still shows roughly
// what a given backup belongs to.
func backupVaultPath(absPath string, unixTS int64) string {
	safe := vaultPathUnsafeChars.ReplaceAllString(strings.TrimPrefix(absPath, string(filepath.Separator)), "_")
	return fmt.Sprintf("_backups/%s.jit-bak-%d", safe, unixTS)
}
