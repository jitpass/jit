// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/vault"
)

// npmrcLinePattern mirrors internal/audit/credfile.go's own pattern.
var npmrcLinePattern = regexp.MustCompile(`^\s*([^=\s]+)\s*=\s*(.*?)\s*$`)

// npmrcVarSanitizer turns an arbitrary npmrc key (e.g.
// "//registry.npmjs.org/:_authToken") into a valid ${VAR_NAME} placeholder
// name. npmrcMultiUnderscore collapses a run introduced by replacing
// invalid characters immediately adjacent to an original literal
// underscore (e.g. the "/:" before "_authToken" would otherwise leave a
// double "__").
var npmrcVarSanitizer = regexp.MustCompile(`[^A-Za-z0-9_]+`)
var npmrcMultiUnderscore = regexp.MustCompile(`_+`)

// NpmrcMigration describes what jit migrate did to one npmrc file.
type NpmrcMigration struct {
	FilePath     string
	BackupPath   string
	TemplatePath string
	ProfileName  string
	ProfilePath  string
	Variables    []string
	// NamespaceMovedFrom mirrors EnvFileMigration's field of the same
	// name: the profile name this file would have used had the vault not
	// already held another migration's secret there (GAPS.md #55).
	NamespaceMovedFrom string
}

// GlobalNpmrcPath returns the fixed location of npm's global config file.
func GlobalNpmrcPath(home string) string {
	return filepath.Join(home, ".npmrc")
}

// DiscoverNpmrcFiles returns every npmrc file with at least one
// secret-shaped line (an "_authtoken"/"_password" key, mirroring
// audit.ScanCredentialFiles' own heuristic) that jit migrate can convert:
// any project-local .npmrc under cwd's tree — NOT a home-wide walk,
// matching DiscoverEnvFiles/DiscoverMCPConfigs' deliberately narrower
// blast radius for real (non-dry-run) mutation — plus, when includeGlobal
// is true, the global ~/.npmrc (a single well-known path under $HOME
// regardless of which project cwd is, so `jit migrate local` never
// includes it — only a `home` run does; see internal/cli's runMigrate).
func DiscoverNpmrcFiles(home, cwd string, includeGlobal bool) ([]string, error) {
	var found []string
	seen := map[string]bool{}

	check := func(path string) error {
		if seen[path] {
			return nil
		}
		seen[path] = true

		// A file already converted to a FIFO by an earlier migration must
		// never be opened for read here — opening a FIFO for read blocks
		// until a writer (jit agent) connects, which would hang this scan
		// forever on a machine with no agent running. DiscoverEnvFiles
		// guards the same way; the cwd walk below already filters FIFOs
		// via d.Info() before ever calling check, but the fixed
		// globalPath call doesn't go through that walk, so check must
		// guard for itself too.
		info, statErr := os.Lstat(path)
		if statErr != nil {
			if os.IsNotExist(statErr) {
				return nil
			}
			return statErr
		}
		if info.Mode()&fs.ModeNamedPipe != 0 {
			return nil
		}

		lines, err := readLines(path)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if len(findSecretNpmrcLines(lines)) > 0 {
			found = append(found, path)
		}
		return nil
	}

	if includeGlobal {
		if err := check(GlobalNpmrcPath(home)); err != nil {
			return nil, err
		}
	}

	err := filepath.WalkDir(cwd, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// See DiscoverEnvFiles' identical guard: a permission-denied
			// error partway through the tree (~/.Trash, app-sandboxed
			// ~/Library containers, etc. under a real $HOME — GAPS.md
			// #26's home-wide walk) must skip that path, not abort the
			// whole scan.
			if path == cwd {
				return err
			}
			return filepath.SkipDir
		}
		if d.IsDir() {
			if skipDiscoveryDir(cwd, path, d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		// Regular files only, same rule as audit's walk (fsutil.go): an
		// already-mounted FIFO would block check's read forever, and a
		// symlinked .npmrc must not be rewritten through the link.
		if !d.Type().IsRegular() {
			return nil
		}
		if d.Name() != ".npmrc" {
			return nil
		}
		return check(path)
	})
	if err != nil {
		return nil, fmt.Errorf("walking %s: %w", cwd, err)
	}

	sort.Strings(found)
	return found, nil
}

// ApplyNpmrc moves every secret-shaped line ("_authtoken"/"_password" keys)
// out of an npmrc file at path and into v's vault, then replaces path with
// a FIFO serving a template-substituted reconstruction of the original
// file (mount.FormatTemplate): non-secret lines (registry=, save-exact=,
// etc.) pass through byte-for-byte, only the secret lines' values are
// filled in from the vault at serve time. This is unlike ApplyEnvFile,
// where the whole file is secrets — npmrc mixes the two, so a
// dotenv-style "regenerate everything from the vault" mount would either
// lose non-secret settings or wrongly treat them as secrets.
//
// profilesRoot follows the same convention callers already use for
// .env/shell-config: pass the home directory for the global ~/.npmrc
// (npm's exec context isn't tied to any project directory jit would
// know), or the current project root for a project-local .npmrc (which,
// unlike shell-config/MCP, IS naturally tied to the project it's found
// in, the same way a .env file is). global must be true for exactly the
// global ~/.npmrc — profilesRoot alone can't distinguish it from a
// project rooted at $HOME, and the two get different profile names (see
// deriveNpmrcProfileName).
func ApplyNpmrc(v *vault.Vault, profilesRoot, path string, global bool) (NpmrcMigration, error) {
	lines, err := readLines(path)
	if err != nil {
		return NpmrcMigration{}, fmt.Errorf("reading %s: %w", path, err)
	}

	matches := findSecretNpmrcLines(lines)
	if len(matches) == 0 {
		return NpmrcMigration{}, fmt.Errorf("%s has no secret-shaped npmrc lines to migrate", path)
	}

	varNames := make([]string, 0, len(matches))
	seenVar := map[string]bool{}
	for _, m := range matches {
		if seenVar[m.VarName] {
			continue // duplicate key within this file (shell semantics: last wins, already reflected in Value)
		}
		seenVar[m.VarName] = true
		varNames = append(varNames, m.VarName)
	}
	sort.Strings(varNames)

	// Position-blind byte substitution (ApplyNetrc's own guard): a ${VAR}
	// already in the file literally would get the real token filled into it
	// at serve time too, so the mount would no longer round-trip the
	// original bytes. Refuse rather than corrupt.
	joined := strings.Join(lines, "\n")
	for _, name := range varNames {
		if strings.Contains(joined, "${"+name+"}") {
			return NpmrcMigration{}, fmt.Errorf("%s already contains the literal ${%s}, refusing to migrate", path, name)
		}
	}

	// Same merge-and-guard as ApplyEnvFile: load whatever the target
	// profile already holds, and move to "<name>-2"/"-3" if the vault
	// already holds another migration's value at one of these paths
	// (GAPS.md #55) — npm auth tokens are especially collision-prone,
	// since two projects using the same registry host derive the
	// identical variable name.
	profileName, profilePath, entries, movedFrom, err := claimNamespace(v, profilesRoot, deriveNpmrcProfileName(profilesRoot, path, global), varNames)
	if err != nil {
		return NpmrcMigration{}, err
	}

	values := map[string]string{}
	for _, m := range matches {
		values[m.VarName] = m.Value
	}
	meta, err := newProvenance(vault.ClassNpmrc, path)
	if err != nil {
		return NpmrcMigration{}, err
	}
	for _, name := range varNames {
		secretPath := profileName + "/" + name
		if err := v.SetWithMeta(secretPath, []byte(values[name]), meta); err != nil {
			return NpmrcMigration{}, fmt.Errorf("storing %s in vault: %w", name, err)
		}
		entries[name] = secretPath
	}

	if err := writeProfileManifest(profilePath, entries, nil); err != nil {
		return NpmrcMigration{}, fmt.Errorf("writing profile %s: %w", profilePath, err)
	}

	backupPath, err := backupSecretFile(v, path)
	if err != nil {
		return NpmrcMigration{}, fmt.Errorf("backing up %s: %w", path, err)
	}

	template := rewriteNpmrcAsTemplate(lines, matches)
	templatePath := strings.TrimSuffix(profilePath, ".yaml") + ".npmrc.tmpl"
	if err := os.WriteFile(templatePath, template, 0o600); err != nil {
		return NpmrcMigration{}, fmt.Errorf("writing template %s: %w", templatePath, err)
	}

	if err := mount.CreateFIFO(path); err != nil {
		return NpmrcMigration{}, fmt.Errorf("mounting %s: %w", path, err)
	}

	return NpmrcMigration{
		FilePath:           path,
		BackupPath:         backupPath,
		TemplatePath:       templatePath,
		ProfileName:        profileName,
		ProfilePath:        profilePath,
		Variables:          varNames,
		NamespaceMovedFrom: movedFrom,
	}, nil
}

type npmrcSecretMatch struct {
	Index   int
	Key     string
	Value   string
	VarName string
}

func findSecretNpmrcLines(lines []string) []npmrcSecretMatch {
	var matches []npmrcSecretMatch
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		m := npmrcLinePattern.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key := m[1]
		lowerKey := strings.ToLower(key)
		if !strings.Contains(lowerKey, "_authtoken") && !strings.Contains(lowerKey, "_password") {
			continue
		}
		matches = append(matches, npmrcSecretMatch{
			Index:   i,
			Key:     key,
			Value:   unquoteEnvValue(m[2]),
			VarName: npmrcVarName(key),
		})
	}
	// Two DISTINCT keys can sanitize to one variable name
	// ("//reg.example.com/:_authToken" and "//reg.example.com:_authToken"
	// both become REG_EXAMPLE_COM_AUTHTOKEN); disambiguate so each keeps its
	// own vault entry and placeholder. A repeated key still shares a name —
	// ApplyNpmrc's last-value-wins handles those, matching npm itself.
	identities := make([]string, len(matches))
	base := make([]string, len(matches))
	for i, m := range matches {
		identities[i] = m.Key
		base[i] = m.VarName
	}
	for i, name := range assignUniqueVarNames(identities, base) {
		matches[i].VarName = name
	}
	return matches
}

// npmrcVarName turns an npmrc key into a valid ${VAR_NAME} placeholder /
// vault-path-safe name, e.g. "//registry.npmjs.org/:_authToken" ->
// "REGISTRY_NPMJS_ORG_AUTHTOKEN".
func npmrcVarName(key string) string {
	upper := strings.ToUpper(key)
	replaced := npmrcVarSanitizer.ReplaceAllString(upper, "_")
	replaced = npmrcMultiUnderscore.ReplaceAllString(replaced, "_")
	trimmed := strings.Trim(replaced, "_")
	if trimmed == "" {
		trimmed = "NPM_SECRET"
	}
	if trimmed[0] >= '0' && trimmed[0] <= '9' {
		trimmed = "_" + trimmed
	}
	return trimmed
}

// rewriteNpmrcAsTemplate replaces each secret line's value with its
// ${VAR_NAME} placeholder, keeping the original key= prefix and every
// non-secret line untouched.
func rewriteNpmrcAsTemplate(lines []string, matches []npmrcSecretMatch) []byte {
	varByIndex := make(map[int]string, len(matches))
	for _, m := range matches {
		varByIndex[m.Index] = m.VarName
	}

	out := make([]string, len(lines))
	for i, line := range lines {
		if varName, ok := varByIndex[i]; ok {
			m := npmrcLinePattern.FindStringSubmatch(line)
			out[i] = m[1] + "=${" + varName + "}"
			continue
		}
		out[i] = line
	}
	return []byte(strings.Join(out, "\n"))
}

// deriveNpmrcProfileName names the resulting profile "npmrc" for the
// global ~/.npmrc (a machine singleton — global says which file this is,
// since profilesRoot alone can't distinguish it from a project rooted at
// $HOME), "npmrc-<project-dir-name>" for a project-local .npmrc right at
// the project root (e.g. ~/Documents/notion/.npmrc -> "npmrc-notion" —
// the same directory-basename rule as deriveProfileName, and for the same
// GAPS.md #55 reason: a bare "npmrc" here put every project's auth token
// at the identical machine-global vault path, e.g.
// npmrc/REGISTRY_NPMJS_ORG_AUTHTOKEN, one shared registry host away from
// silently overwriting another project's token), or
// "npmrc-<relative-path>" for one nested deeper — always "npmrc"-prefixed
// so it can never collide with a same-location .env's profile name.
func deriveNpmrcProfileName(profilesRoot, path string, global bool) string {
	if global {
		return "npmrc"
	}
	rel, err := filepath.Rel(profilesRoot, filepath.Dir(path))
	part := ""
	if err == nil && rel != "." {
		part = sanitizeNamePart(strings.ReplaceAll(filepath.ToSlash(rel), "/", "-"))
	}
	if part == "" {
		part = sanitizeNamePart(filepath.Base(profilesRoot))
	}
	if part == "" {
		return "npmrc"
	}
	return "npmrc-" + part
}
