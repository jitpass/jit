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

	"github.com/jitpass/jit/internal/audit"
	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/vault"
)

// This file is the Streamlit secrets category: .streamlit/secrets.toml,
// the file Streamlit's own docs call "secrets" and have st.secrets read
// directly. It follows npmrc's five-function shape (Path/Discover/Apply/
// VarName/Template) — like npmrc it exists both per-project
// (<project>/.streamlit/secrets.toml) and globally
// (~/.streamlit/secrets.toml), it mixes credentials with settings that
// must survive byte-for-byte, and Streamlit has no credential hook of any
// kind, so a template-based mount is the only migration shape that keeps
// `streamlit run` working unchanged.
//
// Before this category existed the file was audit's promise and migrate's
// dead end: scanStreamlitSecretsFile flagged it as a credential_file with
// remedy "migrate", but no category claimed the path, so it fell through
// to loose-secret classification, judged "mixes a secret with other
// content", and the recommended `jit migrate <path>` answered with a skip
// note — exactly the scan-contradicts-migrate shape design/
// dry-run-refactor.md D5 exists to prevent.

// streamlitDirName / streamlitFileName mirror audit's own two-part gate
// (streamlitSecretsDir/streamlitSecretsFile): "secrets.toml" alone is a
// common name (a Rust config, a Helm values file), while
// ".streamlit/secrets.toml" is unambiguous.
const streamlitDirName = ".streamlit"
const streamlitFileName = "secrets.toml" // #nosec G101 -- a filename, not a credential

// streamlitSectionPattern matches a TOML table header, "[db]" or
// "[[nested.servers]]", capturing the dotted name.
var streamlitSectionPattern = regexp.MustCompile(`^\s*\[+\s*([^\]]+?)\s*\]+\s*$`)

// streamlitAssignPattern matches a bare-key single-line assignment,
// capturing (1) indent, (2) key, (3) the "=" and spacing around it, and
// (4) the raw value with trailing whitespace trimmed. The key charset is
// the same line-oriented TOML subset audit's scanner reads (a dotted or
// quoted key simply doesn't match, on both sides).
var streamlitAssignPattern = regexp.MustCompile(`^(\s*)([A-Za-z_][A-Za-z0-9_-]*)(\s*=\s*)(.+?)\s*$`)

// streamlitQuotedValue matches the only value shape this migrator will
// rewrite: one single-line quoted string with no backslash and no embedded
// quote of its own kind. That restriction is what makes the template
// round-trip provably right — the vaulted value is exactly the bytes
// between the quotes, and mount.FormatTemplate substituting those bytes
// back between the same quotes reproduces the original line and stays
// valid TOML (no escape sequence can appear or be needed). A value that
// needs escaping is left in place; `jit scan` keeps reporting it.
var streamlitQuotedValue = regexp.MustCompile(`^"([^"\\]*)"$|^'([^'\\]*)'$`)

// streamlitVarSanitizer / streamlitMultiUnderscore mirror pypirc's pair:
// turn a section+key into a valid ${VAR_NAME} placeholder component.
var streamlitVarSanitizer = regexp.MustCompile(`[^A-Za-z0-9_]+`)
var streamlitMultiUnderscore = regexp.MustCompile(`_+`)

// StreamlitMigration describes what jit migrate did to one secrets.toml.
type StreamlitMigration struct {
	FilePath     string
	BackupPath   string
	TemplatePath string
	ProfileName  string
	ProfilePath  string
	Variables    []string
	// NamespaceMovedFrom mirrors EnvFileMigration's field of the same name:
	// the profile name this file would have used had the vault not already
	// held another migration's secret there (GAPS.md #55).
	NamespaceMovedFrom string
}

// StreamlitGlobalPath returns the machine-wide secrets file Streamlit
// documents alongside the per-project one: ~/.streamlit/secrets.toml.
func StreamlitGlobalPath(home string) string {
	return filepath.Join(home, streamlitDirName, streamlitFileName)
}

// DiscoverStreamlitSecrets walks root for .streamlit/secrets.toml files
// holding at least one line this migrator can move. Rooting at a project
// directory finds that project's file; rooting at $HOME additionally finds
// the global ~/.streamlit/secrets.toml, which is just the copy that
// happens to sit there — the same one-walk stance audit's
// classifyStreamlitSecrets takes, and unlike npmrc there is no separate
// fixed path to check. WalkDir over one regular file yields just that
// file, which is how an explicitly named secrets.toml routes here too.
func DiscoverStreamlitSecrets(root string) ([]string, error) {
	var found []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// See DiscoverEnvFiles' identical guard: a permission-denied
			// error partway through the tree must skip that path, not
			// abort the whole discovery.
			if path == root {
				return err
			}
			return filepath.SkipDir
		}
		if d.IsDir() {
			if skipDiscoveryDir(root, path, d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		// Regular files only, same rule as audit's walk: an
		// already-mounted FIFO would block the read below forever, and a
		// symlinked secrets.toml must not be rewritten through the link.
		if !d.Type().IsRegular() {
			return nil
		}
		if d.Name() != streamlitFileName || filepath.Base(filepath.Dir(path)) != streamlitDirName {
			return nil
		}
		lines, err := readLines(path)
		if err != nil {
			return nil // unreadable — skip it, the scan keeps reporting it
		}
		if len(findSecretStreamlitLines(lines)) > 0 {
			found = append(found, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking %s: %w", root, err)
	}
	sort.Strings(found)
	return found, nil
}

// ApplyStreamlitSecrets moves every credential-shaped quoted value out of
// a secrets.toml and into v's vault, then replaces the file with a FIFO
// serving a template-substituted reconstruction (mount.FormatTemplate):
// table headers, non-secret settings and comments pass through
// byte-for-byte, only each credential's value is filled in from the vault
// at serve time, inside the original line's own quotes.
//
// profilesRoot follows npmrc's convention: the project directory (the
// parent of .streamlit) for a project file, $HOME for the global file.
// global must be true for exactly ~/.streamlit/secrets.toml — the two get
// different profile names (see deriveStreamlitProfileName).
func ApplyStreamlitSecrets(v *vault.Vault, profilesRoot, path string, global bool) (StreamlitMigration, error) {
	lines, err := readLines(path)
	if err != nil {
		return StreamlitMigration{}, fmt.Errorf("reading %s: %w", path, err)
	}

	matches := findSecretStreamlitLines(lines)
	if len(matches) == 0 {
		return StreamlitMigration{}, fmt.Errorf("%s has no credentials to migrate", path)
	}

	varNames := make([]string, 0, len(matches))
	seenVar := map[string]bool{}
	for _, m := range matches {
		if seenVar[m.VarName] {
			continue // a repeated key; last value wins, as TOML readers do
		}
		seenVar[m.VarName] = true
		varNames = append(varNames, m.VarName)
	}
	sort.Strings(varNames)

	// Position-blind byte substitution (ApplyNetrc's own guard):
	// mount.FormatTemplate fills ${VAR} wherever it appears, so a
	// placeholder already sitting in the file literally would get the real
	// value written into it at serve time, and the mount would no longer
	// round-trip the original bytes. Refuse rather than corrupt.
	joined := strings.Join(lines, "\n")
	for _, name := range varNames {
		if strings.Contains(joined, "${"+name+"}") {
			return StreamlitMigration{}, fmt.Errorf("%s already contains the literal ${%s}, refusing to migrate", path, name)
		}
	}

	// Same merge-and-guard as ApplyEnvFile/ApplyNpmrc: move to "<name>-2"
	// if the vault already holds another migration's value at one of these
	// paths (GAPS.md #55).
	profileName, profilePath, entries, movedFrom, err := claimNamespace(v, profilesRoot, deriveStreamlitProfileName(profilesRoot, global), varNames)
	if err != nil {
		return StreamlitMigration{}, err
	}

	values := map[string]string{}
	for _, m := range matches {
		values[m.VarName] = m.Value
	}
	meta, err := newProvenance(vault.ClassStreamlit, path)
	if err != nil {
		return StreamlitMigration{}, err
	}
	for _, name := range varNames {
		secretPath := profileName + "/" + name
		if err := v.SetWithMeta(secretPath, []byte(values[name]), meta); err != nil {
			return StreamlitMigration{}, fmt.Errorf("storing %s in vault: %w", name, err)
		}
		entries[name] = secretPath
	}

	if err := writeProfileManifest(profilePath, entries, nil); err != nil {
		return StreamlitMigration{}, fmt.Errorf("writing profile %s: %w", profilePath, err)
	}

	backupPath, err := backupSecretFile(v, path)
	if err != nil {
		return StreamlitMigration{}, fmt.Errorf("backing up %s: %w", path, err)
	}

	template := rewriteStreamlitAsTemplate(lines, matches)
	templatePath := strings.TrimSuffix(profilePath, ".yaml") + ".secrets.toml.tmpl"
	if err := os.WriteFile(templatePath, template, 0o600); err != nil {
		return StreamlitMigration{}, fmt.Errorf("writing template %s: %w", templatePath, err)
	}

	if err := mount.CreateFIFO(path); err != nil {
		return StreamlitMigration{}, fmt.Errorf("mounting %s: %w", path, err)
	}

	return StreamlitMigration{
		FilePath:           path,
		BackupPath:         backupPath,
		TemplatePath:       templatePath,
		ProfileName:        profileName,
		ProfilePath:        profilePath,
		Variables:          varNames,
		NamespaceMovedFrom: movedFrom,
	}, nil
}

type streamlitSecretMatch struct {
	Index   int
	Section string
	Key     string
	Value   string // the unquoted value — exactly the bytes between the quotes
	Quote   byte   // the original quote character, '"' or '\''
	VarName string
}

// findSecretStreamlitLines returns every credential line this migrator
// will move, tagged with the TOML table it belongs to so two sections'
// identically named keys can't collide on one variable name (the exact
// collision audit's scanner tolerates for a read-only finding and its own
// doc comment says a migrator must not — see scanStreamlitSecretsFile).
//
// Detection mirrors the scanner's two-signal split through the same
// exported helpers, so the two judge a line the same way: a value matching
// a known vendor format migrates on the value alone; otherwise a
// secret-shaped key name (audit.LooksLikeSecretKey) migrates unless the
// name or value reads as a non-secret. On top of that sits this side's own
// stricter shape rule: only a single-line quoted string with no escapes is
// rewritable provably right (streamlitQuotedValue), so a flagged line
// outside that shape stays in place and keeps its scan finding.
//
// Multi-line strings ("""...""" / ”'...”') are skipped wholesale: a
// line INSIDE one can look exactly like an assignment, and rewriting it
// would corrupt the string.
func findSecretStreamlitLines(lines []string) []streamlitSecretMatch {
	var matches []streamlitSecretMatch
	section := ""
	inMultiline := false
	for i, line := range lines {
		if strings.Count(line, `"""`)%2 == 1 || strings.Count(line, `'''`)%2 == 1 {
			inMultiline = !inMultiline
			continue
		}
		if inMultiline {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if m := streamlitSectionPattern.FindStringSubmatch(line); m != nil {
			section = m[1]
			continue
		}
		m := streamlitAssignPattern.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key, raw := m[2], m[4]
		q := streamlitQuotedValue.FindStringSubmatch(raw)
		if q == nil {
			continue // unquoted, escaped, commented or multi-part — not rewritable provably right
		}
		value, quote := q[1], byte('"')
		if raw[0] == '\'' {
			value, quote = q[2], '\''
		}
		if value == "" || audit.IsAlreadyMasked(value) {
			continue
		}
		if _, _, ok := audit.MatchKnownTokenPattern(value); !ok {
			// The value check ran even though the KEY decides below, which
			// is the point of having it: `foo = "sk-proj-..."` is still a
			// live OpenAI key. From here the weaker name signal carries.
			if !audit.LooksLikeSecretKey(key) || audit.LooksLikeNonSecretName(key) || audit.LooksLikeNonSecretValue(value) {
				continue
			}
		}
		matches = append(matches, streamlitSecretMatch{
			Index:   i,
			Section: section,
			Key:     key,
			Value:   value,
			Quote:   quote,
			VarName: streamlitVarName(section, key),
		})
	}
	// Two DISTINCT section/key pairs can sanitize to one variable name
	// ([my-db] password and [my_db] password both become MY_DB_PASSWORD);
	// disambiguate so each keeps its own vault entry and placeholder.
	// Repeats of one pair still share a name — last-value-wins above.
	identities := make([]string, len(matches))
	base := make([]string, len(matches))
	for i, m := range matches {
		identities[i] = m.Section + "\x00" + m.Key
		base[i] = m.VarName
	}
	for i, name := range assignUniqueVarNames(identities, base) {
		matches[i].VarName = name
	}
	return matches
}

// streamlitVarName builds the placeholder / vault-path name from the table
// and key, e.g. table "db" + key "password" -> "DB_PASSWORD", and a
// top-level key stands alone. Including the table is what keeps two tables
// each holding a "password" from landing on the same vault path — the
// collision pypircVarName folds the section in to avoid, and the one
// audit's own scanner doc flags as unacceptable in a migrator.
func streamlitVarName(section, key string) string {
	name := key
	if section != "" {
		name = section + "_" + key
	}
	upper := strings.ToUpper(name)
	replaced := streamlitVarSanitizer.ReplaceAllString(upper, "_")
	replaced = streamlitMultiUnderscore.ReplaceAllString(replaced, "_")
	trimmed := strings.Trim(replaced, "_")
	if trimmed == "" {
		trimmed = "STREAMLIT_SECRET"
	}
	if trimmed[0] >= '0' && trimmed[0] <= '9' {
		trimmed = "_" + trimmed
	}
	return trimmed
}

// deriveStreamlitProfileName names the profile "streamlit" for the global
// ~/.streamlit/secrets.toml and "streamlit-<project>" for a project's own
// file, mirroring deriveNpmrcProfileName. The project part comes from
// profilesRoot's basename (the directory holding .streamlit), not from a
// relative path — the file's location inside the project is fixed by
// Streamlit, so unlike npmrc there is no subdirectory to encode.
func deriveStreamlitProfileName(profilesRoot string, global bool) string {
	if global {
		return "streamlit"
	}
	part := sanitizeNamePart(filepath.Base(profilesRoot))
	if part == "" {
		return "streamlit"
	}
	return "streamlit-" + part
}

// rewriteStreamlitAsTemplate replaces each credential's value with its
// ${VAR_NAME} placeholder inside the line's original quotes, preserving
// indentation, key and spacing around "=" — and every other line
// byte-for-byte. Serving substitutes the vaulted bytes back between those
// same quotes, which streamlitQuotedValue guarantees is valid TOML (the
// value holds no quote of that kind and no backslash).
func rewriteStreamlitAsTemplate(lines []string, matches []streamlitSecretMatch) []byte {
	byIndex := make(map[int]streamlitSecretMatch, len(matches))
	for _, m := range matches {
		byIndex[m.Index] = m
	}

	out := make([]string, len(lines))
	for i, line := range lines {
		match, ok := byIndex[i]
		if !ok {
			out[i] = line
			continue
		}
		// Capture groups: 1 = indent, 2 = key, 3 = the "=" and spacing.
		// Reusing them keeps `password = "x"` from being normalized to
		// `password="x"`, so a re-migration of an unchanged file
		// reproduces the original formatting exactly.
		m := streamlitAssignPattern.FindStringSubmatch(line)
		q := string(match.Quote)
		out[i] = m[1] + m[2] + m[3] + q + "${" + match.VarName + "}" + q
	}
	return []byte(strings.Join(out, "\n"))
}
