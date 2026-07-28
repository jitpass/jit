// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/vault"
)

// This file is the ~/.pypirc category: the Python packaging counterpart to
// npmrc's registry auth token. It follows npmrc's five-function shape
// (Path/Discover/Apply/VarName/Template) rather than sharing an abstraction
// with it, matching how every other category here is written — the parts that
// genuinely generalize (claimNamespace, newProvenance, writeProfileManifest,
// mount.FormatTemplate) are already shared helpers, and what's left is the
// format parsing, which is exactly what differs. npmrc is flat key=value,
// .netrc is a whitespace token stream, .pypirc is sectioned INI.

// pypircSectionPattern matches an INI section header, "[pypi]".
var pypircSectionPattern = regexp.MustCompile(`^\s*\[([^\]]+)\]\s*$`)

// pypircLinePattern matches a "key = value" pair. .pypirc uses spaces around
// "=" by convention (unlike npmrc), but both forms are valid, so the pattern
// tolerates either.
var pypircLinePattern = regexp.MustCompile(`^(\s*)([^=\s]+)(\s*=\s*)(.*?)\s*$`)

// pypircVarSanitizer / pypircMultiUnderscore mirror npmrc's pair: turn an
// arbitrary section name into a valid ${VAR_NAME} placeholder component.
var pypircVarSanitizer = regexp.MustCompile(`[^A-Za-z0-9_]+`)
var pypircMultiUnderscore = regexp.MustCompile(`_+`)

// PypircMigration describes what jit migrate did to ~/.pypirc.
type PypircMigration struct {
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

// PypircPath returns .pypirc's one fixed location. packaging.python.org
// specifies $HOME/.pypirc, and twine, uv, poetry and setuptools all read
// exactly that path. A $PYPIRC / --config-file override pointing elsewhere is
// out of scope for a first cut — the same "narrower first, the audit finding
// stays visible otherwise" stance DiscoverNetrc and DiscoverSOPSAge document.
func PypircPath(home string) string {
	return filepath.Join(home, ".pypirc")
}

// DiscoverPypirc returns ~/.pypirc when it holds at least one credential worth
// moving, and nothing otherwise. Home-only by design: unlike .npmrc (which is
// legitimately per-project and so gets a cwd walk), .pypirc is a machine
// singleton, so there is no project tree to search.
func DiscoverPypirc(home string) ([]string, error) {
	path := PypircPath(home)
	// Same guard as DiscoverNetrc/DiscoverSOPSAge: a file already converted to
	// a FIFO by an earlier migration must never be opened for read here —
	// opening a FIFO for read blocks until a writer (jit agent) connects,
	// which would hang this scan forever on a machine with no agent running.
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil
	}
	lines, err := readLines(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(findSecretPypircLines(lines)) == 0 {
		return nil, nil
	}
	return []string{path}, nil
}

// ApplyPypirc moves every repository section's password out of ~/.pypirc and
// into v's vault, then replaces the file with a FIFO serving a
// template-substituted reconstruction (mount.FormatTemplate): the
// [distutils] index list, repository URLs and usernames pass through
// byte-for-byte, only each password's value is filled in from the vault at
// serve time.
//
// The mount (rather than a pointer file) is what keeps `twine upload`,
// `uv publish` and `poetry publish` working unchanged — they read this file
// directly, so a decoy with no live read path would simply break publishing.
func ApplyPypirc(v *vault.Vault, home, path string) (PypircMigration, error) {
	lines, err := readLines(path)
	if err != nil {
		return PypircMigration{}, fmt.Errorf("reading %s: %w", path, err)
	}

	matches := findSecretPypircLines(lines)
	if len(matches) == 0 {
		return PypircMigration{}, fmt.Errorf("%s has no credentials to migrate", path)
	}

	varNames := make([]string, 0, len(matches))
	seenVar := map[string]bool{}
	for _, m := range matches {
		if seenVar[m.VarName] {
			continue // a repeated section name; last value wins, as the INI readers do
		}
		seenVar[m.VarName] = true
		varNames = append(varNames, m.VarName)
	}
	sort.Strings(varNames)

	// Same merge-and-guard as ApplyEnvFile/ApplyNpmrc: move to "<name>-2" if
	// the vault already holds another migration's value at one of these paths
	// (GAPS.md #55).
	profileName, profilePath, entries, movedFrom, err := claimNamespace(v, home, "pypirc", varNames)
	if err != nil {
		return PypircMigration{}, err
	}

	values := map[string]string{}
	for _, m := range matches {
		values[m.VarName] = m.Value
	}
	meta, err := newProvenance(vault.ClassPypirc, path)
	if err != nil {
		return PypircMigration{}, err
	}
	for _, name := range varNames {
		secretPath := profileName + "/" + name
		if err := v.SetWithMeta(secretPath, []byte(values[name]), meta); err != nil {
			return PypircMigration{}, fmt.Errorf("storing %s in vault: %w", name, err)
		}
		entries[name] = secretPath
	}

	if err := writeProfileManifest(profilePath, entries, nil); err != nil {
		return PypircMigration{}, fmt.Errorf("writing profile %s: %w", profilePath, err)
	}

	backupPath, err := backupSecretFile(v, path)
	if err != nil {
		return PypircMigration{}, fmt.Errorf("backing up %s: %w", path, err)
	}

	template := rewritePypircAsTemplate(lines, matches)
	templatePath := strings.TrimSuffix(profilePath, ".yaml") + ".pypirc.tmpl"
	if err := os.WriteFile(templatePath, template, 0o600); err != nil {
		return PypircMigration{}, fmt.Errorf("writing template %s: %w", templatePath, err)
	}

	if err := mount.CreateFIFO(path); err != nil {
		return PypircMigration{}, fmt.Errorf("mounting %s: %w", path, err)
	}

	return PypircMigration{
		FilePath:           path,
		BackupPath:         backupPath,
		TemplatePath:       templatePath,
		ProfileName:        profileName,
		ProfilePath:        profilePath,
		Variables:          varNames,
		NamespaceMovedFrom: movedFrom,
	}, nil
}

type pypircSecretMatch struct {
	Index   int
	Section string
	Key     string
	Value   string
	VarName string
}

// pypircSecretKeys are the credential-bearing keys in a repository section.
// "username" is deliberately absent: for a token login it is the literal
// "__token__", and even for a password login the username is not the secret.
// The other keys a section holds (repository, ca_cert) are not credentials.
var pypircSecretKeys = []string{"password"}

// findSecretPypircLines returns every credential line, tagged with the section
// it belongs to so two repositories can't collide on one variable name.
//
// [distutils] is skipped: it holds the index-servers list, never a credential.
// A key outside any section is skipped too — .pypirc has no meaningful
// top-level keys, and a stray one is far more likely to be a malformed file
// than a credential worth rewriting.
func findSecretPypircLines(lines []string) []pypircSecretMatch {
	var matches []pypircSecretMatch
	section := ""
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if m := pypircSectionPattern.FindStringSubmatch(line); m != nil {
			section = strings.TrimSpace(m[1])
			continue
		}
		if section == "" || strings.EqualFold(section, "distutils") {
			continue
		}
		m := pypircLinePattern.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key := m[2]
		if !isPypircSecretKey(key) {
			continue
		}
		value := unquoteEnvValue(m[4])
		if value == "" {
			continue // an empty password is nothing to move
		}
		matches = append(matches, pypircSecretMatch{
			Index:   i,
			Section: section,
			Key:     key,
			Value:   value,
			VarName: pypircVarName(section, key),
		})
	}
	return matches
}

func isPypircSecretKey(key string) bool {
	for _, k := range pypircSecretKeys {
		if strings.EqualFold(key, k) {
			return true
		}
	}
	return false
}

// pypircVarName builds the placeholder / vault-path name from the section and
// key, e.g. section "blockaidpypi" + key "password" ->
// "BLOCKAIDPYPI_PASSWORD". Including the section is what keeps two
// repositories in one file from landing on the same vault path — the same
// collision npmrcVarName avoids by folding in the registry host.
func pypircVarName(section, key string) string {
	upper := strings.ToUpper(section + "_" + key)
	replaced := pypircVarSanitizer.ReplaceAllString(upper, "_")
	replaced = pypircMultiUnderscore.ReplaceAllString(replaced, "_")
	trimmed := strings.Trim(replaced, "_")
	if trimmed == "" {
		trimmed = "PYPI_PASSWORD"
	}
	if trimmed[0] >= '0' && trimmed[0] <= '9' {
		trimmed = "_" + trimmed
	}
	return trimmed
}

// rewritePypircAsTemplate replaces each credential's value with its
// ${VAR_NAME} placeholder, preserving the line's original indentation, key and
// spacing around "=" — and every other line byte-for-byte.
func rewritePypircAsTemplate(lines []string, matches []pypircSecretMatch) []byte {
	varByIndex := make(map[int]string, len(matches))
	for _, m := range matches {
		varByIndex[m.Index] = m.VarName
	}

	out := make([]string, len(lines))
	for i, line := range lines {
		varName, ok := varByIndex[i]
		if !ok {
			out[i] = line
			continue
		}
		// Capture groups: 1 = leading indent, 2 = key, 3 = the "=" and the
		// spacing around it. Reusing them keeps "password = x" from being
		// normalized to "password=x", so a re-migration of an unchanged file
		// reproduces the original formatting exactly.
		m := pypircLinePattern.FindStringSubmatch(line)
		out[i] = m[1] + m[2] + m[3] + "${" + varName + "}"
	}
	return []byte(strings.Join(out, "\n"))
}
