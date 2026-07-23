// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package migrate

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/jitpass/jit/internal/audit"
	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/vault"
)

// LooseSecretFileMigration describes one loose secret file moved into the
// vault and neutralized: the whole file was one or more bare tokens (a JWT in
// token.txt), matching none of the structured formats, so it is replaced with
// a git-safe pointer file rather than mounted. The retrieval path is `jit
// vault get`, deliberately — a bare secret file with no live reader gains
// nothing from a FIFO mount and would only make `cat token.txt` hand back a
// decoy. See docs/audit/findings.md.
type LooseSecretFileMigration struct {
	Path               string
	ProfileName        string
	ProfilePath        string
	Variables          []string
	BackupPath         string
	NamespaceMovedFrom string
	// Mounted is true for the --mount variant (ApplyLooseSecretFileMount): the
	// file became a live FIFO serving a template, not a static pointer.
	// TemplatePath is the on-disk template the mount renders (empty when not
	// mounted). The caller registers the mount with these.
	Mounted      bool
	TemplatePath string
}

// looseSecretNameRe collapses every run of non-alphanumeric characters in a
// vendor label into a single underscore, so a variable name derived from it is
// a clean env-style identifier.
var looseSecretNameRe = regexp.MustCompile(`[^A-Za-z0-9]+`)

// looseSecretName turns a token's vendor label into a stable, env-style
// variable name: "JSON Web Token (JWT)" -> "JSON_WEB_TOKEN_JWT". This is the
// name the secret lands under in the vault, so it must be deterministic (a
// re-run has to reproduce it exactly) and readable (the user retrieves it with
// `jit vault get <profile>/<name>`).
func looseSecretName(vendor string) string {
	name := looseSecretNameRe.ReplaceAllString(vendor, "_")
	name = strings.Trim(name, "_")
	name = strings.ToUpper(name)
	if name == "" {
		return "SECRET"
	}
	return name
}

// deriveLooseProfileName names the profile after the file's own basename
// (without extension), sanitized to profile.Path's allowed character set:
// "token.txt" -> "token". claimNamespace handles a collision with an existing
// profile of that name. Falls back to "secret" when nothing usable remains.
func deriveLooseProfileName(path string) string {
	base := filepath.Base(path)
	if ext := filepath.Ext(base); ext != "" && ext != base {
		base = strings.TrimSuffix(base, ext)
	}
	base = looseSecretNameRe.ReplaceAllString(base, "-")
	base = strings.Trim(base, "-")
	if base == "" {
		return "secret"
	}
	return strings.ToLower(base)
}

// scanFileLines returns path's lines exactly as audit.FindFileTokens' scanner
// splits them, so a token's per-line Start/End offsets align with the returned
// strings. Bounded the same way FindFileTokens is (a scanner error returns what
// was read so far; an over-long line is the caller's guard, not this one's).
func scanFileLines(path string) ([]string, error) {
	f, err := os.Open(path) // #nosec G304 -- explicitly-named migrate target, same trust boundary as every Apply* path
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, nil
}

// ClassifyLooseSecretFile decides whether path is a "pure" loose secret file:
// a plain file whose entire meaningful content is bare secret tokens (every
// non-blank line is nothing but one or more detected tokens, no other text).
// Only these are safe to vault-and-neutralize by replacing the whole file —
// a file that mixes a token with other content (a config with `api_key=sk-...`
// plus real settings) would lose that content, so it returns pure=false and is
// left for template migration / manual handling.
//
// Returns the detected tokens in file order and pure=true only when there is at
// least one token line and no non-blank line carries anything but tokens.
func ClassifyLooseSecretFile(path string) (tokens []audit.FileToken, pure bool, err error) {
	tokens, err = audit.FindFileTokens(path)
	if err != nil {
		return nil, false, err
	}
	if len(tokens) == 0 {
		return nil, false, nil
	}

	lines, err := scanFileLines(path)
	if err != nil {
		return tokens, false, err
	}

	byLine := make(map[int][]audit.FileToken, len(lines))
	for _, tk := range tokens {
		byLine[tk.Line] = append(byLine[tk.Line], tk)
	}

	anyTokenLine := false
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue // blank/whitespace-only lines don't disqualify a pure file
		}
		lineTokens := byLine[i+1] // FindFileTokens' Line is 1-based
		if len(lineTokens) == 0 {
			return tokens, false, nil // a non-blank line with no token — not pure
		}
		// Blank out every token span; whatever remains must be whitespace, or
		// the line mixes a secret with other content (the embedded case).
		blanked := []byte(line)
		for _, tk := range lineTokens {
			for j := tk.Start; j < tk.End && j < len(blanked); j++ {
				blanked[j] = ' '
			}
		}
		if strings.TrimSpace(string(blanked)) != "" {
			return tokens, false, nil
		}
		anyTokenLine = true
	}
	return tokens, anyTokenLine, nil
}

// ApplyLooseSecretFile vaults every bare token in a pure loose secret file
// (ClassifyLooseSecretFile), then replaces the file with a git-safe pointer
// file — vault-and-neutralize. Order matters for safety, identical to
// ApplyEnvFile's: every vault write, the profile manifest, and the backup all
// happen before the original file is overwritten, so a failure partway never
// leaves the file gone with nothing usable in its place.
func ApplyLooseSecretFile(v *vault.Vault, profilesRoot, path string) (LooseSecretFileMigration, error) {
	tokens, pure, err := ClassifyLooseSecretFile(path)
	if err != nil {
		return LooseSecretFileMigration{}, fmt.Errorf("inspecting %s: %w", path, err)
	}
	if !pure || len(tokens) == 0 {
		// Should never happen — discovery only routes pure files here — but a
		// hard stop beats overwriting a file we misjudged.
		return LooseSecretFileMigration{}, fmt.Errorf("%s is not a pure secret file jit can move whole", path)
	}

	varNames, values := nameLooseTokens(tokens)

	profileName, profilePath, entries, movedFrom, err := claimNamespace(v, profilesRoot, deriveLooseProfileName(path), varNames)
	if err != nil {
		return LooseSecretFileMigration{}, err
	}

	meta, err := newProvenance(vault.ClassLooseFile, path)
	if err != nil {
		return LooseSecretFileMigration{}, err
	}
	for _, name := range varNames {
		secretPath := profileName + "/" + name
		if err := v.SetWithMeta(secretPath, []byte(values[name]), meta); err != nil {
			return LooseSecretFileMigration{}, fmt.Errorf("storing %s in vault: %w", name, err)
		}
		entries[name] = secretPath
	}

	if err := writeProfileManifest(profilePath, entries, varNames); err != nil {
		return LooseSecretFileMigration{}, fmt.Errorf("writing profile %s: %w", profilePath, err)
	}

	backupPath, err := backupSecretFile(v, path)
	if err != nil {
		return LooseSecretFileMigration{}, fmt.Errorf("backing up %s: %w", path, err)
	}

	if err := ReplaceWithPointerFile(path, entries, varNames); err != nil {
		return LooseSecretFileMigration{}, fmt.Errorf("replacing %s with a pointer file: %w", path, err)
	}

	return LooseSecretFileMigration{
		Path:               path,
		ProfileName:        profileName,
		ProfilePath:        profilePath,
		Variables:          varNames,
		BackupPath:         backupPath,
		NamespaceMovedFrom: movedFrom,
	}, nil
}

// nameLooseTokens assigns each detected token a stable, unique, env-style
// variable name derived from its vendor, disambiguating repeats of the same
// vendor within one file with a 1-based suffix. Returns the names aligned to
// tokens (names[i] is tokens[i]'s), which double as the manifest order since
// every name is unique, plus the name→value map. Shared by both the
// neutralize and the --mount paths so a file migrated either way names its
// secrets identically.
func nameLooseTokens(tokens []audit.FileToken) (names []string, values map[string]string) {
	base := make([]string, len(tokens))
	counts := map[string]int{}
	for i, tk := range tokens {
		base[i] = looseSecretName(tk.Vendor)
		counts[base[i]]++
	}
	names = make([]string, len(tokens))
	values = make(map[string]string, len(tokens))
	used := map[string]int{}
	for i, tk := range tokens {
		name := base[i]
		if counts[name] > 1 {
			used[name]++
			name = fmt.Sprintf("%s_%d", name, used[name])
		}
		names[i] = name
		values[name] = tk.Value
	}
	return names, values
}

// buildLooseTemplate reconstructs the file as a template: every token span is
// replaced by its ${VAR} placeholder, everything else passes through verbatim
// (the same shape rewriteNpmrcAsTemplate produces for npmrc). Replacing each
// line's spans right-to-left keeps earlier byte offsets valid as later ones are
// rewritten. names is aligned to tokens.
func buildLooseTemplate(lines []string, tokens []audit.FileToken, names []string) []byte {
	type span struct {
		start, end int
		name       string
	}
	byLine := make(map[int][]span, len(lines))
	for i, tk := range tokens {
		byLine[tk.Line] = append(byLine[tk.Line], span{tk.Start, tk.End, names[i]})
	}

	out := make([]string, len(lines))
	for i, line := range lines {
		spans := byLine[i+1] // FindFileTokens' Line is 1-based
		if len(spans) == 0 {
			out[i] = line
			continue
		}
		sort.Slice(spans, func(a, b int) bool { return spans[a].start > spans[b].start })
		s := line
		for _, sp := range spans {
			if sp.start < 0 || sp.end > len(s) || sp.start > sp.end {
				continue // defensive: a span that doesn't fit the line is skipped, never panics
			}
			s = s[:sp.start] + "${" + sp.name + "}" + s[sp.end:]
		}
		out[i] = s
	}
	return []byte(strings.Join(out, "\n"))
}

// ApplyLooseSecretFileMount is the --mount variant: instead of replacing the
// file with a static pointer, it turns the file into a live FIFO serving a
// template (the file with every token swapped for a ${VAR} placeholder), so a
// program that reads the path keeps working — getting the real value under a
// `jit run` grant, a decoy otherwise. Unlike neutralize, this also handles an
// embedded secret (a token mixed with other content): the non-token content is
// preserved verbatim in the template. The caller registers the mount from the
// returned TemplatePath. Same safety ordering as every other Apply*: vault
// writes, manifest, template, and backup all precede the FIFO swap.
func ApplyLooseSecretFileMount(v *vault.Vault, profilesRoot, path string) (LooseSecretFileMigration, error) {
	tokens, _, err := ClassifyLooseSecretFile(path)
	if err != nil {
		return LooseSecretFileMigration{}, fmt.Errorf("inspecting %s: %w", path, err)
	}
	if len(tokens) == 0 {
		return LooseSecretFileMigration{}, fmt.Errorf("%s contains no token jit can mount", path)
	}
	lines, err := scanFileLines(path)
	if err != nil {
		return LooseSecretFileMigration{}, fmt.Errorf("reading %s: %w", path, err)
	}

	names, values := nameLooseTokens(tokens)
	// Manifest/vault order is the unique set of names, first-seen (names is
	// already unique per token, so this preserves file order).
	order := names

	profileName, profilePath, entries, movedFrom, err := claimNamespace(v, profilesRoot, deriveLooseProfileName(path), order)
	if err != nil {
		return LooseSecretFileMigration{}, err
	}

	meta, err := newProvenance(vault.ClassLooseFile, path)
	if err != nil {
		return LooseSecretFileMigration{}, err
	}
	for _, name := range order {
		secretPath := profileName + "/" + name
		if err := v.SetWithMeta(secretPath, []byte(values[name]), meta); err != nil {
			return LooseSecretFileMigration{}, fmt.Errorf("storing %s in vault: %w", name, err)
		}
		entries[name] = secretPath
	}

	if err := writeProfileManifest(profilePath, entries, order); err != nil {
		return LooseSecretFileMigration{}, fmt.Errorf("writing profile %s: %w", profilePath, err)
	}

	backupPath, err := backupSecretFile(v, path)
	if err != nil {
		return LooseSecretFileMigration{}, fmt.Errorf("backing up %s: %w", path, err)
	}

	template := buildLooseTemplate(lines, tokens, names)
	templatePath := strings.TrimSuffix(profilePath, ".yaml") + ".loose.tmpl"
	if err := os.WriteFile(templatePath, template, 0o600); err != nil {
		return LooseSecretFileMigration{}, fmt.Errorf("writing template %s: %w", templatePath, err)
	}

	if err := mount.CreateFIFO(path); err != nil {
		return LooseSecretFileMigration{}, fmt.Errorf("mounting %s: %w", path, err)
	}

	return LooseSecretFileMigration{
		Path:               path,
		ProfileName:        profileName,
		ProfilePath:        profilePath,
		Variables:          order,
		BackupPath:         backupPath,
		NamespaceMovedFrom: movedFrom,
		Mounted:            true,
		TemplatePath:       templatePath,
	}, nil
}
