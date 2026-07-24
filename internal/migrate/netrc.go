// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/vault"
)

// netrcVarSanitizer/netrcMultiUnderscore mirror npmrc.go's own pair: a
// netrc "machine" hostname (e.g. "api.github.com") becomes a valid
// ${VAR_NAME} placeholder / vault-path-safe name the same way an npmrc key
// does.
var netrcVarSanitizer = regexp.MustCompile(`[^A-Za-z0-9_]+`)
var netrcMultiUnderscore = regexp.MustCompile(`_+`)

// NetrcMigration describes what jit migrate did to ~/.netrc.
type NetrcMigration struct {
	FilePath     string
	BackupPath   string
	TemplatePath string
	ProfileName  string
	ProfilePath  string
	Variables    []string
	// NamespaceMovedFrom mirrors every other Apply* migration's field of
	// the same name (GAPS.md #55).
	NamespaceMovedFrom string
}

// NetrcPath returns .netrc's one fixed location. curl/git/ftp all read
// exactly this path by default; a $NETRC env var override (curl-specific,
// pointing at a different file) is out of scope for v1 — same "narrower
// first cut, the audit finding stays visible otherwise" stance
// DiscoverSOPSAge documents for its own out-of-scope cases.
func NetrcPath(home string) string {
	return filepath.Join(home, ".netrc")
}

// netrcToken is one whitespace-delimited token, with its byte offsets in
// the original file — kept (not just the text) so ApplyNetrc can splice a
// replacement into the EXACT byte span a value occupied, the same
// byte-substitution discipline locateSOPSAgeSecret uses for the age key
// line. .netrc's grammar allows a value to sit on its own line or share a
// line with several others (both `machine host login user password pass`
// and one keyword per line are valid, real files use both), so — unlike
// npmrc's line-oriented rewrite — this can't be done line-by-line; only a
// token-position splice preserves arbitrary original formatting exactly.
type netrcToken struct {
	text       string
	start, end int
}

func isNetrcSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

// tokenizeNetrc splits data on runs of whitespace, recording each token's
// byte span. It knows nothing about netrc's keyword grammar — that's
// walkNetrcTokens' job — so a macdef body's own words tokenize like
// anything else; walkNetrcTokens is what skips over them.
func tokenizeNetrc(data []byte) []netrcToken {
	var toks []netrcToken
	i, n := 0, len(data)
	for i < n {
		for i < n && isNetrcSpace(data[i]) {
			i++
		}
		if i >= n {
			break
		}
		start := i
		for i < n && !isNetrcSpace(data[i]) {
			i++
		}
		toks = append(toks, netrcToken{text: string(data[start:i]), start: start, end: i})
	}
	return toks
}

// netrcPasswordMatch is one `password` token found under some machine
// context, with the var name it will become.
type netrcPasswordMatch struct {
	Machine string
	VarName string
	Token   netrcToken
}

// walkNetrcTokens interprets data's tokens against netrc's actual grammar
// (RFC-less, but curl/ftp/git all agree on this shape): `machine <name>`
// or `default` opens a context; `login`/`account` name the following
// token as a value this migration leaves alone (a username, not a
// secret — see this file's package-level scope note); `password` names
// the following token as the value this migration vaults; `macdef <name>`
// opens a macro body that runs verbatim to the next blank line (or EOF)
// and must never be interpreted as machine/login/password tokens, since a
// macro body is free-form text a user wrote for curl/ftp scripting, not
// netrc grammar.
//
// Returned matches are in file order (ascending token.start) by
// construction — ApplyNetrc's splice depends on that and re-asserts it
// defensively rather than trusting this comment alone.
func walkNetrcTokens(data []byte) []netrcPasswordMatch {
	toks := tokenizeNetrc(data)
	var matches []netrcPasswordMatch
	currentMachine := ""
	skipUntil := -1 // byte offset; tokens starting before this are inside an opaque macdef body

	for i := 0; i < len(toks); i++ {
		tok := toks[i]
		if tok.start < skipUntil {
			continue
		}
		switch tok.text {
		case "machine":
			if i+1 < len(toks) {
				currentMachine = toks[i+1].text
				i++
			}
		case "default":
			currentMachine = "default"
		case "login", "account":
			// Value is intentionally not extracted (see package doc note):
			// a netrc username/account is conventionally not the secret.
			if i+1 < len(toks) {
				i++
			}
		case "password":
			if i+1 < len(toks) {
				value := toks[i+1]
				matches = append(matches, netrcPasswordMatch{
					Machine: currentMachine,
					VarName: netrcVarName(currentMachine, matches),
					Token:   value,
				})
				i++
			}
		case "macdef":
			if i+1 < len(toks) {
				nameTok := toks[i+1]
				i++
				// A macro body runs from right after its name token to the
				// first blank line (two consecutive newlines) or EOF — netrc's
				// own termination rule, mirrored from curl/ftp's parsers. Scan
				// the RAW bytes, not tokens: whitespace inside the body is
				// exactly what makes it a blank-line-terminated block, and
				// tokenizing first would have already destroyed that.
				skipUntil = netrcMacdefBodyEnd(data, nameTok.end)
			}
		}
	}
	return matches
}

// netrcMacdefBodyEnd returns the byte offset just past the first blank
// line (an empty line: "\n\n" or "\n\r\n") found after from, or len(data)
// if none exists — a macro with no trailing blank line runs to EOF, which
// is valid per curl/ftp's own netrc parsers. from is the byte just past
// the macro NAME token, still mid-line ("macdef init" has no newline
// before from) — the body itself starts on the NEXT line, so the first
// newline found is that declaration line's own terminator, never a body
// blank line, and must be consumed before blank-line scanning begins. A
// body of literally zero lines (from is already at EOF, or the very next
// line IS blank) is legal and returns immediately.
func netrcMacdefBodyEnd(data []byte, from int) int {
	declEnd := bytes.IndexByte(data[from:], '\n')
	if declEnd < 0 {
		return len(data) // "macdef name" with nothing after it: no body, no terminator
	}
	i := from + declEnd + 1 // start of the macro body's first real line
	for i < len(data) {
		nl := bytes.IndexByte(data[i:], '\n')
		if nl < 0 {
			return len(data)
		}
		lineEnd := i + nl + 1
		// The line just consumed (data[i:lineEnd]) is blank if it's only a
		// bare newline or CRLF — i.e. nothing but whitespace before the '\n'.
		if len(bytes.TrimSpace(data[i:lineEnd])) == 0 {
			return lineEnd
		}
		i = lineEnd
	}
	return len(data)
}

// netrcVarName turns a netrc machine name into a ${VAR_NAME}/vault-path
// leaf, e.g. "api.github.com" -> "API_GITHUB_COM_PASSWORD". Unlike
// npmrcVarName's "duplicate key: last wins" (npmrc lines are literally
// shell-config-adjacent, later assignment overrides), netrc's real-world
// precedence is the OPPOSITE: curl/ftp/git all stop at the FIRST matching
// `machine` block, so a repeated machine name (or two `password` lines
// under one block, malformed but not impossible) must keep its first
// occurrence's canonical name and give every later duplicate a numbered
// suffix — reusing the first name for a later occurrence would silently
// vault the value nothing actually uses under the name everything reads.
func netrcVarName(machine string, existing []netrcPasswordMatch) string {
	base := netrcVarSanitizer.ReplaceAllString(strings.ToUpper(machine), "_")
	base = netrcMultiUnderscore.ReplaceAllString(base, "_")
	base = strings.Trim(base, "_")
	if base == "" {
		base = "NETRC_SECRET"
	}
	if base[0] >= '0' && base[0] <= '9' {
		base = "_" + base
	}
	base += "_PASSWORD"

	n := 1
	for _, m := range existing {
		if strings.HasPrefix(m.VarName, base) {
			n++
		}
	}
	if n == 1 {
		return base
	}
	return fmt.Sprintf("%s_%d", base, n)
}

// DiscoverNetrc returns []string{NetrcPath(home)} if that file exists,
// is a regular file (not already a jit mount), and has at least one
// `password` line to migrate — or an empty slice otherwise. A single
// fixed path, like SOPS's keys.txt: `.netrc` is a machine-wide credential
// store with no project directory to root a scan in, so this is checked
// only from jit migrate home's wholeHome branch, mirroring
// DiscoverSOPSAge/DiscoverGCPADC exactly.
func DiscoverNetrc(home string) ([]string, error) {
	path := NetrcPath(home)
	// Same guard as DiscoverSOPSAge/DiscoverGCPADC: a file already
	// converted to a FIFO by an earlier migration must never be opened for
	// read here — opening a FIFO for read blocks until a writer (jit agent)
	// connects, which would hang this scan forever on a machine with no
	// agent running.
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
	data, err := os.ReadFile(path) // #nosec G304 -- fixed ~/.netrc path, not external input
	if err != nil {
		return nil, err
	}
	if len(walkNetrcTokens(data)) == 0 {
		return nil, nil
	}
	return []string{path}, nil
}

// ApplyNetrc moves every `password` value in ~/.netrc into v's vault and
// replaces the file with a FIFO serving a template-substituted
// reconstruction (mount.FormatTemplate) — the same "file mixes secret and
// non-secret content" shape as npmrc/GCP-ADC/SOPS's age key: `machine`/
// `login`/`account`/comment-adjacent structure survives byte-for-byte,
// only each password token's exact span is replaced by its placeholder.
func ApplyNetrc(v *vault.Vault, home, path string) (NetrcMigration, error) {
	// Same reason as DiscoverNetrc's guard, on Apply's own read: a path
	// that became a FIFO since discovery must fail loud here, not block
	// forever inside os.ReadFile waiting for a writer.
	info, err := os.Lstat(path)
	if err != nil {
		return NetrcMigration{}, fmt.Errorf("checking %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return NetrcMigration{}, fmt.Errorf("%s is not a regular file (already a live mount?)", path)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- fixed ~/.netrc path, not external input
	if err != nil {
		return NetrcMigration{}, fmt.Errorf("reading %s: %w", path, err)
	}

	matches := walkNetrcTokens(data)
	if len(matches) == 0 {
		return NetrcMigration{}, fmt.Errorf("%s has no `password` lines to migrate", path)
	}

	varNames := make([]string, len(matches))
	for i, m := range matches {
		varNames[i] = m.VarName
		// Position-blind byte substitution (locateSOPSAgeSecret's own
		// guard): a placeholder that already occurs literally in the file
		// would get the real value written into it at serve time too.
		if bytes.Contains(data, []byte("${"+m.VarName+"}")) {
			return NetrcMigration{}, fmt.Errorf("%s already contains the literal ${%s}, refusing to migrate", path, m.VarName)
		}
	}
	sort.Strings(varNames)

	profileName, profilePath, entries, movedFrom, err := claimNamespace(v, home, "netrc", varNames)
	if err != nil {
		return NetrcMigration{}, err
	}

	meta, err := newProvenance(vault.ClassNetrc, path)
	if err != nil {
		return NetrcMigration{}, err
	}
	for _, m := range matches {
		secretPath := profileName + "/" + m.VarName
		if err := v.SetWithMeta(secretPath, []byte(m.Token.text), meta); err != nil {
			return NetrcMigration{}, fmt.Errorf("storing %s in vault: %w", m.VarName, err)
		}
		entries[m.VarName] = secretPath
	}

	if err := writeProfileManifest(profilePath, entries, nil); err != nil {
		return NetrcMigration{}, fmt.Errorf("writing profile %s: %w", profilePath, err)
	}

	backupPath, err := backupSecretFile(v, path)
	if err != nil {
		return NetrcMigration{}, fmt.Errorf("backing up %s: %w", path, err)
	}

	template := spliceNetrcTemplate(data, matches)
	templatePath := strings.TrimSuffix(profilePath, ".yaml") + ".netrc.tmpl"
	if err := os.WriteFile(templatePath, template, 0o600); err != nil { // #nosec G703 -- templatePath is internally derived (claimNamespace's hardcoded "netrc" namespace + a fixed suffix, both sanitized by profile.Path), not user-controlled path input
		return NetrcMigration{}, fmt.Errorf("writing template %s: %w", templatePath, err)
	}

	if err := mount.CreateFIFO(path); err != nil {
		return NetrcMigration{}, fmt.Errorf("mounting %s: %w", path, err)
	}

	return NetrcMigration{
		FilePath:           path,
		BackupPath:         backupPath,
		TemplatePath:       templatePath,
		ProfileName:        profileName,
		ProfilePath:        profilePath,
		Variables:          varNames,
		NamespaceMovedFrom: movedFrom,
	}, nil
}

// spliceNetrcTemplate replaces each match's exact token byte span with its
// ${VAR_NAME} placeholder, copying every other byte — including all
// whitespace and newline structure — unchanged. matches must be in
// ascending Token.start order (walkNetrcTokens' construction order,
// re-asserted here rather than trusted blindly: a caller that fed matches
// out of order would silently corrupt the splice, and this is the one
// place that would go unnoticed until someone diffed the rebuilt file).
func spliceNetrcTemplate(data []byte, matches []netrcPasswordMatch) []byte {
	sorted := make([]netrcPasswordMatch, len(matches))
	copy(sorted, matches)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Token.start < sorted[j].Token.start })

	var buf []byte
	last := 0
	for _, m := range sorted {
		buf = append(buf, data[last:m.Token.start]...)
		buf = append(buf, []byte("${"+m.VarName+"}")...)
		last = m.Token.end
	}
	buf = append(buf, data[last:]...)
	return buf
}
