// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"bytes"
	"io"
	"path/filepath"
	"strings"
	"unicode"
)

// maxContentScanSize bounds how large a file the generic content sweep will
// read. A vendor token or JWT lives in text config/dump files, never in a
// multi-megabyte blob; the cap keeps `jit scan <a-huge-file>` from reading a
// database export or media file line by line looking for a prefix that
// structurally can't hide there in bulk.
const maxContentScanSize = 5 << 20 // 5 MiB

// maxContentLineSize raises bufio.Scanner's default 64 KiB token limit: a
// minified .json or a base64 dump can put a long-but-legitimate line in front
// of the sweep, and the default would error the scan out at that line rather
// than just reading past it. A JWT or vendor token is short, but the LINE it
// sits on may not be.
const maxContentLineSize = 1 << 20 // 1 MiB

// credentialFileNameHints gate which files the MACHINE-WIDE walk will content
// -scan (see classifyCredentialDump). A file whose own name announces that it
// holds credentials is worth opening; everything else is left to the
// name-based category scanners, so the walk's cost stays bounded.
//
// This list can afford to be broad — including the word "token", which sank
// the old suspicious_filename category — because of one difference that
// matters: this gate only decides what to READ. A finding still requires a
// vendor-format match in the CONTENT. A crypto researcher's tokens.csv full
// of contract addresses passes the name gate, matches no vendor pattern, and
// produces nothing. The old category reported on the name alone, which is
// exactly why it was noise.
var credentialFileNameHints = []string{
	"credential", "secret", "token", "apikey", "api_key", "api-key",
	"password", "passwd", "auth",
}

// credentialFileNameHintStops removes stems that contain a hint word without
// meaning it, BEFORE the hints are matched: "tokenize" covers every
// tokenizer_config.json / tokenizer.model a cloned ML repo carries (routinely
// megabytes each, and every one was being fully content-scanned per walk for
// the "token" inside its name), and "author" covers AUTHORS files and
// authorized_keys. Removal, not rejection, so a name like
// "tokenizer_secrets.txt" still hints on the words that remain.
var credentialFileNameHintStops = strings.NewReplacer("tokenize", "", "author", "")

// credentialDumpSkipExts are extensions whose contents cannot usefully hold a
// greppable plaintext credential, skipped so a 2 MB PDF named
// "Token_Scanning_Report.pdf" isn't read for nothing. Real machines are full
// of these: the twelve scans behind this feature turned up token-named PDFs,
// spreadsheets and images on nearly every one. Only an open()-saving
// optimization for the common formats — the NUL sniff in FindFileTokens is
// what actually keeps every binary format out of the line scanner.
var credentialDumpSkipExts = map[string]bool{
	".pdf": true, ".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
	".zip": true, ".gz": true, ".tar": true, ".xlsx": true, ".xls": true,
	".mp4": true, ".mov": true, ".woff": true, ".woff2": true, ".ttf": true,
	".docx": true, ".pptx": true, ".dmg": true, ".sqlite": true,
	".webp": true, ".heic": true, ".7z": true, ".tgz": true,
}

// classifyCredentialDump content-scans a walked file whose NAME says it holds
// credentials, and reports any vendor-format value inside it.
//
// The motivating case (2026-07-28, a twelfth developer scan) is the file the
// AWS IAM console hands you when you download an access key:
// "~/Downloads/<hash>-credentials.csv", holding a live AKIA key and its secret
// access key. `jit scan <that file>` reported it HIGH; a bare `jit scan` —
// the command the README opens with — reported the machine CLEAN, because the
// content sweep ran only on explicitly-named files and no category scanner
// claims a .csv in Downloads. The same shape recurs across the sample:
// jwt-secret.txt, credentials.json, cursor2-token-secret.txt, api_key.json.
//
// This is the bounded version of the "sweep every walked file" decision
// scanFileContentForTokens' doc comment declines to make: the patterns are
// low-false-positive by design, so the open question was never accuracy but
// cost, and a filename gate answers that without changing what a match means.
func classifyCredentialDump(cfg Config, path, name string) []Finding {
	if credentialDumpSkipExts[strings.ToLower(filepath.Ext(name))] {
		return nil
	}
	lower := credentialFileNameHintStops.Replace(strings.ToLower(name))
	hinted := false
	for _, hint := range credentialFileNameHints {
		if strings.Contains(lower, hint) {
			hinted = true
			break
		}
	}
	// Terraform state earns the same read on a different argument. Its name
	// carries no hint word, so nothing here would ever open it — yet it is
	// where Terraform records every attribute it wrote, secret ones included,
	// in plaintext by design (HashiCorp's own documentation). The gate still
	// only decides what to READ: a state file full of ordinary resource
	// attributes matches no vendor pattern and produces nothing.
	if !hinted && !isTerraformState(name) {
		return nil
	}
	findings, err := scanFileContentForTokens(cfg, path)
	if err != nil {
		return nil // unreadable — skip it, never fail the whole scan
	}
	return findings
}

// scanFileContentForTokens sweeps a file's raw text for values matching a
// known vendor credential format (knownTokenPatterns) and emits an
// exposed_secret finding for each. This is the detector behind `jit scan
// <file>` catching a bare JWT dropped in a token.txt — the name-based
// category scanners can't, because the file matches none of their naming
// rules.
//
// On a machine-wide walk it runs only for files classifyCredentialDump's
// name gate admits, not for every file: the vendor-prefix patterns are
// low-false-positive by design, so the constraint is cost, not accuracy.
//
// Private-key bodies are ceded to ScanPrivateKeys / inspectPrivateKeyFile,
// which report the same key far more richly (passphrase, permissions,
// location) — so the sweep skips the "*Private Key" patterns to avoid
// double-reporting one file under two finding types.
//
// An unreadable or over-large file yields no findings (skip, never fail),
// the same forgiveness every category scanner extends.
func scanFileContentForTokens(cfg Config, path string) ([]Finding, error) {
	tokens, err := FindFileTokens(path)
	if err != nil {
		return nil, err
	}

	exampleLines := sourceExampleLines(path, tokens)

	var findings []Finding
	byVendor := map[string]int{} // index into findings; one per (file, vendor): see below
	for _, tk := range tokens {
		// One finding per (file, vendor). record_id is
		// finding_type+file_path+key_name and key_name is the vendor, so a
		// second occurrence of the same vendor in the same file would collide
		// on record_id anyway; collapsing here keeps the report from listing
		// structurally identical duplicates. The first occurrence's line
		// number is the one reported — EXCEPT when that line was a source
		// comment and a later one is not: the collapse must not let a
		// documentation example shadow a real credential further down the
		// same file, uncounting both.
		if i, ok := byVendor[tk.Vendor]; ok {
			if !findings[i].SourceExample || exampleLines[tk.Line] {
				continue
			}
		}

		ln := tk.Line
		vendor := tk.Vendor
		f := cfg.ValueFinding(ValueFindingParams{
			FindingType:  FindingTypeExposedSecret,
			FilePath:     path,
			Line:         &ln,
			KeyName:      vendor,
			RawValue:     tk.Value,
			BaseSeverity: SeverityHigh,
			Confidence:   ConfidenceHigh,
			Evidence:     "value matches a known vendor credential format",
		})
		f.SourceExample = exampleLines[ln]
		f.AssignedName = tk.AssignedName
		if i, ok := byVendor[tk.Vendor]; ok {
			findings[i] = f
		} else {
			byVendor[tk.Vendor] = len(findings)
			findings = append(findings, f)
		}
	}
	return findings, nil
}

// sourceCodeExts are the extensions sourceExampleLines will judge comment
// context in. Shell scripts are deliberately absent: a commented-out
// `# export TOKEN=...` in someone's setup script is exactly the shape a REAL
// leaked credential takes, while a comment in compiled-language source is
// overwhelmingly a documentation example.
var sourceCodeExts = map[string]bool{
	".go": true, ".rs": true, ".py": true, ".rb": true, ".js": true,
	".jsx": true, ".ts": true, ".tsx": true, ".java": true, ".kt": true,
	".swift": true, ".c": true, ".h": true, ".cc": true, ".cpp": true,
	".hpp": true, ".cs": true, ".php": true, ".scala": true, ".lua": true,
	".sql": true, ".m": true, ".mm": true,
}

// sourceCommentLeads are the line-leading markers that make a source line a
// comment. Line-leading ONLY, on purpose: searching for "//" anywhere before
// the match would classify every `postgres://user:pass@host` string literal
// as a comment — the scheme separator IS the marker. A trailing comment
// holding a credential therefore stays counted, which errs the right way.
var sourceCommentLeads = []string{"//", "/*", "*", "#", "--"}

// sourceExampleLines returns the token-holding lines of a source-code file
// whose match sits in a comment (see Finding.SourceExample), nil for
// non-source files. One extra pass over a file the sweep has already read
// once; bounded by the same line scanner.
func sourceExampleLines(path string, tokens []FileToken) map[int]bool {
	if len(tokens) == 0 || !sourceCodeExts[strings.ToLower(filepath.Ext(path))] {
		return nil
	}
	want := map[int]bool{}
	for _, tk := range tokens {
		want[tk.Line] = true
	}

	file, err := openFile(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	example := map[int]bool{}
	scanner := newLineScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if !want[lineNum] {
			continue
		}
		trimmed := strings.TrimSpace(scanner.Text())
		for _, lead := range sourceCommentLeads {
			if strings.HasPrefix(trimmed, lead) {
				example[lineNum] = true
				break
			}
		}
	}
	return example
}

// isPureTokenFile reports whether path's entire meaningful content is bare
// vendor-format tokens: every non-blank line is nothing but token spans.
// This mirrors the vendor-token half of migrate.ClassifyLooseSecretFile's
// purity rule (assignment spans can't make a file pure — their "key=" prefix
// survives the blanking), and is what decides an exposed_secret's remedy:
// a pure file is `jit migrate <path>`-able (vault-and-neutralize), while a
// file that mixes tokens with other content is not something bare migrate
// will touch, so promising "migrate" for it would be a command that answers
// with a skip note (review finding, 2026-07-28).
func isPureTokenFile(path string) bool {
	tokens, err := FindFileTokens(path)
	if err != nil || len(tokens) == 0 {
		return false
	}
	byLine := make(map[int][]FileToken)
	for _, tk := range tokens {
		byLine[tk.Line] = append(byLine[tk.Line], tk)
	}

	file, err := openFile(path)
	if err != nil {
		return false
	}
	defer file.Close()

	scanner := newLineScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		spans := byLine[lineNum]
		if len(spans) == 0 {
			return false
		}
		blanked := []byte(line)
		for _, tk := range spans {
			for i := tk.Start; i < tk.End && i < len(blanked); i++ {
				blanked[i] = ' '
			}
		}
		if strings.TrimSpace(string(blanked)) != "" {
			return false
		}
	}
	return true
}

// FileToken is one vendor-token/JWT match found in a file's raw text by
// FindFileTokens: enough for a scanner to report it and for `jit migrate` to
// extract and vault it. Line is 1-based; Start/End are byte offsets within
// that line (not the whole file), which the template migrator uses to swap a
// token span for a placeholder while keeping the rest of the line verbatim.
type FileToken struct {
	Line     int
	Start    int
	End      int
	Vendor   string
	Verified bool
	Value    string
	// AssignedName is the name this value was assigned to on its line, when
	// the line offers one that is unmistakably a label rather than a payload
	// (see assignedCredentialName). "" is the common case and means only that
	// nothing safe to print was found — never that the value is less real.
	AssignedName string
}

// FindFileTokens sweeps path's raw text for values matching a known vendor
// credential format (knownTokenPatterns), returning every match in file order.
// This is the shared detection behind both `jit scan <file>`'s exposed_secret
// findings and `jit migrate <file>`'s loose-secret handling, so the two can
// never disagree about what counts as a movable token. Private-key bodies are
// ceded to ScanPrivateKeys (see scanFileContentForTokens' doc), so patterns
// whose vendor ends in "Private Key" are skipped here too.
//
// An unreadable, non-regular, or over-large file returns no tokens and no
// error (skip, never fail) — the same forgiveness every category scanner
// extends; a scanner error mid-read returns what was found so far.
func FindFileTokens(path string) ([]FileToken, error) {
	file, err := openFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if info, statErr := file.Stat(); statErr != nil || !info.Mode().IsRegular() || info.Size() > maxContentScanSize {
		return nil, nil
	}

	// A NUL in the first block means a binary file — a SQLite db, a .docx, a
	// mach-o — which a line-based text sweep can't usefully read; the
	// extension skip-list catches the common formats without an open(), this
	// catches all the rest. (UTF-16 text is skipped too: every ASCII-range
	// credential in it is NUL-interleaved, unreachable for these patterns
	// anyway.)
	head := make([]byte, 512)
	n, _ := io.ReadFull(file, head)
	if bytes.IndexByte(head[:n], 0) >= 0 {
		return nil, nil
	}

	var tokens []FileToken
	scanner := newLineScanner(io.MultiReader(bytes.NewReader(head[:n]), file))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Claim character ranges as they're matched so a value caught by a
		// specific prefix (sk-proj-…) isn't re-reported by a more generic one
		// (sk-…) that overlaps it — knownTokenPatterns is ordered
		// specific-first precisely so this "first claim wins" is correct.
		var claimed [][2]int
		overlaps := func(lo, hi int) bool {
			for _, c := range claimed {
				if lo < c[1] && c[0] < hi {
					return true
				}
			}
			return false
		}

		for _, tp := range knownTokenPatterns {
			if strings.HasSuffix(tp.vendor, "Private Key") {
				continue // ScanPrivateKeys owns key bodies; don't double-report
			}
			for _, loc := range tp.pattern.FindAllStringIndex(line, -1) {
				lo, hi := loc[0], loc[1]
				if overlaps(lo, hi) {
					continue
				}
				match := line[lo:hi]
				if tp.exclude != nil && tp.exclude.MatchString(match) {
					continue // a known false-positive shape (e.g. a template placeholder)
				}
				// Same placeholder rejection MatchKnownTokenPattern applies, so
				// a template's "ghp_xxxxxxxx…" isn't reported as an exposed
				// secret by the content scanner either. Left unclaimed on
				// purpose: a more generic pattern overlapping this span (sk-
				// under sk-proj-) is filler for the same reason and gets
				// rejected here too.
				if isPlaceholderToken(match, tp.humanReadable) {
					continue
				}
				claimed = append(claimed, [2]int{lo, hi})
				tokens = append(tokens, FileToken{
					Line:         lineNum,
					Start:        lo,
					End:          hi,
					Vendor:       tp.vendor,
					Verified:     tp.verified,
					Value:        match,
					AssignedName: assignedCredentialName(line, lo),
				})
			}
		}
	}
	// A scanner error (an over-long line past maxContentLineSize, a mid-read
	// I/O error) returns what we found so far rather than failing the run —
	// partial detection beats none.
	return tokens, nil
}

// credentialNameLead caps how far back along a line assignedCredentialName
// looks. A credential's own name sits within a few words of it; anything
// further is unrelated text that happens to share the line, and in a
// one-line JSON transcript the whole rest of the session shares the line.
const credentialNameLead = 120

// assignedCredentialName returns the name a credential on this line was
// assigned to — "HOMEBREW_TAP_GITHUB_TOKEN" for
// `gh secret set HOMEBREW_TAP_GITHUB_TOKEN -R jitpass/jit --body "github_pat_…"` —
// or "" when the line offers none.
//
// Why this exists: a report that says "An exposed GitHub Fine-Grained
// Personal Access Token in 2 files" describes the PATTERN that matched, and
// every finding of that vendor reads identically. A real scan (2026-08-09)
// buried a live Homebrew-tap token — the credential that decides what
// `brew install` delivers — as the fourth of six such lines, indistinguishable
// from this repository's own test vectors. What told them apart was the name
// beside the value, which jit had already read and thrown away.
//
// It reports a NAME, never surrounding text. The report's closing promise is
// that no secret value is ever printed in full, and a line next to a
// credential routinely holds another one — a password matching no vendor
// pattern would be leaked by the very feature meant to explain the leak. A
// name that satisfies every rule below is a label, not a payload.
//
// The rules, each one closing a way a value could pass as a name:
//
//   - Nearest first, scanning back from the match, so the name that wins is
//     the one beside the credential rather than one earlier on the line.
//   - LooksLikeSecretKey, the same predicate the .env and MCP scanners use to
//     decide a variable name looks like a credential's. It is what rejects
//     "body" in `--body "github_pat_…"` and accepts the token name three
//     words earlier.
//   - An underscore, a hyphen, or an interior capital. Names are written
//     API_KEY, api-key or apiKey; a bare lowercase run like
//     "mysecretpassword" satisfies LooksLikeSecretKey on the word "secret"
//     alone and is exactly the shape of the thing this must not print.
//   - Not itself a known credential format, so a value whose own text passes
//     the rules above is still refused.
func assignedCredentialName(line string, matchStart int) string {
	if matchStart <= 0 || matchStart > len(line) {
		return ""
	}
	before := line[:matchStart]
	if len(before) > credentialNameLead {
		before = before[len(before)-credentialNameLead:]
	}
	words := strings.FieldsFunc(before, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '-' && r != '.'
	})
	for i := len(words) - 1; i >= 0; i-- {
		w := strings.Trim(words[i], "-._")
		if len(w) < minAnchorLen || len(w) > maxCredentialNameLen {
			continue
		}
		if !LooksLikeSecretKey(w) || !writtenLikeAName(w) {
			continue
		}
		if _, _, matched := MatchKnownTokenPattern(w); matched {
			continue
		}
		return w
	}
	return ""
}

// maxCredentialNameLen is the longest run still readable as a label. Real
// names are short; a long one is a value that happened to satisfy the rules.
const maxCredentialNameLen = 48

// writtenLikeAName reports whether s is punctuated or cased the way people
// write identifiers, rather than being one undifferentiated lowercase run.
func writtenLikeAName(s string) bool {
	if strings.ContainsAny(s, "_-.") {
		return true
	}
	for _, r := range s {
		if unicode.IsUpper(r) {
			return true
		}
	}
	return false
}
