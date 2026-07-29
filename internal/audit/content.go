// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"bufio"
	"bytes"
	"io"
	"path/filepath"
	"strings"
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

	var findings []Finding
	seenVendor := map[string]bool{} // one finding per (file, vendor): see below
	for _, tk := range tokens {
		// One finding per (file, vendor). record_id is
		// finding_type+file_path+key_name and key_name is the vendor, so a
		// second occurrence of the same vendor in the same file would collide
		// on record_id anyway; collapsing here keeps the report from listing
		// structurally identical duplicates. The first occurrence's line
		// number is the one reported.
		if seenVendor[tk.Vendor] {
			continue
		}
		seenVendor[tk.Vendor] = true

		ln := tk.Line
		vendor := tk.Vendor
		findings = append(findings, cfg.ValueFinding(ValueFindingParams{
			FindingType:  FindingTypeExposedSecret,
			FilePath:     path,
			Line:         &ln,
			KeyName:      vendor,
			RawValue:     tk.Value,
			BaseSeverity: SeverityHigh,
			Confidence:   ConfidenceHigh,
			Evidence:     "value matches a known vendor credential format",
		}))
	}
	return findings, nil
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

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), maxContentLineSize)
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
	scanner := bufio.NewScanner(io.MultiReader(bytes.NewReader(head[:n]), file))
	scanner.Buffer(make([]byte, 0, 64*1024), maxContentLineSize)
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
					Line:     lineNum,
					Start:    lo,
					End:      hi,
					Vendor:   tp.vendor,
					Verified: tp.verified,
					Value:    match,
				})
			}
		}
	}
	// A scanner error (an over-long line past maxContentLineSize, a mid-read
	// I/O error) returns what we found so far rather than failing the run —
	// partial detection beats none.
	return tokens, nil
}
