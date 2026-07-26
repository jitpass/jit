// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"bufio"
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

// scanFileContentForTokens sweeps a file's raw text for values matching a
// known vendor credential format (knownTokenPatterns) and emits an
// exposed_secret finding for each. This is the detector behind `jit scan
// <file>` catching a bare JWT dropped in a token.txt — the name-based
// category scanners can't, because the file matches none of their naming
// rules. It is deliberately run ONLY on a file the user named explicitly:
// the vendor-prefix patterns are low-false-positive by design, but sweeping
// every file of a machine-wide walk with them is a separate, unshipped
// decision (it would change the baseline full-scan findings for everyone).
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

	var tokens []FileToken
	scanner := bufio.NewScanner(file)
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
				if isPlaceholderToken(match) {
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
