// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Shell history is the surface every other category scanner misses, for a
// reason that is structural rather than accidental: a credential reaches a
// history file by being TYPED, so it is never in a file whose name, location
// or format says "credentials live here". A token pasted into a one-off
// `curl -H "Authorization: Bearer …"` is invisible to every name-gated
// scanner in this package, and stays on disk indefinitely — history files are
// append-only in practice and are routinely committed to dotfile repos and
// swept up by Time Machine.
//
// What makes this cheap to do correctly is that the detection already exists:
// knownTokenPatterns and the vendor-format machinery behind exposed_secret
// answer "is this a credential" identically here. What is NEW is the source
// and the parsing.
//
// The remedy is the part that had to be thought about. `jit migrate
// <historyfile>` redacts each occurrence in place (internal/migrate/
// shellhistory.go shares this file's detection through HistoryLineTokens), so
// an ordinary finding is migratable — but redaction is cleanup, not the fix:
// the value already sat on disk in plaintext. A production-flagged credential
// therefore stays manual, because for that one no command substitutes for
// rotation. See annotateRemedies.

// historyFileNames are the history files checked relative to HomeDir. The
// list is deliberately small and fixed: these are the defaults for the shells
// that ship on macOS plus fish, and a wildcard sweep for "*history*" would
// re-introduce exactly the name-only guessing that schema 0.10.0 removed.
//
// $HISTFILE is consulted separately (see historyTargets) because a user who
// moved their history somewhere else has not thereby stopped having one.
var historyFileNames = []string{
	".zsh_history",
	".bash_history",
	".sh_history",
	".history", // ksh and some sh setups
	filepath.Join(".local", "share", "fish", "fish_history"),
}

// maxHistoryScanSize is a sanity bound, not a performance one. The generic
// content sweep stops at maxContentScanSize (5 MiB) because it runs every
// vendor pattern over every line, which costs ~1.8 MB/s — a ceiling that made
// sense for config files, which do not grow on their own.
//
// History files do exactly that, and only that. Measured on a real machine, a
// 5.1 MiB file fell off the far side of that ceiling and produced ZERO
// findings, silently: precisely the "a file size above which the scanner goes
// quiet" failure newLineScanner's doc comment exists to prevent, arriving at
// the one file most likely to cross it. Since historyLineMayHoldToken (below)
// takes the per-line cost from ~5.6µs to ~15ns for the ~95% of command lines
// that cannot hold a token, the ceiling that forced the choice is gone: a
// 50 MiB history now costs tens of milliseconds. This bound is left far above
// any plausible history purely so a pathological file cannot pin the scan,
// and crossing it is REPORTED (a degraded scanner), never a silent skip.
const maxHistoryScanSize = 256 << 20

// historyTargets returns the history files to scan, de-duplicated by absolute
// path. $HISTFILE is included when it names something outside the fixed list —
// a user who set HISTFILE=~/.cache/zsh/history still has a history file, and
// the fixed list alone would report their machine clean.
func historyTargets(cfg Config) []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if p == "" {
			return
		}
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		if seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, name := range historyFileNames {
		add(filepath.Join(cfg.HomeDir, name))
	}
	// HISTFILE is read from the environment of the process running jit, which
	// is the user's own shell — the same shell whose history is at issue.
	if hf := os.Getenv("HISTFILE"); hf != "" {
		if strings.HasPrefix(hf, "~/") {
			hf = filepath.Join(cfg.HomeDir, hf[2:])
		}
		add(hf)
	}
	return out
}

// isShellHistoryName reports whether name is a history file this scanner
// recognizes. Used by `jit scan <path>` to route an explicitly named history
// file here, the same way isShellConfigName routes a named .zshrc — the
// machine-wide scan reaches these by fixed path, not by name, so without this
// `jit scan ~/.zsh_history` would fall through to the generic sweep and lose
// the format parsing (and with it every line number).
func isShellHistoryName(name string) bool {
	for _, n := range historyFileNames {
		if name == filepath.Base(n) {
			return true
		}
	}
	return false
}

// ScanShellHistories sweeps every shell history file for values matching a
// known vendor credential format.
//
// Read-only, like everything else in this package: no flag on `jit scan`
// rewrites, redacts or truncates a history file. Redaction is a fix, and
// fixes belong to `jit migrate` (see the package doc comment).
func ScanShellHistories(cfg Config) ([]Finding, error) {
	var findings []Finding
	var failures []string
	for _, path := range historyTargets(cfg) {
		fileFindings, err := scanShellHistoryFile(cfg, path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			// One unreadable history file must not cost us the others, but it
			// must not pass as "nothing there" either.
			failures = append(failures, fmt.Sprintf("%s: %v", ShortenHome(cfg.HomeDir, path), err))
			continue
		}
		findings = append(findings, fileFindings...)
	}
	if len(failures) > 0 {
		return findings, fmt.Errorf("%s", strings.Join(failures, "; "))
	}
	return findings, nil
}

// scanShellHistoryFile reports every vendor-format credential in one history
// file.
//
// One finding per (file, vendor), first occurrence winning, exactly as
// scanFileContentForTokens does and for the same reason: record_id is
// (finding_type, file_path, key_name) and key_name is the vendor, so a second
// occurrence of one vendor in one file would collide on it anyway. The
// practical cost is higher here than for a config file — a history plausibly
// holds two different GitHub tokens issued months apart, and only the first is
// named — so the finding's evidence reports the total occurrence count, and
// `jit scan --full` shows the line.
func scanShellHistoryFile(cfg Config, path string) ([]Finding, error) {
	f, err := openFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil
	}
	if info.Size() > maxHistoryScanSize {
		return nil, fmt.Errorf("history file is %d bytes, above the %d-byte scan bound; not read",
			info.Size(), int64(maxHistoryScanSize))
	}

	type hit struct {
		line   int
		end    int // last line of a key block; 0 when it was never closed
		value  string
		vendor string
		count  int
	}
	order := []string{}
	byVendor := map[string]*hit{}

	// openKey is the key block whose END marker has not been seen yet. A key
	// is the one credential shape that spans lines, and the report needs both
	// ends of it: "delete those lines by hand" is unfollowable if the reader
	// is told only where the block starts.
	var openKey *hit

	scanner := newLineScanner(f)
	lineNum := 0
	for scanner.Scan() {
		raw := scanner.Text()
		lineNum++
		// Nested rather than the two early `continue`s this replaced: the END
		// marker has to be tested against every RAW line, and the body of a
		// pasted key is not a history entry at all, so historyCommand rejects
		// exactly the lines the closing marker lives on.
		if cmd, _, ok := historyCommand(raw); ok && historyLineMayHoldToken(cmd) {
			for _, tk := range matchLineTokens(cmd) {
				h, seen := byVendor[tk.Vendor]
				if !seen {
					h = &hit{line: lineNum, value: tk.Value, vendor: tk.Vendor}
					byVendor[tk.Vendor] = h
					order = append(order, tk.Vendor)
					if IsPrivateKeyVendor(tk.Vendor) {
						openKey = h
					}
				}
				h.count++
			}
		}
		// Tested AFTER the line's own tokens, and against the same raw line,
		// so a key pasted as ONE history entry closes on the line it opened:
		// its BEGIN and END markers are both in that single line, and a block
		// that starts and ends at 2866 is the truthful answer there.
		if openKey != nil && isKeyBlockEnd(raw) {
			openKey.end = lineNum
			openKey = nil
		}
	}

	var findings []Finding
	for _, vendor := range order {
		h := byVendor[vendor]
		ln := h.line
		if IsPrivateKeyVendor(vendor) {
			findings = append(findings, cfg.privateKeyInHistoryFinding(path, vendor, ln, h.end, h.count))
			continue
		}
		f := cfg.ValueFinding(ValueFindingParams{
			FindingType:  FindingTypeShellHistorySecret,
			FilePath:     path,
			Line:         &ln,
			KeyName:      h.vendor,
			RawValue:     h.value,
			BaseSeverity: SeverityHigh,
			Confidence:   ConfidenceHigh,
			Evidence:     "a value matching a known vendor credential format was typed at the shell and recorded in history",
		})
		// Appended rather than passed in: ValueFinding's vendor-match branch
		// overwrites Evidence wholesale (a positive format match outranks
		// whatever the caller believed), and the repeat count is the one thing
		// it cannot know. It matters because only the first occurrence gets a
		// finding — see this function's doc comment — so without the count a
		// history holding three different GitHub tokens reads as holding one.
		if h.count > 1 {
			f.Evidence = fmt.Sprintf("%s; %d occurrences in this file, the first at line %d", f.Evidence, h.count, ln)
		}
		findings = append(findings, f)
	}
	return findings, lineScanErr(scanner)
}

// privateKeyInHistoryFinding builds the finding for key material typed at the
// prompt. Deliberately NOT a ValueFinding: the matched text is the
// "-----BEGIN … KEY-----" header, which is public knowledge, so a masked
// "value preview" of it would be theatre — and worse, every key of a given
// type shares that header byte-for-byte, so hashing it as a value would fold
// every private key on the machine into one cause group and one "secret".
//
// Critical rather than High: unlike a token, a private key cannot be rotated
// by clicking a button in a dashboard, and whatever it authorizes (a
// production host, a signing identity) it authorizes until someone
// regenerates and redistributes it.
func (c Config) privateKeyInHistoryFinding(path, vendor string, line, end, count int) Finding {
	f := c.baseFinding()
	f.FindingType = FindingTypeShellHistorySecret
	f.FilePath = path
	f.Line = &line
	// Set whenever the block CLOSED, including when it closed on the line it
	// opened — a key pasted as one history entry is a one-line block, and
	// "line 2866 through line 2866" is a known extent, not a missing one.
	// Only an unclosed block (end 0) leaves this nil, because there the file
	// genuinely does not say how far the key runs.
	if end >= line {
		f.EndLine = &end
	}
	f.KeyName = &vendor
	f.Severity = SeverityCritical
	f.Confidence = ConfidenceHigh
	f.Evidence = "private key material was typed at the shell and recorded in history; the key body is on the surrounding lines"
	if count > 1 {
		f.Evidence = fmt.Sprintf("%s (%d occurrences, the first at line %d)", f.Evidence, count, line)
	}
	// Manual, and set here rather than left to annotateRemedies' default:
	// there is no command for this one. See IsPrivateKeyVendor.
	f.Remedy = RemedyManual
	f.RecordID = RecordID(f.FindingType, f.FilePath, f.KeyName)
	return f
}

// historyCommand strips a history file's own metadata from a line and returns
// the command text, the byte offset where that text begins in the raw line,
// and whether the line carries a command at all. The offset is what lets
// HistoryLineTokens hand `jit migrate` spans into the RAW line — a redaction
// that spliced at command-relative offsets would land 15 bytes early on every
// zsh extended_history line and cut the timestamp instead of the credential.
//
// This is not cosmetic. Every zsh extended_history line begins with a 10-digit
// epoch timestamp, and a scanner that treats the raw line as flat text both
// pays to match vendor patterns against that timestamp and — measured — has
// every single line defeat any cheap length-based prefilter. Parsing the
// format first is what makes historyLineMayHoldToken work at all.
//
// Formats handled:
//
//	zsh, extended_history:  ": 1782826755:0;git status"
//	zsh/bash/sh, plain:     "git status"
//	bash, HISTTIMEFORMAT:   "#1782826755" on its own line, then the command
//	fish:                   "- cmd: git status", with "  when: …" metadata
//
// A zsh multi-line command is stored with an escaped newline and continues on
// the next physical line; those continuations are returned as their own
// command text, which is correct for this scanner (a credential token cannot
// span a line break) and keeps the reported line number pointing at the
// physical line a user has to go and delete.
func historyCommand(line string) (cmd string, offset int, ok bool) {
	// zsh extended history: ": <epoch>:<elapsed>;<command>"
	if rest, restOK := strings.CutPrefix(line, ": "); restOK {
		if semi := strings.IndexByte(rest, ';'); semi >= 0 {
			meta := rest[:semi]
			if colon := strings.IndexByte(meta, ':'); colon > 0 &&
				isAllDigits(meta[:colon]) && isAllDigits(meta[colon+1:]) {
				return rest[semi+1:], len(": ") + semi + 1, true
			}
		}
	}
	// fish: "- cmd: <command>", with indented "  when:"/"  paths:" metadata.
	if rest, restOK := strings.CutPrefix(line, "- cmd: "); restOK {
		return rest, len("- cmd: "), true
	}
	if strings.HasPrefix(line, "  ") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "when:") || strings.HasPrefix(trimmed, "paths:") ||
			strings.HasPrefix(trimmed, "- ") {
			return "", 0, false
		}
	}
	// bash with HISTTIMEFORMAT writes "#<epoch>" on its own line. Only an
	// all-digit body is metadata; "#!/bin/sh" and a real "# note" are not.
	if rest, restOK := strings.CutPrefix(line, "#"); restOK && rest != "" && isAllDigits(rest) {
		return "", 0, false
	}
	return line, 0, true
}

// HistoryLineTokens returns every vendor-format credential in one raw history
// line, with Start/End as byte offsets into that raw line — metadata included —
// rather than into the extracted command text. It is the detection half `jit
// migrate`'s history redaction shares with this scanner: a span returned here
// is exactly what scanShellHistoryFile would report, relocated so a caller
// holding the original file bytes can splice the credential out without
// re-implementing the format parsing. Detection stays in this read-only
// package so scan and migrate can never disagree about what counts.
func HistoryLineTokens(line string) []FileToken {
	cmd, off, ok := historyCommand(line)
	if !ok || !historyLineMayHoldToken(cmd) {
		return nil
	}
	toks := matchLineTokens(cmd)
	for i := range toks {
		toks[i].Start += off
		toks[i].End += off
	}
	// Sorted by position, because matchLineTokens returns matches in
	// knownTokenPatterns' DECLARATION order, not the order they appear in the
	// line — it runs each pattern over the whole line in turn. A caller that
	// reasonably reads "every match in this line" as "in reading order" gets
	// silently wrong behavior otherwise, and migrate's redaction splice, which
	// copies data[prev:span.start] forward, gets a descending pair and panics
	// on the slice bounds. A line holding an AWS key before a GitHub token
	// does exactly that, since GitHub's pattern is declared first.
	sort.Slice(toks, func(a, b int) bool { return toks[a].Start < toks[b].Start })
	return toks
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// historyLineMayHoldToken is a cheap rejection test run before the vendor
// patterns: false means no pattern in knownTokenPatterns can match this line,
// so the line can be skipped without running any of them.
//
// It exists because the honest cost of this feature was otherwise unacceptable.
// Running all ~55 patterns over every line measures ~1.8 MB/s, and a machine
// whose entire `jit scan` takes 0.20s would have spent 1.1s more on a 2 MB
// history and 2.5s more on a 4.7 MB one — a 6x to 13x slowdown for one file.
// This test measures ~130x faster than the pattern loop, which puts the added
// cost back into the noise.
//
// It admits 14% of lines on a real 592-line history (measured 2026-08-04), not
// the ~5% an earlier revision of this comment claimed. The gap is the two
// broadest conditions: "@" takes every `ssh user@host` and every email
// address, and a 10-character run of token-body characters takes ordinary
// words like "kubectl", "deployments" and "docker-compose". That is fine for
// a scan, where the alternative is running every pattern anyway — but the
// number is load-bearing for internal/guard, which forks a process per
// admitted line at the interactive prompt, so it is stated here rather than
// estimated there.
//
// Two alternatives were measured and rejected. A single combined alternation
// over every pattern ran 3x SLOWER than the individual patterns, because Go's
// regexp loses its per-pattern literal-prefix optimization under a large
// alternation. A run-length test that counted "." as part of a run admitted
// every line, since "registry.npmjs.org" and any dotted hostname qualify.
//
// CORRECTNESS OBLIGATION: this must never reject a line a pattern would match.
// TestHistoryPrefilterNeverDropsAMatch enforces that against every entry in
// knownTokenPatterns, and is the test to extend when a pattern is added.
//
// The three admitting conditions, and what each covers:
//
//   - "-----BEGIN": the private-key header patterns, which contain no long
//     alphanumeric run at all.
//
//     KNOWN GAP: admitting these currently buys nothing. matchLineTokens
//     skips every "… Private Key" vendor (ceded to ScanPrivateKeys), and
//     ScanPrivateKeys only walks key FILES — it never sees a history line. So
//     key material typed at the prompt is admitted here, costs the caller a
//     full pattern pass (and, in internal/guard, a process fork), and is then
//     always reported clean. The condition stays because closing the gap
//     means reporting these, not because it is currently doing anything;
//     removing it would have to be undone. Closing it needs a decision this
//     comment cannot make: the matched span is the HEADER, not the key body,
//     so redacting it would destroy the line without moving a secret.
//
//   - "@": both connection-string patterns, whose match is anchored on the
//     "user:pass@" userinfo and whose password may be short.
//
//   - "eyJ": the JWT pattern, whose segments are "+"-quantified rather than
//     "{10,}" — "eyJa.b.c" is a legal match for it with no long run anywhere.
//     (An earlier revision of this comment said "eyJa.b."; that one is NOT a
//     match, since the pattern's trailing \b needs the third segment. The
//     literal is still checked rather than assumed, for the reason below.)
//     Every REAL JWT carries a base64 header far longer than the threshold, but
//     "no real credential is that short" is the reasoning that produces silent
//     misses, so the literal is checked instead of assumed.
//
//   - a run of 10+ [A-Za-z0-9_-]: every vendor-prefix pattern. Ten is set by
//     the shortest possible match among them — SendGrid's
//     "SG.xxxxxxxxxx.yyyyyyyyyy" has dot-separated segments of exactly 10, and
//     Slack's "xoxb-" plus 10 body characters is a 15-long run. "." is
//     deliberately NOT part of a run, or every dotted hostname would qualify.
func historyLineMayHoldToken(line string) bool {
	if strings.Contains(line, "-----BEGIN") || strings.IndexByte(line, '@') >= 0 ||
		strings.Contains(line, "eyJ") {
		return true
	}
	run := 0
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' {
			run++
			if run >= historyTokenRunLen {
				return true
			}
			continue
		}
		run = 0
	}
	return false
}

// historyTokenRunLen is the shortest run of token-body characters any entry in
// knownTokenPatterns can match within. See historyLineMayHoldToken.
const historyTokenRunLen = 10

// matchLineTokens returns every vendor-format match in one line, with the same
// first-claim-wins overlap resolution and placeholder rejection FindFileTokens
// applies, so a value reported here means exactly what it means there.
//
// Private-key headers are INCLUDED here, unlike in FindFileTokens. That looks
// like an inconsistency and is the opposite: FindFileTokens cedes them to
// ScanPrivateKeys, which inspects the key FILE (passphrase, permissions) and
// reports it far better than a raw match could — but ScanPrivateKeys walks
// files, and no file holds a history line. Ceding here ceded to nobody, so a
// key pasted at the prompt was admitted by the prefilter, cost a full pattern
// pass (and a process fork in internal/guard), and was then always reported
// clean.
//
// What a match means here is narrower than for any other vendor, and callers
// must respect it: the pattern is the "-----BEGIN … KEY-----" HEADER, not the
// key body. It is conclusive evidence that key material was typed, and it is
// NOT the secret. See IsPrivateKeyVendor.
func matchLineTokens(line string) []FileToken {
	var claimed [][2]int
	overlaps := func(lo, hi int) bool {
		for _, c := range claimed {
			if lo < c[1] && c[0] < hi {
				return true
			}
		}
		return false
	}
	var out []FileToken
	for _, tp := range knownTokenPatterns {
		for _, loc := range tp.pattern.FindAllStringIndex(line, -1) {
			lo, hi := loc[0], loc[1]
			if overlaps(lo, hi) {
				continue
			}
			match := line[lo:hi]
			if tp.exclude != nil && tp.exclude.MatchString(match) {
				continue
			}
			if isPlaceholderToken(match, tp.humanReadable) {
				continue
			}
			claimed = append(claimed, [2]int{lo, hi})
			out = append(out, FileToken{
				Start:    lo,
				End:      hi,
				Vendor:   tp.vendor,
				Verified: tp.verified,
				Value:    match,
			})
		}
	}
	return out
}

// IsPrivateKeyVendor reports whether a vendor label from HistoryLineTokens
// names private-key material rather than an ordinary credential.
//
// The distinction decides what a caller may DO with the match, so it is
// exported rather than left to a string check at each call site. Every other
// vendor's match IS the secret, so `jit migrate` vaults it and splices it out.
// A private-key match is only the header line: splicing that out would leave
// the base64 body sitting in the file while making the file look cleaned, and
// would store a header — public knowledge — in the vault as if it were a
// credential. So this material is REPORTED (jit scan, and internal/guard
// blocks it before it is ever written) and never redacted; the remedy is to
// regenerate the key, which no command of jit's can do.
func IsPrivateKeyVendor(vendor string) bool {
	return strings.HasSuffix(vendor, "Private Key")
}

// isKeyBlockEnd reports whether a raw history line carries the closing marker
// of a PEM key block.
//
// Substring rather than a regexp, and matched on "END" plus "PRIVATE KEY"
// separately, because the two markers are not always adjacent on the line
// being tested: a key pasted as one history entry has the whole body sitting
// between them. What this must NOT do is bound the distance between them or
// insist on the surrounding dashes — a quoted paste, a heredoc, and a
// `ssh-keygen -f /dev/stdout` capture all punctuate the marker differently,
// and a missed END costs the reader the end of the range while a false one
// costs a range that stops early.
func isKeyBlockEnd(line string) bool {
	i := strings.Index(line, "END")
	if i < 0 {
		return false
	}
	return strings.Contains(line[i:], "PRIVATE KEY")
}

// IsShellHistoryPath reports whether path is one of the history files this
// scanner owns. Used by the report and coverage layers, which treat a
// credential sitting in history differently from one in a config file (the
// title names the location, the detail line carries the line number), and by
// `jit migrate`'s routing — an explicitly named history file goes to
// in-place redaction (migrate.ApplyShellHistory), never to the generic
// loose-secret categories, whose whole-file semantics would destroy the
// shell's own record.
func IsShellHistoryPath(path string) bool {
	return isShellHistoryName(filepath.Base(path))
}
