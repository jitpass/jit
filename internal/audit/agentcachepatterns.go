// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"bytes"
	"fmt"
	"regexp/syntax"
	"sort"
	"strings"
	"sync"
)

// The vendor-pattern sweep of AI agent caches: what crossReferenceAgentCaches
// cannot do, done cheaply enough to run on every scan.
//
// The cross-reference finds a cached copy by searching for a value some other
// finding just confirmed. That is exact and noise-free, and it has one blind
// spot by construction: once the origin is protected (a .env now holding a
// jit://vault pointer) there is no value left to search for, so a copy the
// migrate sweep could not remove — an agent was writing the file, or the store
// is binary — vanished from every later report while the plaintext stayed on
// disk. Measured 2026-09-21: a token in ~/.claude/file-history, reported before
// the migrate and by nothing after it.
//
// This sweep finds a vendor-format token by its SHAPE, so it needs no origin.
// It is the same knownTokenPatterns the content scanner runs — the same
// placeholder rejection, the same first-claim-wins — pointed at the cache
// trees. The reason it was not simply pointed there before is cost: those
// patterns are regexes, and running fifty of them over 75 MB of transcripts
// took 29 seconds on the machine this was built on. A whole-Mac scan takes
// under half a second. So:
//
//   - Every pattern is reduced to the fixed bytes any of its matches must
//     begin with — its literal LEAD, derived from the regex itself (never
//     retyped beside it), one per alternation branch: "AKIA" and "ASIA", not
//     the "A" the parser factors them into.
//   - One pass over the file finds every lead occurrence (the same bucketed
//     fixed-string scan the cross-reference uses), and the regex runs only on
//     a window around each hit. 43k candidate positions and 36 matches over
//     81 MB in 1.9 s, same machine.
//   - A pattern with no lead (the scheme-less "user:pass@host" form starts
//     with a character class) names an ANCHOR instead — a literal every match
//     must contain — and is windowed on both sides of it.
//
// The obligation this takes on is the one every prefilter has: it must never
// drop a match the full regex would have found. TestPatternLeadsNeverDropAMatch
// holds that over the shared admit corpus, the same way the shell-history
// prefilter is held.
//
// Textual files only. A binary store is the cross-reference's territory — a
// NUL-sniffed SQLite page is not something a `\b`-anchored pattern can be
// trusted on — and the exact-string search already covers it whenever the
// origin is known.

// patternAnchors could name, for a pattern whose regex has no literal lead,
// a literal every one of its matches must contain. It is empty on purpose.
// The scheme-less connection string was swept through an "@" anchor until
// 2026-09-21, when a real transcript reported "sip:894…@zoomcrc.com" and
// "from:notifications@calendly.com" as database credentials: in prose
// about mail and meetings, "word:word@host" is ordinary text. A shape with
// no fixed bytes is not admitted to the sweep (design/scan-and-protect.md
// D6); it keeps matching in the files the content scanner reads, where it
// has earned its place, and a vaulted password's copy in a transcript is
// the deep scan's to find by value. TestPatternSweepSkipsShapesWithoutLeads
// pins the exact set left out.
var patternAnchors = map[string]string{}

// patternNeedle is one fixed string to look for and the pattern it belongs to.
type patternNeedle struct {
	lit     string
	pattern int  // index into knownTokenPatterns
	anchor  bool // lit may sit anywhere inside the match, not only at its start
}

// patternLeadIndex is the needle set over knownTokenPatterns, bucketed by
// first byte like substrIndex.
type patternLeadIndex struct {
	needles []patternNeedle
	byFirst [256][]int
}

var (
	leadIndexOnce sync.Once
	leadIndex     *patternLeadIndex
)

// cachePatternIndex is the process-wide index, built once from the pattern
// table.
func cachePatternIndex() *patternLeadIndex {
	leadIndexOnce.Do(func() { leadIndex = buildPatternLeadIndex() })
	return leadIndex
}

// sweptByPattern reports whether a table entry takes part in this sweep.
// Private-key bodies are ceded to ScanPrivateKeys, as FindFileTokens does.
func sweptByPattern(tp tokenPattern) bool {
	if strings.HasSuffix(tp.vendor, "Private Key") {
		return false
	}
	lits, _ := patternLeads(tp)
	return len(lits) > 0
}

// patternLeads returns the needles for one pattern: its literal leads, or its
// anchor, or nothing.
func patternLeads(tp tokenPattern) (lits []string, anchor bool) {
	if l := regexLiteralLeads(tp.pattern.String()); len(l) > 0 {
		return l, false
	}
	if a, ok := patternAnchors[tp.vendor]; ok {
		return []string{a}, true
	}
	return nil, false
}

func buildPatternLeadIndex() *patternLeadIndex {
	idx := &patternLeadIndex{}
	for i, tp := range knownTokenPatterns {
		if !sweptByPattern(tp) {
			continue
		}
		lits, anchor := patternLeads(tp)
		for _, l := range lits {
			idx.byFirst[l[0]] = append(idx.byFirst[l[0]], len(idx.needles))
			idx.needles = append(idx.needles, patternNeedle{lit: l, pattern: i, anchor: anchor})
		}
	}
	return idx
}

// regexLiteralLeads derives the fixed bytes every match of expr must begin
// with — one per alternation branch — skipping leading zero-width assertions.
// Empty when some branch has no such lead, or when the lead is case-folded
// (a "(?i)" pattern has no single byte sequence to look for).
func regexLiteralLeads(expr string) []string {
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return nil
	}
	return leadsOf(re)
}

func leadsOf(node *syntax.Regexp) []string {
	switch node.Op {
	case syntax.OpCapture:
		return leadsOf(node.Sub[0])
	case syntax.OpLiteral:
		if node.Flags&syntax.FoldCase != 0 {
			return nil
		}
		return []string{string(node.Rune)}
	case syntax.OpAlternate:
		var out []string
		for _, sub := range node.Sub {
			l := leadsOf(sub)
			if len(l) == 0 {
				return nil // one branch without a lead makes the whole pattern unindexable
			}
			out = append(out, l...)
		}
		return out
	case syntax.OpConcat:
		// The parser factors "AKIA|ASIA" into A(?:KIA|SIA): a literal head
		// followed by an alternation. Expand the head across the branches so
		// the needles are the full prefixes, not the shared first byte.
		head := ""
		for _, sub := range node.Sub {
			switch sub.Op {
			case syntax.OpWordBoundary, syntax.OpNoWordBoundary, syntax.OpBeginLine, syntax.OpBeginText, syntax.OpEmptyMatch:
				continue
			case syntax.OpLiteral:
				if sub.Flags&syntax.FoldCase != 0 {
					return leadOrNil(head)
				}
				head += string(sub.Rune)
				continue
			case syntax.OpCapture, syntax.OpAlternate:
				tails := leadsOf(sub)
				if len(tails) == 0 {
					return leadOrNil(head)
				}
				out := make([]string, 0, len(tails))
				for _, t := range tails {
					out = append(out, head+t)
				}
				return out
			default:
				return leadOrNil(head)
			}
		}
		return leadOrNil(head)
	}
	return nil
}

func leadOrNil(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

// Window sizes around a candidate. A lead match starts AT the hit, so the
// window needs one byte before it (for the pattern's `\b`) and room after it
// for the longest token; a JWT can run past 8 KiB, so a match that reaches
// the window's end is retried in a wider one. An anchor sits inside its
// match, so the window opens on both sides.
const (
	leadWindow      = 8 << 10
	anchorWindow    = 1 << 10
	maxPatternMatch = 1 << 20
)

// matches returns every vendor-format match in data, in file order, with the
// same first-claim-wins overlap rule, exclude list and placeholder rejection
// FindFileTokens applies — a value reported here means exactly what it means
// there. Line numbers are filled in for every token returned.
func (x *patternLeadIndex) matches(data []byte) []FileToken {
	if len(x.needles) == 0 || len(data) == 0 {
		return nil
	}
	type cand struct{ at, needle int }
	var cands []cand
	for i := 0; i < len(data); i++ {
		for _, ni := range x.byFirst[data[i]] {
			n := x.needles[ni].lit
			if len(data)-i < len(n) || string(data[i:i+len(n)]) != n {
				continue
			}
			cands = append(cands, cand{i, ni})
		}
	}
	if len(cands) == 0 {
		return nil
	}
	// Position order, and within one position the table's order: the table
	// is specific-first (sk-proj- before sk-), so the more specific pattern
	// claims the span and the generic one then overlaps and yields — the
	// same "first claim wins" FindFileTokens relies on.
	//
	// One assumption, and a test that pins it (TestSweepOverlapMatchesFind
	// FileTokens): FindFileTokens resolves overlaps by TABLE priority, this
	// by POSITION then table. The two agree whenever a nested specific
	// pattern starts at the same byte as its generic parent (every sk-*
	// pair) or earlier (the scheme'd URL over the scheme-less one). They
	// would disagree only for a specific pattern listed first that starts
	// LATER than a generic one enclosing it — no such pair exists in the
	// table, and the test is what keeps a future one from going unnoticed.
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].at != cands[j].at {
			return cands[i].at < cands[j].at
		}
		return x.needles[cands[i].needle].pattern < x.needles[cands[j].needle].pattern
	})

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
	for _, c := range cands {
		n := x.needles[c.needle]
		if overlaps(c.at, c.at+len(n.lit)) {
			continue
		}
		tp := knownTokenPatterns[n.pattern]
		lo, hi := matchAround(data, tp, c.at, n.anchor)
		if lo < 0 {
			continue
		}
		if overlaps(lo, hi) {
			continue
		}
		match := string(data[lo:hi])
		if tp.exclude != nil && tp.exclude.MatchString(match) {
			continue
		}
		if isPlaceholderToken(match, tp.humanReadable) {
			continue
		}
		claimed = append(claimed, [2]int{lo, hi})
		line, col := lineAround(data, lo)
		out = append(out, FileToken{
			Start:        lo,
			End:          hi,
			Vendor:       tp.vendor,
			Verified:     tp.verified,
			Value:        match,
			AssignedName: assignedCredentialName(line, col),
		})
	}
	if len(out) == 0 {
		return nil
	}
	// Line numbers in one pass: the tokens are in file order once sorted by
	// Start, and counting newlines cumulatively is O(file), not O(file ×
	// tokens).
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	lineNo, pos := 1, 0
	for i := range out {
		lineNo += bytes.Count(data[pos:out[i].Start], []byte{'\n'})
		pos = out[i].Start
		out[i].Line = lineNo
	}
	return out
}

// matchAround runs tp's regex on a window around at and returns the absolute
// span of the match that covers it, or lo = -1 when none does. A lead match
// must START at at (the lead is the match's first bytes); an anchor match
// must contain at.
func matchAround(data []byte, tp tokenPattern, at int, anchor bool) (lo, hi int) {
	wlo, whi := at-1, at+leadWindow
	if anchor {
		wlo, whi = at-anchorWindow, at+anchorWindow
	}
	for {
		if wlo < 0 {
			wlo = 0
		}
		if whi > len(data) {
			whi = len(data)
		}
		grew := false
		for _, m := range tp.pattern.FindAllIndex(data[wlo:whi], -1) {
			s, e := wlo+m[0], wlo+m[1]
			if anchor {
				if s > at || at >= e {
					continue
				}
			} else if s != at {
				continue
			}
			// A match that runs to the window's edge may be cut short (a
			// `\b` holds at end-of-input). Widen and look again, up to the
			// longest token this sweep will believe in.
			if e == whi && whi < len(data) && whi-at < maxPatternMatch {
				grew = true
				break
			}
			return s, e
		}
		if !grew {
			return -1, -1
		}
		whi = at + (whi-at)*4
	}
}

// lineAround returns the line containing offset, bounded so a minified
// megabyte line costs a bounded read, and offset's column within it.
func lineAround(data []byte, offset int) (line string, col int) {
	const bound = 4 << 10
	lo := offset - bound
	if lo < 0 {
		lo = 0
	}
	if i := bytes.LastIndexByte(data[lo:offset], '\n'); i >= 0 {
		lo += i + 1
	}
	hi := offset + bound
	if hi > len(data) {
		hi = len(data)
	}
	if i := bytes.IndexByte(data[offset:hi], '\n'); i >= 0 {
		hi = offset + i
	}
	return string(data[lo:hi]), offset - lo
}

// agentCachePatternFindings reports the vendor-format values in one textual
// cache file as exposed_secret findings — one per (file, vendor), the content
// scanner's rule, since record_id is finding_type+file_path+key_name — tagged
// with the agent and cache area so the report groups them where the
// cross-reference's copies already sit.
func (c Config) agentCachePatternFindings(path, agent string, data []byte, skipValues map[string]bool) []Finding {
	tokens := cachePatternIndex().matches(data)
	if len(tokens) == 0 {
		return nil
	}
	occurrences := map[string]int{}
	for _, tk := range tokens {
		occurrences[tk.Vendor]++
	}
	area := AgentCacheArea(c.HomeDir, path)
	where := possessive(agent) + " cache"
	if area != "" {
		where = possessive(agent) + " " + area
	}
	var findings []Finding
	seen := map[string]bool{}
	for _, tk := range tokens {
		if skipValues[tk.Value] || seen[tk.Vendor] {
			continue
		}
		seen[tk.Vendor] = true
		ln := tk.Line
		f := c.ValueFinding(ValueFindingParams{
			FindingType:  FindingTypeExposedSecret,
			FilePath:     path,
			Line:         &ln,
			KeyName:      tk.Vendor,
			RawValue:     tk.Value,
			BaseSeverity: SeverityHigh,
			Confidence:   ConfidenceHigh,
			Evidence:     "value matches a known vendor credential format",
		})
		// After ValueFinding, which writes the standard vendor sentence: the
		// same shape ScanAgentStores gives a store finding, so the two read
		// alike in a report.
		f.Evidence = fmt.Sprintf("%s (found in %s)", f.Evidence, where)
		f.AssignedName = tk.AssignedName
		f.Occurrences = occurrences[tk.Vendor]
		f.Agent = agent
		f.CacheArea = area
		findings = append(findings, f)
	}
	return findings
}

// CachePatternTokens is the sweep's matcher over bytes already in hand, for
// `jit migrate redact`: the same needles, windows, overlap rule, excludes
// and placeholder rejection the scan applies, so what redact rewrites is
// exactly what the scan reported — one Start/End span per token, absolute
// offsets into data, the line filled in. The caller decides what to do with
// binary content; this only matches.
func CachePatternTokens(data []byte) []FileToken {
	return cachePatternIndex().matches(data)
}
