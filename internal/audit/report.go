// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fatih/color"

	"github.com/jitpass/jit/internal/style"
	"github.com/jitpass/jit/internal/termtext"
)

// Report glyphs, aliased from internal/style — the single ASCII-swap point
// both this package and internal/cli now share. They used to be a hand-copied
// mirror of cli/style.go's block with a "change the two together" comment,
// which is the kind of instruction that holds right up until it doesn't.
const (
	reportGlyphOK   = style.GlyphOK
	reportGlyphWarn = style.GlyphWarn
	reportGlyphRisk = style.GlyphRisk
)

// highlightCmds renders `backtick`-delimited command spans cyan (the house
// color for something the reader can run) and drops the backticks — the
// audit-package twin of internal/cli's hlCmds, for the same reason as the
// glyphs above. When color is off the spans pass through as clean text.
func highlightCmds(s string) string {
	cmd := style.Path
	var b strings.Builder
	for {
		i := strings.IndexByte(s, '`')
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		j := strings.IndexByte(s[i+1:], '`')
		if j < 0 {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(s[:i])
		b.WriteString(cmd.Sprint(s[i+1 : i+1+j]))
		s = s[i+1+j+1:]
	}
}

// findingTypeLabels are human-readable section headers, in AllFindingTypes
// order, matching docs/audit/example-report.md's preview format. Keys are
// enum labels, not credential material — see finding.go's justification for
// the same gosec G101 pattern-match false positive.
var findingTypeLabels = map[string]string{ // #nosec G101 -- enum label keys, not credentials
	FindingTypeShellConfigSecret:  "Shell Configs",
	FindingTypeEnvFilePresent:     ".env Files",
	FindingTypeCredentialFile:     "Credential Files",
	FindingTypeMCPEmbeddedSecret:  "AI Tool / MCP Configs",
	FindingTypePrivateKeyRisk:     "Private Keys",
	FindingTypeIACVariableFile:    "IaC Variable Files",
	FindingTypeWrappableCLIToken:  "Wrappable CLI Tokens",
	FindingTypeSOPSAgeKey:         "SOPS Age Keys",
	FindingTypeExposedSecret:      "Exposed Secrets",
	FindingTypeShellHistorySecret: "Shell History",
	FindingTypeAgentCachedSecret:  "AI Agent Caches",
}

// The severity ladder spends the semantic inks rather than shades of one
// hue, so a rung is told apart by what its ink MEANS and by the word, never
// by how yellow it is. It used to run red-bold / amber-bold / amber / cyan,
// which read on a real terminal as three different yellows (bold amber
// renders as bright yellow, i.e. orange, in most themes) plus a cyan that
// the palette reserves for things the reader can type.
//
//	CRITICAL  red bold  a live credential, act now
//	HIGH      red       almost certainly a credential
//	MEDIUM    amber     secret-shaped, unconfirmed
//	LOW       plain     a broad match, probably fine
//	INFO      plain     context only, jit makes no claim
var riskLevelColor = map[string]*color.Color{
	RiskLevelCritical: style.RiskBold,
	RiskLevelHigh:     style.Risk,
	RiskLevelMedium:   style.Warn,
	RiskLevelLow:      style.PlainColor,
	RiskLevelClean:    style.OKBold,
}

// The same ladder as riskLevelColor, so a [high] tag and a HIGH severity
// label are the same red. Info used to be FgWhite — a seventh ink, and one
// that only equals "default" on a dark terminal.
var severityColor = map[string]*color.Color{
	SeverityCritical: style.RiskBold,
	SeverityHigh:     style.Risk,
	SeverityMedium:   style.Warn,
	SeverityLow:      style.PlainColor,
	SeverityInfo:     style.PlainColor,
}

func colorOr(m map[string]*color.Color, key string) *color.Color {
	if c, ok := m[key]; ok {
		return c
	}
	return style.PlainColor
}

// severityRank orders findings worst-first within a category. An unknown
// severity sorts last rather than panicking or landing first, since a
// missing/typo'd severity is a scanner bug, not a reason to hide it up top.
var severityRank = map[string]int{
	SeverityCritical: 0,
	SeverityHigh:     1,
	SeverityMedium:   2,
	SeverityLow:      3,
	SeverityInfo:     4,
}

func rankOf(severity string) int {
	if r, ok := severityRank[severity]; ok {
		return r
	}
	return len(severityRank)
}

// groupFindingsByType buckets findings by FindingType — no ordering here;
// buildRenderItems (called per-group by each renderer) is what decides
// display order and collapsing, so both renderers stay in sync by
// construction rather than by copy-pasted sort logic.
func groupFindingsByType(findings []Finding) map[string][]Finding {
	byType := map[string][]Finding{}
	for _, f := range findings {
		byType[f.FindingType] = append(byType[f.FindingType], f)
	}
	return byType
}

// findingDedupKey identifies findings that are the exact same
// pattern — same severity, same key name, same evidence, same masked
// value — regardless of which file they're in. Line is deliberately
// excluded: two shell configs exporting the same secret-shaped key are
// still the same pattern even if it's line 12 in one and line 40 in the
// other.
func findingDedupKey(f Finding) string {
	key, val := "", ""
	if f.KeyName != nil {
		key = *f.KeyName
	}
	if f.ValuePreview != nil {
		val = *f.ValuePreview
	}
	return f.Severity + "\x00" + key + "\x00" + f.Evidence + "\x00" + val
}

// findingLocation is one file (+ line, if applicable) inside a collapsed
// renderItem's location list.
type findingLocation struct {
	Path string
	Line *int
}

// collapsibleFindingTypes are the categories where identical evidence text
// genuinely means "the same secret, variable name, or key weakness
// repeated" — safe to collapse. IaC's unescalated tier is deliberately
// excluded: its evidence is fixed, rule-level text
// ("infrastructure-as-code variable file — detection only...") that says
// nothing about a specific file's content, so any two unrelated files
// matching the same rule would produce byte-identical evidence and
// collapse into one block that wrongly implies they're related — a real
// case dogfooding turned up (two Secret.yaml manifests from an unrelated
// repo collapsed with a project's own secrets.yaml, sharing nothing but
// the same generic advisory).
var collapsibleFindingTypes = map[string]bool{
	FindingTypeShellConfigSecret: true,
	FindingTypeEnvFilePresent:    true,
	FindingTypeCredentialFile:    true,
	FindingTypeMCPEmbeddedSecret: true,
	FindingTypePrivateKeyRisk:    true,
}

// renderItem is one visual block within a category's finding list. Most
// findings render as a per-file block: every finding for one file, worst
// severity first (a file with two secrets in it is one file with two
// things to fix, not two separate problems). When 2+ DIFFERENT files carry
// the exact same severity/key/evidence/value, they collapse into one block
// instead — dogfooding turned this up constantly (the same MCP server's
// credentials embedded in 3 separate config files, the same secret-shaped
// variable name repeated across 7 unrelated .env files), and repeating an
// identical explanation once per file was the single biggest source of
// visual clutter in a real, dense report.
type renderItem struct {
	collapsed bool
	rep       Finding           // representative finding: severity/key/value/evidence
	findings  []Finding         // per-file item only: every finding for rep.FilePath, worst-first
	locations []findingLocation // collapsed item only: every file sharing rep's pattern, sorted
}

// collapsedHeader is a collapsed renderItem's own header line — printed
// instead of a file path, so it visually starts a new block the same way a
// file path does for a per-file item, rather than reading as a continuation
// of whatever item preceded it.
func collapsedHeader(it renderItem) string {
	if it.rep.KeyName != nil {
		return fmt.Sprintf("%s (same value in %d files):", *it.rep.KeyName, len(it.locations))
	}
	return fmt.Sprintf("same pattern in %d files:", len(it.locations))
}

// itemArchived reports whether a render item is entirely archived. A collapsed
// item spanning both a live and an archived copy of the same secret counts as
// LIVE — the live copy is the actionable one, and sorting the pair down would
// hide it behind the archived duplicate that caused the collapse.
func itemArchived(it renderItem) bool {
	if !it.collapsed {
		return it.rep.Archived
	}
	for _, f := range it.findings {
		if !f.Archived {
			return false
		}
	}
	for _, loc := range it.locations {
		if !LooksArchived(loc.Path) {
			return false
		}
	}
	return true
}

func (it renderItem) sortPath() string {
	if it.collapsed {
		return it.locations[0].Path
	}
	return it.rep.FilePath
}

// buildRenderItems turns one category's findings into ordered display
// blocks: collapsing exact-duplicate patterns that span multiple files,
// then sorting every remaining block (collapsed or per-file) worst
// severity first, file path as the tiebreak.
func buildRenderItems(group []Finding) []renderItem {
	collapsible := len(group) > 0 && collapsibleFindingTypes[group[0].FindingType]

	byKey := map[string][]Finding{}
	var keyOrder []string
	for _, f := range group {
		k := findingDedupKey(f)
		if _, ok := byKey[k]; !ok {
			keyOrder = append(keyOrder, k)
		}
		byKey[k] = append(byKey[k], f)
	}

	var items []renderItem
	perFile := map[string][]Finding{}
	var fileOrder []string

	for _, k := range keyOrder {
		fs := byKey[k]
		distinctPaths := map[string]bool{}
		for _, f := range fs {
			distinctPaths[f.FilePath] = true
		}

		if collapsible && len(distinctPaths) > 1 {
			sort.Slice(fs, func(i, j int) bool { return fs[i].FilePath < fs[j].FilePath })
			seen := map[string]bool{}
			var locs []findingLocation
			for _, f := range fs {
				if seen[f.FilePath] {
					continue
				}
				seen[f.FilePath] = true
				locs = append(locs, findingLocation{Path: f.FilePath, Line: f.Line})
			}
			items = append(items, renderItem{collapsed: true, rep: fs[0], locations: locs})
			continue
		}

		for _, f := range fs {
			if _, ok := perFile[f.FilePath]; !ok {
				fileOrder = append(fileOrder, f.FilePath)
			}
			perFile[f.FilePath] = append(perFile[f.FilePath], f)
		}
	}

	for _, path := range fileOrder {
		fs := perFile[path]
		sort.Slice(fs, func(i, j int) bool {
			if si, sj := rankOf(fs[i].Severity), rankOf(fs[j].Severity); si != sj {
				return si < sj
			}
			if fs[i].Line != nil && fs[j].Line != nil && *fs[i].Line != *fs[j].Line {
				return *fs[i].Line < *fs[j].Line
			}
			if fs[i].KeyName != nil && fs[j].KeyName != nil {
				return *fs[i].KeyName < *fs[j].KeyName
			}
			return false
		})
		items = append(items, renderItem{findings: fs, rep: fs[0]})
	}

	sort.Slice(items, func(i, j int) bool {
		// Live findings before archived ones, ahead of severity. A machine
		// with a lot of deleted-but-not-purged secrets buries the ones the
		// reader can act on: one real scan (2026-07-28) had ~40 findings under
		// ~/.Trash and a handful of live ones, and the live ones sorted last.
		//
		// This is ordering only. Severity, confidence and the exposure score
		// are deliberately untouched: a credential in ~/.Trash is still on
		// disk and still works — "anything running as you can read them" is
		// exactly as true there — so discounting its RISK would under-report a
		// real exposure. What differs is only what the reader can do about it,
		// which is why `jit migrate home` skips these and the report tags them
		// [archived]. Rank follows actionability, not exposure.
		if ai, aj := itemArchived(items[i]), itemArchived(items[j]); ai != aj {
			return !ai
		}
		ri, rj := rankOf(items[i].rep.Severity), rankOf(items[j].rep.Severity)
		if ri != rj {
			return ri < rj
		}
		if pi, pj := items[i].sortPath(), items[j].sortPath(); pi != pj {
			return pi < pj
		}
		// Two collapsed items can tie on both severity and first path (e.g.
		// JAMF_PRO_CLIENT_ID and JAMF_PRO_CLIENT_SECRET both start at the
		// same file) — sort.Slice isn't stable, so without this tiebreak
		// their relative order isn't guaranteed across runs.
		ki, kj := "", ""
		if items[i].rep.KeyName != nil {
			ki = *items[i].rep.KeyName
		}
		if items[j].rep.KeyName != nil {
			kj = *items[j].rep.KeyName
		}
		return ki < kj
	})
	return items
}

// criticalTriggerPaths returns the distinct file paths that tripped the
// production-indicator/public-IP escalation rules (RFC.md §4), sorted for
// deterministic output. Both human and Markdown risk banners used to say
// "see below" with no way to jump straight there — with dozens of findings
// spread across several categories, that made "CRITICAL" cost a full read
// of the report to resolve into an actual file to go fix.
func criticalTriggerPaths(findings []Finding) []string {
	seen := map[string]bool{}
	var paths []string
	for _, f := range findings {
		if !f.ProductionIndicatorMatch && f.PublicIPMatch == nil {
			continue
		}
		if seen[f.FilePath] {
			continue
		}
		seen[f.FilePath] = true
		paths = append(paths, f.FilePath)
	}
	sort.Strings(paths)
	return paths
}

// ShortenHome replaces a leading home directory with "~" for human
// output — on a real machine every finding line otherwise starts with the
// same dozens of /Users/<name>/... characters before the part that matters.
// An empty home disables shortening. Exported because it's the single
// implementation of this rule: internal/cli's displayPath delegates here
// rather than keeping a copy that could drift.
func ShortenHome(home, path string) string {
	if home == "" {
		return path
	}
	if path == home {
		return "~"
	}
	if strings.HasPrefix(path, home+string(filepath.Separator)) {
		return "~" + path[len(home):]
	}
	return path
}

// displayFilePath renders a path for the terminal report: "~"-shortened
// and with spaces backslash-escaped so the line works pasted into a shell
// verbatim. A real support case: a user cat'ed the report's
// `~/Library/Application Support/Claude/claude_desktop_config.json`
// finding, the unquoted space split the path into two arguments, the "No
// such file or directory" that followed read as a false positive, and a
// real HIGH finding went uninvestigated. Backslash-escaping (rather than
// single-quoting) keeps the leading `~` expandable. The Markdown renderer
// deliberately doesn't do this: its paths sit in backtick code spans,
// already unambiguous, and literal backslashes there would be wrong.
func displayFilePath(home, path string) string {
	return strings.ReplaceAll(ShortenHome(home, path), " ", "\\ ")
}

// writeDerivedCredentialAdvisory states what jit found but does not cover.
//
// It is phrased as a boundary rather than a warning, because that is what it
// is: these files are working state a tool wrote for itself, they are supposed
// to exist, and there is nothing here for jit to fix. The reason it gets its
// own block instead of a footnote is that the report immediately above it has
// just accounted for ~/.aws — and a reader who watched jit clean that
// directory would otherwise reasonably conclude it was empty of secrets.
func writeDerivedCredentialAdvisory(w io.Writer, summary ScanSummary, home string) {
	if len(summary.DerivedCredentials) == 0 {
		return
	}
	_, _ = style.Bold.Fprintln(w, "  Outside jit's scope, found anyway:")
	for _, d := range summary.DerivedCredentials {
		fmt.Fprintf(w, "    %s\n", displayFilePath(home, d.Path))
		fmt.Fprintf(w, "      %s\n", d.What)
		if d.Advice != "" {
			fmt.Fprintf(w, "      %s\n", d.Advice)
		}
	}
	fmt.Fprintln(w, "    jit protects credentials you stored; these were minted by the tools that used them.")
	fmt.Fprintln(w, "    It does not manage, rotate or hide them — see docs/security/architecture.md.")
	fmt.Fprintln(w)
}

// archivedTag renders the per-path "[archived]" marker: the same
// LooksArchived test `jit migrate home` uses to skip a finding by default,
// so a reader can map an audit finding onto migrate's skip note instead of
// wondering why the fix plan dropped it (a real, reported confusion: audit
// showed a finding under ~/Documents/archive/, the dry-run showed only a
// skip count, and nothing connected the two). Computed from the path, not
// Finding.Archived, so the renderers stay correct for findings that never
// passed through Scan's tagging pass.
func archivedTag(path string) string {
	if LooksArchived(path) {
		return " [archived]"
	}
	return ""
}

// anyArchived reports whether any finding would carry archivedTag's marker.
func anyArchived(findings []Finding) bool {
	for _, f := range findings {
		if LooksArchived(f.FilePath) {
			return true
		}
	}
	return false
}

// WriteHumanReport renders the full-inventory scan report (RFC.md §4):
// `jit scan --full`, `--unfiltered`, and every targeted `jit scan <path>`.
// The house-style sibling of WriteTriageReport — same header voice, same
// glyph/arrow motifs (design/output-style.md) — keeping what this view is
// for: exact categories, severities, files and lines. Never a real secret
// value — only Finding.ValuePreview, which is already masked by the time it
// reaches here.
//
// home is used only to "~"-shorten paths for display; pass "" to keep
// absolute paths (a report saved to a file is re-read later, often by
// tools that can't expand "~"). Taking it as a parameter instead of
// reading $HOME at render time keeps the output a pure function of its
// arguments — the same reason scanners take Config.HomeDir.
func WriteHumanReport(w io.Writer, findings []Finding, summary ScanSummary, home string) {
	yellow := style.Warn
	green := style.OK
	cmd := style.Path

	who := summary.Endpoint.Username
	if who == "" {
		who = "unknown"
	}
	host := summary.Endpoint.Hostname
	if host == "" {
		host = "unknown"
	}
	where := "~/"
	if home == "" {
		where = "scan targets"
	}
	sizeNote := ""
	if summary.FilesScanned > 0 {
		// Inflected and digit-grouped, the same composition the triage header
		// uses: countWord would inflect but print a bare 25872.
		sizeNote = fmt.Sprintf(" · %s %s", groupDigits(summary.FilesScanned),
			pluralWord(summary.FilesScanned, "file", "files"))
	}
	// "jit scan  ~/ · 25,872 files · 12.2s" — byte-for-byte the shape the
	// triage view carries, because these are two views of one command and a
	// reader moving between them should not have to re-learn the top of the
	// page. It was an em-dash chain carrying user@host and a mid-line "full
	// inventory": a second header shape in a tool that has one, spending its
	// most prominent line on the reader's own username and hostname. Both are
	// things the program knows and the reader already does, and `jit doctor`
	// plus NDJSON's endpoint block are where machine identity earns its place.
	//
	// "jit scan" and not "jit scan --full", even though this is the inventory:
	// this function ALSO renders a targeted `jit scan <path>`, which reaches no
	// --full flag. Naming the flag here told those readers they had passed
	// something they hadn't. The view identifies itself by its shape.
	head := style.Bold.Sprint("jit scan") + "  " + where + sizeNote +
		" · " + formatDuration(summary.ScanDurationMs)
	termtext.Wrap(w, 0, "", head)

	// The unfiltered notice sits ABOVE the numbers, not in a footnote: like
	// the triage view's incomplete-scan banner, it changes what every count
	// below it means, and a saved report must never read as the normal
	// picture.
	if summary.Unfiltered {
		_, _ = yellow.Fprint(w, reportGlyphWarn)
		fmt.Fprint(w, " ")
		termtext.Wrap(w, 2, "  ", "suppression off "+"(--unfiltered) — settings, paths, browser-public build variables and template filler are all shown; the everyday view hides these")
	}
	fmt.Fprintln(w)

	// A partial scan must never be able to look like a complete one — the
	// same banner the triage view carries, in the same position, for the
	// same reason: it changes what every count below it means, and "0
	// findings" from a run that could not read a category is not the claim
	// a reader of a full inventory will think to question.
	if len(summary.DegradedScanners) > 0 {
		yellowBold := style.WarnBold
		noun := "categories"
		if len(summary.DegradedScanners) == 1 {
			noun = "category"
		}
		fmt.Fprint(w, "  ")
		termtext.Wrap(w, 2, "  ", yellowBold.Sprintf("INCOMPLETE SCAN — %d %s could not be read", len(summary.DegradedScanners), noun))
		for _, d := range summary.DegradedScanners {
			fmt.Fprint(w, "    ")
			termtext.Wrap(w, 4, "    ", yellow.Sprintf("%s — %s", d.Scanner, oneLine(shortenHomeInText(home, d.Error))))
		}
		fmt.Fprint(w, "  ")
		termtext.Wrap(w, 2, "  ", "Counts below cover everything else; secrets in the unread categories are not included.")
		fmt.Fprintln(w)
	}

	riskC := colorOr(riskLevelColor, summary.RiskLevel)
	riskGlyph := reportGlyphRisk
	switch summary.RiskLevel {
	case RiskLevelClean:
		riskGlyph = reportGlyphOK
	case RiskLevelMedium, RiskLevelLow:
		riskGlyph = reportGlyphWarn
	}
	fmt.Fprint(w, "  ")
	_, _ = riskC.Fprintf(w, "%s %s", riskGlyph, strings.ToUpper(summary.RiskLevel))
	fmt.Fprintf(w, " — exposure %d/100\n", summary.ExposureScore)
	if matches := summary.ProductionIndicatorCount + summary.PublicIPCount; matches > 0 {
		fmt.Fprint(w, "    ")
		termtext.Wrap(w, 4, "    ", fmt.Sprintf("%s — each file itemized in its category below",
			countWord(matches, "production-indicator/public-IP match", "production-indicator/public-IP matches")))
		// One exemplar, not the list: every trigger path reappears in its
		// category with line numbers, and thirteen near-identical paths
		// before the summary table pushed the table below the fold.
		if paths := criticalTriggerPaths(findings); len(paths) > 0 {
			prefix, suffix := "in ", ""
			if len(paths) > 1 {
				prefix = "e.g. "
				suffix = fmt.Sprintf(" … and %d more", len(paths)-1)
			}
			avail := termtext.Width() - 4 - len(prefix) - termtext.VisibleWidth(suffix)
			fmt.Fprintf(w, "    %s%s%s\n", prefix, termtext.TruncHead(displayFilePath(home, paths[0]), avail), suffix)
		}
	}
	fmt.Fprintln(w)

	countW := len(fmt.Sprintf("%d", summary.TotalFindings))
	for _, ft := range AllFindingTypes {
		n := summary.FindingsByCategory[ft]
		switch {
		case n == 0:
			// Dim the nothing-found rows so the categories that DO have
			// findings are what the eye lands on — the itemized sections
			// below already skip empty categories entirely.
			fmt.Fprintf(w, "  %-22s %*d\n", findingTypeLabels[ft], countW, n)
		case n >= heavyCategoryCount:
			fmt.Fprintf(w, "  %-22s ", findingTypeLabels[ft])
			_, _ = style.Bold.Fprintf(w, "%*d\n", countW, n)
		default:
			fmt.Fprintf(w, "  %-22s %*d\n", findingTypeLabels[ft], countW, n)
		}
	}
	fmt.Fprintf(w, "  %s\n", strings.Repeat(style.GlyphRule, 23+countW))
	fmt.Fprintf(w, "  %-22s %*d\n", "Total", countW, summary.TotalFindings)
	// Good news gets a line too: files jit already protects (live mounts,
	// content served from the encrypted vault) are excluded from the
	// findings above — say so, or their disappearance from the report reads
	// as the scanner having missed them.
	if summary.JitProtectedCount > 0 {
		fmt.Fprint(w, "  ")
		_, _ = green.Fprint(w, reportGlyphOK)
		fmt.Fprint(w, " ")
		termtext.Wrap(w, 4, "    ",
			fmt.Sprintf("%s already protected ", countWord(summary.JitProtectedCount, "live mount", "live mounts"))+
				"— served from the encrypted vault, no plaintext on disk (not scanned)")
	}
	fmt.Fprintln(w)

	// The advisory follows the clean line rather than replacing it: nothing
	// jit scans for was found, which is true and worth saying — and then the
	// one thing that would otherwise make "clean" misleading gets said too.
	if summary.TotalFindings == 0 {
		fmt.Fprint(w, "  ")
		_, _ = green.Fprint(w, reportGlyphOK)
		fmt.Fprintln(w, " No findings — this machine looks clean.")
		fmt.Fprintln(w)
		writeDerivedCredentialAdvisory(w, summary, home)
		return
	}
	writeDerivedCredentialAdvisory(w, summary, home)

	byType := groupFindingsByType(findings)

	// Each non-empty category renders as its own block: a bracketed name in
	// DEFAULT weight, a plain count, and a trailing blank line. Dense reports
	// used to run several categories together separated by a single blank line,
	// so where one category's findings ended and the next began was easy to
	// lose; the brackets plus the blank line before the next one are what give
	// every section an unmistakable start (house style — whitespace over
	// box-rules, and the brackets delimit better than bold would: rule 1 in
	// design/output-style.md). No rule beneath the header.
	//
	// This comment said "a bold header, a rule beneath it" until 2026-08-06,
	// contradicted itself four lines later with "No rule beneath it", and
	// described a `[name] (N)` count format that exists nowhere. The code below
	// was always right and always rule-1 compliant; the prose had drifted, in
	// four places that cited each other (internal/cli/style.go,
	// migrateplan.go twice, and design/output-style.md's own Report section,
	// which disagreed with its own rule 1).
	for _, ft := range AllFindingTypes {
		group := byType[ft]
		if len(group) == 0 {
			continue
		}

		fmt.Fprintf(w, "[%s]", findingTypeLabels[ft])
		fmt.Fprintf(w, " %d\n", summary.FindingsByCategory[ft])
		cols := computeColumns(group)
		for _, item := range buildRenderItems(group) {
			writeRenderItemText(w, item, home, cols)
		}
		// No extra blank here: every render item already ends with its own
		// blank line (the breathing room between rows), which doubles as the
		// section separator before the next bold header.
	}

	// The tag legends render once, above the migrate trailer, and only when
	// some finding actually carries the tag — a tag without an explanation
	// would read as jargon, and the explanation without any tagged finding
	// would be noise. (The unfiltered NOTICE itself sits at the top of the
	// report; this line only decodes the per-finding marker.)
	if anyArchived(findings) {
		_, _ = yellow.Fprint(w, "[archived]")
		termtext.Wrap(w, 10, "  ", " lives under an archived/backup-looking folder — name such a file explicitly to convert it")
	}
	if anyUnfilteredOnly(findings) {
		_, _ = yellow.Fprint(w, "[unfiltered]")
		termtext.Wrap(w, 12, "  ", " reported only because suppression is off — the everyday scan hides or downgrades it")
	}
	// The report's only prior "next step" pointed at an output-format
	// flag, not remediation — a first-time reader of a HIGH/CRITICAL
	// report had no pointer from here to the command that actually fixes
	// any of it. jit migrate's own dry-run trailer already points back
	// at `jit scan` the other way; this closes the loop. When there is a
	// concrete finding, name its real path in the example rather than a
	// `<path>` placeholder: `jit scan` runs pathless but `jit migrate`
	// requires an explicit target (it mutates files, so it never sweeps a
	// whole tree on its own), and re-deriving the flagged path by hand was
	// the friction point. A copy-pasteable command bridges that gap.
	//
	// Findings with no auto-fixable member get NO migrate trailer at all:
	// hasAutoFix's contract is that the copy-pasteable command never answers
	// "Nothing to migrate" — found by adversarial QA, 2026-08-02. Each
	// manual finding's own evidence line says what to do.
	fmt.Fprintln(w)
	if example := firstFindingPath(findings); example != "" {
		fmt.Fprint(w, "  ")
		termtext.Wrap(w, 2, "    ",
			cmd.Sprintf(style.GlyphAction+" jit migrate %s --dry-run", displayFilePath(home, example))+
				"   the guided fix plan for the first flagged file")
	}
	fmt.Fprint(w, "  ")
	// The way back. The triage view points here with "→ jit scan --full  the
	// full inventory · ndjson for machines"; without the reverse link a reader
	// who lands in the inventory first has no pointer to the view that tells
	// them what to DO, and that view is the one the product leads with.
	fmt.Fprintln(w)
	fmt.Fprint(w, "  ")
	_, _ = cmd.Fprint(w, style.GlyphAction+" ")
	termtext.Wrap(w, 4, "    ",
		cmd.Sprint("jit scan")+"   the action-first view · "+
			cmd.Sprint("--format ndjson")+" for machines")
	fmt.Fprint(w, "  ")
	termtext.Wrap(w, 2, "  ", "No secret values are ever printed in full.")
}

// anyUnfilteredOnly reports whether any finding carries the [unfiltered]
// marker, so its legend renders only when it decodes something.
func anyUnfilteredOnly(findings []Finding) bool {
	for _, f := range findings {
		if f.UnfilteredOnly {
			return true
		}
	}
	return false
}

// heavyCategoryCount is where a summary-table count gets bold: a
// double-digit category is where the report's weight actually is, and
// bolding every nonzero row would bold most of the table.
const heavyCategoryCount = 10

// firstFindingPath returns a representative flagged file path for the migrate
// trailer, in the same category order the report renders, so the example names
// a file the reader can actually see above it. Empty string when nothing was
// flagged (a clean report needs no fix example).
func firstFindingPath(findings []Finding) string {
	byType := groupFindingsByType(findings)
	for _, ft := range AllFindingTypes {
		for _, f := range byType[ft] {
			if f.FilePath != "" && hasAutoFix(f) {
				return f.FilePath
			}
		}
	}
	return ""
}

// hasAutoFix reports whether `jit migrate <path>` can actually do something
// with this finding, so the report's copy-pasteable trailer never hands the
// reader a command that answers "Nothing to migrate."
//
// Delegates to the Remedy annotation (annotateRemedies), which is the single
// source of truth for "who can act" — this function used to hardcode two
// manual cases (private keys, ~/.mcp-auth) and silently drifted the moment
// the remedy taxonomy added more (kubernetes Secret manifests,
// production-flagged and mixed-content exposed secrets). Renderers only run
// on annotated findings, so an empty Remedy here would be a caller bug; it
// reads as "no auto fix" rather than guessing.
func hasAutoFix(f Finding) bool {
	return f.Remedy == RemedyMigrate || f.Remedy == RemedyWrap
}

// findingIndent is the left margin every finding row sits at, one step in
// from its file-path header (which itself sits one "* " marker in from the
// category).
const findingIndent = "    "

// columns holds one category's display widths. The bounded fields — line,
// severity, masked value — plus the key align in fixed columns across every
// finding in the category, so a file with several findings reads like a
// structured log. The reason is deliberately NOT a column: it is free-form
// prose with no natural width, so it drops to its own hanging-indent line
// under the key, where it can wrap without breaking the alignment of the
// fields above it. Widths are computed once per category and shared by every
// row so they line up.
type columns struct {
	lineW, sevW, keyW int
	hasLine, hasKey   bool
	hasValue          bool
}

func lineTag(n int) string { return fmt.Sprintf(":%d", n) }

// pluralWord picks the singular or plural form for n — the package-local
// twin of the CLI's helper of the same name, so report text says "1
// finding" / "2 findings" instead of the "N finding(s)" form letter.
func pluralWord(n int, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
}

// countWord renders "1 finding" / "12 findings" — the count and its
// correctly inflected noun together, which is the pairing report call
// sites actually want.
func countWord(n int, singular, plural string) string {
	return fmt.Sprintf("%d %s", n, pluralWord(n, singular, plural))
}

func computeColumns(group []Finding) columns {
	c := columns{}
	for _, f := range group {
		if f.Line != nil {
			c.hasLine = true
			c.lineW = max(c.lineW, len(lineTag(*f.Line)))
		}
		c.sevW = max(c.sevW, len(strings.ToUpper(f.Severity)))
		if f.KeyName != nil {
			c.hasKey = true
			c.keyW = max(c.keyW, len(sanitizeDisplayPtr(f.KeyName)))
		}
		if f.ValuePreview != nil {
			c.hasValue = true
		}
	}
	return c
}

// reasonIndent is the column the key starts at, and therefore where a
// finding's reason line (and a collapsed item's file list) hangs, so the
// prose sits tucked under the key it explains rather than under the margin.
func (c columns) reasonIndent() int {
	n := len(findingIndent)
	if c.hasLine {
		n += c.lineW + 2
	}
	n += c.sevW + 2
	return n
}

// itemUnfilteredOnly reports whether a render item is [unfiltered]-tagged as
// a whole: a collapsed item by its representative, a per-file item only when
// EVERY finding in it is — a file mixing normal and gate-suppressed findings
// is a normal block whose tagged rows explain themselves individually.
func itemUnfilteredOnly(it renderItem) bool {
	if it.collapsed {
		return it.rep.UnfilteredOnly
	}
	for _, f := range it.findings {
		if !f.UnfilteredOnly {
			return false
		}
	}
	return len(it.findings) > 0
}

// writeItemTags renders the amber per-block markers ([archived],
// [unfiltered]) the trailer legends decode, and returns their display width
// so the caller can budget the path truncation around them.
func writeItemTags(w io.Writer, archived, unfiltered bool) {
	yellow := style.Warn
	if archived {
		_, _ = yellow.Fprint(w, " [archived]")
	}
	if unfiltered {
		_, _ = yellow.Fprint(w, " [unfiltered]")
	}
}

func itemTagsWidth(archived, unfiltered bool) int {
	n := 0
	if archived {
		n += len(" [archived]")
	}
	if unfiltered {
		n += len(" [unfiltered]")
	}
	return n
}

// writeRenderItemText renders one renderItem. A per-file item prints its path
// once as a "* "-marked header, a blank line, then each finding spaced out
// beneath. A collapsed item prints its OWN header line first (never omitted) —
// a real user found that a headerless collapsed block sitting directly under
// the previous item's file path read as if it were more findings for that
// same file, when it was actually an unrelated pattern shared by different
// files — then the shared finding and the file list.
func writeRenderItemText(w io.Writer, item renderItem, home string, cols columns) {
	unfiltered := itemUnfilteredOnly(item)
	if item.collapsed {
		// Same "• " marker as a file path: both kinds of header anchor a
		// block, and a category mixing marked files with unmarked collapsed
		// headers read as if only some blocks were "real".
		fmt.Fprintf(w, "  "+style.GlyphBullet+" %s", collapsedHeader(item))
		writeItemTags(w, false, unfiltered)
		fmt.Fprint(w, "\n\n")
		cols.writeFindingRow(w, item.rep, false)
		// The location list is secondary: it locates the shared pattern the row
		// above already explained, secondary by the house rule.
		locIndent := strings.Repeat(" ", cols.reasonIndent())
		for _, loc := range item.locations {
			entry := displayFilePath(home, loc.Path)
			if loc.Line != nil {
				entry = fmt.Sprintf("%s:%d", entry, *loc.Line)
			}
			archived := LooksArchived(loc.Path)
			avail := termtext.Width() - len(locIndent) - 2 - itemTagsWidth(archived, false)
			fmt.Fprintf(w, "%s- %s", locIndent, termtext.TruncHead(entry, avail))
			writeItemTags(w, archived, false)
			fmt.Fprintln(w)
		}
		fmt.Fprintln(w)
		return
	}

	// A "• " marker makes each file the eye's anchor within a category (a
	// real bullet, matching the report's other glyphs — the "─" rules and
	// "└" connectors), and a blank line after it (plus one after every
	// finding) gives the block room to breathe instead of packing rows
	// edge to edge.
	archived := LooksArchived(item.rep.FilePath)
	avail := termtext.Width() - 4 - itemTagsWidth(archived, unfiltered)
	fmt.Fprintf(w, "  "+style.GlyphBullet+" %s", termtext.TruncHead(displayFilePath(home, item.rep.FilePath), avail))
	writeItemTags(w, archived, unfiltered)
	fmt.Fprint(w, "\n\n")
	for _, f := range item.findings {
		cols.writeFindingRow(w, f, true)
		fmt.Fprintln(w)
	}
}

// displayEvidence is Evidence prepared for the terminal: when the pattern
// name the evidence restates is already on the row as the key ("Database
// connection string with embedded credentials … value matches Database
// connection string with embedded credentials's known token format"), the
// restatement compresses to "its" — the NDJSON keeps the full sentence,
// which stands alone there.
func displayEvidence(f Finding) string {
	ev := f.Evidence
	if f.KeyName != nil && ev == fmt.Sprintf("value matches %s's known token format", *f.KeyName) {
		ev = "value matches its known token format"
	}
	return sanitizeDisplay(ev)
}

// writeFindingRow renders one finding: a row of aligned bounded fields
// (severity, key, masked value) with the reason on its own hanging-indent
// line beneath, tucked under the key with a "└" connector. showLine is false
// for a collapsed item's representative finding, since a single line number
// would be misleading when the pattern spans several files at different lines.
// A finding with neither key nor value has nothing to columnize but its
// severity, so its reason stays inline rather than dangling under an empty row.
func (c columns) writeFindingRow(w io.Writer, f Finding, showLine bool) {
	fmt.Fprint(w, findingIndent)
	if c.hasLine {
		lt := ""
		if showLine && f.Line != nil {
			lt = lineTag(*f.Line)
		}
		fmt.Fprintf(w, "%-*s  ", c.lineW, lt)
	}
	// Pad the severity BEFORE coloring it: the ANSI escape codes have no
	// display width, so padding the colored string would misalign the column.
	_, _ = colorOr(severityColor, f.Severity).Fprintf(w, "%-*s", c.sevW, strings.ToUpper(f.Severity))

	indent := strings.Repeat(" ", c.reasonIndent())
	if !c.hasKey && !c.hasValue {
		if ev := displayEvidence(f); ev != "" {
			fmt.Fprint(w, "  ")
			termtext.Wrap(w, c.reasonIndent(), indent, highlightCmds(ev))
		} else {
			fmt.Fprintln(w)
		}
		c.writeUnfilteredNote(w, f, indent)
		return
	}

	if c.hasKey {
		fmt.Fprintf(w, "  %-*s", c.keyW, sanitizeDisplayPtr(f.KeyName))
	}
	if c.hasValue && f.ValuePreview != nil {
		fmt.Fprintf(w, "  %s", sanitizeDisplayPtr(f.ValuePreview))
	}
	fmt.Fprintln(w)

	if ev := displayEvidence(f); ev != "" {
		fmt.Fprintf(w, "%s"+style.GlyphBranch+" ", indent)
		termtext.Wrap(w, c.reasonIndent()+2, indent+"  ", highlightCmds(ev))
	}
	c.writeUnfilteredNote(w, f, indent)
}

// writeUnfilteredNote prints the gate explanation under a tagged finding —
// the per-finding line that makes --unfiltered auditable: it names the rule
// the everyday scan applied, right where the finding it would have hidden is.
func (c columns) writeUnfilteredNote(w io.Writer, f Finding, indent string) {
	if !f.UnfilteredOnly || f.UnfilteredReason == "" {
		return
	}
	fmt.Fprintf(w, "%s"+style.GlyphBranch+" ", indent)
	termtext.Wrap(w, c.reasonIndent()+2, indent+"  ", "shown by --unfiltered: "+sanitizeDisplay(f.UnfilteredReason))
}
