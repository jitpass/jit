// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fatih/color"
)

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
	FindingTypeSuspiciousFilename: "Suspicious Filenames",
	FindingTypeWrappableCLIToken:  "Wrappable CLI Tokens",
}

var riskLevelColor = map[string]*color.Color{
	RiskLevelCritical: color.New(color.FgRed, color.Bold),
	RiskLevelHigh:     color.New(color.FgYellow, color.Bold),
	RiskLevelMedium:   color.New(color.FgYellow),
	RiskLevelLow:      color.New(color.FgCyan),
	RiskLevelClean:    color.New(color.FgGreen, color.Bold),
}

// High and Medium were both plain FgYellow — visually indistinguishable
// in a [high]/[medium] tag. Bold on High matches riskLevelColor's own
// High/Medium weight split two lines above, so the two maps agree.
var severityColor = map[string]*color.Color{
	SeverityCritical: color.New(color.FgRed),
	SeverityHigh:     color.New(color.FgYellow, color.Bold),
	SeverityMedium:   color.New(color.FgYellow),
	SeverityLow:      color.New(color.FgCyan),
	SeverityInfo:     color.New(color.FgWhite),
}

func colorOr(m map[string]*color.Color, key string) *color.Color {
	if c, ok := m[key]; ok {
		return c
	}
	return color.New(color.FgWhite)
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
// repeated" — safe to collapse. IaC's unescalated tier and Suspicious
// Filenames are deliberately excluded: their evidence is fixed, rule-level
// text ("infrastructure-as-code variable file — detection only...") that
// says nothing about a specific file's content, so any two unrelated files
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
		return fmt.Sprintf("%s — same value in %d files:", *it.rep.KeyName, len(it.locations))
	}
	return fmt.Sprintf("same pattern in %d files:", len(it.locations))
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

// WriteHumanReport renders the default jit audit report (RFC.md §4):
// a color-coded risk banner, per-category counts, and exact file:line
// locations. Never a real secret value — only Finding.ValuePreview, which
// is already masked by the time it reaches here.
//
// home is used only to "~"-shorten paths for display; pass "" to keep
// absolute paths (a report saved to a file is re-read later, often by
// tools that can't expand "~"). Taking it as a parameter instead of
// reading $HOME at render time keeps the output a pure function of its
// arguments — the same reason scanners take Config.HomeDir.
func WriteHumanReport(w io.Writer, findings []Finding, summary ScanSummary, home string) {
	who := summary.Endpoint.Username
	if who == "" {
		who = "unknown"
	}
	host := summary.Endpoint.Hostname
	if host == "" {
		host = "unknown"
	}

	fmt.Fprintf(w, "jit audit — risk report for %s@%s\n", who, host)
	fmt.Fprintf(w, "scan time: %s          duration: %dms\n\n", summary.ScanTime, summary.ScanDurationMs)

	_, _ = colorOr(riskLevelColor, summary.RiskLevel).Fprintf(w, "  RISK LEVEL: %s\n", strings.ToUpper(summary.RiskLevel))
	if matches := summary.ProductionIndicatorCount + summary.PublicIPCount; matches > 0 {
		fmt.Fprintf(w, "  (%d production-indicator/public-IP match(es) found)\n", matches)
		for _, path := range criticalTriggerPaths(findings) {
			fmt.Fprintf(w, "    - %s\n", ShortenHome(home, path))
		}
	}
	fmt.Fprintln(w)

	for _, ft := range AllFindingTypes {
		line := fmt.Sprintf("  %-22s %d finding(s)", findingTypeLabels[ft], summary.FindingsByCategory[ft])
		if summary.FindingsByCategory[ft] == 0 {
			// Dim the nothing-found rows so the categories that DO have
			// findings are what the eye lands on — the itemized sections
			// below already skip empty categories entirely.
			_, _ = color.New(color.Faint).Fprintln(w, line)
		} else {
			fmt.Fprintln(w, line)
		}
	}
	fmt.Fprintf(w, "  %s\n", strings.Repeat("─", 35))
	fmt.Fprintf(w, "  Total: %d finding(s)\n", summary.TotalFindings)
	// Good news gets a line too: files jit already protects (live mounts,
	// content served from the encrypted vault) are excluded from the
	// findings above — say so, or their disappearance from the report reads
	// as the scanner having missed them.
	if summary.JitProtectedCount > 0 {
		_, _ = color.New(color.FgGreen).Fprintf(w, "  Already protected by jit: %d live mount(s) — served from the encrypted vault, no plaintext on disk. Not scanned.\n", summary.JitProtectedCount)
	}
	fmt.Fprintln(w)

	if summary.TotalFindings == 0 {
		fmt.Fprintln(w, "No findings — this machine looks clean.")
		return
	}

	byType := groupFindingsByType(findings)

	for _, ft := range AllFindingTypes {
		group := byType[ft]
		if len(group) == 0 {
			continue
		}

		fmt.Fprintf(w, "[%s]\n", findingTypeLabels[ft])
		for _, item := range buildRenderItems(group) {
			writeRenderItemText(w, item, home)
		}
		fmt.Fprintln(w)
	}

	// The report's only prior "next step" pointed at an output-format
	// flag, not remediation — a first-time reader of a HIGH/CRITICAL
	// report had no pointer from here to the command that actually fixes
	// any of it. jit migrate's own dry-run trailer already points back
	// at `jit audit` the other way; this closes the loop.
	fmt.Fprintln(w, "Run `jit migrate local --dry-run` (or `jit migrate home --dry-run`) to see the guided fix plan for what's fixable here.")
	_, _ = color.New(color.Faint).Fprintln(w, "No secret values are ever printed in full. Run `jit audit --format ndjson` for machine-readable output (same redaction rules apply).")
}

// writeRenderItemText renders one renderItem in WriteHumanReport's format.
// A per-file item prints the path once (see buildRenderItems) with every
// finding for it beneath. A collapsed item prints its OWN header line first
// (never omitted) — a real user found that a headerless collapsed block
// sitting directly under the previous item's file path read as if it were
// more findings for that same file, when it was actually an unrelated
// pattern shared by different files entirely. The header is what makes a
// new block visually start, exactly like a file path does for the
// per-file case.
func writeRenderItemText(w io.Writer, item renderItem, home string) {
	if item.collapsed {
		fmt.Fprintf(w, "  %s\n", collapsedHeader(item))
		writeFindingDetailText(w, item.rep, false)
		for _, loc := range item.locations {
			if loc.Line != nil {
				fmt.Fprintf(w, "          - %s:%d\n", ShortenHome(home, loc.Path), *loc.Line)
			} else {
				fmt.Fprintf(w, "          - %s\n", ShortenHome(home, loc.Path))
			}
		}
		return
	}

	fmt.Fprintf(w, "  %s\n", ShortenHome(home, item.rep.FilePath))
	for _, f := range item.findings {
		writeFindingDetailText(w, f, true)
	}
}

// writeFindingDetailText writes one finding's severity/key/value/why lines.
// showLine is false for a collapsed item's representative finding, since a
// single line number would be misleading when the pattern spans multiple
// files at different lines — each location's own line (if any) is shown
// next to its path in the bullet list instead.
func writeFindingDetailText(w io.Writer, f Finding, showLine bool) {
	lineTag := ""
	if showLine && f.Line != nil {
		lineTag = fmt.Sprintf(":%d  ", *f.Line)
	}
	_, _ = colorOr(severityColor, f.Severity).Fprintf(w, "    %s[%s]", lineTag, f.Severity)
	// KeyName is the single most useful piece of context here — without
	// it, a finding says "some value was found" without saying which
	// variable to actually go act on. Every field gets an explicit
	// label so the report is unambiguous without cross-referencing NDJSON.
	if f.KeyName != nil {
		fmt.Fprintf(w, "  key: %s", *f.KeyName)
	}
	fmt.Fprintln(w)
	if f.ValuePreview != nil {
		fmt.Fprintf(w, "        value:  %s\n", *f.ValuePreview)
	}
	if f.Evidence != "" {
		fmt.Fprintf(w, "        why:    %s\n", f.Evidence)
	}
}
