// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"fmt"
	"io"
	"strings"
)

// WriteMarkdownReport renders the same information as WriteHumanReport, in
// Markdown — suitable for saving to a file and opening in a Markdown
// viewer, pasting into docs, or sharing in Slack/Notion. Same guarantee as
// every other renderer: never a real secret value, only Finding.ValuePreview.
func WriteMarkdownReport(w io.Writer, findings []Finding, summary ScanSummary) {
	who := summary.Endpoint.Username
	if who == "" {
		who = "unknown"
	}
	host := summary.Endpoint.Hostname
	if host == "" {
		host = "unknown"
	}

	fmt.Fprintln(w, "# jit scan report")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "**Scanned:** %s@%s  \n", who, host)
	fmt.Fprintf(w, "**Scan time:** %s (%dms)\n\n", summary.ScanTime, summary.ScanDurationMs)

	fmt.Fprintf(w, "## Risk Level: %s\n\n", riskLevelMarkdownBadge(summary.RiskLevel))
	fmt.Fprintf(w, "**Exposure score:** %d/100\n\n", summary.ExposureScore)
	if matches := summary.ProductionIndicatorCount + summary.PublicIPCount; matches > 0 {
		fmt.Fprintf(w, "> %d production-indicator/public-IP match(es) found:\n", matches)
		for _, path := range criticalTriggerPaths(findings) {
			fmt.Fprintf(w, "> - `%s`\n", path)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "| Category | Findings |")
	fmt.Fprintln(w, "|---|---|")
	for _, ft := range AllFindingTypes {
		fmt.Fprintf(w, "| %s | %d |\n", findingTypeLabels[ft], summary.FindingsByCategory[ft])
	}
	fmt.Fprintf(w, "| **Total** | **%d** |\n\n", summary.TotalFindings)

	// Parity with WriteHumanReport's protected line: excluded-but-protected
	// files are stated, never silently absent.
	if summary.JitProtectedCount > 0 {
		fmt.Fprintf(w, "Already protected by jit: %d live mount(s), served from the encrypted vault, no plaintext on disk. Not scanned.\n\n", summary.JitProtectedCount)
	}
	// Same parity, same reason: a shared report that omits the boundary is
	// the version most likely to be read as "jit covers all of this".
	writeDerivedCredentialAdvisoryMarkdown(w, summary)

	if summary.TotalFindings == 0 {
		fmt.Fprintln(w, "No findings. This machine looks clean.")
		return
	}

	writeMarkdownFindings(w, findings, summary, groupFindingsByType(findings))
}

// writeDerivedCredentialAdvisoryMarkdown mirrors the human report's advisory —
// see writeDerivedCredentialAdvisory for why it exists at all. Paths are
// rendered unshortened, matching this renderer's existing convention.
func writeDerivedCredentialAdvisoryMarkdown(w io.Writer, summary ScanSummary) {
	if len(summary.DerivedCredentials) == 0 {
		return
	}
	fmt.Fprintln(w, "## Outside jit's scope, found anyway")
	fmt.Fprintln(w)
	for _, d := range summary.DerivedCredentials {
		fmt.Fprintf(w, "- `%s` — %s", d.Path, d.What)
		if d.Advice != "" {
			fmt.Fprintf(w, " (%s)", d.Advice)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "jit protects credentials you stored; these were minted by the tools that used them. It does not manage, rotate or hide them.")
	fmt.Fprintln(w)
}

func writeMarkdownFindings(w io.Writer, findings []Finding, summary ScanSummary, byType map[string][]Finding) {
	fmt.Fprintln(w, "## Findings")
	fmt.Fprintln(w)

	for _, ft := range AllFindingTypes {
		group := byType[ft]
		if len(group) == 0 {
			continue
		}

		fmt.Fprintf(w, "### %s\n\n", findingTypeLabels[ft])
		for _, item := range buildRenderItems(group) {
			writeRenderItemMarkdown(w, item)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "---")
	// Parity with WriteHumanReport's [archived] legend: tag without
	// explanation is jargon, explanation without a tagged finding is noise.
	if anyArchived(findings) {
		fmt.Fprintln(w, "[archived] findings live under an archived/backup-looking directory: name such a file explicitly to convert it, e.g. `jit migrate <path>`.")
	}
	fmt.Fprintln(w, "Run `jit migrate <path> --dry-run` to see the guided fix plan for a flagged file.")
	if summary.Unfiltered {
		fmt.Fprintln(w, "**Suppression is OFF (`--unfiltered`)**: settings, paths, browser-public build variables and unfilled template values are all shown. Expect noise; this is the auditing view, not the everyday one.")
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, "No secret values are ever printed in full. Run `jit scan --format ndjson` for machine-readable output (same redaction rules apply).")
}

// writeRenderItemMarkdown is WriteMarkdownReport's counterpart to the text
// renderer's writeRenderItemText — same collapsing/ordering (buildRenderItems
// is shared), just Markdown list syntax instead of the plain-text layout.
func writeRenderItemMarkdown(w io.Writer, item renderItem) {
	if item.collapsed {
		fmt.Fprintf(w, "- %s\n", collapsedHeader(item))
		writeFindingDetailMarkdown(w, item.rep, false)
		for _, loc := range item.locations {
			if loc.Line != nil {
				fmt.Fprintf(w, "      - `%s` :%d%s\n", loc.Path, *loc.Line, archivedTag(loc.Path))
			} else {
				fmt.Fprintf(w, "      - `%s`%s\n", loc.Path, archivedTag(loc.Path))
			}
		}
		return
	}

	fmt.Fprintf(w, "- `%s`%s\n", item.rep.FilePath, archivedTag(item.rep.FilePath))
	for _, f := range item.findings {
		writeFindingDetailMarkdown(w, f, true)
	}
}

// writeFindingDetailMarkdown mirrors the terminal's row shape: the bounded
// fields (severity, line, key, masked value) on one line, the free-form
// reason nested beneath — or inline when the finding has neither key nor
// value, exactly like writeFindingRow's compact case.
func writeFindingDetailMarkdown(w io.Writer, f Finding, showLine bool) {
	lineTag := ""
	if showLine && f.Line != nil {
		lineTag = fmt.Sprintf(" :%d", *f.Line)
	}
	fmt.Fprintf(w, "  - **%s**%s", strings.ToUpper(f.Severity), lineTag)
	if f.KeyName == nil && f.ValuePreview == nil {
		if f.Evidence != "" {
			fmt.Fprintf(w, " %s", f.Evidence)
		}
		fmt.Fprintln(w)
		return
	}
	if f.KeyName != nil {
		fmt.Fprintf(w, " `%s`", *f.KeyName)
	}
	if f.ValuePreview != nil {
		fmt.Fprintf(w, " `%s`", *f.ValuePreview)
	}
	fmt.Fprintln(w)
	if f.Evidence != "" {
		fmt.Fprintf(w, "    - %s\n", f.Evidence)
	}
}

func riskLevelMarkdownBadge(level string) string {
	switch level {
	case RiskLevelCritical:
		return "🔴 **CRITICAL**"
	case RiskLevelHigh:
		return "🟠 **HIGH**"
	case RiskLevelMedium:
		return "🟡 **MEDIUM**"
	case RiskLevelLow:
		return "🔵 **LOW**"
	case RiskLevelClean:
		return "🟢 **CLEAN**"
	default:
		return level
	}
}
