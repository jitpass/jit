// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"fmt"
	"io"
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

	fmt.Fprintln(w, "# jit audit report")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "**Scanned:** %s@%s  \n", who, host)
	fmt.Fprintf(w, "**Scan time:** %s (%dms)\n\n", summary.ScanTime, summary.ScanDurationMs)

	fmt.Fprintf(w, "## Risk Level: %s\n\n", riskLevelMarkdownBadge(summary.RiskLevel))
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

	if summary.TotalFindings == 0 {
		fmt.Fprintln(w, "No findings — this machine looks clean.")
		return
	}

	byType := groupFindingsByType(findings)

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
	fmt.Fprintln(w, "Run `jit migrate local --dry-run` (or `jit migrate home --dry-run`) to see the guided fix plan for what's fixable here.")
	fmt.Fprintln(w, "No secret values are ever printed in full. Run `jit audit --format ndjson` for machine-readable output (same redaction rules apply).")
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
				fmt.Fprintf(w, "      - `%s` :%d\n", loc.Path, *loc.Line)
			} else {
				fmt.Fprintf(w, "      - `%s`\n", loc.Path)
			}
		}
		return
	}

	fmt.Fprintf(w, "- `%s`\n", item.rep.FilePath)
	for _, f := range item.findings {
		writeFindingDetailMarkdown(w, f, true)
	}
}

func writeFindingDetailMarkdown(w io.Writer, f Finding, showLine bool) {
	lineTag := ""
	if showLine && f.Line != nil {
		lineTag = fmt.Sprintf(" :%d", *f.Line)
	}
	fmt.Fprintf(w, "  - **[%s]**%s", f.Severity, lineTag)
	if f.KeyName != nil {
		fmt.Fprintf(w, " key: `%s`", *f.KeyName)
	}
	fmt.Fprintln(w)
	if f.ValuePreview != nil {
		fmt.Fprintf(w, "    - value: `%s`\n", *f.ValuePreview)
	}
	if f.Evidence != "" {
		fmt.Fprintf(w, "    - why: %s\n", f.Evidence)
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
