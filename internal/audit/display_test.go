// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"bytes"
	"strings"
	"testing"
)

// A scanned file must not be able to write its own rows into jit's report.
//
// KeyName, ValuePreview and Evidence are copied out of files jit did not write
// — an .mcp.json arrives with a cloned repo, and mcpconfig.go puts its env key
// straight into KeyName — and the human and Markdown renderers printed them
// verbatim. An env key carrying escape sequences could emit raw ANSI and forge
// a finding row indistinguishable from a real one, or use a carriage return to
// scroll a genuine row out of view. Letting the audited material edit the
// verdict is the wrong direction of trust for a security tool.
//
// The findings are built directly rather than scanned out of a fixture: the
// contract under test belongs to the RENDERERS, and routing through a scanner
// would make it hostage to that scanner's own matching heuristics — a change
// there would silently turn this into a test that passes without rendering
// anything hostile at all.
func TestReportRendersNoControlCharactersFromScannedFiles(t *testing.T) {
	hostileKey := "EVIL\x1b[31m\x1b[2K\rFORGED_HIGH_ROW"
	hostilePreview := "sk_l\x1b[0m\x1b[2K\rleaked"
	line := 3

	findings := []Finding{{
		FindingType:  FindingTypeMCPEmbeddedSecret,
		Severity:     SeverityHigh,
		FilePath:     "/Users/alex/cloned-repo/.mcp.json",
		Line:         &line,
		KeyName:      &hostileKey,
		ValuePreview: &hostilePreview,
		Evidence:     "embedded in MCP server \x1b[31m\rforged\x1b[0m's env block",
	}}
	summary := buildScanSummary(Config{Endpoint: Endpoint{Username: "alex", Hostname: "mbp"}}, findings, 0, 0)

	renderers := map[string]func(*bytes.Buffer){
		"human":    func(b *bytes.Buffer) { WriteHumanReport(b, findings, summary, "") },
		"markdown": func(b *bytes.Buffer) { WriteMarkdownReport(b, findings, summary) },
		"triage": func(b *bytes.Buffer) {
			WriteTriageReport(b, findings, summary, "", ComputeCoverage("", "", findings))
		},
	}
	for name, render := range renderers {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			render(&buf)
			// ESC repaints and repositions; CR overwrites the line already
			// printed. jit's own colour codes are suppressed for a non-TTY
			// writer, so any ESC reaching here came from the finding.
			if i := bytes.IndexByte(buf.Bytes(), 0x1b); i >= 0 {
				t.Errorf("report carries an ESC from the scanned file at offset %d: %q", i, excerpt(buf.String(), i))
			}
			if i := bytes.IndexByte(buf.Bytes(), '\r'); i >= 0 {
				t.Errorf("report carries a CR from the scanned file at offset %d: %q", i, excerpt(buf.String(), i))
			}
		})
	}
}

func TestSanitizeDisplay(t *testing.T) {
	cases := map[string]string{
		"plain":            "plain",
		"AWS_SECRET_KEY":   "AWS_SECRET_KEY",
		"esc\x1b[31mred":   "esc�[31mred",
		"carriage\rreturn": "carriage�return",
		"new\nline":        "new�line",
		"del\x7f":          "del�",
		"c1\u0085next":     "c1�next",
		"unicode ok":       "unicode ok",
		"tab\tseparated":   "tab�separated",
	}
	for in, want := range cases {
		if got := sanitizeDisplay(in); got != want {
			t.Errorf("sanitizeDisplay(%q) = %q, want %q", in, got, want)
		}
	}
}

func excerpt(s string, at int) string {
	start := max(0, at-30)
	end := min(len(s), at+30)
	return strings.ReplaceAll(s[start:end], "\n", "\\n")
}
