// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import "strings"

// sanitizeDisplay replaces control characters with U+FFFD so a scanned file
// cannot write its own output into jit's report.
//
// Every interesting string in a finding — a key name, an evidence phrase, a
// file path — is copied out of a file jit did not write, and several of those
// files arrive with a cloned repo. The human and Markdown renderers printed
// them verbatim, so an env key in a project's .mcp.json containing escape
// sequences could emit raw ANSI and forge an extra finding row (a fake
// "HIGH  fake_key  ****" line indistinguishable from a real one), or use a
// carriage return to overwrite and hide a genuine one. For a tool whose whole
// output is a security judgement, letting the audited material edit the verdict
// is the wrong direction of trust.
//
// U+FFFD rather than deletion: the reader should see that something was
// removed. Sanitizing at RENDER time, not at Finding construction, keeps the
// raw value intact for the NDJSON stream — JSON escapes control characters, so
// that consumer was never at risk and machine output stays faithful to the file.
func sanitizeDisplay(s string) string {
	if !strings.ContainsFunc(s, displayUnsafe) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if displayUnsafe(r) {
			b.WriteRune('�')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// displayUnsafe reports whether a rune can influence a terminal or break a
// line: the C0 controls (including ESC, CR and LF), DEL, and the C1 range that
// some terminals still interpret as escape introducers.
func displayUnsafe(r rune) bool {
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f)
}

// sanitizeDisplayPtr is sanitizeDisplay for the optional string fields a
// Finding carries as pointers, returning "" for nil.
func sanitizeDisplayPtr(s *string) string {
	if s == nil {
		return ""
	}
	return sanitizeDisplay(*s)
}
