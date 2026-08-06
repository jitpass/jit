// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"testing"

	"github.com/jitpass/jit/internal/auditlog"
)

func TestMaskValue(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"sk_test_51Mz9x2yZvKQ", "sk_t" + maskSuffix},
		{"ab", maskSuffix},   // at/below reveal length: fully masked
		{"", maskSuffix},     // empty: fully masked
		{"1234", maskSuffix}, // exactly at reveal length: fully masked
		{"12345", "1234" + maskSuffix},
	}
	for _, c := range cases {
		got := MaskValue(c.input)
		if got != c.want {
			t.Errorf("MaskValue(%q) = %q, want %q", c.input, got, c.want)
		}
		// The fixed-length suffix is the point (RFC.md examples don't scale
		// the mask to the true length) — so the only real invariant is that
		// the full raw value never appears verbatim in the output, not that
		// the output is shorter than the input.
		if got == c.input && c.input != "" {
			t.Errorf("MaskValue(%q) returned the raw value unmasked", c.input)
		}
	}
}

func TestIsAlreadyMasked(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		{"****", true},
		{"**", false}, // too short to be confidently "already masked" rather than a real 2-char value
		{"xxxxxxxx", true},
		{"REDACTED", true},
		{"<redacted>", true},
		{"sk_test_51Mz9x2yZvKQ", false},
		{"", false},
		{"postgres://admin:hunter2@db.internal", false},
	}
	for _, c := range cases {
		got := IsAlreadyMasked(c.input)
		if got != c.want {
			t.Errorf("IsAlreadyMasked(%q) = %v, want %v", c.input, got, c.want)
		}
	}
}

// TestJitsOwnRedactionMarkIsRecognised links two lists that describe the same
// thing from opposite ends and were connected only by both spelling
// "<redacted>" by hand.
//
// commonMaskedPlaceholders is a list of markers FOREIGN tools leave behind, so
// it is deliberately not built from auditlog.RedactToken — the overlap is a
// coincidence, not a contract, and coupling them would make jit's own log
// format govern what it recognises in other people's files. What IS a
// contract: jit must never re-flag a value it masked itself. If the audit
// log's placeholder ever changes, `jit scan` would start reporting jit's own
// redaction marks as exposed secrets, and this is what notices.
func TestJitsOwnRedactionMarkIsRecognised(t *testing.T) {
	if !IsAlreadyMasked(auditlog.RedactToken) {
		t.Errorf("jit's own redaction placeholder %q is not recognised as masked; "+
			"jit scan would report its own audit-log redactions as exposed secrets",
			auditlog.RedactToken)
	}
}
