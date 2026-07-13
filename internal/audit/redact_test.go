// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package audit

import "testing"

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
