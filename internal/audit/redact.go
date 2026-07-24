// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"regexp"
	"strings"
)

// revealPrefixLen is how many leading characters of a secret value are shown
// in a masked preview before the fixed mask suffix.
const revealPrefixLen = 4

// maskSuffix is a FIXED-length suffix, not one character per hidden byte —
// RFC.md §4's own examples ("sk_test_5**********", "postgres://ad**********")
// use the same ten-asterisk suffix regardless of the true remaining length.
// A length-proportional mask would leak the secret's real length; a fixed
// suffix doesn't.
const maskSuffix = "**********"

// MaskValue produces a redaction-safe preview of a secret value: the first
// few characters, then a fixed mask suffix. Values at or below the reveal
// length are masked entirely, never partially revealed.
func MaskValue(v string) string {
	if len(v) <= revealPrefixLen {
		return maskSuffix
	}
	return v[:revealPrefixLen] + maskSuffix
}

// alreadyMaskedPattern matches values that are already fully redacted at the
// source (e.g. "****"), so jit scan doesn't re-mask (or re-evaluate for
// production/IP signals) something the scanned file already hid. RFC.md §4:
// "A value that's already masked... is not re-flagged... skipping
// already-masked values for both detections."
var alreadyMaskedPattern = regexp.MustCompile(`^[*xX]{3,}$`)

// commonMaskedPlaceholders are literal tokens treated as already-masked
// regardless of length, matched case-insensitively after trimming.
var commonMaskedPlaceholders = map[string]bool{
	"redacted":   true,
	"<redacted>": true,
	"hidden":     true,
	"[hidden]":   true,
}

// IsAlreadyMasked reports whether v looks like it was already redacted by
// whatever produced the scanned file, rather than being a real value jit
// discovered.
func IsAlreadyMasked(v string) bool {
	trimmed := strings.TrimSpace(strings.Trim(v, `"'`))
	if trimmed == "" {
		return false
	}
	if alreadyMaskedPattern.MatchString(trimmed) {
		return true
	}
	return commonMaskedPlaceholders[strings.ToLower(trimmed)]
}
