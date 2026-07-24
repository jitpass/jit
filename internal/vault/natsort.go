// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package vault

// naturalLess orders a before b like sort.Strings, except that runs of
// digits compare by numeric value instead of byte-by-byte, so a listing
// with numbered keys reads PROJECT_1, PROJECT_2, ..., PROJECT_10 rather
// than the lexical PROJECT_1, PROJECT_10, PROJECT_11, PROJECT_2 (a real
// vault's eleven DESCOPE_PROJECT_n keys rendered exactly that badly).
//
// Numerically-equal runs that differ in leading zeros ("2" vs "02") fall
// back to comparing the raw digit runs right there rather than reading
// further: deciding on the prefix alone is what keeps the order total and
// every path sharing a "group/" prefix contiguous, which the grouped
// `jit vault list` display depends on.
func naturalLess(a, b string) bool {
	for len(a) > 0 && len(b) > 0 {
		ad, bd := digitRunLen(a), digitRunLen(b)
		if ad > 0 && bd > 0 {
			at, bt := trimLeadingZeros(a[:ad]), trimLeadingZeros(b[:bd])
			// Numeric compare without parsing (immune to overflow on
			// absurdly long runs): more significant digits wins, equal
			// widths compare the digits themselves.
			if len(at) != len(bt) {
				return len(at) < len(bt)
			}
			if at != bt {
				return at < bt
			}
			if a[:ad] != b[:bd] {
				return a[:ad] < b[:bd]
			}
			a, b = a[ad:], b[bd:]
			continue
		}
		if a[0] != b[0] {
			return a[0] < b[0]
		}
		a, b = a[1:], b[1:]
	}
	return len(a) < len(b)
}

func digitRunLen(s string) int {
	n := 0
	for n < len(s) && s[n] >= '0' && s[n] <= '9' {
		n++
	}
	return n
}

func trimLeadingZeros(s string) string {
	for len(s) > 1 && s[0] == '0' {
		s = s[1:]
	}
	return s
}
