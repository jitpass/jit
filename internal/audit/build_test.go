// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import "testing"

// The evidence line printed "…embedded credentials's known token format" dozens
// of times in one real report, because every site built the possessive with a
// hand-written "%s's". Vendor names ending in "s" are not rare here — several
// pattern names end in "credentials", "Secrets" or "Keys".
func TestPossessiveHandlesNamesEndingInS(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Database connection string with embedded credentials", "Database connection string with embedded credentials'"},
		{"JSON Web Token (JWT)", "JSON Web Token (JWT)'s"},
		{"AWS Access Key ID", "AWS Access Key ID's"},
		{"Claude Code", "Claude Code's"},
		{"SOPS", "SOPS'"},
	}
	for _, c := range cases {
		if got := possessive(c.in); got != c.want {
			t.Errorf("possessive(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
