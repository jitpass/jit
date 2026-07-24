// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package vault

import (
	"strings"
	"testing"
)

func TestNaturalLess(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		// Plain strings keep sort.Strings behavior.
		{"a", "b", true},
		{"b", "a", false},
		{"a", "a", false},
		{"aws/s3-access-key", "stripe/dev-key", true},
		{"a", "a/b", true},
		// Digit runs compare numerically — the whole point.
		{"KEY_2", "KEY_10", true},
		{"KEY_10", "KEY_2", false},
		{"KEY_9", "KEY_10", true},
		{"KEY_10", "KEY_11", true},
		{"a2/x", "a10/x", true},
		{"x1y2", "x1y10", true},
		// A bare prefix sorts before its digit-extended sibling.
		{"file", "file2", true},
		// Numerically-equal runs with different leading zeros decide on
		// the raw digits immediately — total order, so every "a02/" entry
		// stays contiguous instead of interleaving with "a2/" ones.
		{"a02/z", "a2/a", true},
		{"a2/a", "a02/z", false},
	}
	for _, c := range cases {
		if got := naturalLess(c.a, c.b); got != c.want {
			t.Errorf("naturalLess(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// TestVaultListNaturalOrder pins the display bug that motivated
// naturalLess: eleven PROJECT_n keys listing as 1, 10, 11, 2, 3, ...
func TestVaultListNaturalOrder(t *testing.T) {
	v := newTestVault(t)
	for _, p := range []string{
		"descope/PROJECT_10",
		"descope/PROJECT_2",
		"descope/PROJECT_1",
		"descope/PROJECT_11",
	} {
		if err := v.Set(p, []byte("value")); err != nil {
			t.Fatalf("Set(%q): %v", p, err)
		}
	}

	got, err := v.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := "descope/PROJECT_1,descope/PROJECT_2,descope/PROJECT_10,descope/PROJECT_11"
	if strings.Join(got, ",") != want {
		t.Errorf("List = %v, want numeric order [%s]", got, want)
	}
}
