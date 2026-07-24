// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package wrap

import "testing"

func TestExtractYAML(t *testing.T) {
	doc := []byte(`
top: value
github.com:
    nested:
        deep: deepvalue
    empty:
list:
    - a
    - b
`)
	cases := []struct {
		selector string
		want     string
		found    bool
	}{
		{"top", "value", true},
		{"github.com/nested/deep", "deepvalue", true}, // dotted key survives as one segment
		{"github.com/empty", "", false},               // present but empty is not a token
		{"github.com/missing", "", false},
		{"list/0", "", false}, // sequences are deliberately not descended
		{"top/deeper", "", false},
	}
	for _, tc := range cases {
		got, found := extractYAML(doc, tc.selector)
		if got != tc.want || found != tc.found {
			t.Errorf("extractYAML(%q) = (%q, %v), want (%q, %v)", tc.selector, got, found, tc.want, tc.found)
		}
	}

	if _, found := extractYAML([]byte("not: [valid"), "not"); found {
		t.Error("expected not-found for unparseable YAML")
	}
}
