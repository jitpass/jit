// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package wrap

import "testing"

func TestExtractJSON(t *testing.T) {
	doc := []byte(`{
		"token": "top-token",
		"user": {"token": "nested-token", "id": 42},
		"empty": "",
		"list": ["a"]
	}`)
	cases := []struct {
		selector string
		want     string
		found    bool
	}{
		{"token", "top-token", true},
		{"user/token", "nested-token", true},
		{"user/id", "", false}, // a number is not a token
		{"empty", "", false},
		{"missing", "", false},
		{"list/0", "", false}, // arrays are deliberately not descended
		{"user/token/deeper", "", false},
	}
	for _, tc := range cases {
		got, found := extractJSON(doc, tc.selector)
		if got != tc.want || found != tc.found {
			t.Errorf("extractJSON(%q) = (%q, %v), want (%q, %v)", tc.selector, got, found, tc.want, tc.found)
		}
	}
	if _, found := extractJSON([]byte("{broken"), "token"); found {
		t.Error("expected not-found for unparseable JSON")
	}
}
