// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package wrap

import "testing"

func TestExtractTOML(t *testing.T) {
	doc := []byte(`
# a comment
color = "auto"
bare = plainvalue

[default]
  api_key = "sk_test_abc123" # trailing comment
  quoted_single = 'single'

[other.sub]
  api_key = "sk_other"

[[contexts]]
  token = "ctx-token"
`)
	cases := []struct {
		selector string
		want     string
		found    bool
	}{
		{"color", "auto", true},
		{"bare", "plainvalue", true},
		{"default/api_key", "sk_test_abc123", true}, // trailing comment stripped
		{"default/quoted_single", "single", true},
		{"other/api_key", "sk_other", true},   // dotted section matches its first segment
		{"contexts/token", "ctx-token", true}, // [[array]] section, first entry
		{"default/missing", "", false},
		{"missing_section/key", "", false},
		{"api_key", "", false}, // section key isn't visible at top level
		{"a/b/c", "", false},   // selectors are at most section/key
	}
	for _, tc := range cases {
		got, found := extractTOML(doc, tc.selector)
		if got != tc.want || found != tc.found {
			t.Errorf("extractTOML(%q) = (%q, %v), want (%q, %v)", tc.selector, got, found, tc.want, tc.found)
		}
	}
}
