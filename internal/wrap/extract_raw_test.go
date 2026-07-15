// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package wrap

import "testing"

func TestExtractRaw(t *testing.T) {
	cases := []struct {
		name  string
		data  string
		want  string
		found bool
	}{
		{"bare token", "hf_abc123", "hf_abc123", true},
		{"trailing newline", "hf_abc123\n", "hf_abc123", true},
		{"surrounding whitespace", "\thf_abc123 \n", "hf_abc123", true},
		{"empty file", "", "", false},
		{"whitespace only", " \n\t\n", "", false},
		{"two tokens", "hf_abc123\nhf_def456\n", "", false}, // not a single-credential file
		{"prose", "this is not a token file", "", false},
	}
	for _, tc := range cases {
		got, found := extractRaw([]byte(tc.data), "")
		if got != tc.want || found != tc.found {
			t.Errorf("%s: extractRaw = (%q, %v), want (%q, %v)", tc.name, got, found, tc.want, tc.found)
		}
	}
}
