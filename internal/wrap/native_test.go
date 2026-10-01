// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package wrap

import (
	"strings"
	"testing"
)

func TestDelegationForNativeTools(t *testing.T) {
	for tool, category := range map[string]string{"aws": "aws", "terraform": "terraform"} {
		entry, ok := Lookup(tool)
		if !ok {
			t.Fatalf("%s missing from catalog", tool)
		}
		d, err := Delegation(entry, []string{"/Users/me/.creds"})
		if err != nil {
			t.Fatalf("Delegation(%s): %v", tool, err)
		}
		if d.Category != category {
			t.Errorf("%s delegates to category %q, want %q", tool, d.Category, category)
		}
		// The category's files, never the home directory: a directory
		// target is walked for project files only.
		if got := strings.Join(d.Command, " "); got != "migrate /Users/me/.creds --only "+category {
			t.Errorf("%s delegation command = %q", tool, got)
		}
		if _, err := Delegation(entry, nil); err == nil || !strings.Contains(err.Error(), "nothing to protect") {
			t.Errorf("%s with no files: err = %v, want nothing to protect", tool, err)
		}
	}
}

func TestDelegationRefusesShimEntry(t *testing.T) {
	gh, _ := Lookup("gh")
	if _, err := Delegation(gh, []string{"/Users/me/.creds"}); err == nil {
		t.Fatal("expected an error delegating a shim entry")
	}
}
