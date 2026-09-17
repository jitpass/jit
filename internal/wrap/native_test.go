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
		d, err := Delegation("/Users/me", entry)
		if err != nil {
			t.Fatalf("Delegation(%s): %v", tool, err)
		}
		if d.Category != category {
			t.Errorf("%s delegates to category %q, want %q", tool, d.Category, category)
		}
		// An absolute path, never the literal "home": migrate resolves its
		// argument against the working directory, so the literal failed
		// from every directory without a home/ entry.
		if got := strings.Join(d.Command, " "); got != "migrate /Users/me --only "+category {
			t.Errorf("%s delegation command = %q", tool, got)
		}
	}
}

func TestDelegationRefusesShimEntry(t *testing.T) {
	gh, _ := Lookup("gh")
	if _, err := Delegation("/Users/me", gh); err == nil {
		t.Fatal("expected an error delegating a shim entry")
	}
}
