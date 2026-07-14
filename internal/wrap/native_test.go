// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

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
		d, err := Delegation(entry)
		if err != nil {
			t.Fatalf("Delegation(%s): %v", tool, err)
		}
		if d.Category != category {
			t.Errorf("%s delegates to category %q, want %q", tool, d.Category, category)
		}
		if got := strings.Join(d.Command, " "); got != "migrate home --only "+category {
			t.Errorf("%s delegation command = %q", tool, got)
		}
	}
}

func TestDelegationRefusesShimEntry(t *testing.T) {
	gh, _ := Lookup("gh")
	if _, err := Delegation(gh); err == nil {
		t.Fatal("expected an error delegating a shim entry")
	}
}
