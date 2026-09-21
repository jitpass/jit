// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"strings"
	"testing"
	"time"
)

// TestMatchKnownTokenPatternBoundsLargeValues guards the shared fuzz hang: the
// ~100-pattern vendor gauntlet is one linear RE2 scan per pattern, so a
// multi-megabyte value cost seconds and a value scanned more than once by a
// parser drove FuzzScanEnvFile / ShellConfig / MCPConfig into a multi-second
// hang (2026-09-10). maxTokenScanLen caps the inspected prefix, so the cost is
// flat regardless of value size.
func TestMatchKnownTokenPatternBoundsLargeValues(t *testing.T) {
	// The threshold is generous because -race and CI load inflate wall-clock
	// by ~20x; it still separates cleanly, since the unbounded gauntlet took
	// ~2.5 s per 4 MiB uninstrumented (tens of seconds under race), while the
	// capped scan is flat at a few ms (~1-2 s under race).
	for _, sz := range []int{1 << 20, 5 << 20} {
		val := strings.Repeat("a1B2_-", sz/6+1)[:sz]
		start := time.Now()
		MatchKnownTokenPattern(val)
		if el := time.Since(start); el > 5*time.Second {
			t.Errorf("len=%d took %s; the token gauntlet is not bounded", sz, el)
		}
	}
}

// TestMatchKnownTokenPatternStillMatchesWithinBound confirms the cap did not
// break real detection: a token at the very front of an oversized value (the
// realistic shape — a credential followed by junk) still matches.
func TestMatchKnownTokenPatternStillMatchesWithinBound(t *testing.T) {
	// A real token ends at a delimiter (the pattern needs the trailing \b)
	// and is mixed enough not to read as a placeholder.
	// azbycxdwevfugthsirjqkplomn0123456789 is exactly 36 chars and mixed.
	val := "ghp_azbycxdwevfugthsirjqkplomn0123456789 " + strings.Repeat("x", 2<<20)
	vendor, _, ok := MatchKnownTokenPattern(val)
	if !ok || vendor == "" {
		t.Fatalf("a GitHub PAT at the front of a large value must still match, got ok=%v vendor=%q", ok, vendor)
	}
}
