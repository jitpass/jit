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
	// A fixed wall-clock limit flaked on loaded CI runners (5.1 s against a
	// 5 s limit, 2026-09-26), since -race and load inflate every scan alike.
	// So the test compares against itself on the same machine: a value of
	// exactly the cap is the baseline, and a bounded scan of a far larger
	// value costs about the same. The unbounded gauntlet grows with the
	// value, 80x at 5 MiB against the 64 KiB cap, which no load hides.
	baseline := fastestScan(strings.Repeat("a1B2_-", maxTokenScanLen/6+1)[:maxTokenScanLen])
	for _, sz := range []int{1 << 20, 5 << 20} {
		val := strings.Repeat("a1B2_-", sz/6+1)[:sz]
		if el := fastestScan(val); el > 8*baseline+50*time.Millisecond {
			t.Errorf("len=%d took %s against %s at the cap; the token gauntlet is not bounded", sz, el, baseline)
		}
	}
}

// fastestScan is the best of three scans of val, so one pause on a busy
// machine doesn't decide the comparison.
func fastestScan(val string) time.Duration {
	best := time.Duration(1<<63 - 1)
	for range 3 {
		start := time.Now()
		MatchKnownTokenPattern(val)
		if el := time.Since(start); el < best {
			best = el
		}
	}
	return best
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
