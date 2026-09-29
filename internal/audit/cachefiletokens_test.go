// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"path/filepath"
	"strings"
	"testing"
)

// withLineLimit cuts lines at n for one test, so a line past the limit
// needs kilobytes, not the megabyte every regex would run over.
func withLineLimit(t *testing.T, n int) {
	t.Helper()
	prev := lineLimit
	lineLimit = n
	t.Cleanup(func() { lineLimit = prev })
}

// A token past the line limit is found in a file-shaped cache by the
// indexed sweep, as the scan finds it: one long pasted line in
// paste-cache is the common case.
func TestCacheFileTokensFindATokenPastTheLineLimit(t *testing.T) {
	withLineLimit(t, 4096)
	home := "/Users/someone"
	paste := filepath.Join(home, ".claude", "paste-cache", "long.txt")
	token := "ntn_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0"
	data := []byte(strings.Repeat("filler ", 1000) + token + " end\n")

	got := CacheFileTokens(home, paste, data)
	if len(got) != 1 || string(data[got[0].Start:got[0].End]) != token {
		t.Fatalf("tokens = %+v, want the one past the limit", got)
	}
}

// A token the line limit cuts matches short in the content scanner and
// whole in the indexed sweep. The whole one wins: redacting the short span
// would leave the rest of the secret in the file.
func TestCacheFileTokensKeepATokenCutByTheLineLimitWhole(t *testing.T) {
	withLineLimit(t, 4096)
	home := "/Users/someone"
	paste := filepath.Join(home, ".claude", "paste-cache", "cut.txt")
	token := "glpat-" + "Xk4mT9pQ2vR7wL3nB8cY5zJ1hF6dS0gA"
	// The cut lands 24 characters into the body: enough for {20,}.
	at := 4096 - 30
	words := strings.Repeat("filler ", at/7)
	data := []byte(strings.Repeat("y", at-len(words)) + words + token + " end\n")

	if short := TextTokens(data); len(short) != 1 || short[0].End != 4096 {
		t.Fatalf("fixture: the content scanner should match short at the cut, got %+v", short)
	}
	got := CacheFileTokens(home, paste, data)
	if len(got) != 1 || string(data[got[0].Start:got[0].End]) != token {
		t.Fatalf("tokens = %+v, want the whole token", got)
	}
}
