// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMCPLineLocationIsBudgeted guards the fix for the fuzz hang: locating a
// finding's line is one bytes.Index over the whole file, so doing it for every
// finding is O(findings x filesize). A hostile .mcp.json with many token-
// shaped values in a multi-megabyte file drove that into a multi-second hang
// (2026-09-10). scanMCPConfigFile now skips line location once findings x
// filesize passes mcpLineLocateBudget, degrading to the grep-locator fallback
// (a nil Line) instead of hanging.
//
// The assertion is on that behavior, not on wall-clock time (which is fragile
// under -race and CI load): past the budget, findings come back lineless.
func TestMCPLineLocationIsBudgeted(t *testing.T) {
	// 24 real GitHub-PAT values (findings) plus a ~4 MiB ignored field, so
	// findings x filesize (24 x ~4 MiB ~= 100 MiB) clears the 64 MiB budget
	// while the file stays under the 5 MiB parse cap and only 24 values are
	// ever token-scanned. json.Unmarshal drops "_pad" (not in the struct),
	// so the padding costs nothing but bytes.
	var b strings.Builder
	b.WriteString(`{"mcpServers":{`)
	const n = 24
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `"s%d":{"env":{"T":"ghp_%036d"}}`, i, i)
	}
	b.WriteString(`},"_pad":"`)
	b.WriteString(strings.Repeat("x", 4<<20))
	b.WriteString(`"}`)

	dir := t.TempDir()
	path := filepath.Join(dir, ".mcp.json")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := scanMCPConfigFile(Config{HomeDir: dir}, path)
	if err != nil {
		t.Fatalf("scanMCPConfigFile: %v", err)
	}
	if len(findings) != n {
		t.Fatalf("got %d findings, want %d", len(findings), n)
	}
	for _, f := range findings {
		if f.Line != nil {
			t.Errorf("past the line-location budget a finding must be lineless (grep fallback), got line %d", *f.Line)
		}
	}
}

// TestMCPLineLocationRunsForRealFiles is the other half: a normal small config
// is nowhere near the budget, so its findings keep their exact line numbers.
func TestMCPLineLocationRunsForRealFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".mcp.json")
	body := `{
  "mcpServers": {
    "gh": {
      "env": { "TOKEN": "ghp_000000000000000000000000000000000001" }
    }
  }
}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := scanMCPConfigFile(Config{HomeDir: dir}, path)
	if err != nil {
		t.Fatalf("scanMCPConfigFile: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Line == nil {
		t.Fatal("a real config's finding must keep its exact line number")
	}
	if *findings[0].Line != 4 {
		t.Errorf("line = %d, want 4", *findings[0].Line)
	}
}
