// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Mark All Reviewed names every row of the last scan. One whose line moved
// since must not cost the others their marks: it comes back as missed, and
// the rest are marked. Only when nothing at all is marked does review fail.
func TestReviewMarksTheRestWhenOneTargetMoved(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	readme := filepath.Join(home, "billing-sync", "README.md")
	if err := os.MkdirAll(filepath.Dir(readme), 0o700); err != nil {
		t.Fatal(err)
	}
	body := "line one\nexport GITHUB_TOKEN=" + "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8" + "\n"
	if err := os.WriteFile(readme, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reviewFormat = "text" })

	out, err := runRoot(t, "", "review", "--format", "json", readme+":9", readme+":2")
	if err != nil {
		t.Fatalf("review: %v\n%s", err, out)
	}
	var result reviewResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("decode %q: %v", out, err)
	}
	if len(result.Reviewed) != 1 || result.Reviewed[0].Line == nil || *result.Reviewed[0].Line != 2 {
		t.Errorf("reviewed = %+v, want the finding on line 2", result.Reviewed)
	}
	if len(result.Missed) != 1 || !strings.HasSuffix(result.Missed[0], "README.md:9") {
		t.Errorf("missed = %q, want README.md:9", result.Missed)
	}

	out, err = runRoot(t, "", "review", "--format", "text", readme+":9")
	if err == nil || !strings.Contains(err.Error(), "nothing to mark on") {
		t.Errorf("a lone moved target: err = %v, want it named\n%s", err, out)
	}
}
