// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanExcludePathsSkipsWholeSubtrees(t *testing.T) {
	home := t.TempDir()
	for _, dir := range []string{"keep", "skip", "skip-not"} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(home, dir, ".env"), "DATABASE_PASSWORD=q8f3n2v9x1m4k7p0z5w6r2t8y3u1i4o7\n")
	}

	cfg := Config{HomeDir: home, RunID: "r", ScannerVersion: "test", ExcludePaths: []string{filepath.Join(home, "skip")}}
	findings, summary, err := Scan(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, f := range findings {
		files = append(files, filepath.Base(filepath.Dir(f.FilePath)))
	}
	for _, f := range findings {
		if cfg.Excluded(f.FilePath) {
			t.Errorf("finding from an excluded path: %s", f.FilePath)
		}
	}
	if len(findings) == 0 || !contains(files, "keep") || !contains(files, "skip-not") {
		t.Errorf("findings came from %v, want keep and skip-not", files)
	}
	if got := summary.ExcludedPaths; len(got) != 1 || got[0] != filepath.Join(home, "skip") {
		t.Errorf("summary.ExcludedPaths = %v", got)
	}
}

func TestExcludedMatchesOnlyAtPathBoundaries(t *testing.T) {
	cfg := Config{ExcludePaths: []string{"/Users/me/work/"}}
	for path, want := range map[string]bool{
		"/Users/me/work":            true,
		"/Users/me/work/app/.env":   true,
		"/Users/me/work-old/.env":   false,
		"/Users/me/workspace/.env":  false,
		"/Users/me/other/work/.env": false,
	} {
		if got := cfg.Excluded(path); got != want {
			t.Errorf("Excluded(%q) = %v, want %v", path, got, want)
		}
	}
}
