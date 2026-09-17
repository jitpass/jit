// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"os"
	"path/filepath"
	"testing"
)

// A folder scan must count the files it looked at, like the machine-wide
// scan does; it reported 0 under a list of findings from those very files.
func TestTargetedScanCountsFilesAndHonoursExcludes(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "project")
	for _, rel := range []string{"a/.env", "b/.env", "third/.env", "README.md"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(project, rel)), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(project, rel), "DATABASE_PASSWORD=q8f3n2v9x1m4k7p0z5w6r2t8y3u1i4o7\n")
	}

	_, summary, err := TargetedScan(Config{HomeDir: home, RunID: "r", ScannerVersion: "t"}, []string{project})
	if err != nil {
		t.Fatal(err)
	}
	if summary.FilesScanned != 4 {
		t.Errorf("FilesScanned = %d, want 4", summary.FilesScanned)
	}

	cfg := Config{HomeDir: home, RunID: "r", ScannerVersion: "t", ExcludePaths: []string{filepath.Join(project, "third")}}
	findings, summary, err := TargetedScan(cfg, []string{project})
	if err != nil {
		t.Fatal(err)
	}
	if summary.FilesScanned != 3 {
		t.Errorf("FilesScanned with third excluded = %d, want 3", summary.FilesScanned)
	}
	for _, f := range findings {
		if cfg.Excluded(f.FilePath) {
			t.Errorf("finding from an excluded folder: %s", f.FilePath)
		}
	}
	if len(summary.ExcludedPaths) != 1 {
		t.Errorf("summary.ExcludedPaths = %v", summary.ExcludedPaths)
	}
}
