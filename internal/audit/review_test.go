// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// reviewToken is assembled at runtime, never written as one literal, so
// push protection does not read it as a leaked token.
var reviewToken = "ghp" + "_" + tokenBody(36)

func reviewedScan(t *testing.T, cfg Config, file string) ([]Finding, ScanSummary) {
	t.Helper()
	findings, summary, err := TargetedScan(cfg, []string{file})
	if err != nil {
		t.Fatalf("TargetedScan: %v", err)
	}
	return findings, summary
}

// A marked finding leaves the report and is counted; moving its line
// keeps the mark; changing its value brings it back; --unfiltered shows
// it tagged; the store never holds the value.
func TestReviewMarkMatchesTheValueNotTheLine(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "client_test.py")
	writeFileIn(t, file, "token = \""+reviewToken+"\"\n")
	storePath := filepath.Join(dir, "state", "scan-reviewed.json")
	store, err := LoadReviewStore(storePath)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{HomeDir: dir}
	findings, _ := reviewedScan(t, cfg, file)
	if len(findings) != 1 {
		t.Fatalf("got %d findings before any mark, want 1", len(findings))
	}
	if _, err := store.Mark(findings[0], "GitHub token", time.Unix(1_790_000_000, 0)); err != nil {
		t.Fatal(err)
	}
	raw, err := store.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(storePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(storePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), reviewToken) {
		t.Fatal("the store holds the value")
	}
	store, _ = LoadReviewStore(storePath)
	cfg.Reviewed = store

	findings, summary := reviewedScan(t, cfg, file)
	if len(findings) != 0 || summary.Reviewed != 1 {
		t.Fatalf("after the mark: %d findings, reviewed %d; want 0 and 1", len(findings), summary.Reviewed)
	}

	writeFileIn(t, file, "\n\n\ntoken = \""+reviewToken+"\"\n")
	if findings, _ := reviewedScan(t, cfg, file); len(findings) != 0 {
		t.Fatal("moving the line brought the finding back")
	}

	unfiltered := cfg
	unfiltered.Unfiltered = true
	findings, _ = reviewedScan(t, unfiltered, file)
	if len(findings) != 1 || !findings[0].UnfilteredOnly || !strings.Contains(findings[0].UnfilteredReason, "reviewed") {
		t.Fatalf("--unfiltered should keep it, tagged: %+v", findings)
	}

	writeFileIn(t, file, "token = \""+reviewToken[:len(reviewToken)-1]+"Q\"\n")
	if findings, summary := reviewedScan(t, cfg, file); len(findings) != 1 || summary.Reviewed != 0 {
		t.Fatalf("a changed value must be reported again: %d findings, reviewed %d", len(findings), summary.Reviewed)
	}
}

// A copy of a secret jit already holds is fixed by Redact or rotation,
// never by a mark.
func TestReviewRefusesCacheAndVaultCopies(t *testing.T) {
	store := &ReviewStore{path: filepath.Join(t.TempDir(), "r.json")}
	for _, f := range []Finding{
		{FindingType: FindingTypeVaultCopy, FilePath: "/x"},
		{FindingType: FindingTypeAgentCachedSecret, FilePath: "/x"},
		{FindingType: FindingTypeExposedSecret, FilePath: "/x", CacheArea: "transcripts"},
	} {
		if _, err := store.Mark(f, "", time.Now()); err == nil {
			t.Errorf("%s in %q was marked", f.FindingType, f.CacheArea)
		}
	}
}

func TestReviewUnmarkByLine(t *testing.T) {
	one, two := 1, 2
	store := &ReviewStore{Marks: []ReviewMark{{ID: "a", Path: "/f", Line: &one}, {ID: "b", Path: "/f", Line: &two}, {ID: "c", Path: "/g"}}}
	if gone := store.Unmark("/f", &two); len(gone) != 1 || gone[0].ID != "b" {
		t.Fatalf("unmark line 2: %+v", gone)
	}
	if gone := store.Unmark("/f", nil); len(gone) != 1 || len(store.Marks) != 1 {
		t.Fatalf("unmark file: %+v, left %+v", gone, store.Marks)
	}
}
