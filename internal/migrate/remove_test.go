// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestRestorePointerFileRoundTrip: an in-place pointer file (what a
// backup-suffixed .env.bak becomes, GAPS.md #34) restores to a plain
// dotenv file with the real vault values — `jit migrate remove`'s path for
// files that were never live mounts.
func TestRestorePointerFileRoundTrip(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".env.bak")
	writeFile(t, path, "API_KEY=sk_stale_but_real\n")

	v := newTestVault(t)
	if _, err := ApplyEnvFile(v, root, path); err != nil {
		t.Fatalf("ApplyEnvFile: %v", err)
	}
	if !IsPointerFile(path) {
		t.Fatal("precondition: .env.bak should be an in-place pointer file after migration")
	}

	names, err := RestorePointerFile(v, path)
	if err != nil {
		t.Fatalf("RestorePointerFile: %v", err)
	}
	if len(names) != 1 || names[0] != "API_KEY" {
		t.Errorf("names = %v, want [API_KEY]", names)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(data), "API_KEY=sk_stale_but_real") {
		t.Errorf("restored content = %q, want the real value back", data)
	}
	if IsPointerFile(path) {
		t.Error("file still sniffs as a pointer file after restore")
	}
}

func TestDiscoverPointerArtifacts(t *testing.T) {
	root := t.TempDir()
	v := newTestVault(t)

	// An in-place pointer file (.env.bak) and a live mount whose .pointers
	// companion we plant by hand (ApplyEnvFile doesn't write companions —
	// that's the CLI's job).
	bakPath := filepath.Join(root, ".env.bak")
	writeFile(t, bakPath, "A=1\n")
	if _, err := ApplyEnvFile(v, root, bakPath); err != nil {
		t.Fatalf("ApplyEnvFile: %v", err)
	}
	companion := filepath.Join(root, ".env.pointers")
	writeFile(t, companion, "# jit pointer file\nA=jit://vault/x/A\n")
	writeFile(t, filepath.Join(root, ".env.example"), "A=placeholder\n") // ordinary file, matched by the wildcard but not a pointer file

	companions, inPlace, err := DiscoverPointerArtifacts(root)
	if err != nil {
		t.Fatalf("DiscoverPointerArtifacts: %v", err)
	}
	if len(companions) != 1 || companions[0] != companion {
		t.Errorf("companions = %v, want [%s]", companions, companion)
	}
	if len(inPlace) != 1 || inPlace[0] != bakPath {
		t.Errorf("inPlace = %v, want [%s]", inPlace, bakPath)
	}
}

func TestDropBackupRecords(t *testing.T) {
	root := t.TempDir()
	recA := BackupRecord{OriginalPath: "/proj/a/.env", VaultPath: "_backups/a", UnixTS: 1}
	recB := BackupRecord{OriginalPath: "/proj/b/.env", VaultPath: "_backups/b", UnixTS: 2}
	for _, r := range []BackupRecord{recA, recB} {
		if err := appendBackupRecord(root, r); err != nil {
			t.Fatalf("appendBackupRecord: %v", err)
		}
	}

	if err := DropBackupRecords(root, []BackupRecord{recA}); err != nil {
		t.Fatalf("DropBackupRecords: %v", err)
	}
	recs, err := LoadBackupRecords(root)
	if err != nil {
		t.Fatalf("LoadBackupRecords: %v", err)
	}
	if len(recs) != 1 || recs[0].VaultPath != "_backups/b" {
		t.Errorf("records after drop = %v, want just recB", recs)
	}

	// Dropping the last record removes the index file itself — an empty
	// index would make `jit migrate undo` half-fail confusingly, the same
	// reasoning vault clean already applies.
	if err := DropBackupRecords(root, []BackupRecord{recB}); err != nil {
		t.Fatalf("DropBackupRecords(last): %v", err)
	}
	if _, err := os.Stat(BackupIndexPath(root)); !os.IsNotExist(err) {
		t.Errorf("undo index should be gone once its last record is dropped (stat err: %v)", err)
	}
}

// Dropping one created-file record must not take the others with it.
//
// RecordCreatedFile writes a record with no VaultPath (there are no bytes to
// store — the undo is a deletion), and the drop-set used to key on VaultPath
// alone. Every created-file record therefore keyed on the empty string, so
// `jit migrate remove` on an AWS project silently discarded the
// RemoveOnRestore record for an unrelated file like ~/.terraformrc, and a
// later `jit migrate undo` left that jit-written file behind permanently.
func TestDropBackupRecordsKeepsOtherCreatedFileRecords(t *testing.T) {
	root := t.TempDir()
	if err := RecordCreatedFile(root, "/home/u/.aws/config"); err != nil {
		t.Fatalf("RecordCreatedFile(aws): %v", err)
	}
	if err := RecordCreatedFile(root, "/home/u/.terraformrc"); err != nil {
		t.Fatalf("RecordCreatedFile(terraform): %v", err)
	}
	recs, err := LoadBackupRecords(root)
	if err != nil {
		t.Fatalf("LoadBackupRecords: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("setup wrote %d records, want 2", len(recs))
	}

	var awsRec BackupRecord
	for _, r := range recs {
		if r.OriginalPath == "/home/u/.aws/config" {
			awsRec = r
		}
	}
	if err := DropBackupRecords(root, []BackupRecord{awsRec}); err != nil {
		t.Fatalf("DropBackupRecords: %v", err)
	}

	left, err := LoadBackupRecords(root)
	if err != nil {
		t.Fatalf("LoadBackupRecords after drop: %v", err)
	}
	if len(left) != 1 || left[0].OriginalPath != "/home/u/.terraformrc" {
		t.Fatalf("dropping the AWS created-file record also dropped unrelated ones: %v "+
			"(undo can no longer remove the jit-written ~/.terraformrc)", left)
	}
}

// Concurrent appends must not lose records: the index is what makes every
// backup reachable, and a dropped record leaves the plaintext file jit just
// rewrote recoverable only by hand through `jit vault get`.
func TestAppendBackupRecordSurvivesConcurrentWriters(t *testing.T) {
	root := t.TempDir()
	const writers = 12

	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- appendBackupRecord(root, BackupRecord{
				OriginalPath: fmt.Sprintf("/proj/%d/.env", i),
				VaultPath:    fmt.Sprintf("_backups/%d", i),
				UnixTS:       int64(i + 1),
			})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("appendBackupRecord: %v", err)
		}
	}

	recs, err := LoadBackupRecords(root)
	if err != nil {
		t.Fatalf("LoadBackupRecords: %v", err)
	}
	if len(recs) != writers {
		t.Fatalf("got %d records from %d concurrent appends: overlapping "+
			"read-modify-write lost %d backup(s)", len(recs), writers, writers-len(recs))
	}
}
