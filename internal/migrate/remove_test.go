// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package migrate

import (
	"os"
	"path/filepath"
	"strings"
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
