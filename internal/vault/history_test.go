// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOverwriteArchivesPreviousVersionAndRestoreBringsItBack(t *testing.T) {
	v := newTestVault(t)
	if err := v.Set("stripe/dev-key", []byte("old-token")); err != nil {
		t.Fatalf("Set 1: %v", err)
	}
	if err := v.Set("stripe/dev-key", []byte("new-token")); err != nil {
		t.Fatalf("Set 2: %v", err)
	}

	versions, err := v.HistoryVersions("stripe/dev-key")
	if err != nil {
		t.Fatalf("HistoryVersions: %v", err)
	}
	if len(versions) != 1 {
		t.Fatalf("versions = %d, want 1", len(versions))
	}
	if versions[0].Version != envelopeVersion {
		t.Errorf("archived envelope version = %d, want %d", versions[0].Version, envelopeVersion)
	}

	// Restore the old value; the botched rotation is undone...
	if err := v.Restore("stripe/dev-key", 0); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	got, err := v.Get("stripe/dev-key")
	if err != nil {
		t.Fatalf("Get after restore: %v", err)
	}
	if string(got) != "old-token" {
		t.Errorf("Get after restore = %q, want old-token", got)
	}

	// ...and the restore itself is restorable: the displaced new value
	// became the newest history version.
	versions, err = v.HistoryVersions("stripe/dev-key")
	if err != nil {
		t.Fatalf("HistoryVersions after restore: %v", err)
	}
	if len(versions) != 1 {
		t.Fatalf("versions after restore = %d, want 1", len(versions))
	}
	if err := v.Restore("stripe/dev-key", 0); err != nil {
		t.Fatalf("Restore back: %v", err)
	}
	if got, _ := v.Get("stripe/dev-key"); string(got) != "new-token" {
		t.Errorf("Get after restore-of-restore = %q, want new-token", got)
	}
}

func TestHistoryIsBounded(t *testing.T) {
	v := newTestVault(t)
	for i := 0; i < HistoryKeep+3; i++ {
		if err := v.Set("stripe/dev-key", []byte{byte('a' + i)}); err != nil {
			t.Fatalf("Set %d: %v", i, err)
		}
	}
	versions, err := v.HistoryVersions("stripe/dev-key")
	if err != nil {
		t.Fatalf("HistoryVersions: %v", err)
	}
	if len(versions) != HistoryKeep {
		t.Errorf("versions = %d, want exactly HistoryKeep (%d)", len(versions), HistoryKeep)
	}
}

func TestHistoryHiddenFromListAndPurgedByRemove(t *testing.T) {
	v := newTestVault(t)
	if err := v.Set("stripe/dev-key", []byte("one")); err != nil {
		t.Fatalf("Set 1: %v", err)
	}
	if err := v.Set("stripe/dev-key", []byte("two")); err != nil {
		t.Fatalf("Set 2: %v", err)
	}

	paths, err := v.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(paths) != 1 || paths[0] != "stripe/dev-key" {
		t.Errorf("List = %v, want just the live secret", paths)
	}

	if err := v.Remove("stripe/dev-key"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(filepath.Join(v.Root, "vault", historyDirName, "stripe/dev-key")); !os.IsNotExist(err) {
		t.Errorf("history dir survives Remove (err=%v), want gone — rm must mean gone", err)
	}
	if versions, _ := v.HistoryVersions("stripe/dev-key"); len(versions) != 0 {
		t.Errorf("HistoryVersions after Remove = %v, want none", versions)
	}
}

func TestRestoreErrors(t *testing.T) {
	v := newTestVault(t)
	if err := v.Restore("stripe/dev-key", 0); err == nil {
		t.Error("Restore with no history succeeded, want error")
	}
	if err := v.Set("stripe/dev-key", []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := v.Set("stripe/dev-key", []byte("two")); err != nil {
		t.Fatal(err)
	}
	if err := v.Restore("stripe/dev-key", 12345); err == nil {
		t.Error("Restore with a bogus stamp succeeded, want error")
	}
}

func TestBackupsAreNeverArchived(t *testing.T) {
	v := newTestVault(t)
	if err := v.Set("_backups/some/file", []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := v.Set("_backups/some/file", []byte("two")); err != nil {
		t.Fatal(err)
	}
	if versions, _ := v.HistoryVersions("_backups/some/file"); len(versions) != 0 {
		t.Errorf("backup overwrite grew history (%d versions), want none", len(versions))
	}
}
