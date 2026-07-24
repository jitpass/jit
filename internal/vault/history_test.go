// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

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
		t.Errorf("history dir survives Remove (err=%v), want gone, rm must mean gone", err)
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

// TestRestoreOldestVersionAtHistoryCapacity pins a confirmed data-loss
// bug: with history full (HistoryKeep versions), restoring the OLDEST
// version used to fail AND destroy it — Restore archived the displaced
// live value via archiveVersion, whose prune pushed the count past the
// cap and deleted the very file the rename was about to restore.
func TestRestoreOldestVersionAtHistoryCapacity(t *testing.T) {
	v := newTestVault(t)
	values := []string{"v0", "v1", "v2", "v3", "v4", "v5"}
	if len(values) != HistoryKeep+1 {
		t.Fatalf("test wants exactly HistoryKeep+1 values, adjust for HistoryKeep=%d", HistoryKeep)
	}
	for _, val := range values {
		if err := v.Set("p/key", []byte(val)); err != nil {
			t.Fatalf("Set(%s): %v", val, err)
		}
	}
	versions, err := v.HistoryVersions("p/key")
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != HistoryKeep {
		t.Fatalf("expected a full history of %d, got %d", HistoryKeep, len(versions))
	}
	oldest := versions[len(versions)-1].ArchiveStamp

	if err := v.Restore("p/key", oldest); err != nil {
		t.Fatalf("Restore(oldest at capacity): %v", err)
	}
	got, err := v.Get("p/key")
	if err != nil {
		t.Fatalf("Get after restore: %v", err)
	}
	if string(got) != "v0" {
		t.Errorf("restored value = %q, want the oldest archived %q", got, "v0")
	}
	// The displaced live value must be archived, and the count must be
	// back within the cap: 5 - restored-out + live-archived = 5.
	after, err := v.HistoryVersions("p/key")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != HistoryKeep {
		t.Errorf("history after restore = %d versions, want %d", len(after), HistoryKeep)
	}
	// And the restore must itself be restorable: newest archived is the
	// displaced live value.
	if err := v.Restore("p/key", 0); err != nil {
		t.Fatalf("Restore back: %v", err)
	}
	if got, _ := v.Get("p/key"); string(got) != "v5" {
		t.Errorf("restore-back value = %q, want the displaced live %q", got, "v5")
	}
}
