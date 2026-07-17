// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package migrate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBackupSecretFileWritesUndoIndexRecord(t *testing.T) {
	v := newTestVault(t)
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	writeFile(t, envPath, "API_KEY=sk_live_123\n")

	if _, err := ApplyEnvFile(v, dir, envPath); err != nil {
		t.Fatalf("ApplyEnvFile: %v", err)
	}

	recs, err := LoadBackupRecords(v.Root)
	if err != nil {
		t.Fatalf("LoadBackupRecords: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(recs))
	}
	if recs[0].OriginalPath != envPath {
		t.Errorf("OriginalPath = %q, want %q, the lossy vault path can't be reversed, this record is the only mapping back", recs[0].OriginalPath, envPath)
	}
	if exists, _ := v.Exists(recs[0].VaultPath); !exists {
		t.Errorf("record's VaultPath %q has no vault entry behind it", recs[0].VaultPath)
	}
}

// TestRestoreFromBackupRoundTripsMountedEnvFile is the core undo
// guarantee: migrate a real .env (the file becomes a FIFO), restore it,
// and get the EXACT original bytes back as a plain regular file —
// comments, ordering, quoting, everything.
func TestRestoreFromBackupRoundTripsMountedEnvFile(t *testing.T) {
	v := newTestVault(t)
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	original := "# comment survives\nexport API_KEY=sk_live_123\nDB_URL=\"postgres://x?a=1\"\n\n"
	writeFile(t, envPath, original)

	if _, err := ApplyEnvFile(v, dir, envPath); err != nil {
		t.Fatalf("ApplyEnvFile: %v", err)
	}
	info, err := os.Lstat(envPath)
	if err != nil {
		t.Fatalf("stat mounted file: %v", err)
	}
	if info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatal("setup: expected ApplyEnvFile to have replaced the file with a FIFO")
	}

	recs, err := LoadBackupRecords(v.Root)
	if err != nil {
		t.Fatalf("LoadBackupRecords: %v", err)
	}
	latest := LatestBackups(recs)
	if len(latest) != 1 {
		t.Fatalf("len(latest) = %d, want 1", len(latest))
	}
	if err := RestoreFromBackup(v, latest[0]); err != nil {
		t.Fatalf("RestoreFromBackup: %v", err)
	}

	restored, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("reading restored file: %v", err)
	}
	if string(restored) != original {
		t.Errorf("restored content = %q, want the exact original %q", restored, original)
	}
	info, err = os.Lstat(envPath)
	if err != nil {
		t.Fatalf("stat restored file: %v", err)
	}
	if !info.Mode().IsRegular() {
		t.Errorf("restored file mode = %v, want a plain regular file, not a pipe", info.Mode())
	}
}

func TestRestoreFromBackupRoundTripsShellConfig(t *testing.T) {
	v := newTestVault(t)
	home := t.TempDir()
	t.Setenv("HOME", home) // ApplyShellConfig writes its profile to the home-rooted global store
	rcPath := filepath.Join(home, ".zshrc")
	original := "# my shell setup\nexport AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI\nalias ll='ls -la'\n"
	writeFile(t, rcPath, original)

	if _, err := ApplyShellConfig(v, rcPath); err != nil {
		t.Fatalf("ApplyShellConfig: %v", err)
	}
	rewritten, err := os.ReadFile(rcPath)
	if err != nil {
		t.Fatalf("reading rewritten rc: %v", err)
	}
	if string(rewritten) == original {
		t.Fatal("setup: expected ApplyShellConfig to have rewritten the file")
	}

	latest := latestFor(t, v.Root, rcPath)
	if err := RestoreFromBackup(v, latest); err != nil {
		t.Fatalf("RestoreFromBackup: %v", err)
	}
	restored, err := os.ReadFile(rcPath)
	if err != nil {
		t.Fatalf("reading restored rc: %v", err)
	}
	if string(restored) != original {
		t.Errorf("restored .zshrc = %q, want the exact original %q", restored, original)
	}
}

// TestRestoreFromBackupSnapshotsCurrentStateFirst: an undo must itself be
// undoable — whatever regular-file content is being overwritten gets
// captured as a new (now latest) backup record before the restore, so a
// second undo round-trips back to the pre-undo state instead of anything
// being destroyed outright.
func TestRestoreFromBackupSnapshotsCurrentStateFirst(t *testing.T) {
	v := newTestVault(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	rcPath := filepath.Join(home, ".zshrc")
	original := "export STRIPE_API_KEY=sk_live_abc\n"
	writeFile(t, rcPath, original)

	if _, err := ApplyShellConfig(v, rcPath); err != nil {
		t.Fatalf("ApplyShellConfig: %v", err)
	}
	migrated, err := os.ReadFile(rcPath)
	if err != nil {
		t.Fatalf("reading migrated rc: %v", err)
	}

	if err := RestoreFromBackup(v, latestFor(t, v.Root, rcPath)); err != nil {
		t.Fatalf("RestoreFromBackup (undo): %v", err)
	}

	// The latest record must now be the pre-restore snapshot: restoring
	// again round-trips back to the migrated state.
	if err := RestoreFromBackup(v, latestFor(t, v.Root, rcPath)); err != nil {
		t.Fatalf("RestoreFromBackup (redo): %v", err)
	}
	after, err := os.ReadFile(rcPath)
	if err != nil {
		t.Fatalf("reading redone rc: %v", err)
	}
	if string(after) != string(migrated) {
		t.Errorf("after undo+undo = %q, want the migrated state %q back, the pre-restore snapshot must be the newest record", after, migrated)
	}
}

func TestBackupSecretFileSameSecondNeverOverwrites(t *testing.T) {
	v := newTestVault(t)
	path := filepath.Join(t.TempDir(), ".zshrc")

	writeFile(t, path, "state-one\n")
	first, err := backupSecretFile(v, path)
	if err != nil {
		t.Fatalf("backupSecretFile (first): %v", err)
	}
	writeFile(t, path, "state-two\n")
	second, err := backupSecretFile(v, path)
	if err != nil {
		t.Fatalf("backupSecretFile (second): %v", err)
	}

	if first == second {
		t.Fatalf("two same-second backups landed on one vault path %q, the later would silently destroy the earlier's bytes", first)
	}
	got, err := v.Get(first)
	if err != nil {
		t.Fatalf("Get(first backup): %v", err)
	}
	if string(got) != "state-one\n" {
		t.Errorf("first backup = %q, want its original bytes intact", got)
	}
}

func TestLatestBackupsPicksNewestPerPathAndBreaksTiesByOrder(t *testing.T) {
	recs := []BackupRecord{
		{OriginalPath: "/a", VaultPath: "old-a", UnixTS: 100},
		{OriginalPath: "/b", VaultPath: "only-b", UnixTS: 150},
		{OriginalPath: "/a", VaultPath: "new-a", UnixTS: 200},
		{OriginalPath: "/a", VaultPath: "tie-a", UnixTS: 200}, // later in append order = newer
	}
	latest := LatestBackups(recs)
	if len(latest) != 2 {
		t.Fatalf("len(latest) = %d, want 2", len(latest))
	}
	if latest[0].OriginalPath != "/a" || latest[0].VaultPath != "tie-a" {
		t.Errorf("latest for /a = %+v, want the tie broken toward the later (chronologically newer) record", latest[0])
	}
	if latest[1].VaultPath != "only-b" {
		t.Errorf("latest for /b = %+v", latest[1])
	}
}

// TestValidateRestorePathRejectsUntrustworthyDestinations locks in the
// destination-side gate: backups.yaml is unauthenticated, so a record whose
// OriginalPath is relative or carries a ".." must never be honored, or
// `jit migrate undo` becomes an arbitrary-file-write primitive that borrows
// the user's own undo auth to drop a decrypted secret wherever the record
// names.
func TestValidateRestorePathRejectsUntrustworthyDestinations(t *testing.T) {
	bad := []string{
		"",                     // empty
		"relative/path",        // not absolute
		"../escape",            // relative traversal
		"/home/user/../../etc", // absolute but non-canonical traversal
		"/a//b",                // redundant separators (non-canonical)
		"/a/./b",               // "." element (non-canonical)
	}
	for _, p := range bad {
		if err := validateRestorePath(p); err == nil {
			t.Errorf("validateRestorePath(%q) = nil, want an error, this path should never receive a restored secret", p)
		}
	}
	for _, p := range []string{"/Users/x/.env", "/Users/x/code/proj/.env"} {
		if err := validateRestorePath(p); err != nil {
			t.Errorf("validateRestorePath(%q) = %v, want nil for a legitimate absolute canonical path", p, err)
		}
	}
}

// TestRestoreFromBackupErrorsOnUntrustworthyPath confirms the validation is
// wired into RestoreFromBackup itself (not just the helper) and fires before
// any vault read or filesystem write.
func TestRestoreFromBackupErrorsOnUntrustworthyPath(t *testing.T) {
	v := newTestVault(t)
	rec := BackupRecord{OriginalPath: "/tmp/../etc/evil", VaultPath: "_backups/whatever", UnixTS: 1}
	if err := RestoreFromBackup(v, rec); err == nil {
		t.Fatal("RestoreFromBackup accepted a non-canonical destination path")
	}
}

// TestRestoreFromBackupDoesNotFollowSymlink is the symlink-redirect
// guarantee: if a symlink occupies the restore destination, the plaintext
// must land at the destination path itself as a fresh regular file — never
// get written through the link into the victim it points at.
func TestRestoreFromBackupDoesNotFollowSymlink(t *testing.T) {
	v := newTestVault(t)
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	original := "API_KEY=sk_live_secret\n"
	writeFile(t, envPath, original)
	if _, err := ApplyEnvFile(v, dir, envPath); err != nil {
		t.Fatalf("ApplyEnvFile: %v", err)
	}
	rec := latestFor(t, v.Root, envPath)

	// Replace the mounted FIFO with a symlink pointing at a victim file an
	// attacker wants overwritten with the decrypted secret.
	victim := filepath.Join(dir, "victim.txt")
	writeFile(t, victim, "do-not-touch\n")
	if err := os.Remove(envPath); err != nil {
		t.Fatalf("removing FIFO: %v", err)
	}
	if err := os.Symlink(victim, envPath); err != nil {
		t.Fatalf("planting symlink: %v", err)
	}

	if err := RestoreFromBackup(v, rec); err != nil {
		t.Fatalf("RestoreFromBackup: %v", err)
	}

	if got, _ := os.ReadFile(victim); string(got) != "do-not-touch\n" {
		t.Errorf("victim was written through the symlink: got %q, the secret must never follow a link", got)
	}
	info, err := os.Lstat(envPath)
	if err != nil {
		t.Fatalf("stat restored path: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Error("restore path is still a symlink; expected a fresh regular file at the destination itself")
	}
	if got, _ := os.ReadFile(envPath); string(got) != original {
		t.Errorf("restored content = %q, want the original at the destination path itself", got)
	}
}

// latestFor returns the newest backup record for path, failing the test
// if none exists.
func latestFor(t *testing.T, root, path string) BackupRecord {
	t.Helper()
	recs, err := LoadBackupRecords(root)
	if err != nil {
		t.Fatalf("LoadBackupRecords: %v", err)
	}
	for _, r := range LatestBackups(recs) {
		if r.OriginalPath == path {
			return r
		}
	}
	t.Fatalf("no backup record for %s", path)
	return BackupRecord{}
}
