// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

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

// Undo says it restores a file "byte-for-byte", and it did — for content.
// The permission bits were not restored: every restore created the file at
// jit's 0600 default, so a 0644 .env came back 0600. Tightening is the safer
// direction, but it's still a silent change to a file the user was told was
// put back as it was, and it breaks anything that has to read the file as
// another account or through a container bind-mount.
func TestRestoreFromBackupRestoresOriginalFileMode(t *testing.T) {
	v := newTestVault(t)
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	writeFile(t, envPath, "API_KEY=sk_live_123\n")
	if err := os.Chmod(envPath, 0o644); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

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
	if recs[0].Mode != "644" {
		t.Errorf("recorded Mode = %q, want \"644\"; without it the restore can't know what to put back", recs[0].Mode)
	}
	if err := RestoreFromBackup(v, recs[0]); err != nil {
		t.Fatalf("RestoreFromBackup: %v", err)
	}
	info, err := os.Lstat(envPath)
	if err != nil {
		t.Fatalf("stat restored file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Errorf("restored mode = %#o, want %#o, the file the user had back exactly as it was", got, 0o644)
	}
}

// A record with no Mode is every backup taken before the field existed. It
// must keep restoring at 0600 — the historical behavior — rather than
// landing on a zero mode no one can read.
func TestRestoreFromBackupDefaultsModeWhenUnrecorded(t *testing.T) {
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
	rec := recs[0]
	rec.Mode = "" // as a pre-Mode index entry would deserialize
	if err := RestoreFromBackup(v, rec); err != nil {
		t.Fatalf("RestoreFromBackup: %v", err)
	}
	info, err := os.Lstat(envPath)
	if err != nil {
		t.Fatalf("stat restored file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("restored mode = %#o, want %#o for an unrecorded mode", got, 0o600)
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

// TestRestoreFromBackupSnapshotsCurrentStateFirst: whatever regular-file
// content an undo is about to overwrite is captured into the vault first, so
// nothing is ever destroyed outright — the guarantee `jit migrate undo`'s own
// documentation makes.
//
// This test used to assert the snapshot became the next undo TARGET, i.e. that
// a second undo round-tripped back to the migrated state. That is the toggle
// behaviour that made `jit migrate undo` non-idempotent: the command restores
// "from their encrypted pre-migration backups", and a snapshot of the migrated
// file is not one of those. Both halves are now asserted separately — the
// snapshot is stored and recoverable, and it never answers "what did this file
// look like before jit".
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

	// The migrated state must have been snapshotted into the vault before it
	// was overwritten — "nothing is ever simply destroyed", per the command's
	// own documentation. It is recoverable by hand with `jit vault get`.
	recs, err := LoadBackupRecords(v.Root)
	if err != nil {
		t.Fatalf("LoadBackupRecords: %v", err)
	}
	var snapshot *BackupRecord
	for i := range recs {
		if recs[i].OriginalPath == rcPath && recs[i].Snapshot {
			snapshot = &recs[i]
		}
	}
	if snapshot == nil {
		t.Fatalf("no pre-restore snapshot recorded for %s: the overwritten state was destroyed", rcPath)
	}
	stored, err := v.Get(snapshot.VaultPath)
	if err != nil {
		t.Fatalf("snapshot %s is recorded but not in the vault: %v", snapshot.VaultPath, err)
	}
	if string(stored) != string(migrated) {
		t.Errorf("snapshot holds %q, want the migrated state %q", stored, migrated)
	}

	// But it is NOT an undo target: a second undo restores the same
	// pre-migration content, it does not toggle the migration back on. The
	// command restores "from their encrypted pre-migration backups"; a
	// snapshot of the migrated file is not one of those.
	if err := RestoreFromBackup(v, latestFor(t, v.Root, rcPath)); err != nil {
		t.Fatalf("RestoreFromBackup (second undo): %v", err)
	}
	after, err := os.ReadFile(rcPath)
	if err != nil {
		t.Fatalf("reading rc after second undo: %v", err)
	}
	if string(after) != original {
		t.Errorf("second undo = %q, want the pre-migration content %q (undo must be idempotent, not a toggle)", after, original)
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

// `jit migrate undo` must be idempotent: running it twice has to leave the
// file in the same restored state, not put the migration back.
//
// It did put it back. RestoreFromBackup snapshots whatever occupies the path
// before overwriting it (so an undo is itself undoable), and that snapshot
// went into the same index with a newer timestamp — so LatestBackups, which
// picks the newest record per path, chose the snapshot of the MIGRATED file on
// the second run. The user got the credential-stripped file back, reported as a
// successful restore of a backup "taken 3 seconds ago", with the pristine
// backup now permanently unreachable from undo.
func TestUndoIsIdempotent(t *testing.T) {
	v := newTestVault(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials")
	const original = "[default]\naws_secret_access_key = ORIGINAL\n"
	writeFile(t, path, original)

	if _, err := backupSecretFile(v, path); err != nil {
		t.Fatalf("backupSecretFile: %v", err)
	}
	// Stand in for the migration's own rewrite.
	writeFile(t, path, "[default]\ncredential_process = jit aws-credential-process\n")

	restore := func(pass int) {
		t.Helper()
		recs, err := LoadBackupRecords(v.Root)
		if err != nil {
			t.Fatalf("pass %d: LoadBackupRecords: %v", pass, err)
		}
		for _, rec := range LatestBackups(recs) {
			if rec.OriginalPath != path {
				continue
			}
			if err := RestoreFromBackup(v, rec); err != nil {
				t.Fatalf("pass %d: RestoreFromBackup: %v", pass, err)
			}
			return
		}
		t.Fatalf("pass %d: no undo target for %s", pass, path)
	}

	restore(1)
	got, err := os.ReadFile(path) // #nosec G304 -- test path
	if err != nil {
		t.Fatalf("reading after first undo: %v", err)
	}
	if string(got) != original {
		t.Fatalf("first undo restored %q, want the pre-migration content", got)
	}

	restore(2)
	got, err = os.ReadFile(path) // #nosec G304 -- test path
	if err != nil {
		t.Fatalf("reading after second undo: %v", err)
	}
	if string(got) != original {
		t.Fatalf("second undo re-applied the migration: file is now %q, want %q still", got, original)
	}
}

// The same, for a file migration CREATED: undo removes it, and a second undo
// must leave it removed rather than writing it back.
//
// This was the worse half of the same bug — the second undo re-created
// ~/.aws/config complete with the credential_process line pointing at jit,
// for credentials that had just been un-vaulted.
func TestUndoIsIdempotentForCreatedFiles(t *testing.T) {
	v := newTestVault(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	writeFile(t, path, "[default]\ncredential_process = jit aws-credential-process\n")

	if err := RecordCreatedFile(v.Root, path); err != nil {
		t.Fatalf("RecordCreatedFile: %v", err)
	}

	for pass := 1; pass <= 2; pass++ {
		recs, err := LoadBackupRecords(v.Root)
		if err != nil {
			t.Fatalf("pass %d: LoadBackupRecords: %v", pass, err)
		}
		var done bool
		for _, rec := range LatestBackups(recs) {
			if rec.OriginalPath != path {
				continue
			}
			if err := RestoreFromBackup(v, rec); err != nil {
				t.Fatalf("pass %d: RestoreFromBackup: %v", pass, err)
			}
			done = true
		}
		if !done {
			t.Fatalf("pass %d: no undo target for %s", pass, path)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("after undo pass %d the jit-created file is back (stat err %v); "+
				"undo re-created a config with a dangling credential_process line", pass, err)
		}
	}
}
