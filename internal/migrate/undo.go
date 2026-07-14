// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package migrate

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/vault"
)

// BackupRecord is one row in the backups.yaml undo index: which file was
// backed up, where in the vault its encrypted bytes live, and when. The
// index exists because backupVaultPath's sanitization is lossy (every
// disallowed character run collapses to "_"), so the vault path alone
// can't be reversed back into the original filesystem path — `jit
// migrate undo` needs the mapping recorded at backup time. Paths are
// bookkeeping metadata, not secret material (mounts.yaml already stores
// mount paths the same way), so the index lives alongside the vault, not
// inside it.
type BackupRecord struct {
	OriginalPath string `yaml:"original_path"`
	VaultPath    string `yaml:"vault_path"`
	UnixTS       int64  `yaml:"unix_ts"`
	// RemoveOnRestore marks a file that did NOT exist before migration and
	// was CREATED by it (the only case today: ~/.aws/config, which migrate
	// writes fresh to hold a credential_process line when a credentials-only
	// AWS setup has no config yet). There's no pre-migration content to put
	// back — "byte-for-byte" means the file being gone again — so undo
	// removes it instead of restoring bytes, and VaultPath is empty. Without
	// this, undo restored ~/.aws/credentials but left the jit-created config
	// behind, leaving both static keys AND a dangling credential_process
	// pointing at jit.
	RemoveOnRestore bool `yaml:"remove_on_restore,omitempty"`
}

type backupIndexFile struct {
	Backups []BackupRecord `yaml:"backups"`
}

// BackupIndexPath returns the undo index's location under root, alongside
// mounts.yaml.
func BackupIndexPath(root string) string {
	return filepath.Join(root, "backups.yaml")
}

// appendBackupRecord adds rec to the undo index — called by
// backupSecretFile for every encrypted backup it stores, so every
// backup taken from now on is restorable by path. (Backups taken by
// builds before this index existed are still in the vault under
// _backups/, just not indexed — recoverable by hand via `jit vault
// get`, invisible to `jit migrate undo`.)
func appendBackupRecord(root string, rec BackupRecord) error {
	path := BackupIndexPath(root)
	idx, err := loadBackupIndex(path)
	if err != nil {
		return err
	}
	idx.Backups = append(idx.Backups, rec)
	data, err := yaml.Marshal(idx)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// RecordCreatedFile appends a RemoveOnRestore record for a file migration
// created that did not exist beforehand, so `jit migrate undo` removes it
// rather than leaving a jit-written file behind (see BackupRecord's
// RemoveOnRestore field). absPath must already be absolute; the caller has
// it in hand at write time.
func RecordCreatedFile(root, absPath string) error {
	return appendBackupRecord(root, BackupRecord{
		OriginalPath:    absPath,
		RemoveOnRestore: true,
		UnixTS:          time.Now().Unix(),
	})
}

// LoadBackupRecords returns every backup the undo index records, in
// append (chronological) order. A missing index means no backups have
// been recorded yet — an empty slice, not an error.
func LoadBackupRecords(root string) ([]BackupRecord, error) {
	idx, err := loadBackupIndex(BackupIndexPath(root))
	if err != nil {
		return nil, err
	}
	return idx.Backups, nil
}

func loadBackupIndex(path string) (backupIndexFile, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- fixed, well-known path under jit's own config directory
	if err != nil {
		if os.IsNotExist(err) {
			return backupIndexFile{}, nil
		}
		return backupIndexFile{}, fmt.Errorf("reading %s: %w", path, err)
	}
	var idx backupIndexFile
	if err := yaml.Unmarshal(data, &idx); err != nil {
		return backupIndexFile{}, fmt.Errorf("parsing %s: %w", path, err)
	}
	return idx, nil
}

// LatestBackups reduces recs to the most recent record per OriginalPath,
// sorted by path for deterministic output. A timestamp tie is broken by
// later position in recs — append order is chronological, so the later
// record is the newer backup even within the same second.
func LatestBackups(recs []BackupRecord) []BackupRecord {
	latest := make(map[string]BackupRecord, len(recs))
	for _, r := range recs {
		if cur, ok := latest[r.OriginalPath]; !ok || r.UnixTS >= cur.UnixTS {
			latest[r.OriginalPath] = r
		}
	}
	out := make([]BackupRecord, 0, len(latest))
	for _, r := range latest {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].OriginalPath < out[j].OriginalPath })
	return out
}

// RestoreFromBackup writes rec's backed-up bytes back to rec.OriginalPath
// exactly as they were captured, replacing whatever is there now — a live
// mount's FIFO, a rewritten shell config/MCP config/kubeconfig, a pointer
// file. Two properties matter:
//
//   - Whatever currently occupies the path is snapshotted into the vault
//     first (via backupSecretFile, so it lands in the same indexed
//     _backups/ namespace) — an undo is itself undoable, and an edit
//     someone made to the rewritten file since migration is never simply
//     destroyed. A FIFO is the one exception: a pipe has no at-rest
//     content to read (and opening it for read would block on a writer),
//     and everything it served lives in the vault already.
//
//   - The current occupant is removed BEFORE the write, never opened in
//     place: os.WriteFile against a live mount's FIFO would block forever
//     waiting for a reader.
//
// Callers are responsible for the mount-side bookkeeping when the path is
// a registered mount (stopping the agent's Serve goroutine first, removing
// the registry entry and the .pointers companion) — same division of labor
// as UnmountFile. Restored files get 0600 regardless of the original's
// mode: every file this package backs up held a secret, so the most
// restrictive plausible mode is the only safe default.
//
// The destination is validated and the write is symlink-safe. backups.yaml
// is unencrypted, unauthenticated bookkeeping (see BackupRecord) — a
// tampered or corrupted index that named an arbitrary OriginalPath used to
// turn `jit migrate undo` into an arbitrary-file-write primitive: it
// decrypts a chosen backup and drops the plaintext at whatever path the
// record named, borrowing the user's own fresh undo auth. validateRestorePath
// rejects a non-absolute or non-canonical (".."-bearing) destination, and
// the write below opens with O_EXCL|O_NOFOLLOW after the remove, so a
// symlink an attacker plants in the TOCTOU window between the remove and the
// create can never redirect the plaintext write through it (O_EXCL fails on
// a path that reappeared at all, O_NOFOLLOW refuses to follow a final-element
// symlink) — the write either lands at exactly the validated path or fails
// loud, never silently follows.
func RestoreFromBackup(v *vault.Vault, rec BackupRecord) error {
	if err := validateRestorePath(rec.OriginalPath); err != nil {
		return err
	}

	// A file migration created fresh (RemoveOnRestore) has no pre-migration
	// content: restoring it to its original state means removing it. Snapshot
	// whatever is there now first (so this removal is itself undoable, exactly
	// like the overwrite path below), then delete. A path that's already gone
	// is success, not an error — undo is idempotent.
	if rec.RemoveOnRestore {
		if info, statErr := os.Lstat(rec.OriginalPath); statErr == nil && info.Mode().IsRegular() {
			if _, err := backupSecretFile(v, rec.OriginalPath); err != nil {
				return fmt.Errorf("snapshotting current %s before removing it: %w", rec.OriginalPath, err)
			}
		}
		if err := os.Remove(rec.OriginalPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("removing %s: %w", rec.OriginalPath, err)
		}
		return nil
	}

	data, err := v.Get(rec.VaultPath)
	if err != nil {
		return fmt.Errorf("reading backup %s from the vault: %w", rec.VaultPath, err)
	}

	if info, statErr := os.Lstat(rec.OriginalPath); statErr == nil && info.Mode().IsRegular() {
		if _, err := backupSecretFile(v, rec.OriginalPath); err != nil {
			return fmt.Errorf("snapshotting current %s before restoring over it: %w", rec.OriginalPath, err)
		}
	}

	// RetireFIFO instead of a bare remove: when the occupant is a live
	// mount's pipe, a reader blocked in open(2) at this instant (a file
	// watcher mid-poll) would wait forever on the unlinked pipe's vnode —
	// GAPS.md #57's real incident happened on exactly this line, stranding
	// a VS Code tab as empty-and-loading while the restore itself
	// succeeded. release (after the write below) hands any such reader the
	// restored content.
	release, err := mount.RetireFIFO(rec.OriginalPath)
	if err != nil {
		return fmt.Errorf("removing %s: %w", rec.OriginalPath, err)
	}
	// O_CREATE|O_EXCL|O_NOFOLLOW, not os.WriteFile's O_CREATE|O_TRUNC: the
	// latter follows a symlink present at open time, and something (a
	// racing attacker, or an unexpected reappearance) can occupy the path
	// between the Remove above and this open. O_EXCL makes the create fail
	// rather than clobber whatever is there; O_NOFOLLOW makes it fail rather
	// than write through a symlink. See this function's doc comment.
	f, err := os.OpenFile(rec.OriginalPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("creating %s (something reappeared at this path — refusing to write a secret through it): %w", rec.OriginalPath, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("writing %s: %w", rec.OriginalPath, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing %s: %w", rec.OriginalPath, err)
	}
	if err := release(data); err != nil {
		return fmt.Errorf("releasing readers of the old mount at %s (the file itself was restored): %w", rec.OriginalPath, err)
	}
	return nil
}

// validateRestorePath confines a backup record's restore destination to an
// absolute, canonical path before RestoreFromBackup writes a decrypted
// secret to it. The undo index it comes from is unauthenticated (see
// BackupRecord and RestoreFromBackup's doc comment), so a `..`-bearing or
// relative OriginalPath must never be honored — the source (vault) side is
// already validated by sanitizeSecretPath; this is the matching gate on the
// destination side. IsAbs plus an exact filepath.Clean match is sufficient:
// Clean resolves every interior ".." and collapses redundant separators, so
// any path that survives unchanged has no traversal left in it.
func validateRestorePath(p string) error {
	if p == "" {
		return fmt.Errorf("backup record has an empty original_path — refusing to restore")
	}
	if !filepath.IsAbs(p) {
		return fmt.Errorf("refusing to restore to non-absolute path %q", p)
	}
	if p != filepath.Clean(p) {
		return fmt.Errorf("refusing to restore to non-canonical path %q (contains \"..\", \".\", or redundant separators)", p)
	}
	return nil
}
