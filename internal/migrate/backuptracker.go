// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"fmt"
	"path/filepath"

	"github.com/jitpass/jit/internal/vault"
)

// BackupTracker dedups backups of a shared file across the per-unit Apply
// calls of a single migrate run (GAPS.md #65). AWS, kubeconfig, and
// Terraform Cloud each migrate multiple units — profiles, users, hosts —
// that live in ONE file, and the CLI applies them in a per-unit loop. Every
// Apply call backs up the file it's about to rewrite, so without dedup the
// second profile backs up ~/.aws/credentials AFTER the first was already
// stripped from it, the third after two were, and so on: a chain of
// progressively-degraded snapshots.
//
// `jit migrate undo` restores the most-recent backup per path
// (LatestBackups), so it would restore the LAST, most-stripped snapshot —
// silently dropping every unit removed before the final one. The reported
// case: a two-profile ~/.aws/credentials came back from undo with the first
// profile's keys gone. A single-profile file was always fine, which is
// exactly why this shipped.
//
// A BackupTracker, created once per run and shared across a category's
// per-unit Apply calls, makes the FIRST backup of a path the only one — the
// pristine pre-run state, which is what undo must restore. It also remembers
// files the run CREATED (~/.aws/config written fresh to hold a
// credential_process line): a later unit in the same run must neither back
// such a file up (that backup would win over the RemoveOnRestore record and
// leave a jit-written file behind) nor record it created twice.
//
// A nil *BackupTracker is valid and means "no dedup — always back up": the
// single-unit categories (.env, npmrc, shell config, MCP) never share a file
// across two Apply calls in one run, and undo's own pre-restore snapshot
// wants every distinct state preserved. Every method is nil-receiver-safe so
// a caller can hold a nil tracker and call through it unconditionally.
type BackupTracker struct {
	backups map[string]string // abs path -> vault backup path already taken this run
	created map[string]bool   // abs path -> created fresh this run (RemoveOnRestore already recorded)
}

// NewBackupTracker returns a tracker for one migrate run. The CLI creates
// exactly one and threads it through every category's Apply loop.
func NewBackupTracker() *BackupTracker {
	return &BackupTracker{backups: map[string]string{}, created: map[string]bool{}}
}

// BackupSecretFile stores path's exact bytes encrypted in the vault and
// records the undo-index entry, exactly as every migrate category does
// before touching a file. Exported for `jit wrap <tool>`'s scrub step
// (docs/internal/WRAP-PLAN.md §3.3 step 4), so a wrapped tool's config file gets the
// same byte-for-byte `jit migrate undo` guarantee as a migrated one.
func BackupSecretFile(v *vault.Vault, path string) (string, error) {
	return backupSecretFile(v, path)
}

// backupOnce backs up path exactly once for the tracker's run: the first call
// for a given path calls backupSecretFile (storing the pristine bytes and
// recording the undo index entry) and caches the result; later calls for the
// same path return that first vault path without reading or re-storing the
// now-modified file. A nil tracker always backs up — see BackupTracker's doc.
func (t *BackupTracker) backupOnce(v *vault.Vault, path string) (string, error) {
	if t == nil {
		return backupSecretFile(v, path)
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolving %s: %w", path, err)
	}
	if vp, ok := t.backups[absPath]; ok {
		return vp, nil
	}
	vp, err := backupSecretFile(v, path)
	if err != nil {
		return "", err
	}
	t.backups[absPath] = vp
	return vp, nil
}

// alreadyHandled reports whether an earlier unit in this run already gave
// path a disposition — either backed it up (backupOnce) or created it fresh
// (markCreated). A later unit that sees true must not add a second undo-index
// entry for the same path. Always false for a nil tracker.
func (t *BackupTracker) alreadyHandled(path string) bool {
	if t == nil {
		return false
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	if _, ok := t.backups[absPath]; ok {
		return true
	}
	return t.created[absPath]
}

// markCreated records that this run created path fresh (a RemoveOnRestore
// undo record was written for it), so a later unit sharing the same file
// neither backs it up nor records it created again. No-op for a nil tracker.
func (t *BackupTracker) markCreated(path string) {
	if t == nil {
		return
	}
	if absPath, err := filepath.Abs(path); err == nil {
		t.created[absPath] = true
	}
}
