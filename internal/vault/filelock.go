// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package vault

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// WithFileLock runs fn while holding an exclusive advisory lock covering path,
// serializing the read-modify-write cycles that jit's shared state files are
// updated through.
//
// It exists because those cycles had nothing guarding them at all. Both the
// mount registry (mounts.yaml) and the undo index (backups.yaml) are updated by
// load-all → append-or-filter → write-all, from short-lived CLI processes that
// run concurrently by design — a `jit migrate` performs eight registry updates
// in one run while the agent reads the same file, and parallel sessions sharing
// one working tree are an ordinary way to use this tool. Two overlapping
// updates lost one of them: for the registry that silently unregisters a mount,
// and for the undo index it orphans a backup, leaving the plaintext file jit
// just rewrote recoverable only by hand through `jit vault get`.
//
// AtomicWriteFile is the other half and does NOT subsume this one. It stops a
// reader ever seeing a torn or truncated file — which is what made a
// half-written registry able to hang every reader of every mount — but two
// well-formed writes still overwrite each other. Atomicity is about what a
// reader observes; this is about not losing a writer.
//
// The lock is held on a sidecar file rather than on the target: the target is
// replaced by rename on every write, so a lock taken on it would be a lock on
// an unlinked inode the moment the first writer finished. Advisory and
// same-machine only, which is exactly the scope of the problem — every writer
// is a jit process on this machine.
func WithFileLock(path string, fn func() error) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	lockPath := filepath.Join(dir, "."+filepath.Base(path)+".lock")

	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- derived from jit's own state-file path, never external input
	if err != nil {
		return fmt.Errorf("opening lock %s: %w", lockPath, err)
	}
	defer func() { _ = f.Close() }()

	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("locking %s: %w", lockPath, err)
	}
	// Unlock explicitly rather than relying on the close above: the ordering
	// matters if this ever grows a path that keeps the descriptor.
	defer func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN) }()

	// The lock file is deliberately never removed. Unlinking it would let a
	// waiter that already opened the old inode hold a lock on a file nobody
	// else can reach any more, which is worse than one empty 0600 sidecar.
	return fn()
}
