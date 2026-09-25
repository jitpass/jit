// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// Package atomicfile is jit's one atomic, durable file write, with no
// dependency beyond the standard library, so that any package can use it
// without importing what it lives beside. internal/vault wraps it as
// vault.AtomicWriteFile; internal/job and internal/agent use it directly,
// because the agent never imports internal/vault (agent/doc.go).
package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteFile writes data to a temp file in dest's directory, fsyncs it, then
// renames it into place, and fsyncs the directory: a reader never observes a
// partially-written file, and a crash or power loss mid-write leaves the old
// version (or nothing) rather than a corrupt one. The fsync before the
// rename matters: without it, the rename can be durable while the data
// isn't, so a power cut could leave a correctly-named empty or truncated
// file, the one outcome atomicity was supposed to rule out.
//
// The temp file is created exclusively under a fresh random name
// (os.CreateTemp: O_EXCL), so a leftover temp, or a symlink planted where
// one would go, is never written through. The result is mode 0600.
func WriteFile(dest string, data []byte) error {
	dir := filepath.Dir(dest)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	// If anything below fails before the rename, clean up the temp file
	// rather than leaving it behind.
	success := false
	defer func() {
		if !success {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("setting permissions on %s: %w", tmpPath, err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing %s: %w", tmpPath, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("syncing %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, dest); err != nil {
		return fmt.Errorf("renaming %s to %s: %w", tmpPath, dest, err)
	}
	success = true
	// Fsync the directory too, so the rename itself survives power loss.
	// Best-effort: some filesystems don't support fsync on a directory,
	// and the data-before-rename ordering above already holds without it.
	SyncDir(dir)
	return nil
}

// SyncDir best-effort fsyncs a directory so a rename into it survives power
// loss: the durability tail of WriteFile, for a caller that renames an
// already-synced file itself.
func SyncDir(dir string) {
	if d, err := os.Open(dir); err == nil { // #nosec G304 -- a parent directory of jit's own files, not external input
		_ = d.Sync()
		_ = d.Close()
	}
}
