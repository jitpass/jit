// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package lineage

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestIdentifyFIFOReaderFindsRealReader mirrors
// spike/fifo-reader-identify/'s manual verification, automated: a real
// reader process (not this test's own PID) opens the FIFO for read, and
// IdentifyFIFOReader must report its exact PID. No Touch ID/interactive
// approval is needed for this path, unlike most darwin-gated packages
// here, so this can run fully automated in CI.
func TestIdentifyFIFOReaderFindsRealReader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.fifo")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}

	// `sleep` opens no files, so run a tiny reader via `cat` in the
	// background — it blocks on read() until something writes, giving a
	// stable window during which it holds the FIFO open for read.
	cmd := exec.Command("cat", path)
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting reader: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	// Open for write ourselves — blocks until cat's read-open completes,
	// exactly like internal/mount.Serve's own openForWriteOrCancel.
	opened := make(chan *os.File, 1)
	openErr := make(chan error, 1)
	go func() {
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			openErr <- err
			return
		}
		opened <- f
	}()

	var f *os.File
	select {
	case f = <-opened:
	case err := <-openErr:
		t.Fatalf("opening for write: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for reader to connect")
	}
	defer f.Close()

	pid, execPath, ok := IdentifyFIFOReader(path)
	if !ok {
		t.Fatal("IdentifyFIFOReader did not find the connected reader")
	}
	if pid != int32(cmd.Process.Pid) {
		t.Errorf("identified pid = %d, want %d (the real reader)", pid, cmd.Process.Pid)
	}
	if execPath == "" {
		t.Error("execPath is empty, want cat's resolved executable path")
	}

	_, _ = f.Write([]byte("done\n"))
}

// TestIdentifyFIFOReaderNoReaderPresent confirms the "nothing found" path
// doesn't false-positive when no one has the FIFO open at all.
func TestIdentifyFIFOReaderNoReaderPresent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.fifo")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}

	_, _, ok := IdentifyFIFOReader(path)
	if ok {
		t.Error("expected no reader identified — nothing has the FIFO open")
	}
}

// TestIdentifyFIFOReaderPermissionBoundary is a smoke test that scanning
// doesn't crash or hang when the process table includes PIDs jit can't
// introspect (root/other-user processes) — the errno tally in
// spike/fifo-reader-identify/FINDINGS.md confirmed these fail closed
// (EPERM), not that the whole scan aborts.
func TestIdentifyFIFOReaderPermissionBoundary(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root defeats the point of this test")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "test.fifo")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = IdentifyFIFOReader(path)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("scan hung — likely blocked on a permission-restricted process instead of failing that one lookup and continuing")
	}
}

// TestPathHeldOpenSeesRealHolderAndItsAbsence is the safety property the
// GAPS.md #47 reuse decision rests on: a process still holding an fd on
// the FIFO must be seen (held=true → internal/mount isolates), and a FIFO
// nobody holds must come back held=false (→ safe reuse, no rename event
// for a file watcher to chew on). Uses a real separate process (`cat`),
// same as TestIdentifyFIFOReaderFindsRealReader — a same-process reader
// would also be seen (PathHeldOpen deliberately includes our own pid),
// but the separate process is the case that matters.
func TestPathHeldOpenSeesRealHolderAndItsAbsence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.fifo")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}

	if PathHeldOpen(path) {
		t.Fatal("PathHeldOpen = true on a FIFO nobody has opened — false holders would make the reuse path unreachable and the watcher loop unfixable")
	}

	cmd := exec.Command("cat", path)
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting holder: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	// cat blocks in open() until a writer appears — and a blocked open
	// holds no fd yet, which is exactly the state PathHeldOpen must NOT
	// count (a blocked opener rendezvouses safely with the next serve
	// cycle on a reused pipe). Connect a writer so cat's open completes
	// and it genuinely holds the read fd.
	opened := make(chan *os.File, 1)
	openErr := make(chan error, 1)
	go func() {
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			openErr <- err
			return
		}
		opened <- f
	}()
	var f *os.File
	select {
	case f = <-opened:
	case err := <-openErr:
		t.Fatalf("opening for write: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the holder to connect")
	}

	if !PathHeldOpen(path) {
		t.Error("PathHeldOpen = false while cat provably holds the FIFO's read end — a missed holder means reuse against a lingering reader")
	}

	// Release cat (EOF) and let it exit; the FIFO must read as free again.
	_ = f.Close()
	_ = cmd.Wait()
	if PathHeldOpen(path) {
		t.Error("PathHeldOpen = true after the holder exited")
	}
}
