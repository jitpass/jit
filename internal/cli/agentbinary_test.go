// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func writeBinary(t *testing.T, path, content string) {
	t.Helper()
	// Temp + rename, the same near-atomic swap `go build` performs — a new
	// inode every time, which is the primary signal the watcher keys on.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o755); err != nil { // #nosec G306 -- stand-in for an executable
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatalf("Rename: %v", err)
	}
}

func TestWatchOwnBinaryRestartsOnlyOnceQuiescentAndSteady(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jit")
	writeBinary(t, path, "build one")

	var quiescent atomic.Bool // starts false: session "unlocked"
	var restarts atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		watchOwnBinary(ctx, path, 10*time.Millisecond, quiescent.Load, func() {
			restarts.Add(1)
		})
	}()

	// Unchanged binary: no restart no matter how long it watches.
	time.Sleep(100 * time.Millisecond)
	if got := restarts.Load(); got != 0 {
		t.Fatalf("watcher restarted %d times with the binary unchanged", got)
	}

	// Replaced binary, but the session is live (not quiescent): still no
	// restart — a live session or an on-screen prompt must never be killed
	// for a rebuild.
	writeBinary(t, path, "build two, longer content")
	time.Sleep(150 * time.Millisecond)
	if got := restarts.Load(); got != 0 {
		t.Fatalf("watcher restarted %d times while not quiescent, it killed a live session for a rebuild", got)
	}

	// Session locks: now (and only now) the pending change may fire, once.
	quiescent.Store(true)
	deadline := time.Now().Add(2 * time.Second)
	for restarts.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := restarts.Load(); got != 1 {
		t.Fatalf("restarts = %d after quiescence, want exactly 1", got)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watcher kept running after calling restart")
	}
}

func TestWatchOwnBinaryIgnoresAVanishedBinary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jit")
	writeBinary(t, path, "build one")

	var restarts atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watchOwnBinary(ctx, path, 10*time.Millisecond, func() bool { return true }, func() {
		restarts.Add(1)
	})
	// Let the watcher capture its starting fingerprint before the file
	// vanishes — in production the binary trivially exists at agent start.
	time.Sleep(50 * time.Millisecond)

	// Deleted outright (not replaced): exiting would leave launchd
	// respawn-looping a nonexistent program.
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	if got := restarts.Load(); got != 0 {
		t.Fatalf("watcher restarted %d times onto a DELETED binary", got)
	}

	// The binary coming back (a slow reinstall) with new content is a real
	// change and may restart.
	writeBinary(t, path, "build two after reinstall")
	deadline := time.Now().Add(2 * time.Second)
	for restarts.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := restarts.Load(); got != 1 {
		t.Fatalf("restarts = %d after the binary came back changed, want 1", got)
	}
}
