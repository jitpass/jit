// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package mount

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestRetireFIFOReleasesReaderBlockedInOpen is GAPS.md #57's regression
// test: a reader blocked in open(2) on a mount's pipe at the instant
// unmount/undo replaced it used to wait forever on the unlinked vnode —
// the on-disk restore succeeded while the reader (a VS Code tab, in the
// real incident) hung on an empty read that never returned. The retire
// release must complete that reader's rendezvous and hand it the
// replacement content.
func TestRetireFIFOReleasesReaderBlockedInOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := CreateFIFO(path); err != nil {
		t.Fatalf("CreateFIFO: %v", err)
	}

	type readResult struct {
		data []byte
		err  error
	}
	got := make(chan readResult, 1)
	go func() {
		f, err := os.OpenFile(path, os.O_RDONLY, 0) // #nosec G304 -- test-controlled path
		if err != nil {
			got <- readResult{nil, err}
			return
		}
		data, err := io.ReadAll(f)
		_ = f.Close()
		got <- readResult{data, err}
	}()

	// Let the reader reach its blocking open(2). There's no portable way
	// to observe "blocked in open" (it holds no fd yet — the incident's
	// own lsof came up empty for the same reason), so a settle sleep is
	// the honest option.
	time.Sleep(100 * time.Millisecond)

	release, err := RetireFIFO(path)
	if err != nil {
		t.Fatalf("RetireFIFO: %v", err)
	}
	replacement := []byte("API_KEY=restored\n")
	if err := os.WriteFile(path, replacement, 0o600); err != nil {
		t.Fatalf("writing replacement: %v", err)
	}
	if err := release(replacement); err != nil {
		t.Fatalf("release: %v", err)
	}

	select {
	case r := <-got:
		if r.err != nil {
			t.Fatalf("rescued reader errored: %v", r.err)
		}
		if string(r.data) != string(replacement) {
			t.Errorf("rescued reader got %q, want the replacement content %q", r.data, replacement)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reader is still blocked after release, the stranded-open rescue didn't fire")
	}

	if _, err := os.Lstat(path + ".jit-prev"); !os.IsNotExist(err) {
		t.Errorf("retired pipe %s.jit-prev still exists after release (lstat err: %v)", path, err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		t.Errorf("path should be a regular file after the swap (mode %v, err %v)", info.Mode(), err)
	}
}

// No reader waiting: release must quietly remove the retired pipe and
// report nothing — the common case for every unmount on a quiet machine.
func TestRetireFIFONoBlockedReader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := CreateFIFO(path); err != nil {
		t.Fatalf("CreateFIFO: %v", err)
	}

	release, err := RetireFIFO(path)
	if err != nil {
		t.Fatalf("RetireFIFO: %v", err)
	}
	if err := release([]byte("X=1\n")); err != nil {
		t.Fatalf("release with no reader: %v", err)
	}
	if _, err := os.Lstat(path + ".jit-prev"); !os.IsNotExist(err) {
		t.Errorf("retired pipe should be removed even with no reader (lstat err: %v)", err)
	}
}

// A regular file (or nothing) at the path is the non-mount case — plain
// removal, no-op release, so callers can use RetireFIFO unconditionally in
// place of os.Remove.
func TestRetireFIFONonPipeOccupants(t *testing.T) {
	dir := t.TempDir()

	regular := filepath.Join(dir, "config")
	if err := os.WriteFile(regular, []byte("old"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	release, err := RetireFIFO(regular)
	if err != nil {
		t.Fatalf("RetireFIFO(regular file): %v", err)
	}
	if _, err := os.Lstat(regular); !os.IsNotExist(err) {
		t.Errorf("regular file should be removed (lstat err: %v)", err)
	}
	if err := release(nil); err != nil {
		t.Errorf("no-op release errored: %v", err)
	}

	missing := filepath.Join(dir, "never-existed")
	release, err = RetireFIFO(missing)
	if err != nil {
		t.Fatalf("RetireFIFO(missing): %v", err)
	}
	if err := release(nil); err != nil {
		t.Errorf("no-op release errored: %v", err)
	}
}
