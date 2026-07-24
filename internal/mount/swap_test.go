// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package mount

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func isFIFO(t *testing.T, path string) bool {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat %s: %v", path, err)
	}
	return info.Mode()&os.ModeNamedPipe != 0
}

func TestSwapPointerContentIsInertButComplete(t *testing.T) {
	content := SwapPointerContent([]string{"DB_URL", "API_KEY"}, []string{"API_KEY", "DB_URL"})
	s := string(content)

	// Provenance marker first, so IsSwapPointerFile and crash reconciliation
	// recognize it.
	if !strings.HasPrefix(s, swapMarkerPrefix) {
		t.Errorf("content must start with the swap marker, got: %q", s[:min(len(s), 60)])
	}
	// Every line a comment: sourcing must set nothing.
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			t.Errorf("non-comment line would be parseable by a loader: %q", line)
		}
	}
	// Order honored: API_KEY before DB_URL per the order slice.
	if !strings.Contains(s, "API_KEY") || strings.Index(s, "API_KEY") > strings.Index(s, "DB_URL") {
		t.Errorf("variable order not honored:\n%s", s)
	}
}

// TestSwapPointerContentSourcesToNothing is the inertness guarantee against
// a real shell — the clobber trap's structural fix.
func TestSwapPointerContentSourcesToNothing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, SwapPointerContent([]string{"API_KEY"}, nil), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	out, err := exec.Command("/bin/sh", "-c",
		"set -a; . "+path+"; set +a; echo \"API_KEY=[${API_KEY:-<unset>}]\"; [ -f "+path+" ] && echo FILE_OK").CombinedOutput()
	if err != nil {
		t.Fatalf("sh: %v (%s)", err, out)
	}
	got := string(out)
	if !strings.Contains(got, "API_KEY=[<unset>]") {
		t.Errorf("sourcing the swap file set a variable, clobber path still open: %q", got)
	}
	if !strings.Contains(got, "FILE_OK") {
		t.Errorf("swap file did not pass [ -f ]: %q", got)
	}
}

func TestSwapToPointerReplacesFIFOWithRegularFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := CreateFIFO(path); err != nil {
		t.Fatalf("CreateFIFO: %v", err)
	}
	content := SwapPointerContent([]string{"API_KEY"}, nil)
	if err := SwapToPointer(path, content); err != nil {
		t.Fatalf("SwapToPointer: %v", err)
	}
	if isFIFO(t, path) {
		t.Fatal("path is still a FIFO after SwapToPointer")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("swapped file content = %q, want the pointer content", got)
	}
	// No temp/sibling artifacts left behind.
	for _, suffix := range []string{".jit-swap-prev", ".jit-swap-tmp"} {
		if _, err := os.Lstat(path + suffix); !os.IsNotExist(err) {
			t.Errorf("leftover %s after swap", suffix)
		}
	}
}

func TestSwapToPointerIsNoOpOnNonFIFO(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte("original\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := SwapToPointer(path, []byte("would-overwrite")); err != nil {
		t.Fatalf("SwapToPointer on a regular file should be a no-op, got: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "original\n" {
		t.Errorf("SwapToPointer clobbered a non-FIFO file: %q", got)
	}
}

// TestSwapToPointerReleasesBlockedReader is the spike's core finding: a
// reader parked in open() on the FIFO at the swap instant must be released
// (and get the pointer content), not stranded — the property plain atomic
// rename-over loses.
func TestSwapToPointerReleasesBlockedReader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := CreateFIFO(path); err != nil {
		t.Fatalf("CreateFIFO: %v", err)
	}

	reader := exec.Command("/bin/cat", path)
	out := &syncBuffer{}
	reader.Stdout = out
	if err := reader.Start(); err != nil {
		t.Fatalf("start reader: %v", err)
	}
	time.Sleep(150 * time.Millisecond) // parked in open(), no writer yet

	released := make(chan struct{})
	go func() { _ = reader.Wait(); close(released) }()

	content := SwapPointerContent([]string{"API_KEY"}, nil)
	if err := SwapToPointer(path, content); err != nil {
		t.Fatalf("SwapToPointer: %v", err)
	}

	select {
	case <-released:
		if !strings.Contains(out.String(), swapMarkerPrefix) {
			t.Errorf("rescued reader got %q, want the pointer content", out.String())
		}
	case <-time.After(3 * time.Second):
		_ = reader.Process.Kill()
		t.Fatal("reader blocked in open() was stranded across the swap")
	}
}

// TestSwapRoundTripNeverLeavesPathAbsent runs a concurrent stat storm across
// repeated swap/restore cycles: a `[ -f ]` at any instant must see either a
// FIFO or a regular file, never nothing (the intermittent-guard-failure
// window the aside-then-write ordering suffers).
func TestSwapRoundTripNeverLeavesPathAbsent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := CreateFIFO(path); err != nil {
		t.Fatalf("CreateFIFO: %v", err)
	}
	content := SwapPointerContent([]string{"API_KEY"}, nil)

	var absent int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := os.Lstat(path); os.IsNotExist(err) {
				atomic.AddInt64(&absent, 1)
			}
		}
	}()

	for i := 0; i < 200; i++ {
		if err := SwapToPointer(path, content); err != nil {
			t.Fatalf("SwapToPointer iter %d: %v", i, err)
		}
		if err := RestoreFIFO(path); err != nil {
			t.Fatalf("RestoreFIFO iter %d: %v", i, err)
		}
	}
	close(stop)
	wg.Wait()
	if absent != 0 {
		t.Errorf("path was absent in %d samples — intermittent guard-failure window", absent)
	}
	if !isFIFO(t, path) {
		t.Error("path is not a FIFO after the final restore")
	}
}

func TestRestoreFIFOFromPointerAndFreshPath(t *testing.T) {
	dir := t.TempDir()

	// From a regular file.
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, SwapPointerContent([]string{"K"}, nil), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := RestoreFIFO(path); err != nil {
		t.Fatalf("RestoreFIFO from file: %v", err)
	}
	if !isFIFO(t, path) {
		t.Error("RestoreFIFO did not produce a FIFO from a regular file")
	}

	// From nothing.
	fresh := filepath.Join(dir, "fresh.env")
	if err := RestoreFIFO(fresh); err != nil {
		t.Fatalf("RestoreFIFO on fresh path: %v", err)
	}
	if !isFIFO(t, fresh) {
		t.Error("RestoreFIFO did not create a FIFO on a fresh path")
	}

	// Idempotent on an existing FIFO.
	if err := RestoreFIFO(fresh); err != nil {
		t.Fatalf("RestoreFIFO on existing FIFO should be a no-op: %v", err)
	}
	if !isFIFO(t, fresh) {
		t.Error("RestoreFIFO removed an existing FIFO")
	}
}

func TestIsSwapPointerFileProvenance(t *testing.T) {
	dir := t.TempDir()

	// jit's own swap artifact.
	jit := filepath.Join(dir, "a.env")
	if err := os.WriteFile(jit, SwapPointerContent([]string{"K"}, nil), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if !IsSwapPointerFile(jit) {
		t.Error("jit's own swap file not recognized")
	}

	// A user's hand-restored file must NOT be recognized (never clobbered).
	user := filepath.Join(dir, "b.env")
	if err := os.WriteFile(user, []byte("API_KEY=user_restored\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if IsSwapPointerFile(user) {
		t.Error("a user's file was misidentified as jit's swap artifact — would be clobbered")
	}

	// A FIFO is not a pointer file; a missing path is not either.
	fifo := filepath.Join(dir, "c.env")
	if err := CreateFIFO(fifo); err != nil {
		t.Fatalf("CreateFIFO: %v", err)
	}
	if IsSwapPointerFile(fifo) {
		t.Error("a FIFO was misidentified as a swap pointer file")
	}
	if IsSwapPointerFile(filepath.Join(dir, "nope.env")) {
		t.Error("a missing path was misidentified as a swap pointer file")
	}
}

// syncBuffer is a minimal concurrency-safe writer for capturing a child's
// stdout from its own goroutine.
type syncBuffer struct {
	mu sync.Mutex
	b  []byte
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.b = append(s.b, p...)
	return len(p), nil
}
func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return string(s.b)
}
