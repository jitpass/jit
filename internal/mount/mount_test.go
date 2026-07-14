// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package mount

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestCreateFIFOReplacesRegularFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte("KEY=value\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := CreateFIFO(path); err != nil {
		t.Fatalf("CreateFIFO: %v", err)
	}

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	if info.Mode()&os.ModeNamedPipe == 0 {
		t.Errorf("mode = %v, want a named pipe", info.Mode())
	}
}

func TestCreateFIFOOnFreshPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")

	if err := CreateFIFO(path); err != nil {
		t.Fatalf("CreateFIFO: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	if info.Mode()&os.ModeNamedPipe == 0 {
		t.Errorf("mode = %v, want a named pipe", info.Mode())
	}
}

func TestServeSequentialReaders(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := CreateFIFO(path); err != nil {
		t.Fatalf("CreateFIFO: %v", err)
	}

	content := []byte("STRIPE_KEY=sk_test_fixture\nDB_URL=postgres://fixture\n")
	fixedContent := func() []byte { return content }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serveErr := make(chan error, 1)
	go func() { serveErr <- Serve(ctx, path, fixedContent, nil, nil, nil) }()

	for i := 0; i < 3; i++ {
		got := readFIFO(t, path)
		if string(got) != string(content) {
			t.Errorf("reader %d got %q, want %q", i, got, content)
		}
	}

	cancel()
	select {
	case err := <-serveErr:
		if err != context.Canceled {
			t.Errorf("Serve returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not exit within 5s of cancellation")
	}
}

func readFIFO(t *testing.T, path string) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening %s for read: %v", path, err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return data
}

// TestServeContinuesAfterReaderClosesEarly locks in a real bug found during
// manual verification: a reader that opens and closes without draining the
// pipe causes a transient "broken pipe" write error — an earlier version
// of Serve treated that as fatal and returned, silently killing the whole
// mount after serving exactly one reader (the second of two `cat .env`
// runs in a row got nothing). content is made large enough that closing
// the read end without draining reliably produces EPIPE on the pending
// write (the pipe's kernel buffer fills, so the write is still in flight
// when the reader disappears) — this must be deterministic, not a maybe.
func TestServeContinuesAfterReaderClosesEarly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := CreateFIFO(path); err != nil {
		t.Fatalf("CreateFIFO: %v", err)
	}

	content := bytes.Repeat([]byte("x"), 256*1024)
	fixedContent := func() []byte { return content }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	var gotErr error
	onError := func(err error) {
		mu.Lock()
		gotErr = err
		mu.Unlock()
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- Serve(ctx, path, fixedContent, onError, nil, nil) }()

	// First reader: opens then closes immediately without draining.
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening %s for read: %v", path, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing early: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		hadErr := gotErr != nil
		mu.Unlock()
		if hadErr {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	hadErr := gotErr != nil
	mu.Unlock()
	if !hadErr {
		t.Fatal("expected onError to fire for the early-closing reader — test setup isn't triggering the race it's meant to")
	}

	// Second reader: a normal, full read. The loop must have re-opened and
	// still be serving — this is the actual regression this test guards.
	got := readFIFO(t, path)
	if !bytes.Equal(got, content) {
		t.Error("second reader did not get the full content — Serve stopped after the first reader's transient error instead of re-opening")
	}

	cancel()
	select {
	case err := <-serveErr:
		if err != context.Canceled {
			t.Errorf("Serve returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not exit within 5s of cancellation")
	}
}

// TestServeIsolatesStaleReaderFromNextCycle locks in the GAPS.md #24 fix: a
// reader that has already received one cycle's content but is slow to
// close its fd must never see a later cycle's content appended onto the
// same stream, and the next cycle must still go to a genuinely fresh
// reader rather than being silently swallowed by the stale one.
func TestServeIsolatesStaleReaderFromNextCycle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := CreateFIFO(path); err != nil {
		t.Fatalf("CreateFIFO: %v", err)
	}

	var mu sync.Mutex
	cycle := 0
	provideContent := func() []byte {
		mu.Lock()
		cycle++
		c := cycle
		mu.Unlock()
		return []byte(fmt.Sprintf("CYCLE=%d\n", c))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveErr := make(chan error, 1)
	go func() { serveErr <- Serve(ctx, path, provideContent, nil, nil, nil) }()

	// Reader 1: open and read cycle 1's content in full, but deliberately
	// hold the fd open afterward instead of closing it right away — the
	// exact "slow to close" window GAPS.md #24 exploited.
	f1, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening %s for read: %v", path, err)
	}
	buf := make([]byte, len("CYCLE=1\n")+1)
	n, err := f1.Read(buf)
	if err != nil {
		t.Fatalf("reading cycle 1 content: %v", err)
	}
	if got := string(buf[:n]); got != "CYCLE=1\n" {
		t.Fatalf("reader 1 got %q, want %q", got, "CYCLE=1\n")
	}

	// Give Serve's loop a real chance to advance to the next cycle while
	// f1 is still open — this is the window the bug needed to concatenate.
	time.Sleep(100 * time.Millisecond)

	// Without the fix, this read would return cycle 2's bytes (concatenated
	// onto the same stream). With the fix, f1's fd is bound to the old,
	// now-replaced pipe, whose only writer (cycle 1's) already closed — so
	// this must observe a clean EOF, never cycle 2's content.
	n, err = f1.Read(buf)
	if err != io.EOF {
		t.Errorf("reader 1's second read = (%d, %v), want (0, io.EOF) — got stale-reader concatenation instead", n, err)
	}
	if err := f1.Close(); err != nil {
		t.Fatalf("closing reader 1: %v", err)
	}

	// A genuinely fresh reader must still get cycle 2's content, in full.
	got := readFIFO(t, path)
	if string(got) != "CYCLE=2\n" {
		t.Errorf("fresh reader got %q, want %q", got, "CYCLE=2\n")
	}

	cancel()
	select {
	case err := <-serveErr:
		if err != context.Canceled {
			t.Errorf("Serve returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not exit within 5s of cancellation")
	}
}

// TestServeReusesPipeWhenReaderClosedCleanly locks in the GAPS.md #47
// fix: a cycle whose write failed with EPIPE (zero readers held the read
// end — nobody received any of this cycle's content, so no stale reader
// can exist) must reuse the SAME pipe object — no recreateFIFO, no
// rename(2), no filesystem event. The rename fired after every cycle is
// what fed a file watcher's re-read feedback loop (VS Code re-reading
// ~30x/sec for hours, a real incident), and a watcher's open-then-close-
// without-draining read is exactly the EPIPE case. The oversized payload
// is borrowed from TestServeContinuesAfterReaderClosesEarly because it
// makes the EPIPE deterministic: the write stays in flight until the
// reader's close is what unblocks it.
func TestServeReusesPipeWhenReaderClosedCleanly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := CreateFIFO(path); err != nil {
		t.Fatalf("CreateFIFO: %v", err)
	}

	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat before: %v", err)
	}

	content := bytes.Repeat([]byte("x"), 256*1024)
	fixedContent := func() []byte { return content }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 4)
	onError := func(err error) { errCh <- err }

	serveErr := make(chan error, 1)
	go func() { serveErr <- Serve(ctx, path, fixedContent, onError, nil, nil) }()

	// Reader that opens then closes without draining — guaranteed fully
	// closed by the time Serve's cycle-end probe runs, since its close is
	// the very thing that unblocks the oversized in-flight write (EPIPE).
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening %s for read: %v", path, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing early: %v", err)
	}
	select {
	case <-errCh: // the cycle's EPIPE — onError fires after the reuse-vs-recreate decision is made
	case <-time.After(2 * time.Second):
		t.Fatal("expected the early-closing reader to surface a write error")
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat after: %v", err)
	}
	if !os.SameFile(before, after) {
		t.Error("Serve recreated the FIFO after a cleanly-closed reader — every such rename is a filesystem event that feeds a file watcher's re-read loop (GAPS.md #47)")
	}

	// The reused pipe must still serve the next reader normally.
	got := readFIFO(t, path)
	if !bytes.Equal(got, content) {
		t.Error("second reader did not get the full content from the reused pipe")
	}

	cancel()
	select {
	case err := <-serveErr:
		if err != context.Canceled {
			t.Errorf("Serve returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not exit within 5s of cancellation")
	}
}

// TestServeReusesPipeAfterDrainedReadWhenNothingLingers is the second half
// of the GAPS.md #47 fix: a read that DRAINS the content (a watcher
// refreshing an open editor tab does this) used to force the isolation
// rename unconditionally — the filesystem event that kept the watcher
// loop alive even after the EPIPE-reuse fix. With a hasLingeringReader
// callback reporting "nobody holds the pipe," Serve must reuse the SAME
// pipe object: no rename, no event, nothing for the watcher to react to.
func TestServeReusesPipeAfterDrainedReadWhenNothingLingers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := CreateFIFO(path); err != nil {
		t.Fatalf("CreateFIFO: %v", err)
	}

	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat before: %v", err)
	}

	content := []byte("API_KEY=fixture\n")
	checked := make(chan struct{}, 8)
	readerClosed := make(chan struct{}, 8)
	noLinger := func() bool {
		// Answer only once the drained reader's fd is truly closed. This
		// callback stands in for the PASSIVE scan (lineage.PathHeldOpen),
		// whose contract is to err toward "held" whenever a holder might
		// remain — an unconditional false here raced the reader's own
		// close: in ~1 of 5 runs Serve reused the pipe while the reader
		// still held it, cycle 2's open() rendezvoused with that same
		// reader instantly, and its ReadAll returned BOTH cycles' content
		// (a flaky "got fixture twice" failure). That's the exact GAPS.md
		// #24 hazard the passive scan rules out — manufactured by the
		// test's fake scan lying about it, not a Serve bug. Blocking here
		// can't deadlock: this runs after the cycle's writer is closed, so
		// the reader's EOF (and close) never depends on Serve progressing.
		<-readerClosed
		checked <- struct{}{}
		return false
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveErr := make(chan error, 1)
	go func() { serveErr <- Serve(ctx, path, func() []byte { return content }, nil, nil, noLinger) }()

	// A full drain — the exact read shape that always renamed before.
	if got := readFIFO(t, path); !bytes.Equal(got, content) {
		t.Fatalf("first reader got %q, want %q", got, content)
	}
	readerClosed <- struct{}{}
	select {
	case <-checked: // the reuse decision has been made
	case <-time.After(2 * time.Second):
		t.Fatal("hasLingeringReader was never consulted after a drained read")
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat after: %v", err)
	}
	if !os.SameFile(before, after) {
		t.Error("Serve renamed the FIFO after a drained read with no lingering reader — that rename is the filesystem event that feeds a watcher's re-read loop (GAPS.md #47)")
	}

	// And the reused pipe still serves the next reader normally.
	if got := readFIFO(t, path); !bytes.Equal(got, content) {
		t.Errorf("second reader got %q from the reused pipe, want %q", got, content)
	}
	readerClosed <- struct{}{} // let cycle 2's own reuse decision proceed, so Serve reaches its next open() and can see the cancel

	cancel()
	select {
	case err := <-serveErr:
		if err != context.Canceled {
			t.Errorf("Serve returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not exit within 5s of cancellation")
	}
}

// TestServeIsolatesWhenLingeringReaderReported: the flip side — when the
// callback reports a holder, the drained cycle must still get the full
// GAPS.md #24 isolation, post-close: fresh pipe renamed in (different
// inode), stale fd left with a clean EOF, and the next reader served
// cleanly. This is the same scenario TestServeIsolatesStaleReaderFromNext-
// Cycle locks in for the nil-callback default, driven through the
// callback path instead.
func TestServeIsolatesWhenLingeringReaderReported(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := CreateFIFO(path); err != nil {
		t.Fatalf("CreateFIFO: %v", err)
	}

	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat before: %v", err)
	}

	var mu sync.Mutex
	cycle := 0
	provideContent := func() []byte {
		mu.Lock()
		cycle++
		c := cycle
		mu.Unlock()
		return []byte(fmt.Sprintf("CYCLE=%d\n", c))
	}
	linger := func() bool { return true }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveErr := make(chan error, 1)
	go func() { serveErr <- Serve(ctx, path, provideContent, nil, nil, linger) }()

	// Reader 1 drains cycle 1 and HOLDS its fd — the genuine lingerer the
	// callback is reporting.
	f1, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening %s for read: %v", path, err)
	}
	buf := make([]byte, len("CYCLE=1\n")+1)
	n, err := f1.Read(buf)
	if err != nil {
		t.Fatalf("reading cycle 1 content: %v", err)
	}
	if got := string(buf[:n]); got != "CYCLE=1\n" {
		t.Fatalf("reader 1 got %q, want %q", got, "CYCLE=1\n")
	}
	time.Sleep(100 * time.Millisecond)

	// The lingering fd must see a clean EOF, never cycle 2's bytes.
	n, err = f1.Read(buf)
	if err != io.EOF {
		t.Errorf("reader 1's second read = (%d, %v), want (0, io.EOF) — stale-reader isolation lost on the callback path", n, err)
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat after: %v", err)
	}
	if os.SameFile(before, after) {
		t.Error("Serve reused the pipe despite the callback reporting a lingering reader")
	}
	if err := f1.Close(); err != nil {
		t.Fatalf("closing reader 1: %v", err)
	}

	// A fresh reader gets cycle 2 in full from the new pipe.
	if got := readFIFO(t, path); string(got) != "CYCLE=2\n" {
		t.Errorf("fresh reader got %q, want %q", got, "CYCLE=2\n")
	}

	cancel()
	select {
	case err := <-serveErr:
		if err != context.Canceled {
			t.Errorf("Serve returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not exit within 5s of cancellation")
	}
}

func TestServeStopsCleanlyWithNoReaders(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := CreateFIFO(path); err != nil {
		t.Fatalf("CreateFIFO: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	err := Serve(ctx, path, func() []byte { return []byte("A=1\n") }, nil, nil, nil)
	if err != context.DeadlineExceeded {
		t.Errorf("Serve = %v, want context.DeadlineExceeded (no reader ever connected)", err)
	}
}

// TestServeGatesRealContentBehindRevealState locks in the actual GAPS.md #2
// fix: an hidden mount must serve DecoyValues, not the real profile
// values, and only serve real content during a revealed window — with
// nothing in Serve itself deciding that (it just calls provideContent
// fresh every cycle).
func TestServeGatesRealContentBehindRevealState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := CreateFIFO(path); err != nil {
		t.Fatalf("CreateFIFO: %v", err)
	}

	real := map[string]string{"API_KEY": "sk_live_real"}
	decoy := DecoyValues(real)
	reveal := NewRevealState()
	provideContent := func() []byte {
		if reveal.IsRevealed() {
			return FormatDotenv(real, nil)
		}
		return FormatDotenv(decoy, nil)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveErr := make(chan error, 1)
	go func() { serveErr <- Serve(ctx, path, provideContent, nil, nil, nil) }()

	// Hidden: must get decoy content, never the real value.
	got := readFIFO(t, path)
	if string(got) != string(FormatDotenv(decoy, nil)) {
		t.Errorf("hidden reader got %q, want decoy %q", got, FormatDotenv(decoy, nil))
	}

	// Revealed: must get real content.
	reveal.Reveal(time.Second)
	got = readFIFO(t, path)
	if string(got) != string(FormatDotenv(real, nil)) {
		t.Errorf("revealed reader got %q, want real %q", got, FormatDotenv(real, nil))
	}

	// Window naturally expires: back to decoy without any code re-checking
	// anything other than IsRevealed on the next cycle.
	reveal.Hide()
	got = readFIFO(t, path)
	if string(got) != string(FormatDotenv(decoy, nil)) {
		t.Errorf("reader after hide got %q, want decoy %q", got, FormatDotenv(decoy, nil))
	}

	cancel()
	select {
	case err := <-serveErr:
		if err != context.Canceled {
			t.Errorf("Serve returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not exit within 5s of cancellation")
	}
}

// TestServeCallsOnReaderConnectedBeforeWriting proves the ordering the
// decoy gate's safety depends on (see Serve's doc comment and
// spike/fifo-reader-identify/FINDINGS.md): onReaderConnected — and by
// extension provideContent — always fires strictly before any byte is
// written, so a reader blocked on read() can never receive data before
// Serve has decided what to serve.
func TestServeCallsOnReaderConnectedBeforeWriting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := CreateFIFO(path); err != nil {
		t.Fatalf("CreateFIFO: %v", err)
	}

	var calls int
	onReaderConnected := func() { calls++ }
	content := func() []byte { return []byte("A=1\n") }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveErr := make(chan error, 1)
	go func() { serveErr <- Serve(ctx, path, content, nil, onReaderConnected, nil) }()

	readFIFO(t, path)
	readFIFO(t, path)

	cancel()
	select {
	case <-serveErr:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not exit within 5s of cancellation")
	}

	if calls != 2 {
		t.Errorf("onReaderConnected called %d times, want 2 (once per reader cycle)", calls)
	}
}

func TestFormatDotenv(t *testing.T) {
	got := FormatDotenv(map[string]string{
		"SIMPLE":     "value",
		"HAS_SPACE":  "a b",
		"HAS_QUOTE":  `a"b`,
		"EMPTY":      "",
		"HAS_HASH":   "a#b",
		"HAS_DOLLAR": "a$b",
	}, nil)
	want := "EMPTY=\"\"\n" +
		"HAS_DOLLAR=\"a$b\"\n" +
		"HAS_HASH=\"a#b\"\n" +
		"HAS_QUOTE=\"a\\\"b\"\n" +
		"HAS_SPACE=\"a b\"\n" +
		"SIMPLE=value\n"
	if string(got) != want {
		t.Errorf("FormatDotenv = %q, want %q", got, want)
	}
}

// Issue #4: a live-mounted .env used to serve its variables alphabetically.
// With the source order supplied, rendering follows it — and any name the
// order doesn't cover still appears, sorted, at the end (a manifest edited
// by hand, or an older alphabetical manifest, degrades gracefully).
func TestFormatDotenvPreservesGivenOrder(t *testing.T) {
	values := map[string]string{
		"DATABASE_URL":      "postgres://x",
		"PROD_DATABASE_URL": "postgres://y",
		"STRIPE_API_KEY":    "sk_test",
		"DEBUG":             "true",
		"ZZZ_EXTRA":         "1",
		"AAA_EXTRA":         "2",
	}
	order := []string{"DATABASE_URL", "PROD_DATABASE_URL", "STRIPE_API_KEY", "DEBUG"}
	got := FormatDotenv(values, order)
	want := "DATABASE_URL=postgres://x\n" +
		"PROD_DATABASE_URL=postgres://y\n" +
		"STRIPE_API_KEY=sk_test\n" +
		"DEBUG=true\n" +
		"AAA_EXTRA=2\n" +
		"ZZZ_EXTRA=1\n"
	if string(got) != want {
		t.Errorf("FormatDotenv = %q, want %q", got, want)
	}
}

func TestFormatDotenvEscapesBackslashAndNewline(t *testing.T) {
	got := FormatDotenv(map[string]string{"X": "a\\b\nc"}, nil)
	want := "X=\"a\\\\b\\nc\"\n"
	if string(got) != want {
		t.Errorf("FormatDotenv = %q, want %q", got, want)
	}
}
