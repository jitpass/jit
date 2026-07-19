// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// shortSocketPath returns a socket path under /tmp directly, not
// t.TempDir() — t.TempDir()'s path embeds the test name and a nested
// subtest counter, which routinely exceeds the ~104-byte sockaddr_un
// limit on macOS/BSD and fails with a cryptic "bind: invalid argument"
// that has nothing to do with the test's actual logic.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	path := filepath.Join("/tmp", fmt.Sprintf("jit-agent-test-%d-%d.sock", os.Getpid(), time.Now().UnixNano()))
	t.Cleanup(func() { _ = os.Remove(path) })
	return path
}

// fakeFetcher is a deterministic MEKFetcher for tests — counts calls so
// tests can assert exactly how many times a real challenge would have
// fired, and records the reason each one carried, since that string is
// what a human would have read on the prompt.
type fakeFetcher struct {
	key   []byte
	calls *int32
	err   error
	delay time.Duration

	mu      sync.Mutex
	reasons []string
}

func (f *fakeFetcher) FetchMEK(reason string) ([]byte, error) {
	f.mu.Lock()
	f.reasons = append(f.reasons, reason)
	f.mu.Unlock()
	if f.calls != nil {
		atomic.AddInt32(f.calls, 1)
	}
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	if f.err != nil {
		return nil, f.err
	}
	out := make([]byte, len(f.key))
	copy(out, f.key)
	return out, nil
}

func startTestServer(t *testing.T, ttl time.Duration, calls *int32) (*Server, string, func()) {
	t.Helper()
	socketPath := shortSocketPath(t)
	newFetcher := func() MEKFetcher {
		return &fakeFetcher{key: bytes.Repeat([]byte{0x42}, 32), calls: calls}
	}
	s := NewServer(socketPath, newFetcher, ttl)
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = s.Serve(ctx)
		close(done)
	}()

	cleanup := func() {
		cancel()
		_ = s.Close()
		<-done
	}
	return s, socketPath, cleanup
}

func TestServerWrapUnwrapRoundTripViaClient(t *testing.T) {
	_, socketPath, cleanup := startTestServer(t, time.Minute, nil)
	defer cleanup()

	c := NewClient(socketPath)
	dek := bytes.Repeat([]byte{0x07}, 32)

	wrapped, err := c.WrapKey(dek)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	if bytes.Equal(wrapped, dek) {
		t.Error("WrapKey returned the DEK unmodified")
	}

	got, err := c.UnwrapKey(wrapped)
	if err != nil {
		t.Fatalf("UnwrapKey: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Errorf("UnwrapKey = %x, want %x", got, dek)
	}
}

func TestServerCachesMEKAcrossMultipleRequests(t *testing.T) {
	var calls int32
	_, socketPath, cleanup := startTestServer(t, time.Minute, &calls)
	defer cleanup()

	c := NewClient(socketPath)
	for i := 0; i < 5; i++ {
		if _, err := c.WrapKey([]byte("x")); err != nil {
			t.Fatalf("WrapKey (call %d): %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("MEKFetcher called %d times across 5 requests, want exactly 1 (cached)", got)
	}
}

func TestServerReChallengesAfterTTLExpires(t *testing.T) {
	var calls int32
	_, socketPath, cleanup := startTestServer(t, 50*time.Millisecond, &calls)
	defer cleanup()

	c := NewClient(socketPath)
	if _, err := c.WrapKey([]byte("x")); err != nil {
		t.Fatalf("first WrapKey: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := c.WrapKey([]byte("x")); err != nil {
		t.Fatalf("second WrapKey (after TTL): %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("MEKFetcher called %d times, want exactly 2 (one per TTL window)", got)
	}
}

// TestServerTTLSlidesWithActivity locks in the TTL's documented meaning
// (GAPS.md #45): `jit agent --help` and every doc describe it as locking
// "after --ttl of inactivity," but the code used to implement a fixed
// window since the last UNLOCK — a cache hit never extended expiry, so an
// actively-used session re-prompted mid-work at a moment unrelated to the
// user stepping away. Steady activity across more than one full TTL must
// stay on a single challenge.
func TestServerTTLSlidesWithActivity(t *testing.T) {
	var calls int32
	_, socketPath, cleanup := startTestServer(t, 500*time.Millisecond, &calls)
	defer cleanup()

	c := NewClient(socketPath)
	// 9 requests 100ms apart span ~800ms — well past the 500ms TTL — while
	// every gap stays far inside it.
	for i := 0; i < 9; i++ {
		if _, err := c.WrapKey([]byte("x")); err != nil {
			t.Fatalf("WrapKey (call %d): %v", i, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("MEKFetcher called %d times across continuous activity spanning more than one TTL, want exactly 1, the TTL is an inactivity timeout, not a fixed window since unlock", got)
	}

	// And genuine inactivity must still lock: the timer has to have been
	// reset by the last use, not left on the original schedule.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		st, err := c.Status()
		if err != nil {
			t.Fatalf("Status: %v", err)
		}
		if !st.Unlocked {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Error("session still unlocked 3s after the last activity with a 500ms TTL, sliding must not mean never locking")
}

// TestServerClosesConnThatNeverSendsRequest confirms a client that
// connects and then stalls can't pin a handleConn goroutine forever —
// the agent process runs for weeks, so a leaked goroutine per stalled
// connection only ever accumulates. The request-read deadline must close
// the connection; the challenge's own 120s ceiling (which handling may
// legitimately wait out) starts only after a complete request arrives.
func TestServerClosesConnThatNeverSendsRequest(t *testing.T) {
	socketPath := shortSocketPath(t)
	newFetcher := func() MEKFetcher { return &fakeFetcher{key: bytes.Repeat([]byte{0x42}, 32)} }
	s := NewServer(socketPath, newFetcher, time.Minute)
	// Shortened BEFORE Serve's goroutine exists — a field, not a package
	// var, so no other test's in-flight handler can ever observe it.
	s.readTimeout = 200 * time.Millisecond

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx); close(done) }()
	defer func() { cancel(); _ = s.Close(); <-done }()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	// Send nothing. The server must give up and close within the
	// (shortened) read deadline rather than blocking in Decode forever.
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected the read to end with the server closing the connection, got data")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("server never closed a connection whose client sent nothing, a stalled client pins the handler goroutine forever")
	}
}

func TestServerLockDropsSessionImmediately(t *testing.T) {
	var calls int32
	_, socketPath, cleanup := startTestServer(t, time.Minute, &calls)
	defer cleanup()

	c := NewClient(socketPath)
	if _, err := c.WrapKey([]byte("x")); err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	st, err := c.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !st.Unlocked {
		t.Fatal("expected unlocked after WrapKey, got locked")
	}

	if err := c.Lock(); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	st, err = c.Status()
	if err != nil {
		t.Fatalf("Status after Lock: %v", err)
	}
	if st.Unlocked {
		t.Fatal("expected locked after explicit Lock, got unlocked")
	}

	if _, err := c.WrapKey([]byte("x")); err != nil {
		t.Fatalf("WrapKey after Lock (should re-challenge, not fail): %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("MEKFetcher called %d times, want exactly 2 (one before Lock, one after re-unlock)", got)
	}
}

func TestServerUnlockPreWarmsSession(t *testing.T) {
	var calls int32
	_, socketPath, cleanup := startTestServer(t, time.Minute, &calls)
	defer cleanup()

	c := NewClient(socketPath)
	unlocked, remaining, err := c.Unlock()
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if !unlocked || remaining <= 0 {
		t.Errorf("Unlock = (%v, %v), want unlocked with positive remaining TTL", unlocked, remaining)
	}

	if _, err := c.WrapKey([]byte("x")); err != nil {
		t.Fatalf("WrapKey after Unlock: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("MEKFetcher called %d times, want exactly 1 (Unlock pre-warmed, WrapKey reused it)", got)
	}
}

func TestServerOnUnlockFiresOnceForFreshChallengeOnly(t *testing.T) {
	socketPath := shortSocketPath(t)
	newFetcher := func() MEKFetcher { return &fakeFetcher{key: bytes.Repeat([]byte{0x42}, 32)} }
	s := NewServer(socketPath, newFetcher, time.Minute)

	var unlockCalls int32
	s.OnUnlock = func() { atomic.AddInt32(&unlockCalls, 1) }

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx); close(done) }()
	defer func() { cancel(); _ = s.Close(); <-done }()

	c := NewClient(socketPath)
	for i := 0; i < 3; i++ {
		if _, err := c.WrapKey([]byte("x")); err != nil {
			t.Fatalf("WrapKey (call %d): %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&unlockCalls); got != 1 {
		t.Errorf("OnUnlock fired %d times across 3 WrapKey calls (all cache hits after the first), want exactly 1", got)
	}
}

func TestServerOnLockFiresOnExplicitLockButNotWhenAlreadyLocked(t *testing.T) {
	socketPath := shortSocketPath(t)
	newFetcher := func() MEKFetcher { return &fakeFetcher{key: bytes.Repeat([]byte{0x42}, 32)} }
	s := NewServer(socketPath, newFetcher, time.Minute)

	var lockCalls int32
	s.OnLock = func() { atomic.AddInt32(&lockCalls, 1) }

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx); close(done) }()
	defer func() { cancel(); _ = s.Close(); <-done }()

	c := NewClient(socketPath)
	// Locking an already-locked (never unlocked) agent must not fire OnLock.
	if err := c.Lock(); err != nil {
		t.Fatalf("Lock (while already locked): %v", err)
	}
	if got := atomic.LoadInt32(&lockCalls); got != 0 {
		t.Errorf("OnLock fired %d times locking an already-locked agent, want 0", got)
	}

	if _, err := c.WrapKey([]byte("x")); err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	if err := c.Lock(); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if got := atomic.LoadInt32(&lockCalls); got != 1 {
		t.Errorf("OnLock fired %d times after a real unlock+lock, want exactly 1", got)
	}
}

func TestServerAutoLocksAfterTTLAndFiresOnLock(t *testing.T) {
	socketPath := shortSocketPath(t)
	newFetcher := func() MEKFetcher { return &fakeFetcher{key: bytes.Repeat([]byte{0x42}, 32)} }
	s := NewServer(socketPath, newFetcher, 50*time.Millisecond)

	var lockCalls int32
	s.OnLock = func() { atomic.AddInt32(&lockCalls, 1) }

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx); close(done) }()
	defer func() { cancel(); _ = s.Close(); <-done }()

	c := NewClient(socketPath)
	if _, err := c.WrapKey([]byte("x")); err != nil {
		t.Fatalf("WrapKey: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&lockCalls) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := atomic.LoadInt32(&lockCalls); got != 1 {
		t.Errorf("OnLock fired %d times after TTL expiry with no activity, want exactly 1 (auto-lock, no client-side poking needed)", got)
	}

	st, err := c.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Unlocked {
		t.Error("expected locked after TTL auto-lock, got unlocked")
	}
}

// TestClientToleratesSlowChallenge locks in a real bug found during manual
// end-to-end verification: the client's response timeout was 5 seconds,
// but a real Touch ID/passcode challenge can legitimately take longer
// than that for a human to notice and approve — especially when a script
// is running several commands back to back. The client gave up and
// reported a spurious timeout error while the underlying unlock was still
// in flight, even though it went on to succeed a moment later. This test
// uses a delay well past the OLD 5-second bug threshold (but a small
// fraction of the real 130-second timeout) so it fails fast under the old
// behavior without the suite actually waiting anywhere near 130s.
func TestClientToleratesSlowChallenge(t *testing.T) {
	socketPath := shortSocketPath(t)
	newFetcher := func() MEKFetcher {
		return &fakeFetcher{key: bytes.Repeat([]byte{0x42}, 32), delay: 7 * time.Second}
	}
	s := NewServer(socketPath, newFetcher, time.Minute)
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx); close(done) }()
	defer func() { cancel(); _ = s.Close(); <-done }()

	c := NewClient(socketPath)
	start := time.Now()
	if _, err := c.WrapKey([]byte("x")); err != nil {
		t.Fatalf("WrapKey with a 7s challenge delay (well past the old 5s bug threshold): %v", err)
	}
	if elapsed := time.Since(start); elapsed < 7*time.Second {
		t.Errorf("WrapKey returned after %v, want it to have actually waited out the 7s delay", elapsed)
	}
}

func TestServerRefreshCallsOnRefreshAndEnsuresUnlocked(t *testing.T) {
	socketPath := shortSocketPath(t)
	newFetcher := func() MEKFetcher { return &fakeFetcher{key: bytes.Repeat([]byte{0x42}, 32)} }
	s := NewServer(socketPath, newFetcher, time.Minute)

	var refreshCalls int32
	s.OnRefresh = func() { atomic.AddInt32(&refreshCalls, 1) }

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx); close(done) }()
	defer func() { cancel(); _ = s.Close(); <-done }()

	c := NewClient(socketPath)
	if err := c.Refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if got := atomic.LoadInt32(&refreshCalls); got != 1 {
		t.Errorf("OnRefresh called %d times, want 1", got)
	}

	st, err := c.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !st.Unlocked {
		t.Error("expected Refresh to have ensured the session is unlocked (it needs to read the vault), got locked")
	}
}

func TestServerRevealCallsOnRevealWithMountPathAndDurationAndEnsuresUnlocked(t *testing.T) {
	socketPath := shortSocketPath(t)
	newFetcher := func() MEKFetcher { return &fakeFetcher{key: bytes.Repeat([]byte{0x42}, 32)} }
	s := NewServer(socketPath, newFetcher, time.Minute)

	var gotPath string
	var gotDuration time.Duration
	var revealCalls int32
	s.OnReveal = func(mountPath string, requested time.Duration) error {
		gotPath = mountPath
		gotDuration = requested
		atomic.AddInt32(&revealCalls, 1)
		return nil
	}

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx); close(done) }()
	defer func() { cancel(); _ = s.Close(); <-done }()

	c := NewClient(socketPath)
	if err := c.Reveal("/tmp/fixture/.env", 90*time.Second); err != nil {
		t.Fatalf("Reveal: %v", err)
	}
	if got := atomic.LoadInt32(&revealCalls); got != 1 {
		t.Fatalf("OnReveal called %d times, want 1", got)
	}
	if gotPath != "/tmp/fixture/.env" {
		t.Errorf("OnReveal mountPath = %q, want /tmp/fixture/.env", gotPath)
	}
	if gotDuration != 90*time.Second {
		t.Errorf("OnReveal duration = %v, want 90s", gotDuration)
	}

	st, err := c.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !st.Unlocked {
		t.Error("expected Reveal to have ensured the session is unlocked, got locked")
	}
}

func TestServerRevealRejectsMissingMountPath(t *testing.T) {
	socketPath := shortSocketPath(t)
	newFetcher := func() MEKFetcher { return &fakeFetcher{key: bytes.Repeat([]byte{0x42}, 32)} }
	s := NewServer(socketPath, newFetcher, time.Minute)
	s.OnReveal = func(string, time.Duration) error {
		t.Error("OnReveal must not fire for a request with no mount_path")
		return nil
	}

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx); close(done) }()
	defer func() { cancel(); _ = s.Close(); <-done }()

	c := NewClient(socketPath)
	if err := c.Reveal("", time.Minute); err == nil {
		t.Error("expected an error for a missing mount path, got nil")
	}
}

func TestServerRevealPIDCallsOnRevealPIDAndEnsuresUnlocked(t *testing.T) {
	socketPath := shortSocketPath(t)
	newFetcher := func() MEKFetcher { return &fakeFetcher{key: bytes.Repeat([]byte{0x42}, 32)} }
	s := NewServer(socketPath, newFetcher, time.Minute)

	var gotPaths []string
	var gotPID int32
	var calls int32
	s.OnRevealPID = func(mountPaths []string, pid int32, swap bool) error {
		gotPaths = mountPaths
		gotPID = pid
		atomic.AddInt32(&calls, 1)
		return nil
	}

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx); close(done) }()
	defer func() { cancel(); _ = s.Close(); <-done }()

	c := NewClient(socketPath)
	want := []string{"/tmp/fixture/.env", "/tmp/fixture/.env.local"}
	if err := c.RevealForPID(want, 4242); err != nil {
		t.Fatalf("RevealForPID: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("OnRevealPID called %d times, want 1", got)
	}
	if len(gotPaths) != 2 || gotPaths[0] != want[0] || gotPaths[1] != want[1] {
		t.Errorf("OnRevealPID mountPaths = %v, want %v", gotPaths, want)
	}
	if gotPID != 4242 {
		t.Errorf("OnRevealPID pid = %d, want 4242", gotPID)
	}

	st, err := c.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !st.Unlocked {
		t.Error("expected RevealForPID to have ensured the session is unlocked, got locked")
	}
}

func TestServerRevealPIDRejectsMissingArguments(t *testing.T) {
	socketPath := shortSocketPath(t)
	newFetcher := func() MEKFetcher { return &fakeFetcher{key: bytes.Repeat([]byte{0x42}, 32)} }
	s := NewServer(socketPath, newFetcher, time.Minute)
	s.OnRevealPID = func([]string, int32, bool) error {
		t.Error("OnRevealPID must not fire for a request missing mount_paths or target_pid")
		return nil
	}

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx); close(done) }()
	defer func() { cancel(); _ = s.Close(); <-done }()

	c := NewClient(socketPath)
	if err := c.RevealForPID(nil, 4242); err == nil {
		t.Error("expected an error for missing mount paths, got nil")
	}
	if err := c.RevealForPID([]string{"/tmp/fixture/.env"}, 0); err == nil {
		t.Error("expected an error for a missing target pid, got nil")
	}
}

// TestServerRevealPIDReturnsErrorFromCallback mirrors OnReveal's own
// error-surfacing contract (the "silently reported success" bug class): a
// grant the mountManager can't create must fail the RPC, message included.
func TestServerRevealPIDReturnsErrorFromCallback(t *testing.T) {
	socketPath := shortSocketPath(t)
	newFetcher := func() MEKFetcher { return &fakeFetcher{key: bytes.Repeat([]byte{0x42}, 32)} }
	s := NewServer(socketPath, newFetcher, time.Minute)
	s.OnRevealPID = func([]string, int32, bool) error { return fmt.Errorf("no such mount") }

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx); close(done) }()
	defer func() { cancel(); _ = s.Close(); <-done }()

	c := NewClient(socketPath)
	if err := c.RevealForPID([]string{"/tmp/fixture/never-served.env"}, 4242); err == nil {
		t.Error("expected an error when OnRevealPID reports failure, got nil")
	}
}

// TestServerRevealReturnsErrorWhenOnRevealReportsNotFound locks in a real,
// reported bug: OpReveal used to return Response{OK: true} unconditionally,
// so a mount-path mismatch (the CLI forwarding an unresolved relative path
// that never matched the registry's absolute keys) silently reported
// success while revealing nothing. OnReveal's error return must now surface as
// the RPC's own failure, message included.
func TestServerRevealReturnsErrorWhenOnRevealReportsNotFound(t *testing.T) {
	socketPath := shortSocketPath(t)
	newFetcher := func() MEKFetcher { return &fakeFetcher{key: bytes.Repeat([]byte{0x42}, 32)} }
	s := NewServer(socketPath, newFetcher, time.Minute)
	s.OnReveal = func(string, time.Duration) error { return fmt.Errorf("no such mount") }

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx); close(done) }()
	defer func() { cancel(); _ = s.Close(); <-done }()

	c := NewClient(socketPath)
	if err := c.Reveal("/tmp/fixture/never-served.env", time.Minute); err == nil {
		t.Error("expected an error when OnReveal reports the mount wasn't found, got nil")
	}
}

func TestServerStatusWhenNeverUnlocked(t *testing.T) {
	_, socketPath, cleanup := startTestServer(t, time.Minute, nil)
	defer cleanup()

	c := NewClient(socketPath)
	st, err := c.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Unlocked || st.Remaining != 0 {
		t.Errorf("Status = (%v, %v), want (false, 0) before any unlock", st.Unlocked, st.Remaining)
	}
	// An agent that has never unlocked has no history to explain. Reporting
	// an empty-but-present event would make `jit agent status` print a line
	// full of blanks; nil is how "nothing to say" is said.
	if st.LastUnlock != nil || st.LastLock != nil {
		t.Errorf("Status returned provenance before anything ever unlocked: %+v / %+v", st.LastUnlock, st.LastLock)
	}
}

// TestServerRecordsWhoUnlockedIt is GAPS.md #75's regression test. The agent
// used to prompt for Touch ID and then forget entirely that it had: `jit
// agent status` could say "running and locked" and nothing else, so a user
// who saw an unexplained prompt had no way — short of correlating the agent
// log with their shell history — to find out what had asked for their
// secrets. The session's provenance must outlive the session itself, since
// "why did that happen?" is asked AFTER the session has already auto-locked.
func TestServerRecordsWhoUnlockedItAndWhyItLocked(t *testing.T) {
	_, socketPath, cleanup := startTestServer(t, time.Minute, nil)
	defer cleanup()

	c := NewClient(socketPath)
	if _, _, err := c.Unlock(); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	st, err := c.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.LastUnlock == nil {
		t.Fatal("no LastUnlock recorded after a fresh unlock, the agent still can't explain its own prompts")
	}
	if st.LastUnlock.Op != OpUnlock {
		t.Errorf("LastUnlock.Op = %q, want %q", st.LastUnlock.Op, OpUnlock)
	}
	// The peer here is this test binary, identified through the real
	// LOCAL_PEERPID path — no fake. Its identity is whatever `go test`
	// happens to be called, so assert only that the kernel answered at all.
	if st.LastUnlock.ByPID != int32(os.Getpid()) {
		t.Errorf("LastUnlock.ByPID = %d, want this test process's pid %d, the peer-pid lookup is what makes every other field trustworthy", st.LastUnlock.ByPID, os.Getpid())
	}
	if st.LastUnlock.By == "" {
		t.Error("LastUnlock.By is empty, the kernel identified the peer's pid but nothing recorded what it was")
	}

	if err := c.Lock(); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	st, err = c.Status()
	if err != nil {
		t.Fatalf("Status after Lock: %v", err)
	}
	if st.LastUnlock == nil {
		t.Error("LastUnlock disappeared once the session locked, the explanation is needed most AFTER the session is gone")
	}
	if st.LastLock == nil || st.LastLock.Cause == "" {
		t.Fatalf("no lock cause recorded after an explicit Lock: %+v", st.LastLock)
	}
	if !strings.Contains(st.LastLock.Cause, "explicit") {
		t.Errorf("LastLock.Cause = %q, want it to distinguish an explicit lock from the idle timeout, that distinction is the answer to \"why am I being asked again?\"", st.LastLock.Cause)
	}
}

// The idle auto-lock is the cause behind almost every surprise re-prompt, so
// it has to name itself as such — a lock with no cause, or one indistinguishable
// from an explicit lock, leaves the user's actual question unanswered.
func TestServerRecordsIdleTimeoutAsTheLockCause(t *testing.T) {
	_, socketPath, cleanup := startTestServer(t, 50*time.Millisecond, nil)
	defer cleanup()

	c := NewClient(socketPath)
	if _, err := c.WrapKey([]byte("x")); err != nil {
		t.Fatalf("WrapKey: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		st, err := c.Status()
		if err != nil {
			t.Fatalf("Status: %v", err)
		}
		if !st.Unlocked && st.LastLock != nil {
			if !strings.Contains(st.LastLock.Cause, "idle timeout") {
				t.Errorf("LastLock.Cause = %q, want it to name the idle timeout", st.LastLock.Cause)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("session never auto-locked within 3s of a 50ms TTL")
}

// The reason string is the prompt text. A wrap and an unwrap must not read
// alike ("store" vs "read" is the difference between jit taking a secret and
// jit handing one out), and the reason must actually reach the fetcher —
// which is the component that renders it to the human.
func TestServerPassesAPerOpReasonToTheChallenge(t *testing.T) {
	socketPath := shortSocketPath(t)
	fetcher := &fakeFetcher{key: bytes.Repeat([]byte{0x42}, 32)}
	s := NewServer(socketPath, func() MEKFetcher { return fetcher }, 0) // ttl 0: every op re-challenges
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx); close(done) }()
	defer func() { cancel(); _ = s.Close(); <-done }()

	c := NewClient(socketPath)
	if _, err := c.WrapKey([]byte("x")); err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	if _, err := c.UnwrapKey([]byte("not-a-real-ciphertext")); err == nil {
		t.Log("UnwrapKey on garbage failed as expected; only the challenge that preceded it matters here")
	}

	fetcher.mu.Lock()
	reasons := append([]string(nil), fetcher.reasons...)
	fetcher.mu.Unlock()

	if len(reasons) < 2 {
		t.Fatalf("got %d challenge reasons, want one per op: %q", len(reasons), reasons)
	}
	if !strings.Contains(reasons[0], "store a secret") {
		t.Errorf("wrap challenged with %q, want it to say a secret is being stored", reasons[0])
	}
	if !strings.Contains(reasons[1], "read a secret") {
		t.Errorf("unwrap challenged with %q, want it to say a secret is being read", reasons[1])
	}
}

func TestServerChallengeFailurePropagates(t *testing.T) {
	socketPath := shortSocketPath(t)
	newFetcher := func() MEKFetcher {
		return &fakeFetcher{err: errors.New("simulated auth failure")}
	}
	s := NewServer(socketPath, newFetcher, time.Minute)
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx); close(done) }()
	defer func() { cancel(); _ = s.Close(); <-done }()

	c := NewClient(socketPath)
	if _, err := c.WrapKey([]byte("x")); err == nil {
		t.Fatal("expected WrapKey to fail when the MEKFetcher fails, got nil")
	}
}

func TestClientReachable(t *testing.T) {
	_, socketPath, cleanup := startTestServer(t, time.Minute, nil)
	defer cleanup()

	if !NewClient(socketPath).Reachable() {
		t.Error("Reachable() = false, want true while the server is running")
	}
}

func TestClientNotReachableWhenNoAgentRunning(t *testing.T) {
	socketPath := shortSocketPath(t)
	if NewClient(socketPath).Reachable() {
		t.Error("Reachable() = true, want false when nothing is listening")
	}
}

// TestServerRejectsMalformedRequest confirms a bad request gets a clean
// error response rather than hanging or crashing the connection handler.
func TestServerRejectsMalformedRequest(t *testing.T) {
	_, socketPath, cleanup := startTestServer(t, time.Minute, nil)
	defer cleanup()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("not json at all")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp.OK {
		t.Error("expected OK=false for a malformed request")
	}
}

// TestServerRevealFreshChallengeFiresOnUnlockForRevealNotOnUnlock locks in the
// OpReveal-scoped unlock contract: when a LOCKED agent receives a reveal
// request, the resulting fresh challenge must fire OnUnlockForReveal INSTEAD
// of OnUnlock (so an explicit single-file reveal never inherits the blanket
// floor-reveal a plain unlock grants every mount), firing before OnReveal; and
// with OnUnlockForReveal unset, the same path must fall back to OnUnlock so
// a Server without the scoped hook behaves exactly as before.
func TestServerRevealFreshChallengeFiresOnUnlockForRevealNotOnUnlock(t *testing.T) {
	socketPath := shortSocketPath(t)
	newFetcher := func() MEKFetcher { return &fakeFetcher{key: bytes.Repeat([]byte{0x42}, 32)} }
	s := NewServer(socketPath, newFetcher, time.Minute)

	var calls []string
	s.OnUnlock = func() { calls = append(calls, "unlock") }
	s.OnUnlockForReveal = func() { calls = append(calls, "unlock-for-reveal") }
	s.OnReveal = func(string, time.Duration) error { calls = append(calls, "reveal"); return nil }

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx); close(done) }()
	defer func() { cancel(); _ = s.Close(); <-done }()

	c := NewClient(socketPath)
	if err := c.Reveal("/tmp/fixture/.env", time.Minute); err != nil {
		t.Fatalf("Reveal: %v", err)
	}
	want := []string{"unlock-for-reveal", "reveal"}
	if len(calls) != len(want) || calls[0] != want[0] || calls[1] != want[1] {
		t.Errorf("hook sequence = %v, want %v, OnUnlock must NOT fire for a reveal-driven fresh challenge when OnUnlockForReveal is set", calls, want)
	}

	// Fallback: without the scoped hook, the reveal-driven challenge uses
	// OnUnlock, unchanged from the pre-OnUnlockForReveal contract.
	s2 := NewServer(shortSocketPath(t), newFetcher, time.Minute)
	var fallbackCalls []string
	s2.OnUnlock = func() { fallbackCalls = append(fallbackCalls, "unlock") }
	s2.OnReveal = func(string, time.Duration) error { fallbackCalls = append(fallbackCalls, "reveal"); return nil }
	if err := s2.Listen(); err != nil {
		t.Fatalf("Listen (fallback): %v", err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan struct{})
	go func() { _ = s2.Serve(ctx2); close(done2) }()
	defer func() { cancel2(); _ = s2.Close(); <-done2 }()

	c2 := NewClient(s2.socketPath)
	if err := c2.Reveal("/tmp/fixture/.env", time.Minute); err != nil {
		t.Fatalf("Reveal (fallback): %v", err)
	}
	if len(fallbackCalls) != 2 || fallbackCalls[0] != "unlock" || fallbackCalls[1] != "reveal" {
		t.Errorf("fallback hook sequence = %v, want [unlock reveal]", fallbackCalls)
	}
}

// TestServerHistoryRecordsEveryUnlockNotJustTheLast closes the gap the
// last-unlock/last-lock pair structurally cannot: each new unlock overwrites
// the previous one, so "has it been prompting me all afternoon, and for what?"
// had no answer. The ring keeps them all, newest first.
func TestServerHistoryRecordsEveryUnlockNotJustTheLast(t *testing.T) {
	_, socketPath, cleanup := startTestServer(t, 40*time.Millisecond, nil)
	defer cleanup()

	c := NewClient(socketPath)
	for i := 0; i < 3; i++ {
		if _, err := c.WrapKey([]byte("x")); err != nil {
			t.Fatalf("WrapKey %d: %v", i, err)
		}
		time.Sleep(80 * time.Millisecond) // let the TTL lapse: a real re-challenge each time
	}

	events, err := c.History()
	if err != nil {
		t.Fatalf("History: %v", err)
	}

	var unlocks, locks int
	for _, e := range events {
		switch e.Kind {
		case KindUnlock:
			unlocks++
		case KindLock:
			locks++
		default:
			t.Errorf("event with no Kind: %+v", e)
		}
	}
	if unlocks != 3 {
		t.Errorf("history has %d unlocks, want 3, every prompt must be recorded, not just the most recent", unlocks)
	}
	if locks < 2 {
		t.Errorf("history has %d locks, want at least 2 idle-timeout locks between the unlocks", locks)
	}

	// Newest first: the order the CLI prints, decided here so no consumer has
	// to know which end is which.
	for i := 1; i < len(events); i++ {
		if events[i].UnixTime > events[i-1].UnixTime {
			t.Errorf("history is not newest-first at index %d (%d after %d)", i, events[i].UnixTime, events[i-1].UnixTime)
		}
	}
}

// TestServerStatusAnswersDuringAnInFlightChallenge pins the challengeMu/
// s.mu split: an interactive challenge can legitimately sit ~120s waiting
// for a human, and status/history/lock used to queue behind it on the one
// mutex — so `jit agent status`, the exact command a user runs when an
// unexplained prompt is on their screen, hung until the prompt resolved.
// Reads must answer immediately, and status must name the pending
// challenge while it's still pending.
func TestServerStatusAnswersDuringAnInFlightChallenge(t *testing.T) {
	socketPath := shortSocketPath(t)
	newFetcher := func() MEKFetcher {
		return &fakeFetcher{key: bytes.Repeat([]byte{0x42}, 32), delay: 3 * time.Second}
	}
	s := NewServer(socketPath, newFetcher, time.Minute)
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx); close(done) }()
	defer func() { cancel(); _ = s.Close(); <-done }()

	c := NewClient(socketPath)
	wrapDone := make(chan error, 1)
	go func() {
		_, err := c.WrapKey([]byte("x"))
		wrapDone <- err
	}()
	time.Sleep(500 * time.Millisecond) // let the wrap reach the (3s) challenge

	start := time.Now()
	st, err := c.Status()
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Status during a challenge: %v", err)
	}
	if elapsed > time.Second {
		t.Errorf("Status took %v while a challenge was in flight, reads are queueing behind the prompt again", elapsed)
	}
	if st.Unlocked {
		t.Error("Status reported unlocked while the challenge was still awaiting approval")
	}
	if st.PendingUnlock == nil {
		t.Error("Status carried no PendingUnlock while a prompt was on screen, the one moment the question is being asked, and no answer")
	} else if st.PendingUnlock.ByPID != int32(os.Getpid()) {
		t.Errorf("PendingUnlock.ByPID = %d, want this test process's pid %d", st.PendingUnlock.ByPID, os.Getpid())
	}

	// History must answer mid-challenge too — "why do you keep prompting
	// me?" is asked exactly while a prompt is up.
	if _, err := c.History(); err != nil {
		t.Fatalf("History during a challenge: %v", err)
	}

	if err := <-wrapDone; err != nil {
		t.Fatalf("the wrap behind the slow challenge should still have succeeded: %v", err)
	}
	st, err = c.Status()
	if err != nil {
		t.Fatalf("Status after the challenge resolved: %v", err)
	}
	if st.PendingUnlock != nil {
		t.Error("PendingUnlock still set after the challenge resolved, a stale 'prompt is up' line is worse than none")
	}
	if !st.Unlocked {
		t.Error("expected unlocked once the challenge resolved")
	}
}

// TestServerConcurrentUnlockersShareOneChallenge pins what the old
// hold-s.mu-through-the-challenge design bought and challengeMu must keep
// buying: N callers hitting a locked agent at once produce exactly ONE
// prompt, with everyone else reusing the session the first approval
// installed.
func TestServerConcurrentUnlockersShareOneChallenge(t *testing.T) {
	var calls int32
	socketPath := shortSocketPath(t)
	newFetcher := func() MEKFetcher {
		return &fakeFetcher{key: bytes.Repeat([]byte{0x42}, 32), calls: &calls, delay: 300 * time.Millisecond}
	}
	s := NewServer(socketPath, newFetcher, time.Minute)
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx); close(done) }()
	defer func() { cancel(); _ = s.Close(); <-done }()

	c := NewClient(socketPath)
	var wg sync.WaitGroup
	errs := make(chan error, 5)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.WrapKey([]byte("x")); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent WrapKey: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("5 concurrent unlockers triggered %d challenges, want exactly 1, they must serialize behind a single prompt", got)
	}
}

// TestServerHandsOutMEKCopiesNotItsCache locks in ensureUnlocked's copy
// contract (see mekCopy): the cache and its consumers must be able to wipe
// independently. The dangerous direction is lock() wiping the cache while a
// wrap/unwrap that already fetched the MEK is still inside seal()/open() —
// an explicit `jit agent lock` races an in-flight wrap, the DEK gets sealed
// under a partially-zeroed key, and the stored envelope is permanently
// undecryptable with nothing erroring at the time. Sharing one backing
// array is what made that possible; both directions of it are pinned here.
func TestServerHandsOutMEKCopiesNotItsCache(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	s := NewServer(shortSocketPath(t), func() MEKFetcher { return &fakeFetcher{key: key} }, time.Minute)

	// Direction 1: lock() wiping the cache must not zero a copy already
	// handed to an in-flight wrap.
	inFlight, err := s.ensureUnlocked(OpWrap, nil, "")
	if err != nil {
		t.Fatalf("ensureUnlocked: %v", err)
	}
	s.lock("test lock racing an in-flight wrap")
	if !bytes.Equal(inFlight, key) {
		t.Fatal("lock() corrupted a MEK copy an in-flight wrap was still using, a wrap racing an explicit lock would seal the DEK under a zeroed key and lose the secret")
	}

	// Direction 2 (keychainwrap's own reason for copying): a caller's
	// defer wipe(mek) must not zero the cache out from under everyone else.
	first, err := s.ensureUnlocked(OpWrap, nil, "")
	if err != nil {
		t.Fatalf("ensureUnlocked after re-unlock: %v", err)
	}
	wipe(first)
	second, err := s.ensureUnlocked(OpWrap, nil, "") // cache hit, no fresh challenge
	if err != nil {
		t.Fatalf("ensureUnlocked cache hit: %v", err)
	}
	if !bytes.Equal(second, key) {
		t.Fatal("a caller wiping its own MEK copy corrupted the cached session for every later caller")
	}
}

// TestServerSeedHistoryRestoresPastEventsUnderNewOnes pins the durable-
// history contract: events seeded from a previous process's record come
// back through OpHistory underneath (older than) everything the current
// process adds, still newest-first, still capped.
func TestServerSeedHistoryRestoresPastEventsUnderNewOnes(t *testing.T) {
	s, socketPath, cleanup := startTestServer(t, time.Minute, nil)
	defer cleanup()

	seed := make([]SessionEvent, 0, MaxSessionEvents+50)
	for i := 0; i < MaxSessionEvents+50; i++ {
		seed = append(seed, SessionEvent{UnixTime: int64(i), Kind: KindUnlock})
	}
	seed = append(seed, SessionEvent{UnixTime: 9000, Kind: KindStart, Cause: "build test"})
	s.SeedHistory(seed)

	c := NewClient(socketPath)
	if _, _, err := c.Unlock(); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	events, err := c.History()
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(events) == 0 || len(events) > MaxSessionEvents+1 {
		t.Fatalf("history has %d events, want seeded history capped at MaxSessionEvents plus this process's unlock", len(events))
	}
	if events[0].Kind != KindUnlock || events[0].UnixTime < 9000 {
		t.Errorf("newest event = %+v, want this process's own fresh unlock on top", events[0])
	}
	if events[1].Kind != KindStart {
		t.Errorf("second-newest event = %+v, want the seeded start marker directly under the live events", events[1])
	}
	// The oldest seeded events must have been dropped by the cap, keeping
	// the newest.
	last := events[len(events)-1]
	if last.UnixTime < 50 {
		t.Errorf("oldest surviving event is %+v, seeding kept the OLD end of an over-cap history instead of the new end", last)
	}
}

// Asking the agent why it keeps prompting must never itself prompt.
func TestServerHistoryNeverTriggersAChallenge(t *testing.T) {
	var calls int32
	_, socketPath, cleanup := startTestServer(t, time.Minute, &calls)
	defer cleanup()

	if _, err := NewClient(socketPath).History(); err != nil {
		t.Fatalf("History: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Errorf("History triggered %d challenge(s), want 0, an agent you can't ask about its prompts without being prompted is useless", got)
	}
}
