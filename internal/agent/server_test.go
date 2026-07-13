// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

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
// fired.
type fakeFetcher struct {
	key   []byte
	calls *int32
	err   error
	delay time.Duration
}

func (f *fakeFetcher) FetchMEK() ([]byte, error) {
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
		t.Errorf("MEKFetcher called %d times across continuous activity spanning more than one TTL, want exactly 1 — the TTL is an inactivity timeout, not a fixed window since unlock", got)
	}

	// And genuine inactivity must still lock: the timer has to have been
	// reset by the last use, not left on the original schedule.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		unlocked, _, _, _, err := c.Status()
		if err != nil {
			t.Fatalf("Status: %v", err)
		}
		if !unlocked {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Error("session still unlocked 3s after the last activity with a 500ms TTL — sliding must not mean never locking")
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
		t.Fatal("server never closed a connection whose client sent nothing — a stalled client pins the handler goroutine forever")
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
	unlocked, _, _, _, err := c.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !unlocked {
		t.Fatal("expected unlocked after WrapKey, got locked")
	}

	if err := c.Lock(); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	unlocked, _, _, _, err = c.Status()
	if err != nil {
		t.Fatalf("Status after Lock: %v", err)
	}
	if unlocked {
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

	unlocked, _, _, _, err := c.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if unlocked {
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

	unlocked, _, _, _, err := c.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !unlocked {
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

	unlocked, _, _, _, err := c.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !unlocked {
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
	unlocked, remaining, _, _, err := c.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if unlocked || remaining != 0 {
		t.Errorf("Status = (%v, %v), want (false, 0) before any unlock", unlocked, remaining)
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
		t.Errorf("hook sequence = %v, want %v — OnUnlock must NOT fire for a reveal-driven fresh challenge when OnUnlockForReveal is set", calls, want)
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
