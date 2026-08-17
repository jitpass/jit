// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

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

	"github.com/jitpass/jit/internal/lineage"
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

// The sliding TTL is an inactivity timeout, and on its own it is the only
// bound a session has — so a caller that stays just barely active never lets
// it fire. Nothing stopped a process from sending one cheap request every
// TTL-minus-a-bit forever, keeping the MEK resident for as long as it liked on
// the strength of a single Touch ID from that morning. The hard ceiling is
// what that idle timer structurally cannot express.
func TestSessionEndsAtTheHardCeilingDespiteActivity(t *testing.T) {
	var calls int32
	s, socketPath, cleanup := startTestServer(t, 2*time.Second, &calls)
	defer cleanup()

	// Set before any request, so no unlock has armed a timer yet.
	s.mu.Lock()
	s.maxSessionAge = 300 * time.Millisecond
	s.mu.Unlock()

	c := NewClient(socketPath)
	// Eight requests 80ms apart span ~640ms of unbroken activity: every gap is
	// far inside the 2s TTL, so the idle timer never fires and only the
	// ceiling can end this session.
	for i := 0; i < 8; i++ {
		if _, err := c.WrapKey([]byte("x")); err != nil {
			t.Fatalf("WrapKey (call %d): %v", i, err)
		}
		time.Sleep(80 * time.Millisecond)
	}

	if got := atomic.LoadInt32(&calls); got < 2 {
		t.Errorf("continuous activity across a 300ms ceiling produced %d challenge(s), want at least 2: a busy session must still end at the ceiling", got)
	}
}

// Status has to report the bound that will actually end the session. Reporting
// the idle expiry alone would tell someone with a long TTL that they have
// hours left on a session the ceiling ends in minutes — the readout version of
// the "setting that cannot mean what it says" problem validateAgentTTL exists
// to prevent.
func TestStatusReportsTheCeilingWhenItComesFirst(t *testing.T) {
	var calls int32
	s, socketPath, cleanup := startTestServer(t, time.Hour, &calls)
	defer cleanup()

	s.mu.Lock()
	s.maxSessionAge = 2 * time.Second
	s.mu.Unlock()

	c := NewClient(socketPath)
	if _, err := c.WrapKey([]byte("x")); err != nil {
		t.Fatalf("WrapKey: %v", err)
	}

	unlocked, remaining := s.status()
	if !unlocked {
		t.Fatal("session should be unlocked")
	}
	if remaining > 2*time.Second {
		t.Errorf("status reports %s remaining on a session the ceiling ends in 2s (idle TTL is 1h)", remaining)
	}
}

// The ceiling must not shorten an ordinary session. A default-configured
// server has hours of headroom, and a burst of activity inside it is one
// unlock — the ceiling is a backstop, not a second timeout.
func TestHardCeilingLeavesOrdinarySessionsAlone(t *testing.T) {
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
		t.Errorf("MEKFetcher called %d times well inside the ceiling, want exactly 1", got)
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

// A malformed request must leave a durable KindError trail, not just a rejection
// on the wire the caller sees and no one else ever does. (The rejected-peer path
// is the more valuable one but can't be unit-tested here: a same-process dial
// shares this uid and so passes verifyPeerUID; the decode path exercises the
// same recordServeError wiring.)
func TestServerRecordsMalformedRequestAsError(t *testing.T) {
	socketPath := shortSocketPath(t)
	newFetcher := func() MEKFetcher { return &fakeFetcher{key: bytes.Repeat([]byte{0x42}, 32)} }
	s := NewServer(socketPath, newFetcher, time.Minute)
	events := make(chan SessionEvent, 1)
	s.OnServeError = func(e SessionEvent) { events <- e }

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
	if _, err := conn.Write([]byte("this is not json\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	select {
	case e := <-events:
		if e.Kind != KindError || e.Op != "decode" {
			t.Errorf("malformed request recorded as %+v, want Kind=error Op=decode", e)
		}
		if e.Cause == "" {
			t.Error("serve-error event carried no cause detail")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a malformed request produced no serve-error event")
	}
}

// The other half of the rule above: a peer that connects and closes without
// sending a byte is Client.Reachable(), jit's own liveness probe, not an
// attack. It runs from a dozen CLI paths (run, undo, unmount, vault, migrate
// remove, rekey), so recording it filed two KindError lines per `jit run` —
// and kind=error is the channel that is supposed to mean "a process the
// kernel says isn't yours probed the agent". On a real machine every single
// error event in a day's audit log was this probe, which makes the one
// signal worth reading unreadable.
func TestServerIgnoresLivenessProbe(t *testing.T) {
	socketPath := shortSocketPath(t)
	newFetcher := func() MEKFetcher { return &fakeFetcher{key: bytes.Repeat([]byte{0x42}, 32)} }
	s := NewServer(socketPath, newFetcher, time.Minute)
	events := make(chan SessionEvent, 1)
	s.OnServeError = func(e SessionEvent) { events <- e }

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx); close(done) }()
	defer func() { cancel(); _ = s.Close(); <-done }()

	if !NewClient(socketPath).Reachable() {
		t.Fatal("Reachable() on a listening server returned false")
	}

	select {
	case e := <-events:
		t.Errorf("liveness probe recorded a serve-error event, want none: %+v", e)
	case <-time.After(500 * time.Millisecond):
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

func TestServerLockEventOnlyOnRealSessionDrop(t *testing.T) {
	socketPath := shortSocketPath(t)
	newFetcher := func() MEKFetcher { return &fakeFetcher{key: bytes.Repeat([]byte{0x42}, 32)} }
	s := NewServer(socketPath, newFetcher, time.Minute)

	// The load-bearing invariant is the lock EVENT / provenance: it must be
	// recorded only when a session was actually dropped, never on a no-op
	// lock (which would overwrite the real lock's cause). OnLock, the
	// mount-clearing side effect, is deliberately idempotent and may fire on
	// a no-op too (see lockIfGen: a lazy TTL expiry can leave mounts to clear
	// with no session left to record), so its call count is NOT the invariant
	// under test here.
	var lockEvents int32
	s.OnSessionEvent = func(e SessionEvent) {
		if e.Kind == KindLock {
			atomic.AddInt32(&lockEvents, 1)
		}
	}

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx); close(done) }()
	defer func() { cancel(); _ = s.Close(); <-done }()

	c := NewClient(socketPath)
	// Locking an already-locked (never unlocked) agent records no lock event.
	if err := c.Lock(); err != nil {
		t.Fatalf("Lock (while already locked): %v", err)
	}
	if got := atomic.LoadInt32(&lockEvents); got != 0 {
		t.Errorf("lock event recorded %d times locking an already-locked agent, want 0", got)
	}

	if _, err := c.WrapKey([]byte("x")); err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	if err := c.Lock(); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if got := atomic.LoadInt32(&lockEvents); got != 1 {
		t.Errorf("lock event recorded %d times after a real unlock+lock, want exactly 1", got)
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
func TestServerRevealPIDCallsOnRevealPIDAndEnsuresUnlocked(t *testing.T) {
	socketPath := shortSocketPath(t)
	newFetcher := func() MEKFetcher { return &fakeFetcher{key: bytes.Repeat([]byte{0x42}, 32)} }
	s := NewServer(socketPath, newFetcher, time.Minute)

	var gotMounts []RunMount
	var gotPID int32
	var calls int32
	s.OnRevealPID = func(mounts []RunMount, pid int32) error {
		gotMounts = mounts
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
	// A mixed-mode run — swap one mount, grant another — must survive the
	// socket with paths and per-mount modes intact.
	want := []RunMount{
		{Path: "/tmp/fixture/.env", Mode: MountModeSwap},
		{Path: "/tmp/fixture/.npmrc", Mode: MountModeGrant},
	}
	if err := c.RunForPID(want, 4242); err != nil {
		t.Fatalf("RunForPID: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("OnRevealPID called %d times, want 1", got)
	}
	if len(gotMounts) != 2 || gotMounts[0] != want[0] || gotMounts[1] != want[1] {
		t.Errorf("OnRevealPID mounts = %v, want %v (paths and modes intact)", gotMounts, want)
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
	s.OnRevealPID = func([]RunMount, int32) error {
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

// TestGrantGlobalForcesDisclosedChallengeEvenWhenUnlocked is the security
// heart of --with: a global-mount grant must prompt a FRESH Touch ID naming
// the credential even though the session is already unlocked, so a script
// that slipped a --with into a command can't grant a machine-wide
// credential silently.
func TestGrantGlobalForcesDisclosedChallengeEvenWhenUnlocked(t *testing.T) {
	socketPath := shortSocketPath(t)
	fetcher := &fakeFetcher{key: bytes.Repeat([]byte{0x42}, 32)}
	s := NewServer(socketPath, func() MEKFetcher { return fetcher }, time.Minute)
	var granted int32
	s.OnRevealPID = func([]RunMount, int32) error { atomic.AddInt32(&granted, 1); return nil }
	s.OnDescribeGrant = func([]RunMount) string { return "your gcp credential on this machine" }

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx); close(done) }()
	defer func() { cancel(); _ = s.Close(); <-done }()

	c := NewClient(socketPath)
	if _, _, err := c.Unlock(); err != nil { // session now unlocked
		t.Fatalf("Unlock: %v", err)
	}
	fetcher.mu.Lock()
	fetcher.reasons = nil // forget the unlock's reason
	fetcher.mu.Unlock()

	if err := c.GrantGlobalForPID([]RunMount{{Path: "/x/ADC", Mode: MountModeGrant}}, 4242); err != nil {
		t.Fatalf("GrantGlobalForPID: %v", err)
	}
	if atomic.LoadInt32(&granted) != 1 {
		t.Error("OnRevealPID did not fire after an approved disclosed challenge")
	}
	fetcher.mu.Lock()
	reasons := fetcher.reasons
	fetcher.mu.Unlock()
	want := "grant this run access to your gcp credential on this machine"
	if len(reasons) != 1 || reasons[0] != want {
		t.Errorf("disclosed challenge reasons = %v, want exactly [%q] (a FRESH prompt fired despite the unlocked session, worded by the agent)", reasons, want)
	}
}

// TestGrantGlobalPromptIsAgentWordedNotCallerSupplied pins the fix for the
// prompt-spoofing hole: the wording used to be Request.DiscloseReason, chosen
// by whoever sent the RPC, so any same-user process could grant itself a
// machine-wide credential behind a prompt that read like a routine unlock.
// The agent now derives the sentence from the mounts, and a reason on the wire
// still triggers the gate (an older client mid-upgrade must not lose it) while
// contributing nothing to what the human reads.
func TestGrantGlobalPromptIsAgentWordedNotCallerSupplied(t *testing.T) {
	socketPath := shortSocketPath(t)
	fetcher := &fakeFetcher{key: bytes.Repeat([]byte{0x42}, 32)}
	s := NewServer(socketPath, func() MEKFetcher { return fetcher }, time.Minute)
	s.OnRevealPID = func([]RunMount, int32) error { return nil }
	s.OnDescribeGrant = func([]RunMount) string { return "your gcp credential on this machine" }

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx); close(done) }()
	defer func() { cancel(); _ = s.Close(); <-done }()

	c := NewClient(socketPath)
	if _, _, err := c.Unlock(); err != nil { // the session a real run would ride
		t.Fatalf("Unlock: %v", err)
	}
	fetcher.mu.Lock()
	fetcher.reasons = nil
	fetcher.mu.Unlock()

	lie := "unlock the vault for profile \"dev\""
	resp, err := c.call(Request{
		Op:             OpRevealPID,
		RunMounts:      []RunMount{{Path: "/x/ADC", Mode: MountModeGrant}},
		TargetPID:      4242,
		DiscloseReason: lie,
	})
	if err != nil || !resp.OK {
		t.Fatalf("legacy disclosed reveal_pid: %v (%+v)", err, resp)
	}

	fetcher.mu.Lock()
	reasons := fetcher.reasons
	fetcher.mu.Unlock()
	if len(reasons) != 1 {
		t.Fatalf("challenge reasons = %v, want exactly one (the legacy reason field must still TRIGGER the gate)", reasons)
	}
	if strings.Contains(reasons[0], "profile") {
		t.Errorf("prompt = %q, want the agent's own wording — caller-supplied text reached the dialog", reasons[0])
	}
	if reasons[0] != "grant this run access to your gcp credential on this machine" {
		t.Errorf("prompt = %q, want the OnDescribeGrant-derived wording", reasons[0])
	}
}

// TestGrantGlobalPromptFallsBackToAFixedPhrase: with nothing wired to classify
// the mounts, the prompt must degrade to a fixed sentence rather than to a
// best guess assembled from the caller's own path strings — those are
// attacker-chosen too, and swap-mode entries never even reach OnCanGrant.
func TestGrantGlobalPromptFallsBackToAFixedPhrase(t *testing.T) {
	socketPath := shortSocketPath(t)
	fetcher := &fakeFetcher{key: bytes.Repeat([]byte{0x42}, 32)}
	s := NewServer(socketPath, func() MEKFetcher { return fetcher }, time.Minute)
	s.OnRevealPID = func([]RunMount, int32) error { return nil }

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx); close(done) }()
	defer func() { cancel(); _ = s.Close(); <-done }()

	c := NewClient(socketPath)
	if _, _, err := c.Unlock(); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	fetcher.mu.Lock()
	fetcher.reasons = nil
	fetcher.mu.Unlock()

	evil := "/tmp/totally-fine-just-a-dev-unlock"
	if err := c.GrantGlobalForPID([]RunMount{{Path: evil, Mode: MountModeGrant}}, 4242); err != nil {
		t.Fatalf("GrantGlobalForPID: %v", err)
	}
	fetcher.mu.Lock()
	reasons := fetcher.reasons
	fetcher.mu.Unlock()
	if len(reasons) != 1 || strings.Contains(reasons[0], "totally-fine") {
		t.Errorf("prompt = %v, want a fixed phrase with no caller path echoed into it", reasons)
	}
}

// TestGrantGlobalDeclineBlocksTheGrant: a declined disclosed challenge must
// fail the RPC and never grant.
func TestGrantGlobalDeclineBlocksTheGrant(t *testing.T) {
	socketPath := shortSocketPath(t)
	fetcher := &fakeFetcher{key: bytes.Repeat([]byte{0x42}, 32)}
	s := NewServer(socketPath, func() MEKFetcher { return fetcher }, time.Minute)
	var granted int32
	s.OnRevealPID = func([]RunMount, int32) error { atomic.AddInt32(&granted, 1); return nil }

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx); close(done) }()
	defer func() { cancel(); _ = s.Close(); <-done }()

	c := NewClient(socketPath)
	if _, _, err := c.Unlock(); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	// The session rides the cache for the normal unlock; only the disclosed
	// challenge calls the fetcher again — make that one decline.
	fetcher.err = fmt.Errorf("user declined")

	if err := c.GrantGlobalForPID([]RunMount{{Path: "/x/ADC", Mode: MountModeGrant}}, 4242); err == nil {
		t.Error("expected an error when the disclosed challenge is declined")
	}
	if atomic.LoadInt32(&granted) != 0 {
		t.Error("OnRevealPID fired despite a declined disclosed challenge")
	}
}

// TestGrantGlobalPreCheckFailsBeforePrompt: OnCanGrant rejecting an
// unservable mount fails the grant WITHOUT a Touch ID and without granting.
// The disclosed challenge must never fire for a credential jit couldn't serve
// anyway — no burned biometric, and no partial grant later reported as full.
func TestGrantGlobalPreCheckFailsBeforePrompt(t *testing.T) {
	socketPath := shortSocketPath(t)
	fetcher := &fakeFetcher{key: bytes.Repeat([]byte{0x42}, 32)}
	s := NewServer(socketPath, func() MEKFetcher { return fetcher }, time.Minute)
	var granted int32
	s.OnRevealPID = func([]RunMount, int32) error { atomic.AddInt32(&granted, 1); return nil }
	s.OnCanGrant = func([]RunMount) error { return fmt.Errorf("gcp has nothing real to serve") }

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx); close(done) }()
	defer func() { cancel(); _ = s.Close(); <-done }()

	c := NewClient(socketPath)
	if _, _, err := c.Unlock(); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	fetcher.mu.Lock()
	fetcher.reasons = nil // forget the unlock's reason
	fetcher.mu.Unlock()

	if err := c.GrantGlobalForPID([]RunMount{{Path: "/x/ADC", Mode: MountModeGrant}}, 4242); err == nil {
		t.Error("expected the pre-check to fail the grant")
	}
	if atomic.LoadInt32(&granted) != 0 {
		t.Error("OnRevealPID fired despite a failed pre-check")
	}
	fetcher.mu.Lock()
	reasons := fetcher.reasons
	fetcher.mu.Unlock()
	if len(reasons) != 0 {
		t.Errorf("a disclosed challenge (Touch ID) fired despite a failed pre-check: %v", reasons)
	}
}

// TestGrantGlobalDeclineRecordsNoUse: a declined disclosed grant records only
// a denial, never a use. The use is recorded (via ensureUnlockedNotify) only
// AFTER approval, so the audit trail never shows access to a credential the
// user refused.
func TestGrantGlobalDeclineRecordsNoUse(t *testing.T) {
	socketPath := shortSocketPath(t)
	fetcher := &fakeFetcher{key: bytes.Repeat([]byte{0x42}, 32)}
	s := NewServer(socketPath, func() MEKFetcher { return fetcher }, time.Minute)
	s.OnRevealPID = func([]RunMount, int32) error { return nil }

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx); close(done) }()
	defer func() { cancel(); _ = s.Close(); <-done }()

	c := NewClient(socketPath)
	if _, _, err := c.Unlock(); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	// The session rides the cache; only the disclosed challenge re-fetches —
	// make that one decline.
	fetcher.err = fmt.Errorf("user declined")

	if err := c.GrantGlobalForPID([]RunMount{{Path: "/x/ADC", Mode: MountModeGrant}}, 4242); err == nil {
		t.Fatal("expected a declined grant to fail")
	}
	// No pending use for the reveal_pid op — the decline happened before any
	// use could be recorded.
	s.mu.Lock()
	defer s.mu.Unlock()
	for key := range s.pendingUses {
		if key.op == OpRevealPID {
			t.Errorf("a use was recorded for a declined disclosed grant (op %s)", key.op)
		}
	}
}

// TestServerRevealPIDReturnsErrorFromCallback mirrors OnReveal's own
// error-surfacing contract (the "silently reported success" bug class): a
// grant the mountManager can't create must fail the RPC, message included.
func TestServerRevealPIDReturnsErrorFromCallback(t *testing.T) {
	socketPath := shortSocketPath(t)
	newFetcher := func() MEKFetcher { return &fakeFetcher{key: bytes.Repeat([]byte{0x42}, 32)} }
	s := NewServer(socketPath, newFetcher, time.Minute)
	s.OnRevealPID = func([]RunMount, int32) error { return fmt.Errorf("no such mount") }

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
	// Inverted: this branch is taken when unwrapping ARBITRARY BYTES
	// SUCCEEDED, and it used to log that they had failed. An AEAD that opens
	// garbage is the envelope-integrity break, and it produced a reassuring
	// line in a passing test.
	if _, err := c.UnwrapKey([]byte("not-a-real-ciphertext")); err == nil {
		t.Error("UnwrapKey opened arbitrary bytes — the AEAD auth tag is not being checked")
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

// TestOnUnlockRunsOutsideChallengeMu pins the fix for a deadlock that wedged
// the whole agent. OnUnlock is documented as safe to call back into Server,
// but it used to run under challengeMu (via a defer that outlived the call).
// The real OnUnlock is mountManager.start, which resolves every mount through
// Server-as-KeyWrapper — so if the session dropped mid-resolve (the
// screen-lock/sleep watcher, an explicit lock, a `jit vault` command locking on
// its way out), the next unwrap re-entered the challenge path and took a
// non-reentrant mutex a second time on the same goroutine. That goroutine
// parked forever holding it, and every later unlock in the process hung until
// its client timed out, while status and history kept cheerfully answering.
func TestOnUnlockRunsOutsideChallengeMu(t *testing.T) {
	s := NewServer(shortSocketPath(t), func() MEKFetcher {
		return &fakeFetcher{key: bytes.Repeat([]byte{0x42}, 32)}
	}, time.Minute)

	var reResolved atomic.Bool
	s.OnUnlock = func() {
		// Exactly the sequence the screen-lock watcher can produce mid-resolve.
		s.LockWithCause("screen locked")
		_, _ = s.UnwrapKeyLabeled([]byte("not a real wrap"), "some/secret", "")
		reResolved.Store(true)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		mek, err := s.ensureUnlocked(OpUnlock, nil, "")
		if err != nil {
			t.Errorf("ensureUnlocked: %v", err)
		}
		wipe(mek)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("OnUnlock re-entered the challenge path and deadlocked the agent")
	}
	if !reResolved.Load() {
		t.Error("OnUnlock never completed")
	}
}

// An APPROVED disclosed challenge must leave a durable record, not just a
// declined one. `jit audit` used to be able to prove what you refused and
// never what you allowed — the consent feature's whole output, missing.
func TestApprovedDisclosedChallengeIsRecorded(t *testing.T) {
	socketPath := shortSocketPath(t)
	s := NewServer(socketPath, func() MEKFetcher {
		return &fakeFetcher{key: bytes.Repeat([]byte{0x42}, 32)}
	}, time.Minute)
	s.OnRevealPID = func([]RunMount, int32) error { return nil }
	s.OnDescribeGrant = func([]RunMount) string { return "your gcp credential on this machine" }

	var notified []SessionEvent
	var notifyMu sync.Mutex
	s.OnSessionEvent = func(e SessionEvent) {
		notifyMu.Lock()
		notified = append(notified, e)
		notifyMu.Unlock()
	}

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx); close(done) }()
	defer func() { cancel(); _ = s.Close(); <-done }()

	if err := NewClient(socketPath).GrantGlobalForPID([]RunMount{{Path: "/x/ADC", Mode: MountModeGrant}}, 4242); err != nil {
		t.Fatalf("GrantGlobalForPID: %v", err)
	}

	var found *SessionEvent
	for _, e := range s.history() {
		if e.Kind == KindApproved {
			found = &e
			break
		}
	}
	if found == nil {
		t.Fatal("an approved disclosed grant left no event in history")
	}
	if !strings.Contains(found.Cause, "gcp") {
		t.Errorf("approved event cause = %q, want the wording the human actually read", found.Cause)
	}
	if found.AuthMethod == "" {
		t.Error("approved event carries no auth method")
	}

	notifyMu.Lock()
	defer notifyMu.Unlock()
	for _, e := range notified {
		if e.Kind == KindApproved {
			return // also reached the durable log
		}
	}
	t.Error("approved event never reached OnSessionEvent, so it never reaches the durable trail jit audit reads")
}

// TestRecordServeErrorRateLimitsIdenticalFailures pins the durable-trail
// flood defense: recordRejectedClass protects the in-memory ring from
// caller-minted eviction, but every socket-boundary failure used to become
// its own durable line — a peer looping on the same malformed request could
// push real unlock/denial history out of agent-history.jsonl by byte
// pressure. Identical (op, cause) pairs inside serveErrorMinGap fold into
// the next recorded event's Count; distinct causes still record immediately.
func TestRecordServeErrorRateLimitsIdenticalFailures(t *testing.T) {
	s := NewServer(filepath.Join(t.TempDir(), "x.sock"), nil, time.Minute)
	var events []SessionEvent
	s.OnServeError = func(e SessionEvent) { events = append(events, e) }

	for i := 0; i < 100; i++ {
		s.recordServeError("decode", "request too large", nil)
	}
	if len(events) != 1 {
		t.Fatalf("100 identical failures inside the gap wrote %d events, want 1", len(events))
	}

	s.recordServeError("decode", "malformed json", nil)
	if len(events) != 2 {
		t.Fatalf("a DISTINCT cause must record immediately, got %d events", len(events))
	}

	// Age the first pair past the gap: the next identical failure records
	// and carries the fold (1 recorded + 99 suppressed = 100 occurrences).
	s.serveErrMu.Lock()
	s.serveErrSeen["decode\x00request too large"].last = time.Now().Add(-2 * serveErrorMinGap)
	s.serveErrMu.Unlock()
	s.recordServeError("decode", "request too large", nil)
	if len(events) != 3 {
		t.Fatalf("after the gap the failure must record again, got %d events", len(events))
	}
	if events[2].Count != 100 {
		t.Errorf("the recorded event must carry the fold: Count = %d, want 100", events[2].Count)
	}
}

// TestMinProtocolFailsClosed pins the socket-skew defense. Version skew here
// degrades by silent JSON field dropping, which is fail-OPEN for any field
// whose presence is what enforces something: an agent that never heard of
// Disclose ignores it and performs the reveal with no disclosed challenge.
// Unknown OPS always failed closed; unknown FIELDS did not. A request naming
// a protocol above this build's is now refused whole, and the error names the
// fix (restart the service onto the current binary).
func TestMinProtocolFailsClosed(t *testing.T) {
	s := NewServer(filepath.Join(t.TempDir(), "x.sock"), nil, time.Minute)

	resp := s.handle(Request{Op: OpStatus, MinProtocol: Protocol + 1}, nil)
	if resp.OK {
		t.Fatal("a request needing a newer protocol than this build speaks must be refused")
	}
	if !strings.Contains(resp.Error, "jit service restart") {
		t.Errorf("the refusal must name the fix, got %q", resp.Error)
	}

	// At or below this build's protocol, the request is served normally.
	if resp := s.handle(Request{Op: OpStatus, MinProtocol: Protocol}, nil); !resp.OK {
		t.Errorf("a request this build can serve as asked must proceed, got %q", resp.Error)
	}
	if resp := s.handle(Request{Op: OpStatus}, nil); !resp.OK {
		t.Errorf("an ordinary request (no MinProtocol) must proceed, got %q", resp.Error)
	}
}

// TestStatusReportsProtocol: the Protocol stamp is what lets a client check
// what the running agent enforces BEFORE sending a request whose safety
// depends on that enforcement — the only fail-closed option against an agent
// so old it would ignore MinProtocol too (see Client.GrantGlobalForPID).
func TestStatusReportsProtocol(t *testing.T) {
	_, socketPath, cleanup := startTestServer(t, time.Minute, new(int32))
	defer cleanup()

	st, err := NewClient(socketPath).Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Protocol != Protocol {
		t.Errorf("Status.Protocol = %d, want %d", st.Protocol, Protocol)
	}
	if st.Protocol < protocolDisclosedGate {
		t.Errorf("this build must satisfy its own disclosed-gate requirement (%d)", protocolDisclosedGate)
	}
}

// TestDisclosedChallengeBacksOffAfterRefusals is the prompt-storm defense.
// Disclosed challenges deliberately never arm the global denial cooldown (a
// refused grant is "not this", not "stop trying to unlock"), which left the
// widest-scope operations in the product with no throttle at all: a caller in
// a loop could put an unbounded stream of Touch ID dialogs on screen until
// the human approved one to make it stop. That is the exact asymmetry
// consent.Throttled exists to close, and it was never carried over here.
func TestDisclosedChallengeBacksOffAfterRefusals(t *testing.T) {
	var prompts int32
	s := NewServer(filepath.Join(t.TempDir(), "x.sock"), func() MEKFetcher {
		return fnFetcher{fn: func(string) ([]byte, error) {
			atomic.AddInt32(&prompts, 1)
			return nil, errors.New("declined")
		}}
	}, time.Minute)

	c := &caller{pid: 4242, self: lineage.Process{PID: 4242, ExecPath: "/bin/loop"},
		ancestors: []lineage.Process{{PID: 1234, ExecPath: "/bin/zsh"}}}

	// First refusal prompts and arms the pause.
	if _, _, err := s.discloseChallengeOp("grant something wide", OpTrust, c); err == nil {
		t.Fatal("a declined challenge must return an error")
	}
	if got := atomic.LoadInt32(&prompts); got != 1 {
		t.Fatalf("first attempt prompted %d times, want 1", got)
	}

	// A loop retrying immediately gets the pause, NOT another dialog.
	for i := 0; i < 20; i++ {
		_, _, err := s.discloseChallengeOp("grant something wide", OpTrust, c)
		if err == nil {
			t.Fatal("a paused challenge must not succeed")
		}
		if !strings.Contains(err.Error(), "not asking again") {
			t.Fatalf("attempt %d: want the pause message, got %q", i+2, err)
		}
	}
	if got := atomic.LoadInt32(&prompts); got != 1 {
		t.Errorf("a 21-iteration loop put %d dialogs on screen, want 1", got)
	}

	// The key is the op plus the caller's LAUNCHER, not the prompt reason:
	// trustReason renders the caller's own command, so keying on the reason
	// would let a loop mint a fresh key per iteration and out-wait nothing.
	if _, _, err := s.discloseChallengeOp("a completely different reason", OpTrust, c); err == nil ||
		!strings.Contains(err.Error(), "not asking again") {
		t.Errorf("varying the reason must not escape the pause, got %v", err)
	}
	if got := atomic.LoadInt32(&prompts); got != 1 {
		t.Errorf("varying the reason produced %d dialogs, want 1", got)
	}
}

// An approval clears the pause: the point is to make refusing cheap, never to
// lock the operation out. A fresh unlock clears it too (clearDiscloseBackoff),
// on the same "a human at the keyboard is the signal a refusal withheld"
// reasoning the consent backoff already honors.
func TestDisclosedBackoffClearedByApprovalAndUnlock(t *testing.T) {
	var deny atomic.Bool
	deny.Store(true)
	key := bytes.Repeat([]byte{0x42}, 32)
	s := NewServer(filepath.Join(t.TempDir(), "x.sock"), func() MEKFetcher {
		return fnFetcher{fn: func(string) ([]byte, error) {
			if deny.Load() {
				return nil, errors.New("declined")
			}
			k := make([]byte, len(key))
			copy(k, key)
			return k, nil
		}}
	}, time.Minute)
	// A pause long enough that only an explicit clear can end it inside the test.
	s.discloseBackoff = []time.Duration{time.Hour}

	c := &caller{pid: 7, self: lineage.Process{PID: 7, ExecPath: "/bin/tool"}}

	if _, _, err := s.discloseChallengeOp("r", OpGrantCreate, c); err == nil {
		t.Fatal("precondition: the challenge must be declined")
	}
	if err := s.discloseBackoffLocked(OpGrantCreate, c); err == nil {
		t.Fatal("precondition: the pause must be armed")
	}

	// clearDiscloseBackoff is what a FRESH unlock calls.
	s.clearDiscloseBackoff()
	if err := s.discloseBackoffLocked(OpGrantCreate, c); err != nil {
		t.Errorf("a fresh unlock must clear the pause, got %v", err)
	}

	// And an approval clears the key it approved.
	if _, _, err := s.discloseChallengeOp("r", OpGrantCreate, c); err == nil {
		t.Fatal("expected the second decline to re-arm")
	}
	deny.Store(false)
	s.clearDiscloseBackoff() // let the approval through
	if _, mek, err := s.discloseChallengeOp("r", OpGrantCreate, c); err != nil {
		t.Fatalf("approved challenge: %v", err)
	} else {
		wipe(mek)
	}
	if err := s.discloseBackoffLocked(OpGrantCreate, c); err != nil {
		t.Errorf("an approval must leave no pause behind, got %v", err)
	}
}

// TestLazyExpiryStillRecordsTheLock: a session collected lazily (a request
// noticing the expiry before the idle timer's goroutine got there) used to be
// wiped with no KindLock event and no lastLock at all — history showed
// unlock → unlock with nothing between, and the re-prompt had no explanation.
// Recording at collection also survives the usual continuation, where the
// same request goes straight on to a fresh unlock and no timer ever runs for
// the session that ended.
func TestLazyExpiryStillRecordsTheLock(t *testing.T) {
	var events []SessionEvent
	var mu sync.Mutex
	s := NewServer(filepath.Join(t.TempDir(), "x.sock"), func() MEKFetcher {
		return &fakeFetcher{key: bytes.Repeat([]byte{0x42}, 32), calls: new(int32)}
	}, time.Minute)
	s.OnSessionEvent = func(e SessionEvent) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	}

	mek, err := s.ensureUnlocked(OpUnlock, nil, "")
	if err != nil {
		t.Fatalf("ensureUnlocked: %v", err)
	}
	wipe(mek)

	// A use inside the session, still pending in the aggregation window when
	// the session lazily ends — it must land BEFORE the lock in the durable
	// trail, the order lockIfGen documents ("the order it actually
	// happened"), not after it.
	s.recordUse(OpUnwrap, nil, "stripe/live-key")

	// Expire the session in place and stop the timer, modelling the race the
	// bug needed: the timer has not run, and a request arrives.
	s.mu.Lock()
	s.expiry = time.Now().Add(-time.Second)
	if s.lockTimer != nil {
		s.lockTimer.Stop()
	}
	s.mu.Unlock()

	if got := s.touchSession(); got != nil {
		wipe(got)
		t.Fatal("an expired session must not serve the key")
	}

	if _, lastLock := s.provenance(); lastLock == nil {
		t.Error("a lazily-collected session recorded no lastLock: history shows unlock -> unlock with nothing between")
	} else if !strings.Contains(lastLock.Cause, "idle timeout") {
		t.Errorf("lock cause = %q, want the idle timeout that actually ended it", lastLock.Cause)
	}

	mu.Lock()
	defer mu.Unlock()
	var locks int
	lockAt, useAt := -1, -1
	for i, e := range events {
		switch e.Kind {
		case KindLock:
			locks++
			lockAt = i
		case KindUse:
			useAt = i
		}
	}
	if locks != 1 {
		t.Errorf("durable trail got %d lock events, want exactly 1", locks)
	}
	if useAt == -1 {
		t.Error("the session's pending use never reached the durable trail")
	} else if lockAt != -1 && useAt > lockAt {
		t.Errorf("the session's use landed AFTER its lock (use at %d, lock at %d): the trail reordered what happened", useAt, lockAt)
	}
}

// TestDisclosedGrantRefusesAnOldAgent is the fail-closed half that MinProtocol
// structurally cannot cover: an agent old enough to ignore Disclose also
// ignores MinProtocol, so it would perform this machine-wide reveal with no
// prompt at all — the exact silent credential grant the flag exists to
// prevent. The client checks the agent's reported protocol BEFORE sending
// anything, and refuses to ask rather than asking something that cannot
// enforce the answer.
func TestDisclosedGrantRefusesAnOldAgent(t *testing.T) {
	socketPath := shortSocketPath(t)
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = l.Close() }()

	var reveals atomic.Int32
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				var req Request
				if err := json.NewDecoder(conn).Decode(&req); err != nil {
					return
				}
				if req.Op == OpRevealPID {
					reveals.Add(1)
				}
				// A pre-Protocol agent: no protocol field at all, and it
				// would happily serve the reveal.
				_ = json.NewEncoder(conn).Encode(Response{OK: true})
			}()
		}
	}()

	err = NewClient(socketPath).GrantGlobalForPID([]RunMount{{Path: "/x/ADC", Mode: MountModeGrant}}, 4242)
	if err == nil {
		t.Fatal("granting a machine-wide credential through an agent that cannot enforce the disclosed prompt must fail")
	}
	if !strings.Contains(err.Error(), "jit service restart") {
		t.Errorf("the refusal must name the fix, got %q", err)
	}
	if got := reveals.Load(); got != 0 {
		t.Errorf("the reveal was sent %d time(s) to an agent that cannot gate it; it must never leave the client", got)
	}
}

// The same call against a current agent still works, and carries the
// disclosed flag and the MinProtocol requirement — the pre-check must not
// have broken the ordinary path. It must also NOT carry DiscloseReason: the
// legacy trigger briefly rode along "for pre-Disclose agents", but the
// pre-check already refuses every pre-Protocol agent (a superset of that
// era, which release history says never shipped anyway), and a reason
// string on the wire is exactly the caller-visible-text shape the field was
// retired for.
func TestDisclosedGrantSendsRequirementAndLegacyTrigger(t *testing.T) {
	socketPath := shortSocketPath(t)
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = l.Close() }()

	got := make(chan Request, 4)
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				var req Request
				if err := json.NewDecoder(conn).Decode(&req); err != nil {
					return
				}
				got <- req
				_ = json.NewEncoder(conn).Encode(Response{OK: true, Protocol: Protocol})
			}()
		}
	}()

	if err := NewClient(socketPath).GrantGlobalForPID([]RunMount{{Path: "/x/ADC", Mode: MountModeGrant}}, 4242); err != nil {
		t.Fatalf("GrantGlobalForPID against a current agent: %v", err)
	}

	deadline := time.After(5 * time.Second)
	for {
		select {
		case req := <-got:
			if req.Op != OpRevealPID {
				continue // the status pre-check
			}
			if !req.Disclose {
				t.Error("the disclosed flag must still be set")
			}
			if req.MinProtocol < protocolDisclosedGate {
				t.Errorf("MinProtocol = %d, want at least %d so a knowing-but-older agent refuses rather than under-enforcing", req.MinProtocol, protocolDisclosedGate)
			}
			if req.DiscloseReason != "" {
				t.Errorf("DiscloseReason = %q; the deprecated field must stay empty — this version's Client never sends it", req.DiscloseReason)
			}
			return
		case <-deadline:
			t.Fatal("no reveal_pid request arrived")
		}
	}
}

// TestThrottledDisclosedAttemptRecordsNothing is the regression test for a
// real audit-falsification bug the phase-4 review caught: the backoff early
// return handed callers unlockEvent(op, c) — Kind defaulting to KindUnlock —
// and every caller passed it to OnSessionEvent unconditionally, so each
// throttled retry appended a fabricated "unlock" line to the durable trail
// `jit audit` reads: unlocks that never happened, attributed to the caller,
// at connection rate with no cap, and never recorded in the ring (so file
// and ring disagreed). A throttled attempt shows no prompt and must record
// NOTHING; the one real KindDenied from the refusal that armed the pause is
// the whole truth of the episode.
func TestThrottledDisclosedAttemptRecordsNothing(t *testing.T) {
	var events []SessionEvent
	var mu sync.Mutex
	s := NewServer(filepath.Join(t.TempDir(), "x.sock"), func() MEKFetcher {
		return fnFetcher{fn: func(string) ([]byte, error) { return nil, errors.New("declined") }}
	}, time.Minute)
	s.OnSessionEvent = func(e SessionEvent) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	}

	c := &caller{pid: 4242, self: lineage.Process{PID: 4242, ExecPath: "/bin/loop"}}

	// One real declined prompt, then a storm of throttled retries through
	// EVERY caller of discloseChallengeOp.
	if err := s.forceDisclosedChallenge("grant something wide", c); err == nil {
		t.Fatal("the declined challenge must error")
	}
	for i := 0; i < 20; i++ {
		_ = s.forceDisclosedChallenge("grant something wide", c)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 1 || events[0].Kind != KindDenied {
		t.Fatalf("1 real decline + 20 throttled retries recorded %d events (want exactly 1 KindDenied): %+v", len(events), events)
	}
	// And the ring agrees with the file: no unlock ever happened.
	for _, e := range s.history() {
		if e.Kind == KindUnlock {
			t.Fatalf("the in-memory ring carries a fabricated unlock: %+v", e)
		}
	}
}
