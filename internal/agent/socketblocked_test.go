// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// blockedSocket stands up a real listening server and then makes the connect
// fail with a permission error, the way a sandbox does — by taking search
// permission off the socket's parent directory, which yields EACCES on
// connect for exactly the same reason seatbelt's `(deny network-outbound)`
// yields EPERM: something other than the server refused us.
//
// A real listener, not a bare path, is the whole point: the server is UP for
// every assertion below, so a result of ErrNotRunning would be a lie about a
// live service — the bug these tests exist to keep fixed.
func blockedSocket(t *testing.T) (path string, unblock func()) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory modes, so the block below never bites")
	}
	dir := filepath.Join("/tmp", fmt.Sprintf("jit-blocked-%d-%d", os.Getpid(), time.Now().UnixNano()))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	path = filepath.Join(dir, "agent.sock")

	s := NewServer(path, func() MEKFetcher {
		return &fakeFetcher{key: bytes.Repeat([]byte{0x42}, 32)}
	}, time.Minute)
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Serve(ctx) }()

	restore := func() { _ = os.Chmod(dir, 0o700) }
	t.Cleanup(func() {
		restore()
		cancel()
		_ = s.Close()
		<-done
		_ = os.RemoveAll(dir)
	})

	// Sanity: the server really is answering before we wall it off. Without
	// this, a broken server would make every assertion below pass for the
	// wrong reason.
	if _, err := NewClient(path).Status(); err != nil {
		t.Fatalf("Status before blocking = %v, want success (the server must be up for this test to mean anything)", err)
	}
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	return path, restore
}

// TestBlockedSocketIsNotReportedAsNotRunning is the regression proper: a
// refused connect must answer ErrSocketBlocked, never ErrNotRunning. Getting
// this wrong told sandboxed callers their service had stopped and sent them
// to `jit service restart` for a service that was running the whole time.
func TestBlockedSocketIsNotReportedAsNotRunning(t *testing.T) {
	path, _ := blockedSocket(t)

	_, err := NewClient(path).Status()
	if !errors.Is(err, ErrSocketBlocked) {
		t.Errorf("Status on a blocked socket = %v, want ErrSocketBlocked", err)
	}
	if errors.Is(err, ErrNotRunning) {
		t.Errorf("Status on a blocked socket also matched ErrNotRunning (%v): the two states take opposite fixes and must stay distinguishable", err)
	}
}

// TestAbsentSocketStillReportsNotRunning is the negative control for the test
// above: the classification must not have swallowed the ordinary case. A
// socket that nothing is listening on is still ErrNotRunning, and must NOT
// come back as blocked — otherwise a genuinely dead service would be reported
// as a sandbox problem, trading one wrong answer for another.
func TestAbsentSocketStillReportsNotRunning(t *testing.T) {
	// Two shapes of "not running": the service exited and cleaned up its
	// socket (ENOENT), and it died leaving the file behind (ECONNREFUSED).
	t.Run("no socket file", func(t *testing.T) {
		path := shortSocketPath(t)
		_, err := NewClient(path).Status()
		if !errors.Is(err, ErrNotRunning) {
			t.Errorf("Status with no socket = %v, want ErrNotRunning", err)
		}
		if errors.Is(err, ErrSocketBlocked) {
			t.Errorf("Status with no socket matched ErrSocketBlocked (%v), want a plain not-running", err)
		}
	})

	t.Run("stale socket file", func(t *testing.T) {
		path := shortSocketPath(t)
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		_, err := NewClient(path).Status()
		if !errors.Is(err, ErrNotRunning) {
			t.Errorf("Status on a stale socket = %v, want ErrNotRunning", err)
		}
		if errors.Is(err, ErrSocketBlocked) {
			t.Errorf("Status on a stale socket matched ErrSocketBlocked (%v), want a plain not-running", err)
		}
	})
}

// TestBlockedSocketSkipsHealAndRetry pins the second half of the fix. A
// blocked dial must not fire the dial-failed hook (whose CLI implementation
// demands a launchd start of a service that never stopped) and must not burn
// the retry window, since the policy refusing this connect will refuse the
// next one identically.
func TestBlockedSocketSkipsHealAndRetry(t *testing.T) {
	path, _ := blockedSocket(t)

	healed := 0
	c := NewClient(path).
		WithDialRetry(2 * time.Second).
		WithDialFailedHook(func() time.Duration { healed++; return 0 })

	start := time.Now()
	_, err := c.Status()
	elapsed := time.Since(start)

	if !errors.Is(err, ErrSocketBlocked) {
		t.Fatalf("Status = %v, want ErrSocketBlocked", err)
	}
	if healed != 0 {
		t.Errorf("dial-failed hook fired %d times on a blocked socket, want 0: restarting a running service is the wrong fix", healed)
	}
	// Generous bound: the assertion is "returned immediately rather than
	// waiting out the 2s window", not a latency budget.
	if elapsed > time.Second {
		t.Errorf("blocked dial took %s, want an immediate return: re-dialing a policy denial only spends the caller's time", elapsed)
	}
}

// TestReachableFalseOnBlockedSocket covers the other entry point into dial.
// Reachable is what decides between the shared session and an independent
// local unlock, and on a blocked socket the honest answer is false: this
// process cannot use that session no matter who else can.
func TestReachableFalseOnBlockedSocket(t *testing.T) {
	path, unblock := blockedSocket(t)

	if NewClient(path).Reachable() {
		t.Error("Reachable on a blocked socket = true, want false")
	}
	// And back again, to prove the block was what the probe answered rather
	// than a server that had quietly died during the test.
	unblock()
	if !NewClient(path).Reachable() {
		t.Error("Reachable after unblocking = false, want true: the server was up the whole time")
	}
}
