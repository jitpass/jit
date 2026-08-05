// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package agent

import (
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// replyAfter starts a one-shot unix listener that accepts a single
// connection, reads the request, waits delay, then sends an OK response.
// It stands in for the real Server so these tests exercise only the
// Client's blocked-call timing, with no keychain in the loop.
func replyAfter(t *testing.T, delay time.Duration) string {
	t.Helper()
	// shortSocketPath keeps us clear of the unix-socket sun_path length
	// limit that a nested t.TempDir() path blows past on macOS/BSD.
	socketPath := shortSocketPath(t)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	// shortSocketPath already registers the file's removal; we just close
	// the listener so a leftover goroutine can't outlive the test.
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		var req Request
		_ = json.NewDecoder(conn).Decode(&req)
		time.Sleep(delay)
		_ = json.NewEncoder(conn).Encode(Response{OK: true})
	}()
	return socketPath
}

func TestWaitNotifierFiresWhenTheAgentBlocks(t *testing.T) {
	// A reply that lands well after waitNotifyDelay is the shape of a call
	// stuck behind a Touch ID prompt: the notifier must fire exactly once.
	socketPath := replyAfter(t, waitNotifyDelay+300*time.Millisecond)

	var fired int32
	c := NewClient(socketPath).WithWaitNotifier(func() { atomic.AddInt32(&fired, 1) })

	if _, _, err := c.Unlock(); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if got := atomic.LoadInt32(&fired); got != 1 {
		t.Fatalf("wait notifier fired %d times, want exactly 1", got)
	}
}

func TestWaitNotifierStaysSilentOnAPromptFreeCall(t *testing.T) {
	// A reply that beats waitNotifyDelay means no prompt appeared, so the
	// notifier must not fire — the guarantee that keeps it from claiming a
	// challenge that never happened.
	socketPath := replyAfter(t, 0)

	var fired int32
	c := NewClient(socketPath).WithWaitNotifier(func() { atomic.AddInt32(&fired, 1) })

	if _, _, err := c.Unlock(); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	// Give any errantly-scheduled timer the chance to misfire before we check.
	time.Sleep(waitNotifyDelay + 100*time.Millisecond)
	if got := atomic.LoadInt32(&fired); got != 0 {
		t.Fatalf("wait notifier fired %d times on a fast call, want 0", got)
	}
}

// A bounded client giving up on a stalled call must say what the stall almost
// certainly was — a prompt nobody answered — and be errors.Is-matchable so a
// caller can rewrite it. The notifier still fires first, so a captured-stderr
// log shows the explanation and THEN the failure, in that order.
func TestBoundedClientGivesUpWithPromptUnanswered(t *testing.T) {
	socketPath := replyAfter(t, 2*time.Second) // "stuck behind a prompt"

	var notified int32
	c := NewClient(socketPath).
		WithWaitNotifier(func() { atomic.AddInt32(&notified, 1) }).
		WithResponseTimeout(600 * time.Millisecond)

	start := time.Now()
	_, _, err := c.Unlock()
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Unlock succeeded against a server that never answered in time")
	}
	if !errors.Is(err, ErrPromptUnanswered) {
		t.Errorf("err = %v, want errors.Is(_, ErrPromptUnanswered)", err)
	}
	if !strings.Contains(err.Error(), "jit unlock") {
		t.Errorf("err = %v, want the actionable `jit unlock` hint in the message", err)
	}
	if elapsed >= 2*time.Second {
		t.Errorf("gave up after %v, want well before the server's 2s reply", elapsed)
	}
	if atomic.LoadInt32(&notified) != 1 {
		t.Errorf("wait notifier fired %d times, want 1 (the log needs the explanation before the failure)", notified)
	}
}

// A reply that lands inside the bound is a normal call: no error, no
// ErrPromptUnanswered, nothing different from the unbounded client.
func TestBoundedClientStillWaitsOutAQuickPrompt(t *testing.T) {
	socketPath := replyAfter(t, 200*time.Millisecond)
	c := NewClient(socketPath).WithResponseTimeout(2 * time.Second)
	if _, _, err := c.Unlock(); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
}

// WithResponseTimeout may only LOWER the wait. A value at or above the
// default would relabel a genuine anomaly (the 130s ceiling blowing) as
// "prompt unanswered", which is a different problem with a different fix.
func TestWithResponseTimeoutOnlyLowers(t *testing.T) {
	c := NewClient("ignored").WithResponseTimeout(responseTimeout + time.Minute)
	if c.bounded || c.respTimeout != responseTimeout {
		t.Errorf("respTimeout/bounded = %v/%v, want the default kept", c.respTimeout, c.bounded)
	}
	c = NewClient("ignored").WithResponseTimeout(0)
	if c.bounded {
		t.Error("a zero timeout must be a no-op, not an instant give-up")
	}
}
