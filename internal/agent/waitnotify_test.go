// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"encoding/json"
	"net"
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
