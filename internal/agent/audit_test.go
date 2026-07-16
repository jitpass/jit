// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package agent

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestServerRecordsDeniedChallengeWithProvenance pins the fix for the
// audit hole this file exists around: a challenge the human refused used
// to leave no trace anywhere — history, ring, or log — making "something
// asked for my secrets and I said no; what was it?" unanswerable. The
// denial must land in history AND flow through OnSessionEvent (the
// durable-history path) with the failure as its cause.
func TestServerRecordsDeniedChallengeWithProvenance(t *testing.T) {
	var calls int32
	s := NewServer(shortSocketPath(t), func() MEKFetcher {
		return &fakeFetcher{err: errors.New("user declined the prompt"), calls: &calls}
	}, time.Minute)

	var mu sync.Mutex
	var notified []SessionEvent
	s.OnSessionEvent = func(e SessionEvent) {
		mu.Lock()
		notified = append(notified, e)
		mu.Unlock()
	}

	if _, err := s.ensureUnlocked(OpUnwrap, nil, "stripe/live-key"); err == nil {
		t.Fatal("ensureUnlocked succeeded with a failing fetcher")
	}

	events := s.history()
	if len(events) != 1 {
		t.Fatalf("history has %d events after a denied challenge, want exactly 1 (the denial)", len(events))
	}
	e := events[0]
	if e.Kind != KindDenied {
		t.Errorf("event kind = %q, want %q", e.Kind, KindDenied)
	}
	if e.Op != OpUnwrap {
		t.Errorf("event op = %q, want %q", e.Op, OpUnwrap)
	}
	if !strings.Contains(e.Cause, "user declined") {
		t.Errorf("event cause = %q, want it to carry the challenge failure", e.Cause)
	}
	if len(e.Labels) != 1 || e.Labels[0] != "stripe/live-key" {
		t.Errorf("event labels = %v, want the caller-reported secret name", e.Labels)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(notified) != 1 || notified[0].Kind != KindDenied {
		t.Errorf("OnSessionEvent saw %+v, want exactly the denied event — without it the durable history never records the denial", notified)
	}
}

// TestServerDenialCooldownPausesAutomaticRePrompts pins the prompt-storm
// fix: after a declined challenge, automatic callers must be refused
// without a fresh prompt for the cooldown window; an explicit `jit agent
// unlock` bypasses it; and a successful unlock clears it entirely.
func TestServerDenialCooldownPausesAutomaticRePrompts(t *testing.T) {
	var calls int32
	failing := int32(1)
	key := bytes.Repeat([]byte{0x42}, 32)
	s := NewServer(shortSocketPath(t), func() MEKFetcher {
		if atomic.LoadInt32(&failing) == 1 {
			return &fakeFetcher{err: errors.New("user declined"), calls: &calls}
		}
		return &fakeFetcher{key: key, calls: &calls}
	}, time.Minute)

	// 1. The denial itself: one real challenge, refused.
	if _, err := s.ensureUnlocked(OpUnwrap, nil, ""); err == nil {
		t.Fatal("ensureUnlocked succeeded with a failing fetcher")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("fetcher called %d times, want 1", got)
	}

	// 2. An automatic retry inside the cooldown: refused WITHOUT a prompt.
	_, err := s.ensureUnlocked(OpWrap, nil, "")
	if err == nil {
		t.Fatal("a retry inside the denial cooldown succeeded")
	}
	if !strings.Contains(err.Error(), "paused") || !strings.Contains(err.Error(), "jit agent unlock") {
		t.Errorf("cooldown error = %q, want it to say re-prompts are paused and name the override", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("fetcher called %d times after a cooldown-refused retry, want still 1 — the whole point is NOT prompting", got)
	}

	// 3. Explicit unlock bypasses the cooldown (and succeeds now).
	atomic.StoreInt32(&failing, 0)
	mek, err := s.ensureUnlocked(OpUnlock, nil, "")
	if err != nil {
		t.Fatalf("explicit unlock during cooldown: %v — OpUnlock must bypass the pause", err)
	}
	wipe(mek)
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("fetcher called %d times after explicit unlock, want 2", got)
	}

	// 4. The success cleared the cooldown: lock, then an automatic caller
	// challenges again immediately instead of being refused.
	s.lock("test lock")
	mek, err = s.ensureUnlocked(OpWrap, nil, "")
	if err != nil {
		t.Fatalf("unlock after a successful unlock cleared the denial: %v", err)
	}
	wipe(mek)
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Errorf("fetcher called %d times, want 3 — a successful unlock must clear the cooldown", got)
	}
}

// TestServerCollapsesSessionUsesWithLabels pins the use-audit contract:
// cache-hit operations (the ones history used to be structurally blind
// to) appear as KindUse events, collapsed per caller+op, carrying the
// deduplicated caller-reported labels.
func TestServerCollapsesSessionUsesWithLabels(t *testing.T) {
	_, socketPath, cleanup := startTestServer(t, time.Minute, nil)
	defer cleanup()

	c := NewClient(socketPath)
	if _, _, err := c.Unlock(); err != nil { // the fresh challenge; everything after rides the cache
		t.Fatalf("Unlock: %v", err)
	}

	dek := bytes.Repeat([]byte{0x07}, 32)
	wrapped, err := c.WrapKeyLabeled(dek, "stripe/live-key")
	if err != nil {
		t.Fatalf("WrapKeyLabeled: %v", err)
	}
	if _, err := c.WrapKeyLabeled(dek, "stripe/live-key"); err != nil { // duplicate label — must dedupe
		t.Fatalf("WrapKeyLabeled: %v", err)
	}
	if _, err := c.WrapKeyLabeled(dek, "aws/s3-key"); err != nil {
		t.Fatalf("WrapKeyLabeled: %v", err)
	}
	if _, err := c.UnwrapKeyLabeled(wrapped, "stripe/live-key"); err != nil {
		t.Fatalf("UnwrapKeyLabeled: %v", err)
	}

	events, err := c.History()
	if err != nil {
		t.Fatalf("History: %v", err)
	}

	var wrapUse, unwrapUse *SessionEvent
	for i := range events {
		e := &events[i]
		if e.Kind != KindUse {
			continue
		}
		switch e.Op {
		case OpWrap:
			wrapUse = e
		case OpUnwrap:
			unwrapUse = e
		}
	}
	if wrapUse == nil {
		t.Fatalf("no wrap use event in history %+v — cache-hit wraps left no record", events)
	}
	if wrapUse.Count != 3 {
		t.Errorf("wrap use count = %d, want 3 (collapsed into one event)", wrapUse.Count)
	}
	wantLabels := []string{"stripe/live-key", "aws/s3-key"}
	if len(wrapUse.Labels) != len(wantLabels) || wrapUse.Labels[0] != wantLabels[0] || wrapUse.Labels[1] != wantLabels[1] {
		t.Errorf("wrap use labels = %v, want %v (deduplicated, first-seen order)", wrapUse.Labels, wantLabels)
	}
	if wrapUse.By == "" || wrapUse.ByPID == 0 {
		t.Errorf("wrap use event carries no caller provenance: %+v", wrapUse)
	}
	if unwrapUse == nil {
		t.Fatal("no unwrap use event in history — cache-hit unwraps left no record")
	}
	if unwrapUse.Count != 1 || len(unwrapUse.Labels) != 1 || unwrapUse.Labels[0] != "stripe/live-key" {
		t.Errorf("unwrap use event = %+v, want count 1 with the one label", unwrapUse)
	}
}

// TestServerFlushesPendingUsesOnLock pins that the lock — the session
// boundary — flushes the pending use aggregates BEFORE recording itself,
// so history reads "locked, used, unlocked" (newest first) in the order
// things actually happened, and a crash right after a lock has already
// durably recorded what the session was used for.
func TestServerFlushesPendingUsesOnLock(t *testing.T) {
	_, socketPath, cleanup := startTestServer(t, time.Minute, nil)
	defer cleanup()

	c := NewClient(socketPath)
	if _, _, err := c.Unlock(); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if _, err := c.WrapKeyLabeled(bytes.Repeat([]byte{0x07}, 32), "a/b"); err != nil {
		t.Fatalf("WrapKeyLabeled: %v", err)
	}
	if err := c.Lock(); err != nil {
		t.Fatalf("Lock: %v", err)
	}

	events, err := c.History()
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("history has %d events, want 3 (lock, use, unlock newest-first): %+v", len(events), events)
	}
	if events[0].Kind != KindLock || events[1].Kind != KindUse || events[2].Kind != KindUnlock {
		t.Errorf("history order = [%s %s %s], want [lock use unlock] — the lock must flush uses before recording itself", events[0].Kind, events[1].Kind, events[2].Kind)
	}
}

// TestServerUnlockEventCarriesLabel pins that a FRESH challenge caused by
// a labeled operation records the label on the unlock event itself — the
// unlock IS that operation's record; no separate use event should exist.
func TestServerUnlockEventCarriesLabel(t *testing.T) {
	_, socketPath, cleanup := startTestServer(t, time.Minute, nil)
	defer cleanup()

	c := NewClient(socketPath)
	if _, err := c.WrapKeyLabeled(bytes.Repeat([]byte{0x07}, 32), "npm/token"); err != nil {
		t.Fatalf("WrapKeyLabeled: %v", err)
	}

	events, err := c.History()
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("history has %d events, want 1 (just the unlock): %+v", len(events), events)
	}
	e := events[0]
	if e.Kind != KindUnlock || e.Op != OpWrap {
		t.Errorf("event = %+v, want an unlock with op wrap", e)
	}
	if len(e.Labels) != 1 || e.Labels[0] != "npm/token" {
		t.Errorf("unlock labels = %v, want the operation's label", e.Labels)
	}
}

// TestClientDialRetryRidesOutRestartGap pins WithDialRetry's purpose: a
// client that knows the agent is supposed to exist keeps dialing through
// the launchd respawn gap (agent restart, stale-binary self-retirement)
// instead of concluding ErrNotRunning — which callers translate into a
// surprise independent Touch ID prompt.
func TestClientDialRetryRidesOutRestartGap(t *testing.T) {
	socketPath := shortSocketPath(t)

	// The "respawn": the server starts answering only after a gap.
	s := NewServer(socketPath, func() MEKFetcher {
		return &fakeFetcher{key: bytes.Repeat([]byte{0x42}, 32)}
	}, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		time.Sleep(300 * time.Millisecond)
		if err := s.Listen(); err != nil {
			t.Errorf("Listen: %v", err)
			return
		}
		_ = s.Serve(ctx)
	}()
	defer func() { cancel(); _ = s.Close(); <-done }()

	// Without retry: fails during the gap.
	if _, err := NewClient(socketPath).Status(); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("Status during the gap without retry = %v, want ErrNotRunning", err)
	}

	// With retry: rides it out.
	c := NewClient(socketPath).WithDialRetry(2 * time.Second)
	if _, err := c.Status(); err != nil {
		t.Fatalf("Status with dial retry = %v, want success once the agent binds", err)
	}
}
