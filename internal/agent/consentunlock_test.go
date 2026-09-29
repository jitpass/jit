// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package agent

import (
	"bytes"
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/consent"
	"github.com/jitpass/jit/internal/lineage"
)

// promptLog is a fetcher that records every prompt's sentence, approves
// unless decline is set, and hands out one fixed key.
type promptLog struct {
	mu      sync.Mutex
	reasons []string
	decline atomic.Bool
}

func (p *promptLog) fetcher() MEKFetcher {
	key := bytes.Repeat([]byte{0x42}, 32)
	return fnFetcher{fn: func(reason string) ([]byte, error) {
		p.mu.Lock()
		p.reasons = append(p.reasons, reason)
		p.mu.Unlock()
		if p.decline.Load() {
			return nil, errConsentDeclined
		}
		k := make([]byte, len(key))
		copy(k, key)
		return k, nil
	}}
}

func (p *promptLog) since(n int) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.reasons[n:]...)
}

func (p *promptLog) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.reasons)
}

// startUnlockConsentServer is startConsentServer with a prompt log in place
// of the reason-keyed fixture, so a test can count the prompts one request
// cost and read what each said.
func startUnlockConsentServer(t *testing.T) (*Server, *Client, *promptLog) {
	t.Helper()
	log := &promptLog{}
	s := NewServer(shortSocketPath(t), log.fetcher, time.Minute)
	s.Consent = consent.New(time.Minute)
	s.discloseBackoff = nil
	s.identify = func(conn net.Conn) *caller {
		c := callerFromConn(conn)
		if c != nil {
			c.ancestors = []lineage.Process{{PID: 424242, ExecPath: "/usr/local/bin/aws"}}
		}
		return c
	}
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx); close(done) }()
	t.Cleanup(func() { cancel(); _ = s.Close(); <-done })
	return s, NewClient(s.socketPath), log
}

// wrapThenLock stores an aws-class key (which unlocks) and locks again, so
// the next unwrap meets a locked vault and a consent gate at once.
func wrapThenLock(t *testing.T, s *Server, c *Client) []byte {
	t.Helper()
	wrapped, err := c.WrapKeyLabeled(bytes.Repeat([]byte{0x07}, 32), "aws/default/key", "aws")
	if err != nil {
		t.Fatalf("WrapKeyLabeled: %v", err)
	}
	s.LockWithCause("test re-lock")
	if s.SessionUnlocked() {
		t.Fatal("setup: the vault should be locked")
	}
	return wrapped
}

// The case this exists for: a gated credential read on a locked vault used to
// cost two Touch IDs, the consent prompt (whose key was thrown away) and then
// an unlock for the same request. It is one prompt now, which says it
// unlocks, and whose approval leaves the session open.
func TestLockedConsentAsksOnceAndUnlocks(t *testing.T) {
	s, c, log := startUnlockConsentServer(t)
	wrapped := wrapThenLock(t, s, c)
	var fresh atomic.Int32
	s.OnUnlock = func() { fresh.Add(1) }
	before := log.count()

	got, err := c.UnwrapKeyLabeled(wrapped, "aws/default/key", "aws")
	if err != nil || !bytes.Equal(got, bytes.Repeat([]byte{0x07}, 32)) {
		t.Fatalf("unwrap: got %x err %v, want the key", got, err)
	}
	// The session it opened is a fresh unlock like any other: the mounts
	// resolve (OnUnlock), exactly once.
	if n := fresh.Load(); n != 1 {
		t.Errorf("OnUnlock ran %d times after the combined prompt opened the session, want 1", n)
	}
	prompts := log.since(before)
	if len(prompts) != 1 {
		t.Fatalf("a consent read on a locked vault cost %d prompts, want 1: %q", len(prompts), prompts)
	}
	if !strings.Contains(prompts[0], "use your aws credential"+unlockAsWell) {
		t.Errorf("the one prompt must say it also unlocks; got %q", prompts[0])
	}
	if strings.HasPrefix(prompts[0], "unlock the vault") {
		t.Errorf("the prompt must not LEAD with the unlock (it would read as a plain unlock): %q", prompts[0])
	}
	if !s.SessionUnlocked() {
		t.Error("the approval should have opened the session")
	}

	// The trail records both facts, in order: the approval, then the unlock
	// it caused.
	events, err := c.History()
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	approved, unlocked := -1, -1
	for i, e := range events {
		switch {
		case e.Kind == KindApproved && strings.Contains(e.Cause, unlockAsWell):
			approved = i
		case e.Kind == KindUnlock && approved >= 0 && unlocked < 0:
			unlocked = i
		}
	}
	if approved < 0 || unlocked < 0 {
		t.Errorf("want an approval followed by an unlock in history; approved at %d, unlock at %d", approved, unlocked)
	}
}

// With the vault already unlocked, nothing is being unlocked, so the prompt
// must not say so: it would claim an authority the approval does not grant.
func TestUnlockedConsentDoesNotSayUnlock(t *testing.T) {
	_, c, log := startUnlockConsentServer(t)
	wrapped, err := c.WrapKeyLabeled(bytes.Repeat([]byte{0x07}, 32), "aws/default/key", "aws")
	if err != nil {
		t.Fatalf("WrapKeyLabeled: %v", err)
	}
	before := log.count()
	if _, err := c.UnwrapKeyLabeled(wrapped, "aws/default/key", "aws"); err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	prompts := log.since(before)
	if len(prompts) != 1 {
		t.Fatalf("want 1 consent prompt, got %d: %q", len(prompts), prompts)
	}
	if strings.Contains(prompts[0], "unlock") {
		t.Errorf("an unlocked vault's consent prompt mentions unlocking: %q", prompts[0])
	}
}

// Declining the one prompt refuses both halves: no credential, and the vault
// stays locked. No second prompt follows it.
func TestDeclinedCombinedPromptLeavesVaultLocked(t *testing.T) {
	s, c, log := startUnlockConsentServer(t)
	wrapped := wrapThenLock(t, s, c)
	before := log.count()

	log.decline.Store(true)
	if _, err := c.UnwrapKeyLabeled(wrapped, "aws/default/key", "aws"); err == nil {
		t.Fatal("a declined prompt granted the read")
	}
	if n := len(log.since(before)); n != 1 {
		t.Errorf("a declined read cost %d prompts, want 1", n)
	}
	if s.SessionUnlocked() {
		t.Error("a declined prompt opened the session")
	}
}

// Inside the denial cooldown the human just refused an unlock, so the unlock
// is not folded into another question. The consent prompt is today's plain
// one, and the request's own unlock is turned away by the cooldown as before.
func TestDenialCooldownKeepsTheUnlockOutOfTheConsentPrompt(t *testing.T) {
	s, c, log := startUnlockConsentServer(t)
	wrapped := wrapThenLock(t, s, c)
	s.mu.Lock()
	s.lastDenied = time.Now()
	s.lastDeniedCause = "test: refused"
	s.mu.Unlock()
	before := log.count()

	if _, err := c.UnwrapKeyLabeled(wrapped, "aws/default/key", "aws"); err == nil {
		t.Fatal("inside the cooldown the read should fail at the unlock")
	}
	prompts := log.since(before)
	if len(prompts) != 1 {
		t.Fatalf("want exactly the consent prompt, got %d: %q", len(prompts), prompts)
	}
	if strings.Contains(prompts[0], "unlock") {
		t.Errorf("inside the cooldown the consent prompt offered an unlock: %q", prompts[0])
	}
	if s.SessionUnlocked() {
		t.Error("the cooldown was bypassed: the session is open")
	}
}

// adoptDisclosedSession must never replace a live session: the only way one
// could exist is a race it is written to lose gracefully, and replacing it
// would restart the session's clock and ceiling on a key nobody asked for.
func TestAdoptNeverReplacesALiveSession(t *testing.T) {
	s, c, _ := startUnlockConsentServer(t)
	if _, err := c.WrapKeyLabeled(bytes.Repeat([]byte{0x07}, 32), "aws/default/key", "aws"); err != nil {
		t.Fatalf("WrapKeyLabeled: %v", err)
	}
	s.mu.Lock()
	start := s.sessionStart
	s.mu.Unlock()

	other := bytes.Repeat([]byte{0x99}, 32)
	s.challengeMu.Lock()
	ev := s.adoptDisclosedSession(other, OpUnwrap, nil, "")
	s.challengeMu.Unlock()
	if ev != nil {
		t.Error("adopt reported an unlock over a live session")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if bytes.Equal(s.mek, other) {
		t.Error("adopt replaced the live session's key")
	}
	if !s.sessionStart.Equal(start) {
		t.Error("adopt restarted the live session's clock")
	}
}

// The unlock rides in the protected head, so no caller-chosen length pushes
// it out of the dialog, and the sentence still fits.
func TestUnlockWordingSurvivesTruncation(t *testing.T) {
	for _, class := range []string{"aws", "shell_history", "k8s_secret", "1password"} {
		for _, n := range []int{0, 1, 12} {
			got := consentReasonFor(consent.Request{
				Credential:    class,
				PriorRefusals: n,
				Caller: consent.Caller{
					PID:      1,
					ExecPath: "/Users/someone/" + strings.Repeat("very-long-directory/", 8) + "tool",
					Lineage:  "launched by " + strings.Repeat("x", 60),
					Strength: consent.Hard,
				},
			}, true)
			if !strings.Contains(got, class+" credential"+unlockAsWell) {
				t.Errorf("class=%s n=%d: the unlock was cut from %q", class, n, got)
			}
			if !strings.HasSuffix(got, "tool") && !strings.Contains(got, "tool,") {
				t.Errorf("class=%s n=%d: the caller's own name was cut from %q", class, n, got)
			}
			if len([]rune(got)) > maxReasonLen {
				t.Errorf("class=%s n=%d: %d runes, want <= %d: %q", class, n, len([]rune(got)), maxReasonLen, got)
			}
		}
	}

	s := NewServer(shortSocketPath(t), func() MEKFetcher { return nil }, time.Minute)
	s.OnDescribeGrant = func([]RunMount) string { return strings.Repeat("a very long credential description ", 5) }
	got := s.grantReasonFor(nil, true)
	if !strings.HasSuffix(got, unlockAsWell) {
		t.Errorf("--with: the unlock was cut from %q", got)
	}
	if len([]rune(got)) > maxReasonLen {
		t.Errorf("--with: %d runes, want <= %d: %q", len([]rune(got)), maxReasonLen, got)
	}
}

// lapse ends the session the way a busy agent sees it end: past its expiry,
// with the idle timer neutralized, so the first request to look collects it
// lazily (collectIfDoneLocked) and no lockIfGen ever runs for it.
func lapse(s *Server) {
	s.mu.Lock()
	s.expiry = time.Now().Add(-time.Second)
	s.timerGen++
	s.mu.Unlock()
}

// A session that lapsed without its timer (collected lazily by a request)
// ends the approvals that rode in it, as a lock does. It used to leave them to
// a stale timer that never runs once the next unlock re-arms it, so an
// approval carried into the next session. And the combined prompt that
// follows is still remembered: the lapse is settled before the consent
// engine decides, so its clear never overtakes the new answer.
func TestLapsedSessionEndsItsApprovalsAndTheNextOneSticks(t *testing.T) {
	s, c, log := startUnlockConsentServer(t)
	wrapped, err := c.WrapKeyLabeled(bytes.Repeat([]byte{0x07}, 32), "aws/default/key", "aws")
	if err != nil {
		t.Fatalf("WrapKeyLabeled: %v", err)
	}
	if _, err := c.UnwrapKeyLabeled(wrapped, "aws/default/key", "aws"); err != nil {
		t.Fatalf("first read: %v", err) // approves aws for this session
	}
	lapse(s)
	before := log.count()

	if _, err := c.UnwrapKeyLabeled(wrapped, "aws/default/key", "aws"); err != nil {
		t.Fatalf("read after the lapse: %v", err)
	}
	prompts := log.since(before)
	if len(prompts) != 1 || !strings.Contains(prompts[0], "use your aws credential"+unlockAsWell) {
		t.Fatalf("after a lapse the approval must be asked again, with the unlock, in one prompt; got %q", prompts)
	}

	before = log.count()
	if _, err := c.UnwrapKeyLabeled(wrapped, "aws/default/key", "aws"); err != nil {
		t.Fatalf("read after re-approval: %v", err)
	}
	if n := len(log.since(before)); n != 0 {
		t.Errorf("the approval given after the lapse was not remembered: %d more prompt(s)", n)
	}
}

// jit run --with on a locked vault: one prompt naming the credential and the
// unlock, and the run proceeds on the session it opened.
func TestGrantGlobalOnLockedVaultAsksOnce(t *testing.T) {
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
	if err := c.GrantGlobalForPID([]RunMount{{Path: "/x/ADC", Mode: MountModeGrant}}, 4242); err != nil {
		t.Fatalf("GrantGlobalForPID: %v", err)
	}
	fetcher.mu.Lock()
	reasons := append([]string(nil), fetcher.reasons...)
	fetcher.mu.Unlock()
	want := "grant this run access to your gcp credential on this machine" + unlockAsWell
	if len(reasons) != 1 || reasons[0] != want {
		t.Errorf("reasons = %q, want exactly [%q]", reasons, want)
	}
	if atomic.LoadInt32(&granted) != 1 {
		t.Error("the grant did not go through")
	}
	if !s.SessionUnlocked() {
		t.Error("the approval should have opened the session")
	}
}

// gateConsent settles a lapsed session itself, before deciding. On an unwrap
// verifyClassBinding happens to settle it first, which is why this calls the
// gate directly: the gate must not depend on who ran before it. Without its
// own settle, collecting the lapse inside the prompt would clear consent
// after the engine read its clear count, and the new approval would be
// dropped, so the very next read asked again.
func TestGateSettlesALapseBeforeDeciding(t *testing.T) {
	s, c, log := startUnlockConsentServer(t)
	if _, err := c.WrapKeyLabeled(bytes.Repeat([]byte{0x07}, 32), "aws/default/key", "aws"); err != nil {
		t.Fatalf("WrapKeyLabeled: %v", err)
	}
	who := &caller{
		pid:       424242,
		self:      lineage.Process{PID: 424242, ExecPath: "/usr/local/bin/aws"},
		ancestors: []lineage.Process{{PID: 424243, ExecPath: "/usr/local/bin/aws"}},
	}
	lapse(s)
	before := log.count()
	if err := s.gateConsent("aws", who, OpUnwrap); err != nil {
		t.Fatalf("gate after the lapse: %v", err)
	}
	if err := s.gateConsent("aws", who, OpUnwrap); err != nil {
		t.Fatalf("gate again: %v", err)
	}
	if n := len(log.since(before)); n != 1 {
		t.Errorf("two reads after a lapse cost %d prompts, want 1 (the approval must stick)", n)
	}
}
