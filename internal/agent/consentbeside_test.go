// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package agent

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/authprompt"
	"github.com/jitpass/jit/internal/consent"
	"github.com/jitpass/jit/internal/lineage"
)

// dialog is a fake Touch ID that can be withdrawn, as both key stores' can.
// answer decides each prompt: nil approves. It gets the prompt's withdraw
// channel (nil on a plain FetchMEK), so it can wait on the test, on the
// withdrawal, or ignore it the way a finger that already won the race does.
type dialog struct {
	key   []byte
	plain bool // no FetchMEKCancel, like a test double or an old fetcher

	mu        sync.Mutex
	reasons   []string
	viaCancel int
	handedOut [][]byte
	answer    func(withdraw <-chan struct{}) error
	raised    chan struct{}
}

func newDialog() *dialog {
	return &dialog{key: bytes.Repeat([]byte{0x42}, 32), raised: make(chan struct{}, 16)}
}

func (d *dialog) setAnswer(fn func(withdraw <-chan struct{}) error) {
	d.mu.Lock()
	d.answer = fn
	d.mu.Unlock()
}

func (d *dialog) prompt(reason string, withdraw <-chan struct{}, cancelable bool) ([]byte, error) {
	d.mu.Lock()
	d.reasons = append(d.reasons, reason)
	if cancelable {
		d.viaCancel++
	}
	answer := d.answer
	d.mu.Unlock()
	d.raised <- struct{}{}
	if answer != nil {
		if err := answer(withdraw); err != nil {
			return nil, err
		}
	}
	k := append([]byte(nil), d.key...)
	d.mu.Lock()
	d.handedOut = append(d.handedOut, k)
	d.mu.Unlock()
	return k, nil
}

func (d *dialog) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.reasons)
}

func (d *dialog) lastReason() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.reasons[len(d.reasons)-1]
}

type cancelableDialog struct{ d *dialog }

func (f cancelableDialog) FetchMEK(reason string) ([]byte, error) {
	return f.d.prompt(reason, nil, false)
}

func (f cancelableDialog) FetchMEKCancel(reason string, withdraw <-chan struct{}) ([]byte, error) {
	return f.d.prompt(reason, withdraw, true)
}

type plainDialog struct{ d *dialog }

func (f plainDialog) FetchMEK(reason string) ([]byte, error) { return f.d.prompt(reason, nil, false) }

func (d *dialog) fetcher() MEKFetcher {
	if d.plain {
		return plainDialog{d}
	}
	return cancelableDialog{d}
}

// untilWithdrawnOr holds the dialog up until the withdrawal (then fails as
// the key stores do) or until approve is closed.
func untilWithdrawnOr(approve <-chan struct{}) func(<-chan struct{}) error {
	return func(withdraw <-chan struct{}) error {
		select {
		case <-withdraw:
			return authprompt.Outcome(errors.New("Authentication canceled."), true)
		case <-approve:
			return nil
		}
	}
}

// startBesideServer is a server whose disclosed challenges (`trust`, a gated
// unwrap) prompt through d. The broker wait is long, so a test that finishes
// quickly proves the answer was not awaited.
func startBesideServer(t *testing.T, d *dialog, shownWait time.Duration, configure func(*Server)) (*Server, *Client) {
	t.Helper()
	s := NewServer(shortSocketPath(t), d.fetcher, time.Minute)
	s.Consent = consent.New(time.Minute)
	s.discloseBackoff = nil
	s.brokerWait = 30 * time.Second
	s.shownWait = shownWait
	s.identify = func(conn net.Conn) *caller {
		c := callerFromConn(conn)
		if c != nil {
			c.ancestors = []lineage.Process{{PID: 424242, ExecPath: "/usr/local/bin/aws"}}
		}
		return c
	}
	if configure != nil {
		configure(s)
	}
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx); close(done) }()
	t.Cleanup(func() { cancel(); _ = s.Close(); <-done })
	return s, NewClient(s.socketPath)
}

// panelBroker subscribes the way the menu bar app does once it shows requests
// beside the Touch ID, and hands the test every pending request.
func panelBroker(t *testing.T, s *Server, c *Client, want int) (pending <-chan SessionEvent, stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan SessionEvent, 16)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = c.SubscribeBesideTouchID(ctx, func(e SessionEvent) {
			if e.Kind == KindPending {
				ch <- e
			}
		})
	}()
	waitFor(t, "panel broker to register", func() bool { return s.brokerCount() == want })
	var once sync.Once
	return ch, func() { once.Do(func() { cancel(); <-done }) }
}

func receive[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
	var zero T
	return zero
}

func nothingOn[T any](t *testing.T, ch <-chan T, within time.Duration, what string) {
	t.Helper()
	select {
	case <-ch:
		t.Fatalf("%s, want none", what)
	case <-time.After(within):
	}
}

// The change itself: the Touch ID appears as soon as the panel says it has
// drawn the request, with no Allow in front of it, and its sentence is the
// full one (nothing was confirmed first, so no "confirm:").
func TestBesideTouchIDAppearsWhenShownWithoutAnAllow(t *testing.T) {
	d := newDialog()
	s, c := startBesideServer(t, d, 5*time.Second, nil)
	pending, stop := panelBroker(t, s, c, 1)
	defer stop()

	errc := make(chan error, 1)
	go func() { errc <- c.Trust() }()
	req := receive(t, pending, "the pending request")
	if !req.TouchIDFollows || req.ConsentID == "" {
		t.Fatalf("pending = %+v, want TouchIDFollows and a consent id", req)
	}
	shownAt := time.Now()
	if err := c.ConsentShown(req.ConsentID); err != nil {
		t.Fatalf("ConsentShown: %v", err)
	}
	receive(t, d.raised, "the Touch ID")
	if waited := time.Since(shownAt); waited > time.Second {
		t.Errorf("the Touch ID appeared %s after consent_shown, want at once (the 5 s cap must not apply)", waited)
	}
	if err := receive(t, errc, "trust"); err != nil {
		t.Fatalf("trust approved by the fingerprint: %v", err)
	}
	if got := d.lastReason(); got != req.Cause || strings.HasPrefix(got, "confirm: ") {
		t.Errorf("dialog said %q, want the full sentence the panel showed, %q", got, req.Cause)
	}
	if d.viaCancel != 1 {
		t.Errorf("prompts raised withdrawably = %d, want 1: a panel Deny could not take it down", d.viaCancel)
	}
	if e := lastEvent(t, c); e.Kind != KindApproved || e.ConsentID != req.ConsentID || e.AuthMethod == "" {
		t.Errorf("outcome = %+v, want approved, the same consent id, and an auth method", e)
	}
	if err := c.ConsentAnswer(req.ConsentID, false); err == nil {
		t.Error("a Deny after the approval was answered OK")
	}
}

// The last deny check and taking the request off the table are one step: a
// Deny after it is told the request is gone. Were they apart, a Deny landing
// between them would be answered OK while the key was handed over, and the
// panel would show "Denied" for an approval. Tested directly, since over
// the socket the reply always follows the unpark and cannot see the window.
func TestSettleTakesTheRequestOffTheTableWithTheCheck(t *testing.T) {
	s := NewServer(shortSocketPath(t), newDialog().fetcher, time.Minute)
	sub := s.subscribe(true, true, false)
	defer s.unsubscribe(sub)
	pending := unlockEvent(OpRevealPID, nil)
	p, unpark := s.parkWithBrokers(pending)
	if p == nil || !p.follows {
		t.Fatal("setup: the request was not parked beside the Touch ID")
	}
	defer unpark()

	if s.settleBeside(p) {
		t.Fatal("an undenied request settled as denied")
	}
	if err := s.answerConsent(p.event.ConsentID, DecisionDeny); err == nil {
		t.Error("a Deny after the settle was answered OK")
	}
	if authprompt.Withdrawn(p.denied) {
		t.Error("a Deny after the settle still withdrew the request")
	}
}

// A panel that never says it is shown delays the Touch ID by the cap, no
// more, and never refuses it.
func TestBesideTouchIDStartsAtTheCapWhenNotShown(t *testing.T) {
	d := newDialog()
	s, c := startBesideServer(t, d, 300*time.Millisecond, nil)
	pending, stop := panelBroker(t, s, c, 1)
	defer stop()

	errc := make(chan error, 1)
	start := time.Now() // before the request: the server's timer starts after this
	go func() { errc <- c.Trust() }()
	receive(t, pending, "the pending request")
	receive(t, d.raised, "the Touch ID")
	if waited := time.Since(start); waited < 250*time.Millisecond || waited > 3*time.Second {
		t.Errorf("the Touch ID appeared after %s with a silent panel, want about the 300 ms cap", waited)
	}
	if err := receive(t, errc, "trust"); err != nil {
		t.Fatalf("trust: %v", err)
	}
}

// With no broker there is nothing to wait for: the dialog appears at once,
// whatever shownWait is.
func TestNoBrokerNoShownWait(t *testing.T) {
	d := newDialog()
	_, c := startBesideServer(t, d, 10*time.Second, nil)
	start := time.Now()
	if err := c.Trust(); err != nil {
		t.Fatalf("Trust: %v", err)
	}
	if waited := time.Since(start); waited > 2*time.Second {
		t.Errorf("trust with no broker took %s, want no wait", waited)
	}
	if d.count() != 1 {
		t.Errorf("prompts = %d, want 1", d.count())
	}
}

// A Deny before the dialog is up refuses with no dialog at all, recorded
// with no auth method (nobody was asked on screen).
func TestBesideDenyBeforeThePromptShowsNoDialog(t *testing.T) {
	d := newDialog()
	s, c := startBesideServer(t, d, 10*time.Second, nil)
	pending, stop := panelBroker(t, s, c, 1)
	defer stop()

	errc := make(chan error, 1)
	go func() { errc <- c.Trust() }()
	req := receive(t, pending, "the pending request")
	if err := c.ConsentAnswer(req.ConsentID, false); err != nil {
		t.Fatalf("ConsentAnswer(deny): %v", err)
	}
	err := receive(t, errc, "trust")
	if err == nil || !strings.Contains(err.Error(), errDeniedInJitPass.Error()) {
		t.Fatalf("trust after a Deny = %v, want %q", err, errDeniedInJitPass)
	}
	if d.count() != 0 {
		t.Errorf("a Deny before the prompt still raised %d dialogs", d.count())
	}
	if e := lastEvent(t, c); e.Kind != KindDenied || e.AuthMethod != "" || !strings.Contains(e.Cause, errDeniedInJitPass.Error()) {
		t.Errorf("outcome = %+v, want denied in JitPass with no auth method", e)
	}
}

// A Deny while the dialog is up takes it down and refuses. The audit says
// where it was refused, which Cancel on the dialog does not (below).
func TestBesideDenyDuringThePromptWithdrawsIt(t *testing.T) {
	d := newDialog()
	d.setAnswer(untilWithdrawnOr(make(chan struct{})))
	s, c := startBesideServer(t, d, 50*time.Millisecond, nil)
	pending, stop := panelBroker(t, s, c, 1)
	defer stop()

	errc := make(chan error, 1)
	go func() { errc <- c.Trust() }()
	req := receive(t, pending, "the pending request")
	receive(t, d.raised, "the Touch ID")
	if err := c.ConsentAnswer(req.ConsentID, false); err != nil {
		t.Fatalf("ConsentAnswer(deny): %v", err)
	}
	err := receive(t, errc, "trust")
	if err == nil || !strings.Contains(err.Error(), errDeniedInJitPass.Error()) {
		t.Fatalf("trust after a Deny during the prompt = %v, want %q", err, errDeniedInJitPass)
	}
	e := lastEvent(t, c)
	if e.Kind != KindDenied || e.ConsentID != req.ConsentID || e.AuthMethod == "" || !strings.Contains(e.Cause, errDeniedInJitPass.Error()) {
		t.Errorf("outcome = %+v, want denied in JitPass, the same consent id, with the auth method of the dialog shown", e)
	}
	if list, _ := c.ConsentList(); len(list) != 0 {
		t.Errorf("a finished request is still listed: %+v", list)
	}
}

// Cancel on the dialog itself is not a Deny in JitPass: the key store's own
// error is what the audit keeps.
func TestCancelOnTheDialogIsNotDeniedInJitPass(t *testing.T) {
	d := newDialog()
	d.setAnswer(func(<-chan struct{}) error { return errors.New("local authentication failed: Canceled by user.") })
	s, c := startBesideServer(t, d, 50*time.Millisecond, nil)
	_, stop := panelBroker(t, s, c, 1)
	defer stop()

	err := c.Trust()
	if err == nil || strings.Contains(err.Error(), errDeniedInJitPass.Error()) || !strings.Contains(err.Error(), "Canceled by user") {
		t.Fatalf("trust cancelled on the dialog = %v, want the dialog's own cancel, not %q", err, errDeniedInJitPass)
	}
	if e := lastEvent(t, c); e.Kind != KindDenied || strings.Contains(e.Cause, errDeniedInJitPass.Error()) {
		t.Errorf("outcome = %+v, want a denial that does not blame the panel", e)
	}
}

// The race review M2 raised: the fingerprint lands just after the Deny and
// the key store returns the key. The Deny still wins: the vault stays
// locked, nothing is served, and the key that came back is wiped. The
// request is a gated credential on a locked vault, the prompt whose approval
// would also have opened the session.
func TestLateTouchNeverOvertakesADeny(t *testing.T) {
	d := newDialog()
	s, c := startBesideServer(t, d, 50*time.Millisecond, nil)
	wrapped := wrapThenLock(t, s, c)
	pending, stop := panelBroker(t, s, c, 1)
	defer stop()

	// The finger wins inside the key store: it approves after the withdrawal.
	d.setAnswer(func(withdraw <-chan struct{}) error { <-withdraw; return nil })
	d.mu.Lock()
	before := len(d.handedOut)
	d.mu.Unlock()
	for len(d.raised) > 0 { // the setup's own prompts
		<-d.raised
	}

	errc := make(chan error, 1)
	go func() {
		_, err := c.UnwrapKeyLabeled(wrapped, "aws/default/key", "aws")
		errc <- err
	}()
	req := receive(t, pending, "the pending request")
	if !strings.Contains(req.Cause, unlockAnd) {
		t.Fatalf("setup: the prompt should offer the unlock; said %q", req.Cause)
	}
	receive(t, d.raised, "the Touch ID")
	if err := c.ConsentAnswer(req.ConsentID, false); err != nil {
		t.Fatalf("ConsentAnswer(deny): %v", err)
	}
	if err := receive(t, errc, "unwrap"); err == nil {
		t.Fatal("unwrap after a Deny that lost the race succeeded")
	}
	if s.SessionUnlocked() {
		t.Error("a late touch after a Deny opened the session")
	}
	d.mu.Lock()
	got := d.handedOut[before:]
	d.mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("setup: the key store should have returned the key once, got %d", len(got))
	}
	if !bytes.Equal(got[0], make([]byte, len(got[0]))) {
		t.Error("the key a late touch returned was not wiped")
	}
	events, _ := c.History()
	denied := false
	for _, e := range events {
		if e.ConsentID == req.ConsentID {
			if e.Kind == KindApproved || e.Kind == KindUnlock {
				t.Errorf("a Deny that lost the race was recorded as %s: %+v", e.Kind, e)
			}
			denied = denied || (e.Kind == KindDenied && strings.Contains(e.Cause, errDeniedInJitPass.Error()))
		}
	}
	if !denied {
		t.Errorf("no denied-in-JitPass outcome for %s in %+v", req.ConsentID, events)
	}
}

// A fetcher that cannot withdraw its dialog still has the Deny enforced:
// the prompt runs to its end, and the answer is refused anyway.
func TestDenyIsEnforcedWithoutAWithdrawableDialog(t *testing.T) {
	d := newDialog()
	d.plain = true
	approve := make(chan struct{})
	d.setAnswer(untilWithdrawnOr(approve))
	s, c := startBesideServer(t, d, 50*time.Millisecond, nil)
	pending, stop := panelBroker(t, s, c, 1)
	defer stop()

	errc := make(chan error, 1)
	go func() { errc <- c.Trust() }()
	req := receive(t, pending, "the pending request")
	receive(t, d.raised, "the Touch ID")
	if err := c.ConsentAnswer(req.ConsentID, false); err != nil {
		t.Fatalf("ConsentAnswer(deny): %v", err)
	}
	close(approve) // the human touches the sensor on a dialog nobody could take down
	if err := receive(t, errc, "trust"); err == nil || !strings.Contains(err.Error(), errDeniedInJitPass.Error()) {
		t.Fatalf("trust = %v, want %q", err, errDeniedInJitPass)
	}
}

// An older app still sends allow. It is a no-op now: the dialog stays up for
// the fingerprint, and a Deny after it still works.
func TestBesideAllowIsANoOp(t *testing.T) {
	d := newDialog()
	d.setAnswer(untilWithdrawnOr(make(chan struct{})))
	s, c := startBesideServer(t, d, 50*time.Millisecond, nil)
	pending, stop := panelBroker(t, s, c, 1)
	defer stop()

	errc := make(chan error, 1)
	go func() { errc <- c.Trust() }()
	req := receive(t, pending, "the pending request")
	receive(t, d.raised, "the Touch ID")
	if err := c.ConsentAnswer(req.ConsentID, true); err != nil {
		t.Fatalf("ConsentAnswer(allow) = %v, want a quiet no-op", err)
	}
	nothingOn(t, errc, 200*time.Millisecond, "an allow ended the request")
	if err := c.ConsentAnswer(req.ConsentID, false); err != nil {
		t.Fatalf("ConsentAnswer(deny) after an allow: %v", err)
	}
	if err := receive(t, errc, "trust"); err == nil || !strings.Contains(err.Error(), errDeniedInJitPass.Error()) {
		t.Fatalf("trust = %v, want %q", err, errDeniedInJitPass)
	}
	if err := c.ConsentAnswer(req.ConsentID, false); err == nil {
		t.Error("an answer to a finished request was accepted")
	}
}

// One older app connected alongside keeps the old order: its sheet asks
// first, because beside a dialog already up it would ask twice again.
// consent_shown means nothing for such a request.
func TestAnOlderBrokerKeepsAskingFirst(t *testing.T) {
	d := newDialog()
	s, c := startBesideServer(t, d, 50*time.Millisecond, nil)
	oldPending, stopOld := broker(t, s, c)
	defer stopOld()
	newPending, stopNew := panelBroker(t, s, c, 2)
	defer stopNew()

	errc := make(chan error, 1)
	go func() { errc <- c.Trust() }()
	req := receive(t, oldPending, "the pending request (older app)")
	receive(t, newPending, "the pending request (panel)")
	if req.TouchIDFollows {
		t.Fatal("with an older app connected, the request went beside the Touch ID")
	}
	if err := c.ConsentShown(req.ConsentID); err == nil {
		t.Error("consent_shown was accepted for a request that waits for an answer")
	}
	nothingOn(t, d.raised, 300*time.Millisecond, "the Touch ID appeared before the older app answered")
	if err := c.ConsentAnswer(req.ConsentID, true); err != nil {
		t.Fatalf("ConsentAnswer(allow): %v", err)
	}
	if err := receive(t, errc, "trust"); err != nil {
		t.Fatalf("trust: %v", err)
	}
	if err := c.ConsentShown("0000000000000000"); err == nil {
		t.Error("consent_shown for an unknown request was accepted")
	}
}

// The panel quitting during the short wait: the dialog appears at once, as
// with no broker.
func TestPanelLeavingDuringTheWaitRaisesTheDialog(t *testing.T) {
	d := newDialog()
	s, c := startBesideServer(t, d, 10*time.Second, nil)
	pending, stop := panelBroker(t, s, c, 1)

	errc := make(chan error, 1)
	go func() { errc <- c.Trust() }()
	receive(t, pending, "the pending request")
	start := time.Now()
	stop()
	receive(t, d.raised, "the Touch ID")
	if waited := time.Since(start); waited > 2*time.Second {
		t.Errorf("the dialog appeared %s after the panel left, want at once", waited)
	}
	if err := receive(t, errc, "trust"); err != nil {
		t.Fatalf("trust: %v", err)
	}
}

// The refusal backoff counts a panel Deny as it counts the old broker's: the
// next request right after is turned away with no panel and no dialog.
func TestPanelDenyArmsTheRefusalBackoff(t *testing.T) {
	d := newDialog()
	s, c := startBesideServer(t, d, 10*time.Second, func(s *Server) {
		s.discloseBackoff = []time.Duration{time.Minute}
	})
	pending, stop := panelBroker(t, s, c, 1)
	defer stop()

	errc := make(chan error, 1)
	go func() { errc <- c.Trust() }()
	req := receive(t, pending, "the pending request")
	if err := c.ConsentAnswer(req.ConsentID, false); err != nil {
		t.Fatalf("ConsentAnswer(deny): %v", err)
	}
	if err := receive(t, errc, "trust"); err == nil {
		t.Fatal("trust after a Deny succeeded")
	}
	if err := c.Trust(); err == nil {
		t.Fatal("the request right after a Deny was allowed")
	}
	nothingOn(t, pending, 100*time.Millisecond, "the retry during the backoff reached the panel")
	if d.count() != 0 {
		t.Errorf("the retry during the backoff raised %d dialogs", d.count())
	}
}

// The unlock a program asks for goes beside the Touch ID too. A Deny there
// leaves the vault locked and arms the unlock cooldown, as a declined dialog
// does, so the program's retry gets neither a panel nor a dialog.
func TestPanelDenyOnAProgramsUnlockArmsTheCooldown(t *testing.T) {
	d := newDialog()
	s, c := startBesideServer(t, d, 10*time.Second, nil)
	pending, stop := panelBroker(t, s, c, 1)
	defer stop()

	errc := make(chan error, 1)
	go func() { _, err := c.WrapKey(bytes.Repeat([]byte{0x07}, 32)); errc <- err }()
	req := receive(t, pending, "the pending unlock")
	if !req.TouchIDFollows || req.Op == OpUnlock {
		t.Fatalf("pending = %+v, want a program's unlock shown beside the Touch ID", req)
	}
	if err := c.ConsentAnswer(req.ConsentID, false); err != nil {
		t.Fatalf("ConsentAnswer(deny): %v", err)
	}
	if err := receive(t, errc, "wrap"); err == nil || !strings.Contains(err.Error(), errDeniedInJitPass.Error()) {
		t.Fatalf("wrap after a Deny = %v, want %q", err, errDeniedInJitPass)
	}
	if s.SessionUnlocked() {
		t.Fatal("a Deny opened the session")
	}
	if _, err := c.WrapKey(bytes.Repeat([]byte{0x07}, 32)); err == nil || !strings.Contains(err.Error(), "paused") {
		t.Fatalf("the retry right after a Deny = %v, want the cooldown", err)
	}
	nothingOn(t, pending, 100*time.Millisecond, "the retry during the cooldown reached the panel")
	if d.count() != 0 {
		t.Errorf("dialogs raised = %d, want 0", d.count())
	}
}
