// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package agent

import (
	"context"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/consent"
)

// startBrokerServer is a server on which `trust` raises a disclosed
// challenge (consent enabled), with the prompt backoff off so a refused
// request can be retried in the next line, and a broker wait a test can
// sit out.
func startBrokerServer(t *testing.T, calls *int32, wait time.Duration) (*Server, *Client, func()) {
	t.Helper()
	s, socketPath, cleanup := startTestServerWith(t, time.Minute, calls, func(s *Server) {
		s.Consent = consent.New(time.Minute)
		s.discloseBackoff = nil
		s.brokerWait = wait
	})
	return s, NewClient(socketPath), cleanup
}

// broker subscribes as a consent broker and hands every pending request to
// the test on a channel; stop ends the stream.
func broker(t *testing.T, s *Server, c *Client) (pending <-chan SessionEvent, stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan SessionEvent, 16)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = c.SubscribeAsBroker(ctx, func(e SessionEvent) {
			if e.Kind == KindPending {
				ch <- e
			}
		})
	}()
	waitFor(t, "broker to register", func() bool { return s.brokerCount() == 1 })
	return ch, func() { cancel(); <-done }
}

func lastEvent(t *testing.T, c *Client) SessionEvent {
	t.Helper()
	events, err := c.History()
	if err != nil || len(events) == 0 {
		t.Fatalf("History: %v (%d events)", err, len(events))
	}
	return events[len(events)-1]
}

func TestBrokerDenyRefusesWithoutAPrompt(t *testing.T) {
	var calls int32
	s, c, cleanup := startBrokerServer(t, &calls, 10*time.Second)
	defer cleanup()
	pending, stop := broker(t, s, c)
	defer stop()

	errc := make(chan error, 1)
	go func() { errc <- c.Trust() }()

	var req SessionEvent
	select {
	case req = <-pending:
	case <-time.After(5 * time.Second):
		t.Fatal("the broker was never shown the request")
	}
	if req.ConsentID == "" || req.Op != OpRevealPID || req.ByPID != int32(os.Getpid()) || req.Cause == "" {
		t.Fatalf("pending request = %+v, want a consent id, the disclosed op, this pid and the prompt wording", req)
	}
	// The same request is what status and consent_list report while it waits.
	st, err := c.Status()
	if err != nil || st.PendingUnlock == nil || st.PendingUnlock.ConsentID != req.ConsentID {
		t.Errorf("status during a brokered wait = %+v (%v), want PendingUnlock carrying %s", st.PendingUnlock, err, req.ConsentID)
	}
	if list, err := c.ConsentList(); err != nil || len(list) != 1 || list[0].ConsentID != req.ConsentID {
		t.Errorf("ConsentList = %+v (%v), want just %s", list, err, req.ConsentID)
	}

	if err := c.ConsentAnswer(req.ConsentID, false); err != nil {
		t.Fatalf("ConsentAnswer(deny): %v", err)
	}
	err = <-errc
	if err == nil || !strings.Contains(err.Error(), errDeclinedByBroker.Error()) {
		t.Fatalf("trust after a broker deny = %v, want the decline", err)
	}
	if n := atomic.LoadInt32(&calls); n != 0 {
		t.Errorf("fetcher called %d times on a broker deny; a deny must never show the dialog", n)
	}
	e := lastEvent(t, c)
	if e.Kind != KindDenied || e.ConsentID != req.ConsentID || e.AuthMethod != "" {
		t.Errorf("recorded outcome = %+v, want denied, same consent id, no auth method", e)
	}
	if list, _ := c.ConsentList(); len(list) != 0 {
		t.Errorf("an answered request is still listed: %+v", list)
	}
}

func TestBrokerAllowStillRunsTheTouchID(t *testing.T) {
	var calls int32
	s, c, cleanup := startBrokerServer(t, &calls, 10*time.Second)
	defer cleanup()
	pending, stop := broker(t, s, c)
	defer stop()

	errc := make(chan error, 1)
	go func() { errc <- c.Trust() }()
	req := <-pending
	if err := c.ConsentAnswer(req.ConsentID, true); err != nil {
		t.Fatalf("ConsentAnswer(allow): %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("trust after a broker allow: %v", err)
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Errorf("fetcher called %d times; an allow must lead to exactly the dialog it stood in front of", n)
	}
	if e := lastEvent(t, c); e.Kind != KindApproved || e.ConsentID != req.ConsentID {
		t.Errorf("recorded outcome = %+v, want approved with consent id %s", e, req.ConsentID)
	}
}

func TestBrokerSilenceIsARefusal(t *testing.T) {
	var calls int32
	s, c, cleanup := startBrokerServer(t, &calls, 300*time.Millisecond)
	defer cleanup()
	pending, stop := broker(t, s, c)
	defer stop()

	errc := make(chan error, 1)
	go func() { errc <- c.Trust() }()
	<-pending
	err := <-errc
	if err == nil || !strings.Contains(err.Error(), errUnansweredByBroker.Error()) {
		t.Fatalf("unanswered request = %v, want the timeout refusal", err)
	}
	if n := atomic.LoadInt32(&calls); n != 0 {
		t.Errorf("fetcher called %d times after the broker went silent; silence is never an approval", n)
	}
}

func TestBrokerLeavingFallsBackToTheDialog(t *testing.T) {
	var calls int32
	s, c, cleanup := startBrokerServer(t, &calls, 10*time.Second)
	defer cleanup()
	pending, stop := broker(t, s, c)

	errc := make(chan error, 1)
	go func() { errc <- c.Trust() }()
	<-pending
	start := time.Now()
	stop() // the app quit mid-question
	if err := <-errc; err != nil {
		t.Fatalf("trust after the broker left: %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("the request waited out the broker after the broker was gone")
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Errorf("fetcher called %d times, want the plain dialog once the broker is gone", n)
	}
}

func TestPlainSubscriberIsNotABroker(t *testing.T) {
	var calls int32
	s, c, cleanup := startBrokerServer(t, &calls, 10*time.Second)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var sawPending atomic.Bool
	go func() {
		_ = c.Subscribe(ctx, func(e SessionEvent) {
			if e.Kind == KindPending {
				sawPending.Store(true)
			}
		})
	}()
	waitFor(t, "subscription to register", func() bool { return s.subscriberCount() == 1 })

	start := time.Now()
	if err := c.Trust(); err != nil {
		t.Fatalf("Trust: %v", err)
	}
	if time.Since(start) > 5*time.Second || atomic.LoadInt32(&calls) != 1 {
		t.Error("with no broker the dialog must appear directly, without waiting")
	}
	if sawPending.Load() {
		t.Error("a plain subscriber was shown a pending request")
	}
	if e := lastEvent(t, c); e.ConsentID != "" {
		t.Errorf("an unbrokered challenge carries a consent id: %+v", e)
	}
}

func TestConsentAnswerRejectsWhatItCannotResolve(t *testing.T) {
	_, c, cleanup := startBrokerServer(t, nil, 10*time.Second)
	defer cleanup()
	if err := c.ConsentAnswer("nope", true); err == nil {
		t.Error("answering an unknown request succeeded")
	}
	if _, err := c.call(Request{Op: OpConsentAnswer, ConsentID: "nope", Decision: "maybe"}); err == nil || !strings.Contains(err.Error(), "decision") {
		t.Errorf("a decision outside allow/deny was accepted: %v", err)
	}
	if _, err := c.call(Request{Op: OpConsentAnswer}); err == nil {
		t.Error("an answer without a consent id was accepted")
	}
}

func TestScannedReaderIsMarkedLikely(t *testing.T) {
	// A FIFO reader's identity comes from a process-table scan, and the
	// event built from it must say so.
	e := unlockEvent(OpRevealPID, callerForPID(int32(os.Getpid())))
	if e.ByPID != int32(os.Getpid()) || !e.ByLikely || e.By == "" {
		t.Errorf("event for a scanned reader = %+v, want this pid, By set, ByLikely", e)
	}
	if e := unlockEvent(OpRevealPID, &caller{pid: 1}); e.ByLikely {
		t.Error("a kernel-vouched caller was marked likely")
	}
}
