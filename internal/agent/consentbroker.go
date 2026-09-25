// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package agent

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// This file is consent brokering: a subscriber that declared itself a
// BROKER (Request.Broker on "subscribe") is shown every disclosed challenge
// before the Touch ID for it appears, and answers it with "consent_answer".
// It exists for the menu bar app, whose whole reason to be is that it can
// explain a prompt — full command line, launcher, how the caller was
// identified, what deny does — where the system dialog fits one sentence.
//
// The broker adds explanation, never authority:
//
//   - "allow" does not grant anything. It means "go ahead and ask me", and
//     the agent then runs the exact Touch ID it would have run without a
//     broker. The human still approves on the system dialog.
//   - "deny" refuses without a prompt. Reducing access is free, the same
//     doctrine grant_revoke follows, so nothing checks WHO denied.
//   - No answer within brokerWait is a refusal, like a Touch ID nobody
//     touched. It is never an approval.
//   - No broker connected, or every broker gone while a request waits, and
//     the Touch ID appears directly — the path that exists today, which is
//     never left. A CLI-only install behaves exactly as before.
//
// Because "allow" only leads to the system dialog, a same-user process that
// answers a request it did not receive gains nothing: at worst the human
// sees the plain Touch ID they would have seen anyway.

// brokerWait bounds how long a disclosed challenge sits with the broker.
// The requesting client gives up at responseTimeout (130s) and the Touch
// ID that follows an allow needs a few seconds of its own, so this leaves
// room for a human who allows late; a human who never looks is a refusal,
// not a fallback, since the request may have been the loop that prompt
// fatigue exists to stop.
const defaultBrokerWait = 90 * time.Second

// Decisions a broker may send in Request.Decision.
const (
	DecisionAllow = "allow"
	DecisionDeny  = "deny"
)

var (
	errDeclinedByBroker   = errors.New("declined by the user")
	errUnansweredByBroker = errors.New("not answered")
)

// brokerVerdict is what brokerConsent hands back to the challenge.
type brokerVerdict int

const (
	// brokerProceed: show the Touch ID, because no broker was there to ask
	// (or it left mid-question). The human has seen nothing yet, so the
	// dialog carries the whole sentence.
	brokerProceed brokerVerdict = iota
	// brokerAllowed: a broker showed the request and the human pressed
	// Allow. The Touch ID still follows, and may say less (confirmReason).
	brokerAllowed
	brokerDenied
	brokerUnanswered
)

// pendingConsent is one disclosed challenge parked with the broker. answer
// is buffered so the answering RPC never blocks on the waiter, and gone is
// how the registry pokes a waiter to re-check whether any broker is left.
type pendingConsent struct {
	event  SessionEvent
	answer chan string
	gone   chan struct{}
}

func newConsentID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("consent id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// brokerCount is how many live subscribers will answer consent requests.
func (s *Server) brokerCount() int {
	s.subMu.Lock()
	defer s.subMu.Unlock()
	n := 0
	for sub := range s.subscribers {
		if sub.broker {
			n++
		}
	}
	return n
}

// publishBrokers is publish restricted to brokers: a pending request is
// a question for whoever will answer it, not an event in the trail, so a
// plain `jit audit -f` never sees one.
func (s *Server) publishBrokers(e SessionEvent) {
	s.subMu.Lock()
	defer s.subMu.Unlock()
	for sub := range s.subscribers {
		if !sub.broker {
			continue
		}
		select {
		case sub.ch <- e:
		default:
			select {
			case <-sub.lagged:
			default:
				close(sub.lagged)
			}
		}
	}
}

// brokerConsent parks pending with the broker and waits for its answer.
// Called with challengeMu held, like the prompt it stands in front of, so
// requests reach the broker one at a time in the order they would have
// reached the screen. pending is updated in place with the consent id and
// the "pending" kind, so the status line and the outcome event carry it.
func (s *Server) brokerConsent(pending *SessionEvent) brokerVerdict {
	if s.brokerCount() == 0 {
		return brokerProceed
	}
	id, err := newConsentID()
	if err != nil {
		return brokerProceed // no id, no way to answer: ask directly
	}
	pending.Kind = KindPending
	pending.ConsentID = id
	p := &pendingConsent{event: *pending, answer: make(chan string, 1), gone: make(chan struct{}, 1)}

	s.brokerMu.Lock()
	if s.pendingConsents == nil {
		s.pendingConsents = map[string]*pendingConsent{}
	}
	s.pendingConsents[id] = p
	s.brokerMu.Unlock()
	defer func() {
		s.brokerMu.Lock()
		delete(s.pendingConsents, id)
		s.brokerMu.Unlock()
	}()

	s.publishBrokers(p.event)

	timeout := time.NewTimer(s.brokerWait)
	defer timeout.Stop()
	for {
		select {
		case d := <-p.answer:
			if d == DecisionAllow {
				return brokerAllowed
			}
			return brokerDenied
		case <-p.gone:
			if s.brokerCount() == 0 {
				return brokerProceed // the app quit mid-question: ask directly
			}
		case <-timeout.C:
			return brokerUnanswered
		}
	}
}

// promptOrBroker is the one place a prompt reaches the screen: it offers
// pending to the consent broker first when broker is set, then runs the
// Touch ID for reason unless the broker refused. prompted reports whether
// a dialog was actually shown, so a refusal that never reached the screen
// records no auth method. The MEK, when there is one, is the caller's to
// keep or wipe.
func (s *Server) promptOrBroker(pending *SessionEvent, reason string, broker bool) (mek []byte, prompted bool, err error) {
	if broker {
		switch s.brokerConsent(pending) {
		case brokerDenied:
			return nil, false, errDeclinedByBroker
		case brokerUnanswered:
			return nil, false, fmt.Errorf("%w within %s", errUnansweredByBroker, s.brokerWait)
		case brokerAllowed:
			reason = confirmReason(reason)
		case brokerProceed:
		}
	}
	fetcher := s.newFetcher()
	mek, err = fetcher.FetchMEK(reason)
	// The fetcher's own cache is pure residue once FetchMEK has returned
	// its copy; every prompt in the agent comes through here, so this is
	// the site that used to leak a MEK copy per prompt.
	closeFetcher(fetcher)
	return mek, true, err
}

// brokerLeft is called when a broker subscription ends, so a request it
// was shown does not sit out the full wait for an answer that cannot come.
func (s *Server) brokerLeft() {
	s.brokerMu.Lock()
	defer s.brokerMu.Unlock()
	for _, p := range s.pendingConsents {
		select {
		case p.gone <- struct{}{}:
		default:
		}
	}
}

// pendingConsentEvents answers "consent_list": every request currently
// waiting on a broker, oldest first — how a broker that just connected
// learns what is already on the table.
func (s *Server) pendingConsentEvents() []SessionEvent {
	s.brokerMu.Lock()
	defer s.brokerMu.Unlock()
	out := make([]SessionEvent, 0, len(s.pendingConsents))
	for _, p := range s.pendingConsents {
		out = append(out, p.event)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].UnixTime < out[j].UnixTime })
	return out
}

// answerConsent delivers a broker's decision to the waiting challenge.
func (s *Server) answerConsent(id, decision string) error {
	if decision != DecisionAllow && decision != DecisionDeny {
		return fmt.Errorf("consent_answer: decision must be %q or %q", DecisionAllow, DecisionDeny)
	}
	s.brokerMu.Lock()
	p, ok := s.pendingConsents[id]
	s.brokerMu.Unlock()
	if !ok {
		return fmt.Errorf("consent_answer: no request %q is waiting", id)
	}
	select {
	case p.answer <- decision:
		return nil
	default:
		return fmt.Errorf("consent_answer: request %q was already answered", id)
	}
}

// confirmReason is the Touch ID sentence after the app's sheet already showed
// the whole request and the human pressed Allow (design/agent-jobs.md, step
// 4): "confirm: " and the FACTS clause of the full sentence, dropping only
// the explanatory tail after "; " ("it sees output, never the values"). A
// sentence with no tail is kept whole. It never says less than the facts,
// because any same-user process can subscribe as a broker and "allow": the
// dialog is what the fingerprint approves, and it must still say what runs
// and who asked. The audit keeps the full sentence; only the dialog shortens.
//
// A sentence with no tail, or one whose short form would not be shorter or
// would not fit whole, is returned unchanged: truncating a facts clause
// could cut the scope ("until you revoke it"), which is the half that
// changes the decision.
func confirmReason(reason string) string {
	facts, _, hasTail := strings.Cut(reason, "; ")
	short := "confirm: " + facts
	if !hasTail || len([]rune(short)) >= len([]rune(reason)) || len([]rune(short)) > maxReasonLen {
		return reason
	}
	return short
}
