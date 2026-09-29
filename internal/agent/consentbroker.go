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
	"sync"
	"time"

	"github.com/jitpass/jit/internal/authprompt"
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
//
// A broker that set Request.TouchIDFollows shows the request BESIDE the
// Touch ID instead (design/consent-side-panel-plan.md): the human answered
// twice before, once on the app's sheet and again on the dialog. In that
// mode the Touch ID appears at once (after at most shownWait, for the panel
// to be drawn), "allow" is a no-op, and "deny" withdraws a dialog already
// on screen. The authority is the same as above: the fingerprint approves,
// the broker can only refuse, and "consent_shown" grants nothing. A deny is
// checked again after the Touch ID returns, so a finger that wins the race
// inside the key store never overtakes it.

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

// defaultShownWait is how long a request shown beside its Touch ID waits for
// the broker's consent_shown before the dialog appears anyway. The spike
// measured the panel drawn about 125 ms before the dialog would be, so a
// working broker never reaches it; a stuck one delays the prompt by no more
// than this.
const defaultShownWait = 250 * time.Millisecond

var (
	errDeclinedByBroker   = errors.New("declined by the user")
	errUnansweredByBroker = errors.New("not answered")
	// errDeniedInJitPass is a Deny pressed in the broker's panel beside the
	// Touch ID. The audit tells it apart from Cancel on the dialog itself,
	// which keeps the key store's own error.
	errDeniedInJitPass = errors.New("denied in JitPass")
)

// brokerVerdict is what awaitAnswer hands back to the challenge.
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
//
// A follows request (shown beside its Touch ID) uses shown and denied
// instead of answer: each is closed once, under brokerMu, and never
// reopened. denied is the withdraw channel the Touch ID is raised with.
type pendingConsent struct {
	event   SessionEvent
	follows bool
	answer  chan string
	gone    chan struct{}
	shown   chan struct{}
	denied  chan struct{}
}

func newConsentID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("consent id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// brokerModes is how many live subscribers will answer consent requests, and
// whether every one of them shows requests beside the Touch ID.
func (s *Server) brokerModes() (n int, follows bool) {
	s.subMu.Lock()
	defer s.subMu.Unlock()
	follows = true
	for sub := range s.subscribers {
		if sub.broker {
			n++
			follows = follows && sub.follows
		}
	}
	return n, n > 0 && follows
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

// parkWithBrokers registers pending with the connected brokers and shows it
// to them, or returns nil when no broker is connected. pending is updated in
// place with the consent id and the "pending" kind, so the status line and
// the outcome event carry it. unpark removes the request from consent_list
// and from answerConsent's reach; it is safe to call more than once.
//
// The request goes beside the Touch ID (follows) only while EVERY broker
// declared it can show it that way. One that did not is an older app, which
// shows a sheet whose Allow is the only way forward: beside a dialog already
// on screen, that sheet would ask twice again.
func (s *Server) parkWithBrokers(pending *SessionEvent) (p *pendingConsent, unpark func()) {
	brokers, follows := s.brokerModes()
	if brokers == 0 {
		return nil, nil
	}
	id, err := newConsentID()
	if err != nil {
		return nil, nil // no id, no way to answer: ask directly
	}
	pending.Kind = KindPending
	pending.ConsentID = id
	pending.TouchIDFollows = follows
	p = &pendingConsent{
		event:   *pending,
		follows: follows,
		answer:  make(chan string, 1),
		gone:    make(chan struct{}, 1),
		shown:   make(chan struct{}),
		denied:  make(chan struct{}),
	}

	s.brokerMu.Lock()
	if s.pendingConsents == nil {
		s.pendingConsents = map[string]*pendingConsent{}
	}
	s.pendingConsents[id] = p
	s.brokerMu.Unlock()
	var once sync.Once
	unpark = func() {
		once.Do(func() {
			s.brokerMu.Lock()
			delete(s.pendingConsents, id)
			s.brokerMu.Unlock()
		})
	}

	s.publishBrokers(p.event)
	return p, unpark
}

// awaitAnswer waits for a broker's answer to a request that asks first (not
// follows).
func (s *Server) awaitAnswer(p *pendingConsent) brokerVerdict {
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

// promptBesideBroker is the Touch ID for a request the broker shows beside it
// (design/consent-side-panel-plan.md, step 3). The fingerprint approves; the
// broker can only take the dialog down.
//
//  1. Wait at most shownWait for the broker to say the request is on screen,
//     so the dialog does not land before the explanation. The wait grants
//     nothing, and a broker that never signals costs a quarter of a second.
//  2. A deny inside the wait refuses with no dialog at all.
//  3. The Touch ID appears with the full sentence (the dialog is still
//     self-contained: no Allow came first, so nothing was confirmed). A deny
//     while it is up withdraws it.
//  4. After the fetch, the deny is checked again. A fingerprint that lands a
//     few milliseconds after the deny can win the race inside the key store
//     and return the key; a deny is never overtaken that way, so the key is
//     wiped and the request refused.
//
// brokerWait does not apply: the dialog's own timeout bounds the request.
//
// The mode is fixed when the request is parked. An older app that connects
// while a beside request is up reads it from consent_list with the flag set
// and shows its sheet next to the dialog: its allow is a no-op and its Deny
// still works, so that costs polish, not safety. The reverse (a request
// parked for an older app that then quits, leaving a beside app) waits for
// an answer as before, which is why a beside app must still answer pending
// events without the flag (SubscribeBesideTouchID).
func (s *Server) promptBesideBroker(p *pendingConsent, reason string) (mek []byte, prompted bool, err error) {
	wait := time.NewTimer(s.shownWait)
	defer wait.Stop()
waiting:
	for {
		select {
		case <-p.denied:
			return nil, false, errDeniedInJitPass
		case <-p.shown:
			break waiting
		case <-p.gone:
			if s.brokerCount() == 0 {
				break waiting // nobody left to show it: the dialog alone, as without a broker
			}
		case <-wait.C:
			break waiting
		}
	}
	// A deny and the shown signal can arrive together, and select picks
	// either; the deny wins.
	if authprompt.Withdrawn(p.denied) {
		return nil, false, errDeniedInJitPass
	}

	mek, err = s.fetchMEK(reason, p.denied)
	if s.settleBeside(p) {
		// Reported as prompted even in the rare case the deny landed after
		// the check above but before the key store raised its dialog: the
		// key store fails the same way whether its dialog was up or not, so
		// the audit may name an auth method for a dialog that never drew.
		wipe(mek)
		return nil, true, errDeniedInJitPass
	}
	return mek, true, err
}

// settleBeside takes a beside request off the table and reports whether it
// was denied, in one step under brokerMu. After it, a Deny finds no request
// and is told so, instead of being answered OK for a request that was
// already approved: the app must never show "Denied" for a key that was
// handed over.
func (s *Server) settleBeside(p *pendingConsent) (denied bool) {
	s.brokerMu.Lock()
	defer s.brokerMu.Unlock()
	delete(s.pendingConsents, p.event.ConsentID)
	return authprompt.Withdrawn(p.denied)
}

// fetchMEK runs the Touch ID for reason on a fresh fetcher. A non-nil
// withdraw can take the dialog down when the fetcher supports it; one that
// does not (a test double) just prompts, and promptBesideBroker's check
// after the fetch still enforces the deny.
func (s *Server) fetchMEK(reason string, withdraw <-chan struct{}) ([]byte, error) {
	fetcher := s.newFetcher()
	// The fetcher's own cache is pure residue once FetchMEK has returned
	// its copy; every prompt in the agent comes through here, so this is
	// the site that used to leak a MEK copy per prompt.
	defer closeFetcher(fetcher)
	if withdraw != nil {
		if cf, ok := fetcher.(CancelableFetcher); ok {
			return cf.FetchMEKCancel(reason, withdraw)
		}
	}
	return fetcher.FetchMEK(reason)
}

// promptOrBroker is the one place a prompt reaches the screen. With broker
// set and a broker connected, the request is shown to it: beside the Touch
// ID when the broker can do that, otherwise in front of it, waiting for its
// answer. Otherwise the Touch ID for reason appears alone. prompted reports
// whether a dialog was actually shown, so a refusal that never reached the
// screen records no auth method. The MEK, when there is one, is the
// caller's to keep or wipe.
func (s *Server) promptOrBroker(pending *SessionEvent, reason string, broker bool) (mek []byte, prompted bool, err error) {
	if broker {
		if p, unpark := s.parkWithBrokers(pending); p != nil {
			defer unpark()
			if p.follows {
				return s.promptBesideBroker(p, reason)
			}
			verdict := s.awaitAnswer(p)
			// Answered: off the table before the Touch ID, as it always was.
			unpark()
			switch verdict {
			case brokerDenied:
				return nil, false, errDeclinedByBroker
			case brokerUnanswered:
				return nil, false, fmt.Errorf("%w within %s", errUnansweredByBroker, s.brokerWait)
			case brokerAllowed:
				reason = confirmReason(reason)
			case brokerProceed:
			}
		}
	}
	mek, err = s.fetchMEK(reason, nil)
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

// answerConsent delivers a broker's decision to the waiting challenge. For a
// request shown beside its Touch ID, deny withdraws the dialog (again is a
// no-op) and allow is a no-op: the fingerprint is the only approval, and an
// older app that still sends allow must not be told it failed.
func (s *Server) answerConsent(id, decision string) error {
	if decision != DecisionAllow && decision != DecisionDeny {
		return fmt.Errorf("consent_answer: decision must be %q or %q", DecisionAllow, DecisionDeny)
	}
	s.brokerMu.Lock()
	defer s.brokerMu.Unlock()
	p, ok := s.pendingConsents[id]
	if !ok {
		return fmt.Errorf("consent_answer: no request %q is waiting", id)
	}
	if p.follows {
		if decision == DecisionDeny {
			closeOnce(p.denied)
		}
		return nil
	}
	select {
	case p.answer <- decision:
		return nil
	default:
		return fmt.Errorf("consent_answer: request %q was already answered", id)
	}
}

// consentShown answers "consent_shown": the broker has drawn a request that
// is shown beside its Touch ID, so the dialog need not wait any longer.
func (s *Server) consentShown(id string) error {
	s.brokerMu.Lock()
	defer s.brokerMu.Unlock()
	p, ok := s.pendingConsents[id]
	if !ok {
		return fmt.Errorf("consent_shown: no request %q is waiting", id)
	}
	if !p.follows {
		return fmt.Errorf("consent_shown: request %q waits for an answer, not beside a Touch ID", id)
	}
	closeOnce(p.shown)
	return nil
}

// closeOnce closes ch unless it already is. Callers hold brokerMu, so two
// closes never race.
func closeOnce(ch chan struct{}) {
	select {
	case <-ch:
	default:
		close(ch)
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
