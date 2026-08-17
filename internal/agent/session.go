// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package agent

import (
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// This file is the session state machine: obtaining, extending, reporting and
// dropping the one unlocked session the service holds, plus every challenge
// that creates one and the disclosed challenges that confirm a specific
// authorization without creating one.
//
// It exists as its own file because the Server's fields live under three
// distinct locking regimes and reconstructing which field belongs to which
// meant scanning the whole of a 2000-line server.go. Everything here is the
// `mu` (session state) and `challengeMu` / `freshMu` (prompt serialization)
// regimes; grantMu lives in grant.go, trustMu in consent.go. The rules that
// hold across this file:
//
//   - A callback (OnUnlock, OnLock, OnSessionEvent) is NEVER invoked while mu
//     is held. Anything a callback needs is collected under the lock and
//     acted on after releasing it. One acknowledged wrinkle: OnSessionEvent
//     can fire while challengeMu (not mu) is held — challengeUnlock's
//     re-check calls touchSession, whose deferred notifyPendingLock can
//     drain ANOTHER goroutine's just-parked lazy-lock event. The window is a
//     few instructions wide and the sink is a plain file append that never
//     re-enters Server, so it cannot deadlock; a callback that ever calls
//     back into a challenge path would change that.
//   - challengeMu is held across a prompt, so a second caller queues rather
//     than stacking a second dialog on the user's screen.
//   - Every MEK handed out is a copy (mekCopy); the cache is never aliased.

func (s *Server) ensureUnlocked(op string, c *caller, label string) ([]byte, error) {
	return s.ensureUnlockedNotify(s.OnUnlock, op, c, label)
}

// mekCopy returns a fresh copy of the cached MEK. Callers of
// ensureUnlocked get a COPY, never s.mek's own backing array, for the same
// reason keychainwrap.fetchMEK hands out copies: the cache and its
// consumers wipe independently. Here the dangerous direction is the
// reverse of keychainwrap's — not a caller's wipe zeroing the cache, but
// lock() zeroing the cache mid-use: an explicit `jit agent lock` (another
// connection's goroutine, or a `jit vault` command locking on its way out)
// wipes s.mek in place while a wrap/unwrap that already got that slice is
// still inside seal()/open(). A wrap that loses the race seals the DEK
// under a partially-zeroed key and reports success — the stored envelope
// is permanently undecryptable, and nothing anywhere errors at the time.
// Caller must hold s.mu.
func (s *Server) mekCopy() []byte {
	out := make([]byte, len(s.mek))
	copy(out, s.mek)
	return out
}

// verifyClassBinding checks that data really is a wrap of the claimed class
// before anything acts on that claim. It returns nil when there is no live
// session — with no MEK there is nothing to verify against, and this must
// never be the thing that triggers an unlock prompt.
//
// It peeks at the session rather than touching it, deliberately: a request
// that fails this check must not have bought the session a fresh TTL on its
// way to being rejected, or a caller could keep a session alive indefinitely
// with a stream of garbage it never had the key for.
func (s *Server) verifyClassBinding(data []byte, class string, c *caller) error {
	mek := s.peekSession()
	if mek == nil {
		return nil
	}
	defer wipe(mek)
	dek, err := open(mek, data, []byte(class))
	if err != nil {
		// A caller asking for a class it holds no wrap for is the signal this
		// check exists to catch, so it must not vanish just because it was
		// cheap to reject: silently dropping it would make the successful
		// defense invisible to the one person who'd want to know it happened.
		// Recorded as a socket-boundary rejection, not a denial — no human
		// declined anything here, and manufacturing lines indistinguishable
		// from a refused Touch ID is its own small attack.
		if c != nil {
			s.recordRejectedClass(c)
		}
		// Deliberately the same wording open() would produce later. The reply
		// must not tell a caller whether it guessed a real class, only that
		// this ciphertext and this class don't go together.
		return fmt.Errorf("unwrapping: %w", err)
	}
	wipe(dek)
	return nil
}

// forceDisclosedChallenge prompts for a fresh Touch ID with reason as its
// exact wording — ALWAYS, even when the session is already unlocked — as a
// standalone approval gate. Unlike ensureUnlockedNotify it never rides the
// cached session: a disclosed global-mount grant (jit run --with) must put
// the credential's name in front of the human every time, so a script that
// slipped a --with into a command can't grant a machine-wide credential
// silently. The returned MEK is discarded (the session was already
// unlocked; this is a confirmation, not an unlock), so session state is
// untouched. It does NOT arm the global re-prompt cooldown either way, since
// "no, not this global credential" is a targeted refusal, not "stop trying to
// unlock."
//
// reason must be AGENT-DERIVED. Every caller of this function is putting a
// sentence in front of a human who is about to authorize a machine-wide
// credential on the strength of it, so it may never carry a string the
// requesting process chose — the same rule Request.Label documents, on the
// prompt where it matters most.
//
// BOTH outcomes are recorded (approved and declined). The approval used to be
// recorded nowhere at all: `jit audit` had a line for every consent prompt the
// user refused and none for any they accepted, so the trail could prove what
// you blocked and never what you allowed.
func (s *Server) forceDisclosedChallenge(reason string, c *caller) error {
	event, mek, err := s.discloseChallengeOp(reason, OpRevealPID, c)
	wipe(mek)
	// Outside challengeMu — see ensureUnlockedNotify for what happens when a
	// callback runs under it. event is nil for a throttled attempt: no
	// prompt happened, so there is NOTHING to record — see the backoff
	// return in discloseChallengeOp for the audit-falsification bug that
	// made this nil-check load-bearing.
	if event != nil && s.OnSessionEvent != nil {
		s.OnSessionEvent(*event)
	}
	return err
}

// discloseChallengeOp is the serialized half every disclosed challenge shares:
// it holds challengeMu across the prompt (so a disclosed challenge queues
// behind an in-flight one rather than stacking a second dialog) and returns
// the event for the caller to notify on, outside the lock. The event is nil
// exactly when NO PROMPT HAPPENED (the backoff turned the attempt away), and
// every caller must nil-check before notifying; op stamps the non-nil ones,
// so a grant creation's approval and a reveal's approval stay
// distinguishable in history.
//
// On approval it also returns the challenge's MEK instead of discarding it.
// Session state is still never touched — a disclosed challenge remains a
// confirmation, not an unlock — but grant creation needs the key for exactly
// as long as it takes to unwrap the covered DEKs (grant.go), and fetching it
// twice would mean two prompts for one decision. Callers that only wanted the
// confirmation wipe it immediately (forceDisclosedChallenge); every caller
// must wipe it. Nil on any failure.
func (s *Server) discloseChallengeOp(reason, op string, c *caller) (*SessionEvent, []byte, error) {
	s.challengeMu.Lock()
	defer s.challengeMu.Unlock()

	// Checked INSIDE challengeMu, the same placement and the same reason as
	// the denial cooldown on the unlock path: a caller that queued behind
	// the very challenge just refused must be turned away too, or a loop
	// gets a second dialog the instant the first is dismissed.
	//
	// The event returned here is NIL, emphatically. A throttled attempt
	// showed no prompt and unlocked nothing; this used to return
	// unlockEvent(op, c) — whose Kind defaults to KindUnlock — and every
	// caller handed it to OnSessionEvent, so each retry during a pause
	// appended a fabricated "unlock" line to the durable trail `jit audit`
	// reads: unlocks that never happened, attributed to the caller, at
	// connection rate with no cap (the ring never saw them, so the file and
	// the ring disagreed too). The one real KindDenied from the refusal that
	// armed the pause is the whole truth of the episode.
	if err := s.discloseBackoffLocked(op, c); err != nil {
		return nil, nil, err
	}

	pending := unlockEvent(op, c)
	pending.Cause = reason
	s.mu.Lock()
	s.pendingChallenge = pending
	s.mu.Unlock()

	fetcher := s.newFetcher()
	mek, err := fetcher.FetchMEK(reason)
	// The fetcher's own cache is pure residue once FetchMEK has returned its
	// copy. Closing it here matters more than on the unlock path: every
	// consent prompt comes through here, so this is the site that leaked a
	// MEK copy per prompt.
	closeFetcher(fetcher)

	event := unlockEvent(op, c)
	event.AuthMethod = s.authMethod()
	if err != nil {
		event.Kind = KindDenied
		event.Cause = fmt.Sprintf("%s: %s", reason, err)
	} else {
		event.Kind = KindApproved
		event.Cause = reason
	}

	s.mu.Lock()
	s.pendingChallenge = nil
	s.recordEvent(*event)
	s.mu.Unlock()

	s.noteDiscloseOutcomeLocked(op, c, err == nil)

	if err != nil {
		return event, nil, fmt.Errorf("disclosed grant declined: %w", err)
	}
	return event, mek, nil
}

// discloseRefusal is one key's consecutive-refusal state for the disclosed
// prompt backoff.
type discloseRefusal struct {
	count int
	until time.Time
}

// discloseBackoffKey identifies who is being throttled. It is the op plus the
// caller's LAUNCHER, deliberately not the prompt reason and not the caller's
// own argv: trustReason renders the caller's command, which the caller
// chooses, so a loop could otherwise mint a fresh key per iteration and
// out-wait nothing. The launcher is the same coarse anchor the consent
// engine's backoff uses, with the same acknowledged cost (a shared
// interpreter or terminal covers several programs) and the same mitigation —
// the pauses are seconds, they never become a standing refusal, and an
// approval clears them.
func discloseBackoffKey(op string, c *caller) string {
	launcher := ""
	if c != nil {
		launcher = c.launchedBy()
	}
	return op + "\x00" + launcher
}

// maxDiscloseRefusalKeys bounds the map over a weeks-long process. Reached
// only by a caller churning launchers; resetting forfeits escalation state,
// never a prompt.
const maxDiscloseRefusalKeys = 64

// discloseBackoffLocked refuses to prompt while a key is inside its
// post-refusal pause. Caller must hold challengeMu.
//
// Disclosed challenges deliberately do NOT arm the global denial cooldown —
// a refused grant is a targeted "not this", not "stop trying to unlock" —
// which left the widest-scope operations in the product (OpTrust, whose one
// approval waives per-tool consent for a whole tree; grant create and
// extend; a global-credential reveal) with no throttle whatsoever. Any
// same-user process could put an unbounded stream of Touch ID dialogs on
// screen until the human approved one to make it stop. That is the exact
// asymmetry consent.Throttled was introduced to close, in the words of its
// own rationale — "a caller in a loop could simply outlast the user" — and
// it was never carried over to here.
func (s *Server) discloseBackoffLocked(op string, c *caller) error {
	r, ok := s.discloseRefusals[discloseBackoffKey(op, c)]
	if !ok {
		return nil
	}
	if remaining := time.Until(r.until); remaining > 0 {
		// No "run `jit unlock` to clear it" advice, deliberately: the clear
		// is gated on a FRESH unlock, and a disclosed challenge usually runs
		// against an already-open session — where `jit unlock` prompts
		// nobody and clears nothing, so the advice failed exactly when it
		// was most likely to be tried. The pause is seconds; it explains
		// itself.
		return fmt.Errorf("this authorization was declined %s; not asking again for %s",
			plural(r.count, "time"), remaining.Round(time.Second))
	}
	return nil
}

// noteDiscloseOutcomeLocked records an approval (which clears the key) or a
// refusal (which escalates its pause). Caller must hold challengeMu.
func (s *Server) noteDiscloseOutcomeLocked(op string, c *caller, approved bool) {
	key := discloseBackoffKey(op, c)
	if approved {
		delete(s.discloseRefusals, key)
		return
	}
	if s.discloseRefusals == nil {
		s.discloseRefusals = map[string]discloseRefusal{}
	}
	if len(s.discloseRefusals) >= maxDiscloseRefusalKeys {
		if _, known := s.discloseRefusals[key]; !known {
			s.discloseRefusals = map[string]discloseRefusal{}
		}
	}
	r := s.discloseRefusals[key]
	r.count++
	r.until = time.Now().Add(discloseBackoffFor(s.discloseBackoff, r.count))
	s.discloseRefusals[key] = r
}

// discloseBackoffSchedule is the pause after the 1st, 2nd, and 3rd-or-later
// consecutive refusal. Same numbers as the consent engine's, for the same
// reasons: short enough that an accidental decline followed immediately by a
// re-run barely registers, topping out at the denial cooldown's 30s, which
// is long enough that a loop cannot convert patience into approval.
var discloseBackoffSchedule = []time.Duration{
	2 * time.Second,
	8 * time.Second,
	30 * time.Second,
}

func discloseBackoffFor(schedule []time.Duration, refusals int) time.Duration {
	if refusals <= 0 || len(schedule) == 0 {
		return 0
	}
	if refusals > len(schedule) {
		refusals = len(schedule)
	}
	return schedule[refusals-1]
}

// plural renders a refusal count the way consent.Throttled's message does.
func plural(n int, unit string) string {
	if n == 1 {
		return "once"
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

// clearDiscloseBackoff drops every disclosed-prompt pause. Called by a FRESH
// unlock, on the same reasoning that clears the consent backoff there: a
// human who just passed Touch ID is present, and "now" is exactly the signal
// a refusal withheld. An unlock that prompts nobody clears nothing, or any
// process could reset its own pause by asking for a session it already has.
func (s *Server) clearDiscloseBackoff() {
	s.challengeMu.Lock()
	defer s.challengeMu.Unlock()
	s.discloseRefusals = nil
}

func (s *Server) ensureUnlockedNotify(onFresh func(), op string, c *caller, label string) ([]byte, error) {
	mek, _, err := s.ensureUnlockedFresh(onFresh, op, c, label)
	return mek, err
}

// ensureUnlockedFresh is ensureUnlockedNotify plus the one fact its callers
// cannot otherwise recover: whether a HUMAN was actually asked, or whether
// this rode a session that was already open.
//
// The distinction is load-bearing wherever an unlock is treated as a person
// saying "yes, now" — clearing a consent pause, most of all. `jit unlock`
// against an already-unlocked agent challenges nobody, so anything that acts
// on OpUnlock succeeding, rather than on a fresh challenge succeeding, is
// reachable for free by any process that can open the socket.
func (s *Server) ensureUnlockedFresh(onFresh func(), op string, c *caller, label string) ([]byte, bool, error) {
	if mek := s.touchSession(); mek != nil {
		s.recordUse(op, c, label)
		return mek, false, nil
	}

	mek, event, err := s.challengeUnlock(op, c, label)

	// Both callbacks fire only after challengeUnlock has RELEASED challengeMu.
	// They used to run inside it (onFresh via a defer that outlived the call),
	// which made the documented "safe to call back into Server" contract false
	// and deadlocked the agent outright: OnUnlock is mountManager.start, which
	// resolves every mount through Server-as-KeyWrapper, and if the session
	// dropped mid-resolve — the screen-lock/sleep watcher, an explicit `jit
	// lock`, a `jit vault` command locking on its way out — the next unwrap
	// re-entered this path and took challengeMu a second time on the same
	// goroutine. sync.Mutex is not reentrant, so that goroutine parked forever
	// holding it, and every subsequent unlock in the process hung until its
	// client timed out. Status and history kept answering (they only take
	// s.mu), so the agent looked healthy while nothing could unlock.
	if event != nil && s.OnSessionEvent != nil {
		s.OnSessionEvent(*event)
	}
	if err != nil {
		return nil, false, err
	}
	// event != nil is exactly "a fresh challenge produced this session": a
	// cache hit returned above without ever reaching challengeUnlock.
	fresh := event != nil
	if fresh {
		s.notifyFresh(onFresh)
	}
	return mek, fresh, nil
}

// notifyFresh runs a fresh-unlock callback, never re-entrantly.
//
// Moving the callback out from under challengeMu stopped it deadlocking, but
// the shape underneath was worse than a lock-ordering slip: OnUnlock resolves
// mounts THROUGH this same Server, so a session that lapses mid-resolve makes
// the next unwrap unlock again, which fires OnUnlock again, which resolves
// again. Under the old code that recursion happened to hit a non-reentrant
// mutex on the second lap and parked; with the mutex out of the way it is
// simply unbounded, and a stack overflow kills the agent outright instead of
// hanging it. Re-entrancy is the actual bug, so this is where it is fixed.
//
// A callback that arrives while one is running sets pending instead of
// nesting, and the runner makes one more pass when it finishes: a genuine
// second unlock (another goroutine's, or one the resolve itself caused) still
// gets its mounts resolved, and OnUnlock — mountManager.start, idempotent by
// construction — just does its scan twice in the rare case both were really
// the same event. The pass cap is a backstop against a session that keeps
// lapsing mid-resolve turning "once more" into a treadmill; OnRefresh is the
// explicit signal for anything that misses.
func (s *Server) notifyFresh(onFresh func()) {
	if onFresh == nil {
		return
	}
	s.freshMu.Lock()
	if s.freshRunning {
		s.freshPending = true
		s.freshMu.Unlock()
		return
	}
	s.freshRunning = true
	s.freshMu.Unlock()

	for pass := 1; ; pass++ {
		onFresh()
		s.freshMu.Lock()
		if !s.freshPending || pass >= maxFreshPasses {
			s.freshRunning = false
			s.freshPending = false
			s.freshMu.Unlock()
			return
		}
		s.freshPending = false
		s.freshMu.Unlock()
	}
}

// maxFreshPasses bounds notifyFresh's coalescing re-runs. Two is one full pass
// plus one catch-up for whatever arrived during it, which is every case that
// occurs when things are working; more than that means the session is lapsing
// as fast as it opens, and looping harder would not help.
const maxFreshPasses = 2

// challengeUnlock is ensureUnlockedNotify's serialized half: everything that
// must happen behind challengeMu, and nothing that must not. It returns the
// MEK copy, and the session event a FRESH challenge produced (nil when the
// session was already open — a re-check hit, which is not a fresh unlock and
// must not fire onFresh) for the caller to notify on, outside the lock.
//
// challengeMu — not s.mu — is what serializes concurrent callers behind a
// single Touch ID prompt rather than each triggering their own. The second
// caller in line re-checks the session after acquiring it, because the first
// caller's approved challenge is usually exactly the unlock it was waiting
// for. s.mu is only ever held for field access, so a status/history/lock
// request arriving mid-challenge is answered immediately instead of queueing
// for up to the challenge's ~120s ceiling.
func (s *Server) challengeUnlock(op string, c *caller, label string) ([]byte, *SessionEvent, error) {
	s.challengeMu.Lock()
	defer s.challengeMu.Unlock()

	// The caller we queued behind may have just unlocked for us.
	if mek := s.touchSession(); mek != nil {
		s.recordUse(op, c, label)
		return mek, nil, nil
	}

	// The denial cooldown: a challenge the human just declined means "not
	// now", and the very callers that trigger surprise prompts (an MCP
	// server its launcher restarts on failure, a retrying script) ask
	// again within seconds — each retry another prompt, until the only way
	// to make it stop is to approve. Checked HERE, after the challengeMu
	// queue, so the waiters that queued behind the very challenge that got
	// declined are also turned away instead of re-prompting back-to-back.
	// OpUnlock is exempt: an explicit `jit agent unlock` is a human
	// overriding the pause on purpose.
	if op != OpUnlock {
		s.mu.Lock()
		lastDenied := s.lastDenied
		lastCause := s.lastDeniedCause
		cooldown := s.denialCooldown
		s.mu.Unlock()
		// A zero lastDenied (nothing ever declined, or cleared by the last
		// successful unlock) makes sinceDenied enormous, so it never trips.
		if sinceDenied := time.Since(lastDenied); sinceDenied < cooldown {
			// `jit unlock`, the top-level command. This used to say `jit agent
			// unlock`, which the agent→service rename left behind as a
			// deprecated alias that prints help and unlocks nothing — a dead
			// instruction at the exact moment the user is locked out and
			// following instructions.
			return nil, nil, fmt.Errorf("an unlock attempt failed %s ago (%s), automatic re-prompts are paused for another %s (run `jit unlock` to try again now)",
				sinceDenied.Round(time.Second), lastCause, (cooldown - sinceDenied).Round(time.Second))
		}
	}

	// pending is what status reports while the prompt is on screen; its
	// UnixTime is when the prompt APPEARED. The recorded unlock event is
	// built fresh after success, so history carries when the human
	// actually approved, not when they were first asked.
	pending := unlockEvent(op, c)
	s.mu.Lock()
	s.pendingChallenge = pending
	s.mu.Unlock()

	// The reason handed to the fetcher is the prompt the human is about to
	// read, so it is built HERE, where both the op and the caller are known
	// — the fetcher itself has no idea who it's prompting on behalf of.
	// label is deliberately NOT part of it: it's caller-reported, and the
	// one line a human decides by must never carry a fact the caller could
	// have made up (see Request.Label).
	fetcher := s.newFetcher()
	mek, err := fetcher.FetchMEK(challengeReason(op, c))
	// The MEK we keep is the copy FetchMEK returned; the fetcher's own cache
	// has served its purpose the moment we have it.
	closeFetcher(fetcher)

	s.mu.Lock()
	s.pendingChallenge = nil
	if err != nil {
		// The denial is recorded with the same provenance the unlock would
		// have carried — a prompt the user refused used to vanish without
		// a trace, making "what just asked, that I said no to?" the one
		// question history couldn't answer. It also arms the cooldown
		// above.
		event := unlockEvent(op, c)
		event.Kind = KindDenied
		event.Cause = err.Error()
		event.AuthMethod = s.authMethod()
		if label != "" {
			event.Labels = []string{label}
		}
		s.lastDenied = time.Now()
		s.lastDeniedCause = err.Error()
		s.recordEvent(*event)
		s.mu.Unlock()
		return nil, event, fmt.Errorf("unlocking: %w", err)
	}
	s.mek = mek
	// Best-effort: keep the long-lived cached MEK off swap. The transient
	// copies handed to callers are wiped within the request; this is the
	// one buffer that persists for the whole TTL.
	lockMemory(s.mek)
	out := s.mekCopy()
	event := unlockEvent(op, c)
	event.AuthMethod = s.authMethod()
	if label != "" {
		event.Labels = []string{label}
	}
	s.lastUnlock = event
	s.lastDenied = time.Time{}
	s.lastDeniedCause = ""
	s.recordEvent(*event)
	// sessionStart is stamped only here, on a fresh challenge — the one moment
	// a human actually authorized this session. Every later use moves expiry;
	// none of them move this.
	s.sessionStart = time.Now()
	s.expiry = time.Now().Add(s.ttl)
	s.armLockTimer()
	s.mu.Unlock()

	return out, event, nil
}

// touchSession returns a copy of the MEK if the session is still valid —
// extending the inactivity TTL — or nil, meaning a fresh challenge is
// needed. The TTL is a true inactivity timeout (GAPS.md #45), exactly as
// `jit agent --help` and the docs describe it: every use of the still-valid
// session pushes auto-lock back out to a full ttl from now. The code used
// to implement a fixed window since the last unlock instead (a cache hit
// never extended expiry), silently disagreeing with its own help text —
// under that reading, an actively-used session would re-prompt mid-work at
// a moment that has nothing to do with the user having stepped away, which
// is the only thing the auto-lock exists to cover.
// The inactivity TTL is not the only bound: maxSessionAge caps the whole
// session from the unlock that started it, so continuous use extends a
// session but can no longer sustain one forever (see collectIfDoneLocked).
func (s *Server) touchSession() []byte {
	// Ordered so the durable hand-off for a session this call may have
	// collected runs after mu is released (defers unwind last-in-first-out).
	defer s.notifyPendingLock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mek == nil {
		return nil
	}
	if s.collectIfDoneLocked(time.Now()) {
		return nil
	}
	mek := s.mekCopy()
	s.expiry = time.Now().Add(s.ttl)
	s.armLockTimer()
	return mek
}

// peekSession returns a copy of the MEK if the session is live, WITHOUT
// extending the inactivity TTL, re-arming the lock timer, or recording a use.
// It is for work that has to happen BEFORE we decide whether a request
// deserves the session at all — verifying that a caller's claimed class
// actually matches the ciphertext it sent (see OpUnwrap).
//
// Not extending is the point. A request that turns out to be garbage must not
// buy the session another full TTL on its way to being rejected, or the check
// meant to make junk requests cheap would make them useful instead.
func (s *Server) peekSession() []byte {
	defer s.notifyPendingLock() // see touchSession: drained outside mu
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mek == nil {
		return nil
	}
	if s.collectIfDoneLocked(time.Now()) {
		return nil
	}
	return s.mekCopy()
}

// collectIfDoneLocked wipes the session and reports true if it is over —
// either idle past its expiry or older than maxSessionAge. Both are checked
// here rather than left to the lock timer because a timer that hasn't fired
// yet is not evidence that a session is still valid, and the caller is about
// to hand out the key. Caller must hold s.mu.
func (s *Server) collectIfDoneLocked(now time.Time) bool {
	aged := !s.sessionStart.IsZero() && s.maxSessionAge > 0 &&
		!now.Before(s.sessionStart.Add(s.maxSessionAge))
	if now.Before(s.expiry) && !aged {
		return false
	}
	// This collection IS the session's lock, so it is recorded as one. It
	// used to be recorded nowhere: the wipe below nils the MEK silently, and
	// the still-armed idle timer then found hadSession false and wrote no
	// KindLock and no lastLock at all — history showed unlock → unlock with
	// nothing between, which is exactly the "I authorized this twenty
	// minutes ago, why again?" question a lock cause exists to answer. The
	// race needs a request to beat the timer goroutine past expiry: a busy
	// agent, which is the common one. Recording HERE rather than leaving it
	// to the timer also survives the usual continuation, where the same
	// request goes straight on to a fresh unlock and no timer ever runs for
	// the session that ended.
	//
	// The ring and lastLock are updated under mu (both require it); the
	// durable OnSessionEvent hand-off cannot run here, so it is parked for
	// notifyPendingLock to drain outside the lock.
	//
	// Pending uses flush FIRST, exactly as lockIfGen orders them: they
	// happened inside the session this collection ends, and recording the
	// lock ahead of them would file a session's own uses after its end —
	// and, in the usual continuation (the same request goes straight on to
	// a fresh unlock, whose armLockTimer neutralizes the stale timer), after
	// the NEXT session's unlock line too.
	cause := fmt.Sprintf("%s idle timeout", s.ttl)
	if aged {
		cause = fmt.Sprintf("%s maximum session age", s.maxSessionAge)
	}
	event := SessionEvent{UnixTime: now.Unix(), Kind: KindLock, Cause: cause}
	s.lastLock = &event
	flushed := s.flushUsesLocked(true, now)
	s.recordEvent(event)
	s.pendingLockNotify = append(s.pendingLockNotify, append(flushed, event)...)

	wipe(s.mek)
	unlockMemory(s.mek)
	s.mek = nil
	return true
}

// notifyPendingLock hands a lazily-collected session's parked events (its
// flushed uses, then its lock) to the durable sink, outside mu. Every caller
// of collectIfDoneLocked calls it once it has released the lock; it is a
// no-op when nothing was collected, so calling it unconditionally is correct
// and cheap.
func (s *Server) notifyPendingLock() {
	s.mu.Lock()
	events := s.pendingLockNotify
	s.pendingLockNotify = nil
	s.mu.Unlock()
	if s.OnSessionEvent != nil {
		for _, e := range events {
			s.OnSessionEvent(e)
		}
	}
}

// armLockTimer (re)arms the idle auto-lock a full TTL out. Caller must
// hold s.mu. Bumping timerGen is what neutralizes a previously-armed timer
// whose goroutine already started firing (Stop() too late to help): when
// it eventually gets the lock, its generation no longer matches and it
// must not touch the session it no longer times.
func (s *Server) armLockTimer() {
	s.timerGen++
	gen := s.timerGen
	if s.lockTimer != nil {
		s.lockTimer.Stop()
	}
	// Whichever bound runs out first owns the timer. Arming the idle TTL
	// unconditionally would let a session that is busy right up to its hard
	// ceiling sit there past it until something happened to ask — collected
	// lazily by collectIfDoneLocked, with no lock event and nothing in
	// history to explain why the next access re-prompted.
	delay, cause := s.ttl, fmt.Sprintf("%s idle timeout", s.ttl)
	if !s.sessionStart.IsZero() && s.maxSessionAge > 0 {
		if untilCap := time.Until(s.sessionStart.Add(s.maxSessionAge)); untilCap < delay {
			delay = untilCap
			cause = fmt.Sprintf("%s maximum session age", s.maxSessionAge)
		}
	}
	s.lockTimer = time.AfterFunc(delay, func() {
		s.lockIfGen(cause, gen)
	})
}

// lock drops the cached MEK, recording WHY. The provenance record and the
// KindLock event only fire when there was actually a session to drop —
// calling lock on an already-locked agent must not overwrite the cause of
// the lock that actually happened with a no-op's. OnLock (the mount-clearing
// side effect) DOES fire regardless, idempotently: a lazy expiry can nil the
// MEK before the idle timer runs, leaving mounts to clear even when no
// session remains to record (see lockIfGen).
//
// cause is the answer to the question a re-prompt raises ("I authorized this
// twenty minutes ago — why again?"), and it is almost always the idle
// timeout rather than anything the user did. Saying so is the difference
// between the auto-lock looking like policy and looking like a bug.
func (s *Server) lock(cause string) {
	s.lockIfGen(cause, 0)
}

// LockWithCause drops the session exactly as an explicit OpLock would,
// recording cause verbatim in the session provenance — for in-process lock
// triggers (the screen-lock/sleep watcher) that never arrive over the
// socket and so have no caller to attribute. Same no-op-when-locked
// semantics as every other lock.
func (s *Server) LockWithCause(cause string) {
	s.lock(cause)
}

// lockIfGen is lock with an optional timer-generation guard: gen 0 (an
// explicit lock — armLockTimer starts at 1) always proceeds; a nonzero gen
// is an idle timer identifying which arming it came from, and one that no
// longer matches lost a race to a touch/unlock that re-armed after it —
// the session it would drop is not the one it timed.
func (s *Server) lockIfGen(cause string, gen uint64) {
	s.mu.Lock()
	if gen != 0 && gen != s.timerGen {
		s.mu.Unlock()
		return
	}
	// The lock is the session boundary: everything still pending in the
	// use aggregation happened inside the session this lock ends, so it
	// flushes here — recorded (and notified) BEFORE the lock event, the
	// order it actually happened. Unconditional on purpose: a session that
	// lazily expired via touchSession has mek == nil but can still hold
	// pending uses.
	flushed := s.flushUsesLocked(true, time.Now())
	hadSession := s.mek != nil
	if s.mek != nil {
		wipe(s.mek)
		unlockMemory(s.mek)
		s.mek = nil
	}
	s.expiry = time.Time{}
	s.sessionStart = time.Time{}
	if s.lockTimer != nil {
		s.lockTimer.Stop()
		s.lockTimer = nil
	}
	var event *SessionEvent
	if hadSession {
		event = &SessionEvent{UnixTime: time.Now().Unix(), Kind: KindLock, Cause: cause}
		s.lastLock = event
		s.recordEvent(*event)
	}
	s.mu.Unlock()

	// Consent decisions ride the unlock session: clear them when it ends, so a
	// re-lock forces a fresh prompt rather than honoring an approval you gave
	// before you stepped away. Cheap and idempotent when there's nothing to drop.
	//
	// Process grants (s.grants) are deliberately NOT cleared here — the single
	// carve-out from "a re-lock drops every authorization state". Surviving the
	// screen lock is the feature: the human's disclosed challenge approved
	// "unattended, until <deadline>" in so many words, for named secrets and
	// one process tree, and a grant that died with the lock would just be a
	// session. They end by their own deadline, their root exiting, or an
	// explicit revoke (grant.go).
	if s.Consent != nil {
		s.Consent.Clear()
	}
	s.clearTrust()

	s.notifySessionEvents(flushed)
	if hadSession && s.OnSessionEvent != nil {
		s.OnSessionEvent(*event)
	}
	// OnLock runs even when hadSession is false. A lazy TTL expiry via
	// touchSession nils the MEK the moment a request notices the session has
	// lapsed — which can beat this idle timer's own goroutine to s.mu, so by
	// the time the timer runs there is no session left to "drop" (hadSession
	// false), yet the mounts still hold the resolved real content and any
	// open reveal/grant from the session that just ended. Skipping OnLock
	// there left them serving real values while the agent reported locked.
	// OnLock (mountManager.stop) is idempotent and stays silent when it
	// clears nothing, so firing it on a genuine no-op lock costs nothing.
	if s.OnLock != nil {
		s.OnLock()
	}
}

// lockCause names an explicit `jit agent lock` (or a `jit vault` command that
// locks when it's done), attributing it when the kernel identified the caller.
func lockCause(c *caller) string {
	if by := c.launchedBy(); by != "" {
		return fmt.Sprintf("explicit lock, launched by %s", by)
	}
	return "explicit lock"
}

// authMethod is the best-effort "how were you asked" phrase stamped on every
// event a fresh challenge produced. It defers to AuthMethodFn when the CLI has
// wired the biometry probe, and otherwise states the policy jit always uses —
// never a specific method, since LAPolicyDeviceOwnerAuthentication does not
// report whether the fingerprint or the passcode was the one that satisfied it.
func (s *Server) authMethod() string {
	if s.AuthMethodFn != nil {
		if m := s.AuthMethodFn(); m != "" {
			return m
		}
	}
	return "Touch ID or device passcode"
}

// Quiescent reports whether the agent is doing nothing anyone would miss
// if the process exited right now: no live session (locked) and no
// challenge awaiting a human on screen. The stale-binary self-restart
// gates on this — restarting costs nothing while locked (the next use
// re-prompts either way, and a lock has already hidden every mount), but
// killing an unlocked session or a prompt mid-approval trades a warning
// in status for a worse surprise.
func (s *Server) Quiescent() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlocked := s.mek != nil && s.remainingLocked() > 0
	return !unlocked && s.pendingChallenge == nil
}

// lockMemory/unlockMemory pin (and unpin) b's pages so the cached MEK
// can't be written to swap for the lifetime of the session. Best-effort
// defense in depth — macOS encrypts swap by default, mlock rounds to
// whole pages, and the transient per-caller copies are wiped within
// their request anyway — so failures are deliberately ignored: a
// resource-limit refusal must never make an unlock fail. unlockMemory
// runs AFTER wipe, so the page a munlock makes swappable again holds
// only zeros.
func lockMemory(b []byte) {
	if len(b) > 0 {
		_ = unix.Mlock(b)
	}
}

func unlockMemory(b []byte) {
	if len(b) > 0 {
		_ = unix.Munlock(b)
	}
}

// SessionUnlocked reports whether a live session is currently cached, WITHOUT
// challenging or extending the TTL — a pure read. mountManager uses it so a
// teardown-time resolve (restoring a swapped mount when a run exits, which
// can happen while locked) serves real content only when the session is
// already open and stays decoy otherwise, instead of raising a Touch ID
// prompt from a status read or a lock (the "status must never prompt" rule).
func (s *Server) SessionUnlocked() bool {
	unlocked, _ := s.status()
	return unlocked
}

func (s *Server) status() (unlocked bool, remaining time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mek == nil {
		return false, 0
	}
	remaining = s.remainingLocked()
	if remaining <= 0 {
		return false, 0
	}
	return true, remaining
}

// remainingLocked is how long this session actually has left: the idle expiry
// or the hard ceiling, whichever comes first.
//
// Reporting the idle expiry alone would make `jit status` say "locks in 8h"
// on a session that the ceiling ends in twenty minutes — the same "a setting
// that cannot mean what it says" failure validateAgentTTL exists to prevent,
// except here it is the readout rather than the config. Caller must hold s.mu.
func (s *Server) remainingLocked() time.Duration {
	remaining := time.Until(s.expiry)
	if !s.sessionStart.IsZero() && s.maxSessionAge > 0 {
		if untilCap := time.Until(s.sessionStart.Add(s.maxSessionAge)); untilCap < remaining {
			remaining = untilCap
		}
	}
	return remaining
}
