// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// Package consent is the decision core for per-process credential consent
// (design/per-process-credential-consent.md). When a process reaches for a
// credential, jit asks one question: should this caller get the real value?
// The answer comes from, in order: (1) is the caller inside a run you already
// authorized (a --with/--trust/grant-shim, or a descendant of one)? then yes,
// silently; (2) is there a standing decision from an earlier prompt this
// session? then reuse it; (3) otherwise prompt, and remember the answer for
// the scope you chose.
//
// This package is deliberately pure and call-site-agnostic: it knows nothing
// about sockets, FIFOs, the agent, or Touch ID. The two call sites (the agent's
// hook-credential path with kernel-vouched caller identity; the mount serve
// path with best-effort libproc identity) build a Request and supply a Prompter;
// the Strength field records which kind of identity backed the request so the
// prompt UI and audit can be honest about confidence. Keeping the engine pure
// is what lets it be unit-tested without a vault, an agent, or a real prompt.
package consent

import (
	"fmt"
	"strconv"
	"sync"
	"time"
)

// Strength records how trustworthy the caller's identity is. Hard means a
// kernel-vouched identity (a socket peer PID) that a same-user process cannot
// forge; BestEffort means an inferred identity (a libproc scan + PPID walk of a
// FIFO reader) that a determined same-user attacker can spoof. It travels
// through so the prompt and audit can say "this is who's asking" vs "this is
// who's asking, as best we can tell."
//
// It never decides an ALLOW or a DENY — a weak identity is not itself grounds
// to refuse — but it does partition the decision cache (see Request.key), so
// an answer given about one kind of identity is never spent on the other.
type Strength int

const (
	Hard Strength = iota
	BestEffort
)

// Decision is the outcome for one credential access.
type Decision int

const (
	// Undecided is the zero value and is returned only when a prompt could not
	// produce an answer (a headless context with no UI). Callers MUST treat it
	// as deny: fail closed.
	Undecided Decision = iota
	Allow
	Deny
)

// Scope is how long a prompted decision persists, chosen by the user at the
// prompt.
type Scope int

const (
	// Once applies to this access only and is never cached: the next access
	// re-decides.
	Once Scope = iota
	// Session caches until the vault session re-locks (Engine.Clear) or the
	// configured TTL elapses, whichever comes first. This is the "approve
	// gcloud, glide for the session" case.
	Session
	// Always caches with no expiry. The prompter is expected to also perform
	// the durable side effect (installing a --grant shim); the engine only
	// remembers not to prompt again this process's lifetime.
	Always
)

// Caller identifies the process reaching for a credential. ExecPath is the key
// the session cache is keyed on (with the credential), so approving a tool once
// covers every later invocation of that same tool for the session, without
// re-prompting a fresh PID each command. An EMPTY ExecPath means the caller
// could not be identified (a best-effort scan that missed); such a decision is
// deliberately never cached — see Decide — so one unidentifiable process's
// approval can't leak to every other unidentifiable process this session.
type Caller struct {
	PID      int32
	ExecPath string // e.g. "/usr/local/bin/gcloud" — the cache key, per tool ("" = unidentified, never cached)
	Lineage  string // human summary, e.g. "launched by npm install" — for the prompt
	Strength Strength
	// DescendsFromGrant is set by the call site when this caller (or an
	// ancestor) is inside an active jit-run grant. It short-circuits to Allow
	// with no prompt, so a tool you launched through a grant is transparent.
	DescendsFromGrant bool
}

// Request is one credential access awaiting a decision.
type Request struct {
	Credential string // the vault credential name/label, e.g. "aws", "gcp"
	Caller     Caller
	// PriorRefusals is how many times THIS caller's request for THIS
	// credential has already been refused in the current session. It is set
	// by the engine before it calls the Prompter, never by the call site, and
	// exists so the prompt can say so: the third identical dialog in a minute
	// is a materially different question from the first, and a human who
	// can't see that difference has only their patience to answer it with.
	PriorRefusals int
}

// key identifies a cacheable decision. Strength is part of it, so a decision
// made about a kernel-vouched identity is never reused for a merely inferred
// one: the two paths reach this engine with genuinely different confidence
// (a socket peer PID the kernel stands behind, vs. a libproc scan of a FIFO's
// holders that a same-user process can influence), and a shared cache entry
// would let the weaker path spend an approval the user granted on the strength
// of the stronger one.
//
// The cost is a second prompt in the rare case where one tool reaches the same
// credential over both paths in one session. That direction is the right one to
// err in, and it is rare in practice: the socket classes (aws, docker, git,
// kube, terraform) and the FIFO classes (gcp, npmrc, netrc) barely overlap.
func (r Request) key() string {
	return r.Credential + "\x00" + r.Caller.ExecPath + "\x00" + strconv.Itoa(int(r.Caller.Strength))
}

// Prompter asks the user and returns their decision and how long it should
// stick. It is where all side effects live (showing Touch ID, installing a
// shim for Always, writing the audit record). An error means no answer could
// be obtained (headless); the engine surfaces it and the caller fails closed.
type Prompter func(Request) (Decision, Scope, error)

type cached struct {
	decision Decision
	expires  time.Time // zero means no expiry (Always)
}

// refusal tracks consecutive non-approvals for one key, and until when the
// engine is refusing to prompt about it again. Reset by an approval or by
// Clear; see Throttled for why it exists.
type refusal struct {
	count int
	until time.Time
}

// backoffSchedule is the pause after the 1st, 2nd, and 3rd-or-later
// consecutive refusal of the same request. It starts short enough that a
// human who declined by accident and immediately re-ran their command barely
// notices, and tops out at the same 30 seconds the agent's unlock cooldown
// uses — long enough that a loop cannot convert patience into approval.
var backoffSchedule = []time.Duration{
	2 * time.Second,
	8 * time.Second,
	30 * time.Second,
}

// refusalRetention is how long past its pause a refusal record is kept so the
// escalation still remembers it. Long enough that no realistic retry loop
// escapes the schedule, short enough that the map doesn't accumulate for the
// life of a weeks-long agent process.
const refusalRetention = time.Hour

func backoffFor(refusals int) time.Duration {
	if refusals <= 0 {
		return 0
	}
	if refusals > len(backoffSchedule) {
		refusals = len(backoffSchedule)
	}
	return backoffSchedule[refusals-1]
}

// Throttled is returned instead of a prompt while a request is inside its
// post-refusal pause. Callers fail closed on it exactly as they do on any
// other non-Allow outcome; it is a distinct type only so the message can
// explain the wait rather than looking like a fresh refusal.
//
// This is what closes the asymmetry that made refusing a consent prompt
// unaffordable. A declined prompt must not become a session-long Deny — the
// prompter genuinely cannot tell a human's "no" from a keychain error, and
// caching either would lock the credential out with no way back.
//
// Note precisely WHERE that guarantee lives, because it is not in this engine.
// remember caches whatever scope the prompter asks for, Deny included, and
// that is deliberate: a tool that was denied and keeps reading should not earn
// a fresh dialog per read (TestDenyIsCachedForTheSession pins the capability).
// What supplies the guarantee is the SHIPPED prompter — the agent's
// gateConsent returns consent.Once on a failed challenge, so a refusal there is
// never cached and the pause below is what the next attempt meets instead. Any
// new Prompter owes the same choice; an exported func type cannot be made to.
// TestRefusedConsentPausesRatherThanStandingDeny holds that end of it.
//
// So every refusal used to cost the user one full-screen
// modal and cost the caller nothing, and a process asking in a loop produced
// one dialog per iteration until the only way to stop them was to approve.
// The pause makes refusing cheap without making it permanent: the credential
// stays reachable, the next genuine attempt still prompts, and a loop gets
// errors instead of an audience.
//
// The cost is real and worth stating. The key is coarse — credential plus the
// caller's LAUNCHER, which for anything script-driven is a shared interpreter
// or the terminal itself — so refusals earned by one program can pause an
// honest one that happens to resolve to the same launcher. That is why the
// pause is short, why it never becomes a cached Deny, and why an explicit
// `jit unlock` clears it (ClearBackoff): a human at the keyboard saying "now"
// is exactly the signal a refusal withheld, and the same override the agent's
// unlock cooldown has always honored.
type Throttled struct {
	Credential string
	Refusals   int
	RetryAfter time.Duration
}

func (t *Throttled) Error() string {
	return fmt.Sprintf("access to your %s credential was refused %s; not asking again for %s (run `jit unlock` to clear the pause)",
		t.Credential, plural(t.Refusals, "time"), t.RetryAfter.Round(time.Second))
}

func plural(n int, unit string) string {
	if n == 1 {
		return "once"
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

// Engine holds the session's standing decisions.
type Engine struct {
	mu    sync.Mutex
	cache map[string]cached
	// pending single-flights concurrent first accesses for the same key: the
	// first caller becomes the leader and prompts; the rest wait on its channel
	// and re-read the cache it fills, so two tools reaching for the same
	// credential at once produce one Touch ID prompt, not a stampede of them.
	pending map[string]chan struct{}
	// refusals is the backoff state per key. It is deliberately NOT the
	// decision cache: a refusal is never a standing answer (lookup must still
	// miss, so the next attempt after the pause really does re-ask), only a
	// reason to decline to ask again just yet.
	refusals   map[string]refusal
	sessionTTL time.Duration
	now        func() time.Time // injectable for tests
}

// New returns an Engine whose Session-scoped decisions live at most sessionTTL
// (align this with the vault's unlock TTL so consent clears when the session
// re-locks).
func New(sessionTTL time.Duration) *Engine {
	return &Engine{
		cache:      make(map[string]cached),
		pending:    make(map[string]chan struct{}),
		refusals:   make(map[string]refusal),
		sessionTTL: sessionTTL,
		now:        time.Now,
	}
}

// Decide resolves one access. It prompts only when there is neither a grant
// descent nor a live standing decision.
func (e *Engine) Decide(req Request, prompt Prompter) (Decision, error) {
	// (1) Inside a run you already authorized: serve, never prompt.
	if req.Caller.DescendsFromGrant {
		return Allow, nil
	}

	key := req.key()

	// An unidentified caller (empty ExecPath) has no identity to cache a
	// decision against — two such callers are indistinguishable, so one's
	// approval must never be spent by another — and its answer is therefore
	// never remembered. It is NOT exempt from the queue or the backoff: both
	// key on the credential alone in that case, grouping every anonymous
	// caller together. Being harder to identify must not buy a caller more of
	// the user's attention than being honest about who you are, and an
	// exemption here would have been a free prompt generator for anyone
	// willing to obscure their lineage.
	cacheable := req.Caller.ExecPath != ""

	for {
		// (2) A standing decision from earlier this session.
		if cacheable {
			if d, ok := e.lookup(key); ok {
				return d, nil
			}
		}

		// Refused too recently to ask again. Checked inside the loop, after
		// the cache miss, so waiters released by a leader whose prompt was
		// just declined are turned away here rather than each becoming the
		// next leader and prompting in turn — which is what made a hundred
		// concurrent requests cost a hundred dialogs despite the single-flight.
		if err := e.throttle(key, req.Credential); err != nil {
			return Deny, err
		}

		// (3) Ask, and remember for the chosen scope — but only one caller per
		// key prompts at a time; the rest wait for that answer and re-check.
		leader, wait := e.joinFlight(key)
		if !leader {
			<-wait
			continue
		}
		req.PriorRefusals = e.refusalCount(key)
		d, scope, err := prompt(req)
		if err == nil {
			if cacheable {
				e.remember(key, d, scope)
			}
			e.score(key, d)
		}
		e.finishFlight(key)
		if err != nil {
			return Undecided, err
		}
		return d, nil
	}
}

// throttle returns a *Throttled if key is still inside its post-refusal
// pause, and nil if it is free to prompt.
func (e *Engine) throttle(key, credential string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	r, ok := e.refusals[key]
	if !ok {
		return nil
	}
	remaining := r.until.Sub(e.now())
	if remaining <= 0 {
		// The pause is over, but the COUNT is not cleared: only an approval
		// (or a re-lock, or an explicit unlock) resets the escalation.
		// Otherwise a caller could sit out two seconds and be back at the
		// bottom of the schedule forever, which is a rate limit in name only.
		//
		// Long-dormant entries are reclaimed, though. The agent runs for
		// weeks, and a map that only ever grows is a slow leak; an hour of
		// silence is far longer than any flood and is not a way to game the
		// escalation, since waiting an hour between attempts is not a flood.
		if -remaining > refusalRetention {
			delete(e.refusals, key)
		}
		return nil
	}
	return &Throttled{Credential: credential, Refusals: r.count, RetryAfter: remaining}
}

// ClearBackoff drops every pause without touching the standing decisions.
//
// This is the human override, and it is the reason the backoff is safe to key
// as coarsely as it does. `jit unlock` is someone at the keyboard saying "now"
// — the same gesture the agent's unlock cooldown has always exempted — so a
// pause earned by whatever was asking in the background must not outlive it.
// Decisions are deliberately left alone: an unlock is permission to be asked
// again, not permission to skip the asking.
func (e *Engine) ClearBackoff() {
	e.mu.Lock()
	e.refusals = make(map[string]refusal)
	e.mu.Unlock()
}

// score updates the backoff after a completed prompt: an approval clears the
// escalation outright, anything else extends it.
//
// "Anything else" includes a challenge that failed for reasons the user had
// nothing to do with — the prompter cannot distinguish those from a decline,
// which is the same limitation that stops a refusal being cached as a Deny.
// The cost of conflating them here is bounded and self-correcting: a genuinely
// broken keychain adds seconds before each retry rather than locking anything
// out, and the first success clears it.
func (e *Engine) score(key string, d Decision) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if d == Allow {
		delete(e.refusals, key)
		return
	}
	r := e.refusals[key]
	r.count++
	r.until = e.now().Add(backoffFor(r.count))
	e.refusals[key] = r
}

func (e *Engine) refusalCount(key string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.refusals[key].count
}

// joinFlight registers the caller against key: the first returns leader=true
// and owns the prompt; a later caller returns leader=false and a channel that
// closes when the leader is done, at which point it re-reads the cache.
func (e *Engine) joinFlight(key string) (leader bool, wait chan struct{}) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if ch, ok := e.pending[key]; ok {
		return false, ch
	}
	ch := make(chan struct{})
	e.pending[key] = ch
	return true, ch
}

// finishFlight releases key's waiters once the leader has prompted (and, on
// success, cached the answer they'll find on their re-check).
func (e *Engine) finishFlight(key string) {
	e.mu.Lock()
	ch := e.pending[key]
	delete(e.pending, key)
	e.mu.Unlock()
	if ch != nil {
		close(ch)
	}
}

func (e *Engine) lookup(key string) (Decision, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	c, ok := e.cache[key]
	if !ok {
		return Undecided, false
	}
	if !c.expires.IsZero() && !c.expires.After(e.now()) {
		delete(e.cache, key)
		return Undecided, false
	}
	return c.decision, true
}

func (e *Engine) remember(key string, d Decision, scope Scope) {
	if scope == Once {
		return // never cached: the next access re-decides
	}
	var expires time.Time
	if scope == Session {
		expires = e.now().Add(e.sessionTTL)
	}
	e.mu.Lock()
	e.cache[key] = cached{decision: d, expires: expires}
	e.mu.Unlock()
}

// Clear drops every standing decision. Call it when the vault session re-locks
// (idle, screen lock, sleep, explicit lock) so consent never outlives the
// unlock it rode in on.
func (e *Engine) Clear() {
	e.mu.Lock()
	e.cache = make(map[string]cached)
	// Backoff state is session state too. A re-lock is a human coming back to
	// the machine, and making them wait out a pause earned by whatever was
	// asking while they were away would be the throttle punishing the wrong
	// party.
	e.refusals = make(map[string]refusal)
	e.mu.Unlock()
}
