// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

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
	"sync"
	"time"
)

// Strength records how trustworthy the caller's identity is. Hard means a
// kernel-vouched identity (a socket peer PID) that a same-user process cannot
// forge; BestEffort means an inferred identity (a libproc scan + PPID walk of a
// FIFO reader) that a determined same-user attacker can spoof. It never changes
// a decision here; it travels through so the prompt and audit can say "this is
// who's asking" vs "this is who's asking, as best we can tell."
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
	PID       int32
	ExecPath  string // e.g. "/usr/local/bin/gcloud" — the cache key, per tool ("" = unidentified, never cached)
	Lineage   string // human summary, e.g. "launched by npm install" — for the prompt
	Strength  Strength
	// DescendsFromGrant is set by the call site when this caller (or an
	// ancestor) is inside an active jit-run grant. It short-circuits to Allow
	// with no prompt, so a tool you launched through a grant is transparent.
	DescendsFromGrant bool
}

// Request is one credential access awaiting a decision.
type Request struct {
	Credential string // the vault credential name/label, e.g. "aws", "gcp"
	Caller     Caller
}

func (r Request) key() string {
	return r.Credential + "\x00" + r.Caller.ExecPath
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

// Engine holds the session's standing decisions.
type Engine struct {
	mu         sync.Mutex
	cache      map[string]cached
	// pending single-flights concurrent first accesses for the same key: the
	// first caller becomes the leader and prompts; the rest wait on its channel
	// and re-read the cache it fills, so two tools reaching for the same
	// credential at once produce one Touch ID prompt, not a stampede of them.
	pending    map[string]chan struct{}
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

	// An unidentified caller (empty ExecPath) has no stable key to cache under
	// or single-flight on — two such callers are indistinguishable — so it just
	// prompts, every time, and its answer is never remembered.
	if req.Caller.ExecPath == "" {
		d, _, err := prompt(req)
		if err != nil {
			return Undecided, err
		}
		return d, nil
	}

	for {
		// (2) A standing decision from earlier this session.
		if d, ok := e.lookup(key); ok {
			return d, nil
		}

		// (3) Ask, and remember for the chosen scope — but only one caller per
		// key prompts at a time; the rest wait for that answer and re-check.
		leader, wait := e.joinFlight(key)
		if !leader {
			<-wait
			continue
		}
		d, scope, err := prompt(req)
		if err == nil {
			e.remember(key, d, scope)
		}
		e.finishFlight(key)
		if err != nil {
			return Undecided, err
		}
		return d, nil
	}
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
	e.mu.Unlock()
}
