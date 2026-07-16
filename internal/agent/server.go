// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// MEKFetcher provides the raw MEK bytes, challenging (Touch ID/passcode)
// if necessary. internal/keychainwrap's *Wrapper satisfies this.
//
// Server calls newFetcher() to build a FRESH one on every unlock, never
// reusing a single instance across unlocks — a Wrapper caches its MEK
// forever within its own lifetime (see its own doc comment), so reusing
// one across multiple Server-level unlocks would silently skip the
// challenge after the very first, defeating Server's own TTL-based
// re-locking entirely.
//
// reason is what the human reads on the resulting prompt (macOS renders it
// as "jit is trying to <reason>."), built per-unlock by challengeReason from
// who actually asked. It is a parameter rather than a constant inside the
// fetcher because only Server knows that — and a prompt that can't say why
// it appeared is the entire problem this plumbing exists to fix.
type MEKFetcher interface {
	FetchMEK(reason string) ([]byte, error)
}

// Server is the session broker RFC.md Pillar II describes: holds the
// decrypted MEK in memory for up to ttl after the most recent use,
// answering wrap/unwrap requests from other jit processes over a Unix
// socket so they don't each need their own independent Touch ID challenge.
// Peer connections are verified same-user before anything is served (see
// verifyPeerUID) — a different user on a shared machine must never reach
// this socket at all.
//
// Deliberately NOT tied to Server's lock state: any .env mounts a caller
// starts serving (via internal/mount, resolved through this Server acting
// as a vault.KeyWrapper) are driven by OnUnlock/OnLock below, not resolved
// eagerly at process startup — a launchd RunAtLoad agent starting at login,
// before anyone's at their desk, must never trigger a surprise Touch ID
// prompt just because mounts exist. internal/cli/agent.go's OnUnlock
// handler is what actually (re)resolves and starts serving them, once a
// real unlock — explicit or via any wrap/unwrap RPC — has happened.
type Server struct {
	socketPath string
	newFetcher func() MEKFetcher
	ttl        time.Duration

	// OnUnlock, if set, is called after every FRESH challenge succeeds
	// (never for a cache hit) — outside any internal lock, so it's safe
	// for it to call back into Server. OnLock is called after every
	// transition from unlocked to locked (explicit Lock() or TTL expiry),
	// but never for an already-locked no-op. OnRefresh is called on every
	// OpRefresh request, after ensuring the session is unlocked — for a
	// caller (jit migrate) that just registered a brand-new mount and
	// needs the agent to notice it right now, without waiting for the
	// next full lock/unlock cycle: the FIRST unlock a fresh `jit migrate`
	// run itself triggers (via its own vault writes) fires OnUnlock before
	// the new mount is registered, so that scan finds nothing yet — a
	// real bug found during manual verification, fixed by adding this
	// explicit "check again" signal rather than relying on OnUnlock alone.
	OnUnlock  func()
	OnLock    func()
	OnRefresh func()
	// OnUnlockForReveal, if set, replaces OnUnlock for the FRESH challenge an
	// OpReveal request triggers — and only that path. The difference is scope:
	// OnUnlock blanket-reveals every mount for a short default window (the
	// ergonomic "a human just unlocked, let a dev server started right after
	// get real content" default), but an unlock whose sole cause is an
	// explicit `jit agent reveal <path>` is a NARROWING intent — the user named
	// one file, so inheriting the blanket reveal and lighting up every other
	// mount for 60s reads as a bug (a real, reported one). OnUnlockForReveal
	// still resolves real content for every mount (so OnReveal's own reveal of the
	// named path can't be refused for "nothing real resolved"), it just
	// doesn't floor-reveal any of them — OnReveal reveals the one the user asked for,
	// right after. Falls back to OnUnlock when unset, so a Server with no
	// mount manager wired (tests) behaves exactly as before.
	OnUnlockForReveal func()
	// OnReveal, if set, answers an OpReveal request — after ensureUnlocked
	// succeeds, same as OnRefresh — with the mount path and requested
	// duration exactly as the caller sent them. Server has no opinion on
	// what "reveal" means (it never imports internal/mount) or on clamping
	// the requested duration to a sane maximum; that's internal/cli/agent.go
	// mountManager's job entirely, matching OnRefresh's own dependency
	// direction. A non-nil error return becomes the RPC's own failure,
	// message included — a real, reported bug: OpReveal used to return
	// Response{OK: true} unconditionally, so `jit agent reveal .env` (an
	// unresolved relative path that never matches the registry's absolute
	// keys) silently reported success while revealing nothing; the error
	// carries WHY (not found, nothing real resolved to serve, ...) so the
	// CLI can print it instead of that living only in the agent's log
	// (GAPS.md #46).
	OnReveal func(mountPath string, requested time.Duration) error
	// OnStopMount, if set, answers an OpStopMount request — unlike
	// OnRefresh/OnReveal, this does NOT go through ensureUnlocked first:
	// stopping a mount's serving goroutine needs no vault access at all
	// (GAPS.md #35), so it must keep working even while locked — the
	// same reasoning that makes decoy serving itself safe to run before
	// any unlock. `jit unmount` uses this to stop just the one mount
	// it's about to physically replace, without needing to lock (and
	// thereby disturb) every other mount the way it used to.
	OnStopMount func(mountPath string)
	// OnMountStatus, if set, answers "status"'s per-mount question (GAPS.md
	// #37) — called on EVERY OpStatus request, unlocked or not, since
	// reveal state (and even which mounts exist) needs no vault access at
	// all, same reasoning as OnStopMount. Returns the current snapshot;
	// Server doesn't cache or interpret it.
	OnMountStatus func() []MountRevealStatus
	// OnSessionEvent, if set, is called after every fresh unlock and every
	// real lock, with that transition's provenance — so the agent's LOG can
	// carry it, not just the in-memory snapshot `jit agent status` reads.
	//
	// The distinction matters more than it looks: status dies with the
	// process, and launchd restarts this agent across logins and rebuilds. The
	// log is the only record that outlives that, and it was exactly the thing
	// someone had to read (against their own shell history) to work out why a
	// prompt appeared. It logged every lock and not one unlock, so the event
	// that actually prompted them was the one event it never mentioned.
	//
	// Fires OUTSIDE Server's lock, like OnUnlock/OnLock, and before them.
	OnSessionEvent func(SessionEvent)

	// readTimeout bounds how long a connected client gets to send a
	// complete request (and, on the way out, to drain the response).
	// Without it, a client that connects and then stalls — or never
	// writes at all — pins a handleConn goroutine forever, and the agent
	// process lives for weeks at a time, so those leaks only ever
	// accumulate. Deliberately generous for what should be an instant
	// local write, and deliberately NOT applied to handling itself: an
	// unlock inside s.handle can legitimately sit behind a ~120s
	// interactive Touch ID challenge (see Client's responseTimeout).
	// Defaulted by NewServer; a field (not a const) so tests can shorten
	// it before Listen.
	readTimeout time.Duration

	// mu guards the session fields below and is only ever held for quick
	// field access — NEVER across the interactive challenge. challengeMu is
	// what serializes concurrent would-be unlockers behind a single Touch ID
	// prompt (see ensureUnlockedNotify). Keeping those two jobs on one mutex
	// was a real defect: status/history/lock requests queued behind an
	// in-flight challenge for up to the challenge's own ~120s ceiling — and
	// `jit agent status` is exactly what a user runs when a prompt they
	// don't understand is sitting on their screen.
	mu          sync.Mutex
	challengeMu sync.Mutex
	mek         []byte
	expiry      time.Time
	lockTimer   *time.Timer
	// timerGen invalidates stale idle-lock timers: each (re-)arm bumps it,
	// and a fired timer that lost the race to a concurrent touch/unlock
	// (its Stop() came back false because the goroutine was already
	// running) must not drop the session it no longer times. Without this,
	// a request arriving just as the TTL lapsed could have the old timer's
	// lock() collect the FRESH session installed moments later, recording
	// a bogus "idle timeout" immediately after a successful unlock.
	timerGen uint64
	// pendingChallenge, while non-nil, is the challenge currently sitting
	// on the user's screen: who triggered it and when it appeared. Status
	// reports it (Response.PendingUnlock) so the answer to "why is there a
	// prompt right now?" is available at the exact moment the question is
	// being asked — not only after the fact via lastUnlock. Never recorded
	// in history; the unlock event (if the human approves) is.
	pendingChallenge *SessionEvent
	// lastUnlock/lastLock are the session's provenance: who unlocked it and
	// what dropped it (GAPS.md #75). Kept even while locked — the whole point
	// is to still be able to explain a session that has already ended, which
	// is exactly when someone asks.
	lastUnlock *SessionEvent
	lastLock   *SessionEvent
	// events is every unlock and lock this process has seen, oldest first,
	// capped at maxSessionEvents. lastUnlock/lastLock answer "explain the
	// session I'm looking at"; this answers "was it prompting me all
	// afternoon, and for what" — a question a single before/after pair
	// structurally cannot, since each new unlock overwrites the last.
	events []SessionEvent

	listener net.Listener
}

// NewServer builds a Server. newFetcher must return a fresh MEKFetcher
// each call (e.g. func() MEKFetcher { return keychainwrap.New() }).
func NewServer(socketPath string, newFetcher func() MEKFetcher, ttl time.Duration) *Server {
	return &Server{socketPath: socketPath, newFetcher: newFetcher, ttl: ttl, readTimeout: 10 * time.Second}
}

// Listen opens the Unix socket, replacing any stale one left behind by a
// previous run that didn't shut down cleanly.
func (s *Server) Listen() error {
	if err := os.Remove(s.socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing stale socket %s: %w", s.socketPath, err)
	}
	if err := os.MkdirAll(filepath.Dir(s.socketPath), 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(s.socketPath), err)
	}
	l, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", s.socketPath, err)
	}
	if err := os.Chmod(s.socketPath, 0o600); err != nil {
		_ = l.Close()
		return fmt.Errorf("chmod %s: %w", s.socketPath, err)
	}
	s.listener = l
	return nil
}

// Serve accepts connections until ctx is cancelled or the listener fails.
// Call Listen first.
func (s *Server) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = s.listener.Close()
	}()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("accept: %w", err)
		}
		go s.handleConn(conn)
	}
}

// Close shuts down the listener and removes the socket file.
func (s *Server) Close() error {
	var err error
	if s.listener != nil {
		err = s.listener.Close()
	}
	_ = os.Remove(s.socketPath)
	return err
}

func (s *Server) handleConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	// Covers verifyPeerUID's syscalls, the error-path responses, and
	// reading the request itself — everything up to the point real
	// handling (which may wait on a human) starts.
	_ = conn.SetDeadline(time.Now().Add(s.readTimeout))

	if err := verifyPeerUID(conn); err != nil {
		_ = json.NewEncoder(conn).Encode(Response{OK: false, Error: fmt.Sprintf("rejected: %v", err)})
		return
	}

	var req Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		_ = json.NewEncoder(conn).Encode(Response{OK: false, Error: fmt.Sprintf("bad request: %v", err)})
		return
	}

	// Identify the peer BEFORE handling: a `jit run` that execs its child
	// (which is what jit run does) has already replaced its own argv by the
	// time a slow interactive challenge finishes, so asking the kernel
	// afterwards would describe the wrong program. nil is fine and expected
	// (peer already gone) — handling never depends on it.
	c := callerFromConn(conn)

	// Handling can block on an interactive challenge far longer than the
	// request-read bound — clear the deadline for it, then re-bound just
	// the response write.
	_ = conn.SetDeadline(time.Time{})
	resp := s.handle(req, c)
	_ = conn.SetWriteDeadline(time.Now().Add(s.readTimeout))
	_ = json.NewEncoder(conn).Encode(resp)
}

func (s *Server) handle(req Request, c *caller) Response {
	switch req.Op {
	case OpStatus:
		unlocked, remaining := s.status()
		var mounts []MountRevealStatus
		if s.OnMountStatus != nil {
			mounts = s.OnMountStatus()
		}
		lastUnlock, lastLock := s.provenance()
		return Response{OK: true, Unlocked: unlocked, ExpiresInSeconds: int64(remaining.Seconds()), Mounts: mounts, LastUnlock: lastUnlock, LastLock: lastLock, PendingUnlock: s.pendingUnlock(), Build: BuildID(), Version: Version()}
	case OpHistory:
		// Deliberately no ensureUnlocked: reading which prompts have already
		// happened must never itself cause one. An agent you can't ask "why do
		// you keep prompting me?" without being prompted is a joke.
		return Response{OK: true, Events: s.history()}
	case OpLock:
		s.lock(lockCause(c))
		return Response{OK: true, Unlocked: false}
	case OpUnlock:
		// ensureUnlocked hands every caller its own MEK copy (see mekCopy);
		// callers that only wanted the side effect wipe theirs immediately.
		mek, err := s.ensureUnlocked(req.Op, c)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		wipe(mek)
		unlocked, remaining := s.status()
		return Response{OK: true, Unlocked: unlocked, ExpiresInSeconds: int64(remaining.Seconds())}
	case OpRefresh:
		mek, err := s.ensureUnlocked(req.Op, c)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		wipe(mek)
		if s.OnRefresh != nil {
			s.OnRefresh()
		}
		return Response{OK: true}
	case OpReveal:
		if req.MountPath == "" {
			return Response{OK: false, Error: "reveal: missing mount_path"}
		}
		// Reveal-scoped unlock: a fresh challenge here runs OnUnlockForReveal
		// (resolve every mount's real content, floor-reveal none) instead of
		// OnUnlock's blanket floor-reveal, so this explicit reveal lights up only
		// the mount OnReveal reveals below — not every other mount too. Falls back
		// to OnUnlock when OnUnlockForReveal is unset.
		onFresh := s.OnUnlock
		if s.OnUnlockForReveal != nil {
			onFresh = s.OnUnlockForReveal
		}
		mek, err := s.ensureUnlockedNotify(onFresh, req.Op, c)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		wipe(mek)
		if s.OnReveal != nil {
			if err := s.OnReveal(req.MountPath, time.Duration(req.RevealSeconds)*time.Second); err != nil {
				return Response{OK: false, Error: err.Error()}
			}
		}
		return Response{OK: true}
	case OpStopMount:
		if req.MountPath == "" {
			return Response{OK: false, Error: "stop_mount: missing mount_path"}
		}
		// Deliberately no ensureUnlocked here — see OnStopMount's own doc
		// comment for why this must work regardless of lock state.
		if s.OnStopMount != nil {
			s.OnStopMount(req.MountPath)
		}
		return Response{OK: true}
	case OpWrap:
		mek, err := s.ensureUnlocked(req.Op, c)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		defer wipe(mek)
		wrapped, err := seal(mek, req.Data)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Data: wrapped}
	case OpUnwrap:
		mek, err := s.ensureUnlocked(req.Op, c)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		defer wipe(mek)
		dek, err := open(mek, req.Data)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Data: dek}
	default:
		return Response{OK: false, Error: fmt.Sprintf("unknown op %q", req.Op)}
	}
}

// WrapKey and UnwrapKey let *Server itself be used directly as a
// vault.KeyWrapper (structurally — internal/agent doesn't import
// internal/vault just to assert this) for the agent's OWN mount-serving,
// in-process, with no socket round trip. Other processes get the same
// operations via Client, which talks to these same ensureUnlocked/seal/
// open primitives over the socket instead.
// These two are the agent unlocking ITSELF — no socket, so no peer to
// identify (nil caller), and opServeMounts rather than a wire op name, since
// what's really happening is "resolve this project's mounted files", not a
// wrap/unwrap someone asked for.
func (s *Server) WrapKey(dek []byte) ([]byte, error) {
	mek, err := s.ensureUnlocked(opServeMounts, nil)
	if err != nil {
		return nil, err
	}
	defer wipe(mek)
	return seal(mek, dek)
}

func (s *Server) UnwrapKey(wrapped []byte) ([]byte, error) {
	mek, err := s.ensureUnlocked(opServeMounts, nil)
	if err != nil {
		return nil, err
	}
	defer wipe(mek)
	return open(mek, wrapped)
}

func (s *Server) ensureUnlocked(op string, c *caller) ([]byte, error) {
	return s.ensureUnlockedNotify(s.OnUnlock, op, c)
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

// ensureUnlockedNotify is ensureUnlocked with a caller-chosen "a fresh
// challenge just succeeded" callback in place of the default OnUnlock.
// Only OpReveal passes anything other than OnUnlock (see OnUnlockForReveal) —
// every other caller goes through ensureUnlocked. onFresh fires exactly
// where OnUnlock always has: after all internal locks are released, and
// only for a genuine fresh challenge, never a cache hit.
//
// challengeMu — not s.mu — is what serializes concurrent callers behind a
// single Touch ID prompt rather than each triggering their own. The second
// caller in line re-checks the session after acquiring it, because the
// first caller's approved challenge is usually exactly the unlock it was
// waiting for. s.mu is only ever held for field access, so a status/
// history/lock request arriving mid-challenge is answered immediately
// instead of queueing for up to the challenge's ~120s ceiling.
func (s *Server) ensureUnlockedNotify(onFresh func(), op string, c *caller) ([]byte, error) {
	if mek := s.touchSession(); mek != nil {
		return mek, nil
	}

	s.challengeMu.Lock()
	defer s.challengeMu.Unlock()

	// The caller we queued behind may have just unlocked for us.
	if mek := s.touchSession(); mek != nil {
		return mek, nil
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
	mek, err := s.newFetcher().FetchMEK(challengeReason(op, c))

	s.mu.Lock()
	s.pendingChallenge = nil
	if err != nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("unlocking: %w", err)
	}
	s.mek = mek
	out := s.mekCopy()
	event := unlockEvent(op, c)
	s.lastUnlock = event
	s.recordEvent(*event)
	s.expiry = time.Now().Add(s.ttl)
	s.armLockTimer()
	s.mu.Unlock()

	if s.OnSessionEvent != nil {
		s.OnSessionEvent(*event)
	}
	if onFresh != nil {
		onFresh()
	}
	return out, nil
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
func (s *Server) touchSession() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mek == nil {
		return nil
	}
	if !time.Now().Before(s.expiry) {
		// Expired, but the idle-lock timer hasn't collected it yet — don't
		// trust a timer to have fired to enforce the expiry.
		wipe(s.mek)
		s.mek = nil
		return nil
	}
	mek := s.mekCopy()
	s.expiry = time.Now().Add(s.ttl)
	s.armLockTimer()
	return mek
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
	s.lockTimer = time.AfterFunc(s.ttl, func() {
		s.lockIfGen(fmt.Sprintf("%s idle timeout", s.ttl), gen)
	})
}

// lock drops the cached MEK, recording WHY. OnLock only fires if there was
// actually a session to drop — calling lock on an already-locked agent is a
// no-op, not a repeated notification — and so, for the same reason, does the
// provenance record: an already-locked agent must keep the cause of the lock
// that actually happened, not overwrite it with a no-op's.
//
// cause is the answer to the question a re-prompt raises ("I authorized this
// twenty minutes ago — why again?"), and it is almost always the idle
// timeout rather than anything the user did. Saying so is the difference
// between the auto-lock looking like policy and looking like a bug.
func (s *Server) lock(cause string) {
	s.lockIfGen(cause, 0)
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
	hadSession := s.mek != nil
	if s.mek != nil {
		wipe(s.mek)
		s.mek = nil
	}
	s.expiry = time.Time{}
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

	if !hadSession {
		return
	}
	if s.OnSessionEvent != nil {
		s.OnSessionEvent(*event)
	}
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

// unlockEvent snapshots who caused a fresh unlock, at the moment it happened
// — the caller may well have exec'd (jit run) or exited by the time anyone
// runs `jit agent status` to ask.
func unlockEvent(op string, c *caller) *SessionEvent {
	e := &SessionEvent{UnixTime: time.Now().Unix(), Kind: KindUnlock, Op: op}
	if c != nil {
		e.By = c.command()
		e.ByPID = c.pid
		e.LaunchedBy = c.launchedBy()
	}
	return e
}

// maxSessionEvents bounds the in-memory history. An agent process lives for
// weeks across launchd restarts, so this must not grow without limit; 200
// events is several days of ordinary use (a handful of unlock/lock pairs a
// day) and a few kilobytes. Anything older has already been written to the
// agent's log, which is the durable record — this ring is the convenient one.
const maxSessionEvents = 200

// recordEvent appends to the ring. Caller must hold s.mu.
func (s *Server) recordEvent(e SessionEvent) {
	s.events = append(s.events, e)
	if len(s.events) > maxSessionEvents {
		s.events = append([]SessionEvent(nil), s.events[len(s.events)-maxSessionEvents:]...)
	}
}

// history returns the ring NEWEST FIRST — the order it will be read in, and
// the order `jit agent history` prints. Reversing here (rather than in the
// CLI) keeps every consumer, including a --format json one, from having to
// know which end is which.
func (s *Server) history() []SessionEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]SessionEvent, 0, len(s.events))
	for i := len(s.events) - 1; i >= 0; i-- {
		out = append(out, s.events[i])
	}
	return out
}

// pendingUnlock returns a copy of the challenge currently awaiting the
// human's answer, or nil when none is. Only answerable at all because
// status no longer queues behind the challenge itself — the whole point of
// challengeMu — and it turns that fix into an affirmative answer: status
// during a prompt doesn't just return, it explains the prompt.
func (s *Server) pendingUnlock() *SessionEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pendingChallenge == nil {
		return nil
	}
	p := *s.pendingChallenge
	return &p
}

// provenance returns copies, so a status response can never hand a caller a
// pointer into state the agent keeps mutating under its own lock.
func (s *Server) provenance() (lastUnlock, lastLock *SessionEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastUnlock != nil {
		u := *s.lastUnlock
		lastUnlock = &u
	}
	if s.lastLock != nil {
		l := *s.lastLock
		lastLock = &l
	}
	return lastUnlock, lastLock
}

func (s *Server) status() (unlocked bool, remaining time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mek == nil {
		return false, 0
	}
	remaining = time.Until(s.expiry)
	if remaining <= 0 {
		return false, 0
	}
	return true, remaining
}
