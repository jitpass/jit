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

	mu        sync.Mutex
	mek       []byte
	expiry    time.Time
	lockTimer *time.Timer
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
		return Response{OK: true, Unlocked: unlocked, ExpiresInSeconds: int64(remaining.Seconds()), Mounts: mounts, LastUnlock: lastUnlock, LastLock: lastLock, Build: BuildID(), Version: Version()}
	case OpHistory:
		// Deliberately no ensureUnlocked: reading which prompts have already
		// happened must never itself cause one. An agent you can't ask "why do
		// you keep prompting me?" without being prompted is a joke.
		return Response{OK: true, Events: s.history()}
	case OpLock:
		s.lock(lockCause(c))
		return Response{OK: true, Unlocked: false}
	case OpUnlock:
		if _, err := s.ensureUnlocked(req.Op, c); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		unlocked, remaining := s.status()
		return Response{OK: true, Unlocked: unlocked, ExpiresInSeconds: int64(remaining.Seconds())}
	case OpRefresh:
		if _, err := s.ensureUnlocked(req.Op, c); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
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
		if _, err := s.ensureUnlockedNotify(onFresh, req.Op, c); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
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
	return seal(mek, dek)
}

func (s *Server) UnwrapKey(wrapped []byte) ([]byte, error) {
	mek, err := s.ensureUnlocked(opServeMounts, nil)
	if err != nil {
		return nil, err
	}
	return open(mek, wrapped)
}

func (s *Server) ensureUnlocked(op string, c *caller) ([]byte, error) {
	return s.ensureUnlockedNotify(s.OnUnlock, op, c)
}

// ensureUnlockedNotify is ensureUnlocked with a caller-chosen "a fresh
// challenge just succeeded" callback in place of the default OnUnlock.
// Only OpReveal passes anything other than OnUnlock (see OnUnlockForReveal) —
// every other caller goes through ensureUnlocked. onFresh fires exactly
// where OnUnlock did: after the lock is released, and only for a genuine
// fresh challenge, never a cache hit.
func (s *Server) ensureUnlockedNotify(onFresh func(), op string, c *caller) ([]byte, error) {
	s.mu.Lock()

	if s.mek != nil && time.Now().Before(s.expiry) {
		mek := s.mek
		// The TTL is a true inactivity timeout (GAPS.md #45), exactly as
		// `jit agent --help` and the docs describe it: every use of the still-valid
		// session pushes auto-lock back out to a full ttl from now. The
		// code used to implement a fixed window since the last unlock
		// instead (a cache hit never extended expiry), silently
		// disagreeing with its own help text — under that reading, an
		// actively-used session would re-prompt mid-work at a moment that
		// has nothing to do with the user having stepped away, which is
		// the only thing the auto-lock exists to cover.
		s.expiry = time.Now().Add(s.ttl)
		if s.lockTimer != nil {
			s.lockTimer.Stop()
		}
		s.lockTimer = time.AfterFunc(s.ttl, s.idleLock)
		s.mu.Unlock()
		return mek, nil
	}
	if s.mek != nil {
		wipe(s.mek)
		s.mek = nil
	}

	// Held for the whole (possibly slow, interactive) challenge on
	// purpose: concurrent callers must serialize behind the first one
	// rather than each independently triggering their own Touch ID
	// prompt. OnUnlock fires only after releasing the lock below, and
	// only for a fresh challenge — never for a cache hit above.
	//
	// The reason handed to the fetcher is the prompt the human is about to
	// read, so it is built HERE, where both the op and the caller are known
	// — the fetcher itself has no idea who it's prompting on behalf of.
	mek, err := s.newFetcher().FetchMEK(challengeReason(op, c))
	if err != nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("unlocking: %w", err)
	}
	s.mek = mek
	event := unlockEvent(op, c)
	s.lastUnlock = event
	s.recordEvent(*event)
	s.expiry = time.Now().Add(s.ttl)
	if s.lockTimer != nil {
		s.lockTimer.Stop()
	}
	s.lockTimer = time.AfterFunc(s.ttl, s.idleLock)
	s.mu.Unlock()

	if s.OnSessionEvent != nil {
		s.OnSessionEvent(*event)
	}
	if onFresh != nil {
		onFresh()
	}
	return mek, nil
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
	s.mu.Lock()
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

// idleLock is the TTL auto-lock — the time.AfterFunc callback, which takes
// no arguments, hence this rather than a closure at each of the two call
// sites that arm the timer.
func (s *Server) idleLock() {
	s.lock(fmt.Sprintf("%s idle timeout", s.ttl))
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
