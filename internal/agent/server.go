// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

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
type MEKFetcher interface {
	FetchMEK() ([]byte, error)
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

	// Handling can block on an interactive challenge far longer than the
	// request-read bound — clear the deadline for it, then re-bound just
	// the response write.
	_ = conn.SetDeadline(time.Time{})
	resp := s.handle(req)
	_ = conn.SetWriteDeadline(time.Now().Add(s.readTimeout))
	_ = json.NewEncoder(conn).Encode(resp)
}

func (s *Server) handle(req Request) Response {
	switch req.Op {
	case OpStatus:
		unlocked, remaining := s.status()
		var mounts []MountRevealStatus
		if s.OnMountStatus != nil {
			mounts = s.OnMountStatus()
		}
		return Response{OK: true, Unlocked: unlocked, ExpiresInSeconds: int64(remaining.Seconds()), Mounts: mounts, Build: BuildID()}
	case OpLock:
		s.lock()
		return Response{OK: true, Unlocked: false}
	case OpUnlock:
		if _, err := s.ensureUnlocked(); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		unlocked, remaining := s.status()
		return Response{OK: true, Unlocked: unlocked, ExpiresInSeconds: int64(remaining.Seconds())}
	case OpRefresh:
		if _, err := s.ensureUnlocked(); err != nil {
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
		if _, err := s.ensureUnlockedNotify(onFresh); err != nil {
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
		mek, err := s.ensureUnlocked()
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		wrapped, err := seal(mek, req.Data)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Data: wrapped}
	case OpUnwrap:
		mek, err := s.ensureUnlocked()
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
func (s *Server) WrapKey(dek []byte) ([]byte, error) {
	mek, err := s.ensureUnlocked()
	if err != nil {
		return nil, err
	}
	return seal(mek, dek)
}

func (s *Server) UnwrapKey(wrapped []byte) ([]byte, error) {
	mek, err := s.ensureUnlocked()
	if err != nil {
		return nil, err
	}
	return open(mek, wrapped)
}

func (s *Server) ensureUnlocked() ([]byte, error) {
	return s.ensureUnlockedNotify(s.OnUnlock)
}

// ensureUnlockedNotify is ensureUnlocked with a caller-chosen "a fresh
// challenge just succeeded" callback in place of the default OnUnlock.
// Only OpReveal passes anything other than OnUnlock (see OnUnlockForReveal) —
// every other caller goes through ensureUnlocked. onFresh fires exactly
// where OnUnlock did: after the lock is released, and only for a genuine
// fresh challenge, never a cache hit.
func (s *Server) ensureUnlockedNotify(onFresh func()) ([]byte, error) {
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
		s.lockTimer = time.AfterFunc(s.ttl, s.lock)
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
	mek, err := s.newFetcher().FetchMEK()
	if err != nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("unlocking: %w", err)
	}
	s.mek = mek
	s.expiry = time.Now().Add(s.ttl)
	if s.lockTimer != nil {
		s.lockTimer.Stop()
	}
	s.lockTimer = time.AfterFunc(s.ttl, s.lock)
	s.mu.Unlock()

	if onFresh != nil {
		onFresh()
	}
	return mek, nil
}

// lock drops the cached MEK. Safe to call as a time.AfterFunc callback
// (TTL auto-lock) or directly (explicit "lock now"). OnLock only fires if
// there was actually a session to drop — calling lock on an
// already-locked agent is a no-op, not a repeated notification.
func (s *Server) lock() {
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
	s.mu.Unlock()

	if hadSession && s.OnLock != nil {
		s.OnLock()
	}
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
