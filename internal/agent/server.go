// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jitpass/jit/internal/consent"
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
// A fetcher MAY also implement Close() to release whatever it cached; see
// closeFetcher. Whether it does or not, FetchMEK's return value must be a
// COPY the caller owns — never a view onto state Close would destroy — since
// Server keeps that copy as the session key long after closing the fetcher
// that produced it.
type MEKFetcher interface {
	FetchMEK(reason string) ([]byte, error)
}

// closeFetcher ends a fetcher's own MEK cache once we've taken the copy we
// need. A fetcher is built fresh per challenge and dropped immediately, but
// "dropped" is not "gone": keychainwrap's Wrapper pins its cached MEK with
// mlock and, before it grew a Close, never wiped it — so every unlock and
// every disclosed prompt left a plaintext master key in this long-lived
// process that survived the session's lock, the screen-lock wipe and the
// sleep wipe alike, and went away only when the GC reused the page.
//
// Optional by design: MEKFetcher stays a one-method interface so test
// fetchers (which hold no OS resources) don't have to implement anything,
// and a fetcher with nothing to release simply isn't asked to.
//
// Optional also means silent, which is the risk: a fetcher whose Close grew a
// return value would stop matching this assertion, the leak would come back,
// and nothing would fail. ClosableFetcher exists so the production fetcher's
// conformance is asserted at compile time where it is wired up.
func closeFetcher(f MEKFetcher) {
	if c, ok := f.(ClosableFetcher); ok {
		c.Close()
	}
}

// ClosableFetcher is a MEKFetcher that holds resources worth releasing as soon
// as its MEK has been copied out — keychainwrap's *Wrapper, whose cache is
// mlocked and must be wiped rather than left for the GC.
//
// Assert against it wherever a real fetcher is constructed
// (var _ agent.ClosableFetcher = (*keychainwrap.Wrapper)(nil)): closeFetcher's
// check is a runtime type assertion, so without a compile-time counterpart a
// signature change would turn it into a silent no-op.
type ClosableFetcher interface {
	MEKFetcher
	Close()
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

	// maxSessionAge bounds how long ONE unlock can be ridden, no matter how
	// busy it is. ttl is an inactivity timeout and touchSession pushes it out
	// on every use, which is right for a human at a keyboard and wrong as the
	// only bound: nothing stopped a process from sending a cheap request every
	// ttl-minus-a-bit forever, holding the MEK resident indefinitely on a
	// single Touch ID from this morning. This is the ceiling that idle timer
	// can't express — past it the session ends and the next access challenges
	// again, however active it has been. Defaulted by NewServer; a field so
	// tests can shorten it.
	maxSessionAge time.Duration

	// OnUnlock, if set, is called after every FRESH challenge succeeds
	// (never for a cache hit) — outside every internal lock, and never
	// re-entrantly, which is what makes it safe for it to call back into
	// Server (see notifyFresh: it does, on every mount it resolves, and a
	// session that lapses mid-resolve used to turn that into first a deadlock
	// and then an unbounded recursion). OnLock is called after every
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
	// OnRevealPID, if set, answers an OpRevealPID request — after
	// ensureUnlocked succeeds (OnUnlock resolves real content but reveals
	// nothing on its own). The arguments are the caller's per-mount
	// treatments (path + mode) and target pid exactly as sent; what a mode
	// means — how readers are matched against the target's process tree, and
	// when a swap/grant is torn down — lives entirely in the CLI layer
	// (mountManager), keeping Server's no-internal/mount dependency
	// direction. A non-nil error becomes the RPC's own failure.
	OnRevealPID func(mounts []RunMount, pid int32) error
	// OnDescribeGrant, if set, names what a DISCLOSED reveal_pid is about to
	// grant, in the user's own vocabulary ("your gcp, sops credentials"), for
	// the one line the Touch ID prompt puts in front of them. It is the reason
	// the request itself no longer carries one: the wording used to be
	// Request.DiscloseReason, chosen by the calling process, so anything that
	// could reach the socket could grant itself the gcloud ADC behind a prompt
	// reading "unlock the vault for profile dev" — a reassuring lie on exactly
	// the line the human decides by, which is the thing Request.Label's own
	// doc comment forbids.
	//
	// It receives the requested mounts and must resolve them through jit's OWN
	// mount registry (mountManager.credentialMount), never by echoing the
	// caller's path strings back: those are attacker-chosen too, and the
	// swap-mode entries among them never even reach OnCanGrant's validation.
	// Returning "" (or leaving this nil) falls back to a fixed generic phrase,
	// which is less informative but can never be influenced at all.
	OnDescribeGrant func(mounts []RunMount) string
	// OnCanGrant, if set, validates that every grant-mode mount in a
	// DISCLOSED reveal_pid (jit run --with) is currently grantable — served
	// with real content — WITHOUT attaching anything. It runs before the
	// disclosed challenge so an unservable mount fails without burning a Touch
	// ID, and so an approved challenge grants the whole named set or none of
	// it (never a partial grant reported as full). A non-nil error becomes the
	// RPC's failure before any prompt.
	OnCanGrant func(mounts []RunMount) error
	// OnStopMount, if set, answers an OpStopMount request — unlike
	// OnRefresh, this does NOT go through ensureUnlocked first:
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

	// OnServeError, if set, is called with a KindError SessionEvent when the
	// service refuses or fails a connection at the socket boundary: a rejected
	// peer, a malformed request, or the accept loop dying. Separate from
	// OnSessionEvent because these are not session transitions and must NOT
	// enter the in-memory session ring (they'd bury the unlock/lock history a
	// status call reports) — the CLI wires it straight to the durable log so
	// the events reach `jit audit` without polluting the ring. Best-effort and
	// fire-and-forget like the rest; nil discards them.
	OnServeError func(SessionEvent)

	// Consent, if set, turns on per-process credential consent: an OpUnwrap
	// for a credential class (consent.RequiresConsent) is gated by a decision
	// from this engine — a fresh disclosed Touch ID naming the kernel-identified
	// caller and the class, cached for the session. Nil means off (the default);
	// the CLI sets it when the service is started with consent enabled. It never
	// gates the agent's own in-process mount serving (that call has a nil
	// caller), only socket peers reaching a real credential.
	Consent *consent.Engine

	// trustRoots maps a consent trust-root pid (a `jit run --trust`) to its
	// fork-time stamp. A credential access whose caller descends from a live,
	// same-fork-time root skips the consent prompt (design/per-process-
	// credential-consent.md, phase 1c). Guarded by trustMu rather than s.mu
	// because the descent check does sysctl ancestry walks that must not block
	// status/lock; dropped on every re-lock, like the consent cache.
	trustMu    sync.Mutex
	trustRoots map[int32]int64

	// grants are the live process grants (design/process-grants.md, grant.go):
	// scoped DEK caches a disclosed challenge pre-authorized for one process
	// tree until an absolute deadline. Guarded by grantMu for trustMu's exact
	// reason (descent checks walk sysctls). Deliberately NOT dropped on
	// re-lock — surviving the screen lock is the feature the human approved in
	// so many words — which makes this the one carve-out from "a re-lock
	// clears every authorization state"; it earns that by being strictly
	// narrower than the session it stands in for (named secrets, one tree, an
	// absolute deadline, revocable, and never the MEK). Memory-only: a grant
	// never survives the agent process.
	grantMu sync.Mutex
	grants  map[string]*processGrant

	// OnResolveGrant, if set, resolves grant_create's profile NAMES to the
	// concrete secrets they cover — vault path, wrapped DEK bytes, AAD-bound
	// class — through jit's own profile store and vault envelopes (the CLI
	// layer wires it; Server never imports internal/vault or internal/profile).
	// It is OnDescribeGrant's reasoning applied to scope instead of wording:
	// because the agent resolves the names itself, the prompt and the granted
	// set derive from the same facts, and a caller cannot put one profile on
	// the prompt and a different secret set in the grant. Nil disables
	// grant_create entirely.
	OnResolveGrant func(profiles []string, projectRoot string) ([]GrantSecret, error)

	// AuthMethodFn, if set, returns a best-effort description of how the local
	// auth challenge asked the user ("Touch ID or device passcode" vs. "device
	// passcode"), stamped onto the unlock/denied event a fresh challenge
	// produces. The CLI wires it to keychainwrap's biometry probe; nil (a test
	// server, or an old wiring) falls back to the honest policy description in
	// authMethod. Never claims a specific method macOS won't confirm — see
	// SessionEvent.AuthMethod.
	AuthMethodFn func() string

	// identify resolves a connection's peer to a *caller. It defaults to
	// callerFromConn (the kernel LOCAL_PEERPID path). It is a field, not a
	// direct call, only so tests can inject a caller with a known ancestry: a
	// test process cannot choose its own parents, and consent keying now turns
	// on the caller's launcher (consentCaller), so exercising it deterministically
	// needs a controllable lineage. A nil result is always legal (peer gone).
	identify func(net.Conn) *caller

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

	// denialCooldown is how long, after a challenge the human declined,
	// the agent refuses to put a NEW prompt up for anything except an
	// explicit `jit agent unlock`. A declined prompt means "not now" — and
	// the callers most likely to have triggered it (an MCP server a
	// launcher restarts on failure, a retrying script) ask again
	// immediately, turning one deliberate "no" into a prompt storm the
	// user can only end by approving. Prompt fatigue is the exact failure
	// this agent exists to avoid manufacturing. Explicit unlock bypasses
	// it because a human typing `jit agent unlock` IS the "now" a denial
	// withheld. Defaulted by NewServer; a field so tests can shorten it.
	//
	// It is UX hardening, NOT a security boundary, and must never be counted
	// as one: the OpUnlock exemption is reachable by any process that can
	// reach the socket, so it stops an unwitting retry loop and not a
	// deliberate one. The boundary is the human answering the prompt.
	denialCooldown time.Duration

	// useWindow is the collapse window for KindUse events (see recordUse):
	// same-caller same-op uses inside one window merge into a single
	// event. Defaulted by NewServer; a field so tests can shorten it.
	useWindow time.Duration

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
	// freshMu guards notifyFresh's re-entrancy state — its own mutex because
	// it is held across nothing but flag flips, while the callback it governs
	// (a full mount resolve, vault reads and all) runs outside every lock here.
	freshMu      sync.Mutex
	freshRunning bool
	freshPending bool
	mek          []byte
	expiry       time.Time
	// sessionStart is when the current session's fresh challenge succeeded —
	// the anchor maxSessionAge measures from. Unlike expiry it is never
	// pushed forward by use; that is the whole point of it.
	sessionStart time.Time
	lockTimer    *time.Timer
	// lastDenied is when a challenge most recently failed — what the
	// denial cooldown above measures from — and lastDeniedCause is why, so
	// the cooldown refusal can repeat the ORIGINAL failure instead of
	// asserting "declined" about what may have been a keychain error (an
	// uninitialized vault fails the fetch AFTER a successful Touch ID).
	// Zeroed by the next successful unlock, so one approval fully clears
	// the pause.
	lastDenied      time.Time
	lastDeniedCause string
	// pendingUses accumulates KindUse events per caller+op until their
	// collapse window closes (see recordUse/flushUsesLocked) — flushed
	// lazily on later uses, on every lock (the session boundary), and on
	// every history read, so history is always current when actually read.
	pendingUses map[useKey]*useAggregate
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
	// capped at MaxSessionEvents. lastUnlock/lastLock answer "explain the
	// session I'm looking at"; this answers "was it prompting me all
	// afternoon, and for what" — a question a single before/after pair
	// structurally cannot, since each new unlock overwrites the last.
	events []SessionEvent

	listener net.Listener
}

// defaultDenialCooldown pauses automatic re-prompts after a declined
// challenge. 30 seconds is long enough to break the tight retry loops
// that actually storm (a relaunching MCP server retries within a second
// or two) and short enough that a genuine "oops, I meant to approve
// that" only waits half a minute — or types `jit agent unlock`, which
// bypasses it outright.
const defaultDenialCooldown = 30 * time.Second

// DefaultMaxSessionAge is the ceiling on a single unlock's lifetime,
// independent of how continuously it is used. Eight hours covers a working
// day, so someone who unlocked at the start of it is asked again once —
// not mid-afternoon, and not never. Exported because the CLI bounds --ttl
// by it: an inactivity timeout longer than the hard ceiling is a setting
// that cannot mean what it says.
const DefaultMaxSessionAge = 8 * time.Hour

// defaultUseWindow collapses same-caller same-op use events. One minute
// merges a profile resolution's burst of unwraps (all within a second)
// into a single event while keeping separate invocations minutes apart
// as separate history lines.
const defaultUseWindow = time.Minute

// NewServer builds a Server. newFetcher must return a fresh MEKFetcher
// each call (e.g. func() MEKFetcher { return keychainwrap.New() }).
func NewServer(socketPath string, newFetcher func() MEKFetcher, ttl time.Duration) *Server {
	return &Server{
		socketPath:     socketPath,
		newFetcher:     newFetcher,
		ttl:            ttl,
		maxSessionAge:  DefaultMaxSessionAge,
		readTimeout:    10 * time.Second,
		denialCooldown: defaultDenialCooldown,
		useWindow:      defaultUseWindow,
		trustRoots:     map[int32]int64{},
		identify:       callerFromConn,
	}
}

// Listen opens the Unix socket, replacing any stale one left behind by a
// previous run that didn't shut down cleanly.
func (s *Server) Listen() error {
	if err := os.Remove(s.socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing stale socket %s: %w", s.socketPath, err)
	}
	dir := filepath.Dir(s.socketPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	tightenSocketDir(dir)
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

// tightenSocketDir narrows the socket's parent directory to 0700 when it is
// ours and currently wider.
//
// It exists because net.Listen creates the socket at whatever the umask
// allows (0755 under the common 022), and the chmod that fixes that runs one
// syscall later — a window in which the socket is connectable by anyone. A
// 0700 parent closes the window outright, and MkdirAll can't be relied on for
// it: MkdirAll applies its mode only when it CREATES the directory, so a
// jitpass dir left at 0755 by an older build keeps those permissions forever.
//
// Deliberately narrow and deliberately quiet:
//
//   - Only a directory THIS user owns is touched. A socket path under a shared
//     directory (/tmp, as the tests use) belongs to the system, and chmodding
//     it would be both futile and rude.
//   - Failure is not fatal. This is the outer of two layers; verifyPeerUID is
//     the one that actually decides, on every single connection, and an agent
//     that refuses to start over a directory mode would trade a hardening
//     measure for an outage.
func tightenSocketDir(dir string) {
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm()&0o077 == 0 {
		return // unreadable, or already tight enough
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Getuid() {
		return // not ours to narrow
	}
	_ = os.Chmod(dir, 0o700) // #nosec G302 -- a DIRECTORY, not a file: 0700 is the tightest mode that is still traversable by its owner, and G302's 0600 ceiling assumes a regular file. Matches the MkdirAll above.
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
			s.recordServeError("accept", fmt.Sprintf("accept: %v", err), nil)
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

// maxRequestBytes bounds one request. The largest legitimate one is a
// reveal_pid carrying a handful of mount paths, or a wrap/unwrap whose Data is
// a single base64'd 32-byte DEK plus nonce and tag — kilobytes, and this is a
// megabyte. The bound exists because the decoder read straight from the
// connection with no limit: a peer had the whole read deadline to stream
// arbitrary JSON into the agent's heap, and this process is meant to live for
// weeks. Same-user code execution is conceded in the threat model, but the
// concession is that such code reaches the unlocked agent — not that it gets
// to take the service down for everything else on the machine.
const maxRequestBytes = 1 << 20

func (s *Server) handleConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	// Covers verifyPeerUID's syscalls, the error-path responses, and
	// reading the request itself — everything up to the point real
	// handling (which may wait on a human) starts.
	_ = conn.SetDeadline(time.Now().Add(s.readTimeout))

	if err := verifyPeerUID(conn); err != nil {
		// A peer the kernel says isn't this user is the one socket event most
		// worth a durable record: someone else's process probing the agent.
		// Enrich with its lineage while it's still connected — that identity
		// is exactly what the audit trail is for.
		s.recordServeError("reject", fmt.Sprintf("rejected peer: %v", err), s.identify(conn))
		_ = json.NewEncoder(conn).Encode(Response{OK: false, Error: fmt.Sprintf("rejected: %v", err)})
		return
	}

	var req Request
	if err := json.NewDecoder(io.LimitReader(conn, maxRequestBytes)).Decode(&req); err != nil {
		// A peer that closed without sending a single byte is a liveness
		// probe, not a malformed request: Client.Reachable() dials and
		// closes exactly like this, and it runs from a dozen CLI paths
		// (run, undo, unmount, vault, migrate remove, rekey), so recording
		// it would file two KindError events per `jit run`. That noise
		// lands in the durable audit log next to the events kind=error
		// exists for — a peer the kernel says isn't this user, probing the
		// agent — and drowns them. json.Decode reports this exact case as
		// a bare io.EOF; a peer that sent SOME bytes and then died gives
		// io.ErrUnexpectedEOF (or a syntax error) and is still recorded.
		// There's nothing to reply to either way — the peer is gone.
		if errors.Is(err, io.EOF) {
			return
		}
		s.recordServeError("decode", fmt.Sprintf("bad request: %v", err), s.identify(conn))
		_ = json.NewEncoder(conn).Encode(Response{OK: false, Error: fmt.Sprintf("bad request: %v", err)})
		return
	}

	// Identify the peer BEFORE handling: a `jit run` that execs its child
	// (which is what jit run does) has already replaced its own argv by the
	// time a slow interactive challenge finishes, so asking the kernel
	// afterwards would describe the wrong program. nil is fine and expected
	// (peer already gone) — handling never depends on it.
	c := s.identify(conn)

	// Handling can block on an interactive challenge far longer than the
	// request-read bound — clear the deadline for it, then re-bound just
	// the response write.
	_ = conn.SetDeadline(time.Time{})
	resp := s.handle(req, c)
	_ = conn.SetWriteDeadline(time.Now().Add(s.readTimeout))
	_ = json.NewEncoder(conn).Encode(resp)
}

// currentExecutablePath is this process's own binary path, "" when the OS
// declines to say. Best-effort by design: it feeds a diagnostic, and a
// status call must never fail because the answer was unavailable.
func currentExecutablePath() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return exe
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
		return Response{OK: true, Unlocked: unlocked, ExpiresInSeconds: int64(remaining.Seconds()), Mounts: mounts, LastUnlock: lastUnlock, LastLock: lastLock, PendingUnlock: s.pendingUnlock(), Build: BuildID(), Version: Version(), ExecutablePath: currentExecutablePath()}
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
		mek, fresh, err := s.ensureUnlockedFresh(s.OnUnlock, req.Op, c, "")
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		wipe(mek)
		// A FRESH unlock is a human at the keyboard saying "now" — the same
		// reason this op is exempt from the denial cooldown — so it clears
		// consent pauses: the backoff keys on a caller's launcher, coarse
		// enough that refusals earned by one program can pause an honest one,
		// and this is the override that makes that tradeoff acceptable.
		// Standing decisions are untouched: permission to be asked again is
		// not permission to skip the asking.
		//
		// Gated on `fresh`, emphatically. OpUnlock against an already-open
		// session challenges nobody and returns OK, so clearing on success
		// alone would have handed every process on the machine a free reset:
		// refuse, unlock, refuse, unlock — the exact flood this backoff exists
		// to stop, with an extra syscall per round.
		if fresh && s.Consent != nil {
			s.Consent.ClearBackoff()
		}
		unlocked, remaining := s.status()
		return Response{OK: true, Unlocked: unlocked, ExpiresInSeconds: int64(remaining.Seconds())}
	case OpRefresh:
		mek, err := s.ensureUnlocked(req.Op, c, "")
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		wipe(mek)
		if s.OnRefresh != nil {
			s.OnRefresh()
		}
		return Response{OK: true}
	case OpRevealPID:
		if len(req.RunMounts) == 0 {
			return Response{OK: false, Error: "reveal_pid: missing run_mounts"}
		}
		if req.TargetPID <= 0 {
			return Response{OK: false, Error: "reveal_pid: missing target_pid"}
		}
		// The fresh challenge a grant request may cause resolves every mount's
		// real content (so a grant can serve current values) but reveals
		// nothing on its own — real content flows only to the granted tree.
		onFresh := s.OnUnlock
		// The joined mount paths are this use's label: what the session was used FOR.
		paths := make([]string, len(req.RunMounts))
		for i, m := range req.RunMounts {
			paths[i] = m.Path
		}
		// A global-mount grant (jit run --with) forces a fresh, disclosed
		// challenge naming the credential — even though the session is already
		// unlocked — so it can never happen silently on the back of the run's
		// own unlock (see Request.DiscloseReason). Its steps are ordered to
		// keep the audit trail honest:
		//   1. validate every requested mount is grantable BEFORE prompting,
		//      so an unservable mount fails without burning a Touch ID and an
		//      approved challenge grants the whole named set or none of it;
		//   2. prompt — a decline records only a denial, never a use;
		//   3. record the use (via ensureUnlockedNotify) ONLY after approval.
		// The project-mount path (not disclosed) is unchanged: it records
		// use on its own unlock and best-efforts per mount.
		//
		// The request supplies only the FLAG. What the prompt says is derived
		// here, from the mounts, via OnDescribeGrant — see its doc comment for
		// the prompt-spoofing hole that closed. DiscloseReason is still honored
		// as a trigger so an older in-flight client keeps the gate, but its
		// text is discarded.
		if req.Disclose || req.DiscloseReason != "" {
			if s.OnCanGrant != nil {
				if err := s.OnCanGrant(req.RunMounts); err != nil {
					return Response{OK: false, Error: err.Error()}
				}
			}
			if err := s.forceDisclosedChallenge(s.grantReason(req.RunMounts), c); err != nil {
				return Response{OK: false, Error: err.Error()}
			}
		}
		mek, err := s.ensureUnlockedNotify(onFresh, req.Op, c, strings.Join(paths, ", "))
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		wipe(mek)
		if s.OnRevealPID != nil {
			if err := s.OnRevealPID(req.RunMounts, req.TargetPID); err != nil {
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
	case OpTrust:
		// A caller the kernel won't name can't be trusted (no pid to anchor on).
		if c == nil {
			return Response{OK: false, Error: "trust: caller could not be identified"}
		}
		// Registering a trust root needs no vault ACCESS, but it is the single
		// widest thing a caller can ask for: every gated credential its whole
		// process tree touches for the rest of the session, with no per-tool
		// consent prompt. It used to take exactly that — nothing. Any same-user
		// process could send one `trust` RPC and switch off its own consent
		// gate, which is the mitigation that exists precisely for untrusted
		// code running as you (design/per-process-credential-consent.md). The
		// prompt is what makes `jit run --trust` mean what its docs say: the
		// human, not the process, decides to widen the scope.
		//
		// Gated only when consent is actually enforcing — with consent off,
		// trust roots decide nothing, so prompting for one would be a Touch ID
		// that buys the user nothing.
		if s.Consent != nil {
			if err := s.forceDisclosedChallenge(trustReason(c), c); err != nil {
				return Response{OK: false, Error: err.Error()}
			}
		}
		s.trust(c.pid)
		return Response{OK: true}
	case OpWrap:
		mek, err := s.ensureUnlocked(req.Op, c, req.Label)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		defer wipe(mek)
		wrapped, err := seal(mek, req.Data, []byte(req.Class))
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Data: wrapped}
	case OpGrantCreate:
		return s.createGrant(req, c)
	case OpGrantList:
		// Deliberately no ensureUnlocked, OpHistory's reasoning: reading what
		// standing access exists must never itself cost an authentication.
		return Response{OK: true, Grants: s.listGrants()}
	case OpGrantRevoke:
		if req.GrantID == "" {
			return Response{OK: false, Error: "grant_revoke: missing grant_id"}
		}
		return s.revokeGrant(req.GrantID, c)
	case OpGrantExtend:
		if req.GrantID == "" {
			return Response{OK: false, Error: "grant_extend: missing grant_id"}
		}
		return s.extendGrant(req, c)
	case OpUnwrap:
		// A live process grant answers first: the human already approved this
		// exact tree reaching these exact secrets (one disclosed challenge,
		// bounded by a deadline), so a covered unwrap needs no session, no
		// consent gate, and no class re-verification — the class was
		// AEAD-verified against these same wrapped bytes when the grant was
		// created, and the DEK below is keyed to the bytes themselves, so a
		// caller lying about Class now changes nothing it receives. Recorded
		// as its own use op (grant_use): riding a standing grant and riding a
		// minutes-old unlock are different facts in an audit. Any miss falls
		// through to the ordinary path unchanged.
		if dek, path, ok := s.grantUnwrap(c, req.Data); ok {
			s.recordAggregated(KindUse, OpGrantUse, c.command(), c, path)
			return Response{OK: true, Data: dek}
		}
		// Nothing has verified req.Class yet. It is AEAD-bound into the wrap,
		// but that binding is only checked by open() further down, so until
		// then the class is simply a string the caller sent — and it is the
		// string that decides which credential the consent prompt names. A
		// caller with no vault data at all could send {Class:"aws", Data:
		// <garbage>} and put a full Touch ID dialog on the user's screen.
		//
		// So when a session is live, prove the caller actually holds a wrap of
		// that class before any prompt: the MEK is already in hand, the check
		// costs one AEAD open, and a request that fails it never reaches a
		// human.
		//
		// Against a LOCKED agent there is no MEK to check against, so this is
		// a no-op and a garbage unwrap can still reach the unlock prompt. That
		// path is bounded by the denial cooldown rather than by this check —
		// and it is not made worse by garbage, since any caller that can reach
		// the socket can ask for an unlock outright.
		if err := s.verifyClassBinding(req.Data, req.Class, c); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		// Consent is gated BEFORE ensureUnlocked, not after: ensureUnlocked
		// records a use the moment it rides an already-unlocked session, so
		// gating first is what keeps a DENIED unwrap out of the audit log as a
		// use. It needs no MEK (only the caller and the AEAD-bound class), and a
		// consent decline never arms the unlock cooldown, so this reordering
		// costs a cached session nothing and only ever avoids work on a denial.
		if err := s.gateConsent(req.Class, c); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		mek, err := s.ensureUnlocked(req.Op, c, req.Label)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		defer wipe(mek)
		dek, err := open(mek, req.Data, []byte(req.Class))
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
	return s.WrapKeyLabeled(dek, "", "")
}

func (s *Server) UnwrapKey(wrapped []byte) ([]byte, error) {
	return s.UnwrapKeyLabeled(wrapped, "", "")
}

// WrapKeyLabeled/UnwrapKeyLabeled are the vault.LabeledKeyWrapper
// (structural, same non-import convention as KeyWrapper above) variants:
// label is the vault path of the secret whose DEK is being handled, so
// the agent's own mount resolution shows up in history as "serve_mounts
// touched these secrets" instead of an unlabeled blur — the same
// audit-only, caller-reported label RPC callers send in Request.Label.
func (s *Server) WrapKeyLabeled(dek []byte, label, class string) ([]byte, error) {
	mek, err := s.ensureUnlocked(opServeMounts, nil, label)
	if err != nil {
		return nil, err
	}
	defer wipe(mek)
	return seal(mek, dek, []byte(class))
}

func (s *Server) UnwrapKeyLabeled(wrapped []byte, label, class string) ([]byte, error) {
	mek, err := s.ensureUnlocked(opServeMounts, nil, label)
	if err != nil {
		return nil, err
	}
	defer wipe(mek)
	return open(mek, wrapped, []byte(class))
}

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
	// callback runs under it.
	if s.OnSessionEvent != nil {
		s.OnSessionEvent(*event)
	}
	return err
}

// discloseChallengeOp is the serialized half every disclosed challenge shares:
// it holds challengeMu across the prompt (so a disclosed challenge queues
// behind an in-flight one rather than stacking a second dialog) and returns
// the event for the caller to notify on, outside the lock. The event is never
// nil; op stamps it, so a grant creation's approval and a reveal's approval
// stay distinguishable in history.
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

	if err != nil {
		return event, nil, fmt.Errorf("disclosed grant declined: %w", err)
	}
	return event, mek, nil
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
	wipe(s.mek)
	unlockMemory(s.mek)
	s.mek = nil
	return true
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

// recordServeError hands a socket-boundary failure to OnServeError as a
// KindError event: op names which failure ("reject", "decode", "accept"),
// cause carries the detail, and c (when the kernel still named the peer)
// stamps the same By/ByPID/LaunchedBy provenance an unlock would carry — for a
// rejected peer that provenance is the whole point of recording it. No-op when
// no sink is wired (a test server, or the KeyWrapper embedding with no socket).
func (s *Server) recordServeError(op, cause string, c *caller) {
	if s.OnServeError == nil {
		return
	}
	e := SessionEvent{UnixTime: time.Now().Unix(), Kind: KindError, Op: op, Cause: cause}
	if c != nil {
		e.By = c.command()
		e.ByPID = c.pid
		e.LaunchedBy = c.launchedBy()
	}
	s.OnServeError(e)
}

// MaxSessionEvents bounds the in-memory history ring. An agent process
// lives for weeks across launchd restarts, so this must not grow without
// limit; 200 events is several days of ordinary use (a handful of
// unlock/lock pairs a day) and a few kilobytes. Exported because the CLI
// layer seeds the ring from the durable history file and caps its read to
// the same number — anything older is still in the file for whoever wants
// to read it directly.
const MaxSessionEvents = 200

// SeedHistory pre-populates the ring with events restored from the durable
// history file (oldest first, the order they were appended), keeping the
// newest MaxSessionEvents. Call before Listen — it replaces the ring, and
// racing live recordEvent appends would drop them. This is what lets `jit
// agent history` answer for prompts that happened before the most recent
// launchd restart, which is exactly when "why was I being prompted all
// afternoon?" gets asked (the restart happens at login, i.e. the next
// morning). lastUnlock/lastLock stay process-local on purpose: they
// describe THIS process's session, and a restart is why it's locked now.
func (s *Server) SeedHistory(events []SessionEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(events) > MaxSessionEvents {
		events = events[len(events)-MaxSessionEvents:]
	}
	s.events = append([]SessionEvent(nil), events...)
}

// recordEvent appends to the ring, shifting out the oldest in place once
// the cap is reached — the slice is bounded, so shifting beats allocating
// a fresh 200-entry array on every event past the cap. Caller must hold
// s.mu.
func (s *Server) recordEvent(e SessionEvent) {
	s.events = append(s.events, e)
	if len(s.events) > MaxSessionEvents {
		n := copy(s.events, s.events[len(s.events)-MaxSessionEvents:])
		s.events = s.events[:n]
	}
}

// useKey groups uses that collapse into one KindUse event: same op, same
// caller command line. Keyed on the command, not the pid, deliberately —
// a relaunching MCP server is a new pid every time with an identical
// argv, and it's exactly the caller whose uses need collapsing.
type useKey struct {
	op string
	by string
}

// useAggregate is one pending KindUse event still inside its collapse
// window. event holds the FIRST use's full provenance snapshot (pid,
// launcher — later uses from the same command line add nothing but
// count); start is that first use, which becomes the event's time.
type useAggregate struct {
	start time.Time
	event SessionEvent
}

// maxUseLabels caps how many distinct caller-reported secret names one
// collapsed use event carries. Eight names the typical profile in full;
// past that, Count still says how much flowed, the list just stops
// growing.
const maxUseLabels = 8

// recordUse notes a wrap/unwrap/reveal that rode the ALREADY-unlocked
// session — the events history used to be blind to: unlocks said who
// opened the session, locks said what closed it, and everything that
// flowed through in between left no record at all. Collapsed per
// caller+op over useWindow (the same discipline the mount read-storm
// logging applies), so a profile resolution's burst of unwraps is one
// event, not ten. Fresh challenges never come here — the unlock event
// itself carries that use's provenance and label.
//
// Aggregates flush lazily: any later use flushes every EXPIRED aggregate
// (so ongoing activity keeps history current), and lock()/history()
// flush everything (the session boundary, and the moment someone
// actually reads). A crash loses at most the still-pending window —
// bounded, and the durable file gets everything else.
func (s *Server) recordUse(op string, c *caller, label string) {
	// The collapse key is the RAW command line, not the redacted one the
	// event will carry: redaction can map two different callers' argvs onto
	// one string, and merging their aggregates would stamp the first
	// caller's pid onto the second's uses. The raw string never leaves the
	// in-memory pendingUses map (see caller.rawCommand).
	s.recordAggregated(KindUse, op, c.rawCommand(), c, label)
}

// opClassMismatch is the op label for an unwrap rejected because the class the
// caller claimed doesn't match the ciphertext it sent (verifyClassBinding).
// Named in the same terse style as the other socket-boundary rejections
// ("reject", "decode", "accept") because that is what it is.
const opClassMismatch = "class-mismatch"

// recordRejectedClass notes an unwrap turned away by verifyClassBinding.
//
// It collapses on the op ALONE — every caller's rejections merge into one
// aggregate — which is the difference between an audit line and an attack.
// The ring holds MaxSessionEvents and evicts oldest-first, so any event an
// unauthenticated caller can mint on demand is an eviction primitive, and
// collapsing per caller does not help when the caller is what varies:
// useKey.by is the peer's own argv, so one fork per event buys a fresh
// aggregate, and a few hundred execs push every real unlock and denial out of
// `jit audit` — the attack erasing the record of itself.
//
// The cost is that a collapsed line names only the first caller in the window.
// That is the right trade: the count and the fact of a flood are what an
// investigation needs first, and per-caller attribution bought at the price of
// an evictable history is worth nothing.
func (s *Server) recordRejectedClass(c *caller) {
	s.recordAggregated(KindError, opClassMismatch, "", c, "")
}

// recordAggregated is recordUse's general form. collapseBy is the second half
// of the aggregation key: the caller's identity for ordinary uses (so one
// tool's burst is one line), or a constant for events a caller can trigger at
// will (so a flood is one line no matter how many identities it wears).
func (s *Server) recordAggregated(kind, op, collapseBy string, c *caller, label string) {
	now := time.Now()
	key := useKey{op: op, by: collapseBy}

	s.mu.Lock()
	flushed := s.flushUsesLocked(false, now)
	agg := s.pendingUses[key]
	if agg == nil {
		e := unlockEvent(op, c)
		e.Kind = kind
		e.UnixTime = now.Unix()
		agg = &useAggregate{start: now, event: *e}
		if s.pendingUses == nil {
			s.pendingUses = map[useKey]*useAggregate{}
		}
		s.pendingUses[key] = agg
	}
	agg.event.Count++
	if label != "" && len(agg.event.Labels) < maxUseLabels && !containsString(agg.event.Labels, label) {
		agg.event.Labels = append(agg.event.Labels, label)
	}
	s.mu.Unlock()

	s.notifySessionEvents(flushed)
}

// flushUsesLocked materializes pending use aggregates into the ring —
// every one when all is set (a lock or a history read), otherwise only
// those whose collapse window has closed — returning them (oldest first)
// for the caller to hand to OnSessionEvent OUTSIDE s.mu, per that
// callback's contract. Caller must hold s.mu.
func (s *Server) flushUsesLocked(all bool, now time.Time) []SessionEvent {
	if len(s.pendingUses) == 0 {
		return nil
	}
	var out []SessionEvent
	for k, agg := range s.pendingUses {
		if all || now.Sub(agg.start) >= s.useWindow {
			out = append(out, agg.event)
			delete(s.pendingUses, k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UnixTime < out[j].UnixTime })
	for _, e := range out {
		s.recordEvent(e)
	}
	return out
}

// notifySessionEvents hands flushed use events to OnSessionEvent, if set.
// Its own function because three flush sites share the loop.
func (s *Server) notifySessionEvents(events []SessionEvent) {
	if s.OnSessionEvent == nil {
		return
	}
	for _, e := range events {
		s.OnSessionEvent(e)
	}
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// history returns the ring NEWEST FIRST — the order it will be read in, and
// the order `jit agent history` prints. Reversing here (rather than in the
// CLI) keeps every consumer, including a --format json one, from having to
// know which end is which. Pending use aggregates flush first — the moment
// someone actually reads history is exactly when it must be current, and
// an aggregate mid-window would otherwise be invisible right then.
func (s *Server) history() []SessionEvent {
	s.mu.Lock()
	flushed := s.flushUsesLocked(true, time.Now())
	out := make([]SessionEvent, 0, len(s.events))
	for i := len(s.events) - 1; i >= 0; i-- {
		out = append(out, s.events[i])
	}
	s.mu.Unlock()
	s.notifySessionEvents(flushed)
	return out
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
