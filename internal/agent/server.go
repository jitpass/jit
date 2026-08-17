// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package agent

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jitpass/jit/internal/consent"
)

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
	// grantTimers holds each live grant's expiry timer so re-arming or ending
	// one can stop its predecessor instead of leaving it to run out (see
	// armGrantExpiry). Guarded by grantMu, alongside grants itself.
	grantTimers map[string]*time.Timer

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
	// pendingLockNotify is a lazily-collected session's events — its flushed
	// uses, then its lock — already recorded in the ring (and lastLock) but
	// not yet handed to OnSessionEvent, because they were created under mu
	// and that callback must never run there. Appended only by
	// collectIfDoneLocked; drained in order by notifyPendingLock. Guarded by
	// mu.
	pendingLockNotify []SessionEvent
	lockTimer         *time.Timer
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

	// serveErrSeen rate-limits identical socket-boundary failures into the
	// durable trail (see recordServeError). Its own mutex: these fire on
	// connection-handling goroutines before any session state is involved,
	// and must not contend with mu.
	serveErrMu   sync.Mutex
	serveErrSeen map[string]*serveErrNote

	// discloseRefusals is the prompt-storm backoff for disclosed challenges
	// (see discloseBackoffLocked). Guarded by challengeMu, not mu: every
	// read and write happens inside discloseChallengeOp, which holds
	// challengeMu across the whole prompt, so the state a waiter reads is
	// always the one the challenge it queued behind just wrote.
	discloseRefusals map[string]discloseRefusal
	// discloseBackoff is the escalation schedule, a field for the same
	// reason denialCooldown is one: a test that wants to exercise the
	// decline-then-approve sequence should not have to sleep out a real
	// pause. Empty disables the backoff entirely.
	discloseBackoff []time.Duration

	listener net.Listener
	// socketInfo identifies the socket file THIS server bound, so Close can
	// tell its own socket from one a later agent has since claimed at the
	// same path. Without it, a foreground run (or an instance dying in a
	// reload's teardown window) unlinked the LIVE agent's socket on exit:
	// that agent kept its session and every FIFO writer, but held an
	// unlinked inode nothing could dial, so every command reported a healthy
	// process as crashed until a manual restart booted it out.
	socketInfo os.FileInfo
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
		// The disclosed-prompt backoff (discloseBackoffLocked) starts from
		// the shipped schedule; tests override the field.
		discloseBackoff: discloseBackoffSchedule,
		useWindow:       defaultUseWindow,
		trustRoots:      map[int32]int64{},
		identify:        callerFromConn,
	}
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
	// A request that names a protocol this build cannot speak is refused
	// whole, before any dispatch. Unknown OPS already failed closed; unknown
	// FIELDS did not — JSON drops them silently, so a request whose safety
	// rests on a field this agent has never heard of would otherwise be
	// served as though the field had said nothing. Refusing names the fix,
	// because the fix is always the same: the agent is older than the CLI
	// asking, and restarting it onto the current binary resolves it.
	if req.MinProtocol > Protocol {
		return Response{OK: false, Error: fmt.Sprintf(
			"%s: this request needs agent protocol %d but the running service speaks %d — it predates a check this request depends on; run `jit service restart` to move it onto the current binary",
			req.Op, req.MinProtocol, Protocol)}
	}
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
		if fresh {
			if s.Consent != nil {
				s.Consent.ClearBackoff()
			}
			// The disclosed-prompt pauses clear on the same signal and under
			// the same `fresh` gate, for the identical reason.
			s.clearDiscloseBackoff()
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
			// Collapse on the RAW argv, never the redacted form — the same
			// requirement recordUse documents at length and has a test for.
			// Redaction can map two different callers onto one string, and
			// this path has the identical collapse window, so keying on it
			// would stamp the first caller's pid onto the second's uses. A
			// grant covers a whole tree, so two tools under one grant hitting
			// the same window is the ordinary case here, not an exotic one.
			s.recordAggregated(KindUse, OpGrantUse, c.rawCommand(), c, path)
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
