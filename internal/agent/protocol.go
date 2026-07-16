// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package agent

// Request is one RPC sent to a running agent over its Unix socket, one
// JSON object per connection (dial, send exactly one Request, read exactly
// one Response, close — no multiplexing needed for this CLI-tool traffic
// pattern).
type Request struct {
	Op string `json:"op"` // "wrap" | "unwrap" | "unlock" | "lock" | "status" | "refresh" | "reveal" | "stop_mount"
	// Data is the DEK (for "wrap") or the wrapped DEK (for "unwrap").
	// encoding/json base64-encodes a []byte field automatically.
	Data []byte `json:"data,omitempty"`
	// MountPath and RevealSeconds are "reveal"'s own arguments — which mount to
	// reveal and for how long. "stop_mount" reuses MountPath too (which
	// mount to stop serving), leaving RevealSeconds unset. Server doesn't
	// interpret MountPath itself (it never imports internal/mount, same
	// one-way dependency OnRefresh already keeps); it's opaque data
	// handed to OnReveal/OnStopMount.
	MountPath     string `json:"mount_path,omitempty"`
	RevealSeconds int64  `json:"reveal_seconds,omitempty"`
}

const (
	OpWrap      = "wrap"
	OpUnwrap    = "unwrap"
	OpUnlock    = "unlock"
	OpLock      = "lock"
	OpStatus    = "status"
	OpRefresh   = "refresh"
	OpReveal    = "reveal"
	OpStopMount = "stop_mount"
	OpHistory   = "history"
)

// SessionEvent.Kind values.
const (
	KindUnlock = "unlock"
	KindLock   = "lock"
)

// Response answers a Request.
type Response struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	// Data is the wrapped/unwrapped result for "wrap"/"unwrap".
	Data []byte `json:"data,omitempty"`
	// Unlocked and ExpiresInSeconds answer "status" (and are also set on
	// "unlock"/"lock" so a client can confirm the resulting state without
	// a second round trip).
	Unlocked         bool  `json:"unlocked,omitempty"`
	ExpiresInSeconds int64 `json:"expires_in_seconds,omitempty"`
	// Mounts answers "status" too (GAPS.md #37) — per-mount reveal state,
	// so a caller can see "which mount is revealed and for how long" in the
	// same round trip, instead of inferring it (or, before this, having
	// no way to see it at all). Empty on every other Op.
	Mounts []MountRevealStatus `json:"mounts,omitempty"`
	// LastUnlock and LastLock answer "status"'s missing question: not what
	// state the session is in, but who put it there (GAPS.md #75). Status
	// could always say "running and locked" — never "unlocked 10:19:07 by
	// `jit run --profile mcp-jamf`, which Claude Code started; auto-locked
	// 15m later", which is the thing a user staring at an unexplained Touch
	// ID prompt actually needs. Nil when nothing has unlocked (or locked)
	// this agent process yet: in-memory state, like Mounts, not persisted
	// across a restart.
	LastUnlock *SessionEvent `json:"last_unlock,omitempty"`
	LastLock   *SessionEvent `json:"last_lock,omitempty"`
	// PendingUnlock, set on "status" only, is the challenge currently
	// sitting on the user's screen — who triggered it and when the prompt
	// appeared (UnixTime is prompt-appearance, not approval; Kind is empty
	// because nothing has happened yet — this is not a history event, and
	// it never becomes one unless approved). Status can answer during a
	// challenge precisely because reads don't queue behind it, so this is
	// the agent explaining a prompt WHILE the human is staring at it.
	PendingUnlock *SessionEvent `json:"pending_unlock,omitempty"`
	// Events answers "history" — every unlock and lock this agent PROCESS has
	// seen, newest first, bounded by maxSessionEvents. Status deliberately
	// carries only the two latest instead (a status call happens constantly,
	// including from shell prompts; shipping the whole ring each time would
	// be wasteful), so the full sequence needs asking for.
	Events []SessionEvent `json:"events,omitempty"`
	// Build is the serving agent process's own BuildID(), set on "status"
	// (GAPS.md #49) — launchd's KeepAlive keeps an agent process alive
	// across rebuilds and reinstalls indefinitely, so without this there
	// was no way to notice the running agent predates the CLI talking to
	// it: a just-fixed bug looks unfixed, with nothing anywhere saying why.
	Build string `json:"build,omitempty"`
	// Version is the serving agent process's own Version(), set on "status"
	// alongside Build — the human-scale answer ("v0.4.0") to the same
	// question Build answers at revision granularity. Empty when talking to
	// an agent older than this field, which callers must render as
	// unknown, not as a match.
	Version string `json:"version,omitempty"`
}

// SessionEvent is one transition of the agent's session — an unlock or a
// lock — with the provenance the agent learned at the moment it happened.
// Deliberately plain strings/ints (this package's protocol convention), and
// deliberately kernel-derived, never self-reported: see internal/agent's
// caller and internal/lineage.
//
// Every field except UnixTime is best-effort. A caller the kernel wouldn't
// identify (it exited before the agent could look) leaves By/ByPID/LaunchedBy
// empty, and the status line simply says less — identification failing must
// never fail the unlock itself.
type SessionEvent struct {
	UnixTime int64 `json:"unix_time"`
	// Kind is "unlock" or "lock". Callers used to tell the two apart by
	// checking whether Cause was set, which worked only because locks happen
	// to be the only events that carry one — a coincidence, not a contract,
	// and one that would have broken silently the first time an unlock needed
	// a cause of its own.
	Kind string `json:"kind"`
	// Op is the RPC that forced the unlock ("unwrap", "reveal", ...), or
	// "serve_mounts" for the agent's own in-process unlock when it resolves
	// a mount's real content. Empty on a lock event.
	Op string `json:"op,omitempty"`
	// By is the caller's full command line as the kernel reports it, and
	// ByPID its pid — the literal "what asked for this", for a terminal wide
	// enough to print it. The Touch ID prompt gets a much shorter phrasing
	// (see challengeReason); this is the investigative version.
	By    string `json:"by,omitempty"`
	ByPID int32  `json:"by_pid,omitempty"`
	// LaunchedBy is the nearest ancestor that explains the call — "claude",
	// "Code" — with the shells that merely relayed it skipped. Empty when a
	// human ran jit at a prompt themselves, because then there is nothing to
	// explain.
	LaunchedBy string `json:"launched_by,omitempty"`
	// Cause is set on lock events only: what dropped the session ("15m idle
	// timeout" vs. an explicit lock). "Why am I being asked again?" is
	// usually answered here, not by the unlock at all.
	Cause string `json:"cause,omitempty"`
}

// MountRevealStatus is one currently-served mount's reveal state — deliberately
// plain strings/bools/ints, not a type from internal/mount, since this
// package never imports internal/mount (mountManager, the CLI layer,
// populates this via Server.OnMountStatus).
type MountRevealStatus struct {
	Path               string `json:"path"`
	Revealed           bool   `json:"revealed"`
	RevealedForSeconds int64  `json:"revealed_for_seconds,omitempty"`
	// RevealEndedUnix is when the most recent reveal window ended (naturally or
	// force-hidden by a lock), set only while hidden. Reveal expiry is
	// lazy — nothing fires at the moment a window ends — so this is what
	// lets status say "the window ended Xm ago" instead of the revealed line
	// just silently vanishing (GAPS.md #48). Zero if never revealed since
	// the agent started (in-memory, like LastServe).
	RevealEndedUnix int64 `json:"reveal_ended_unix,omitempty"`
	// ReadsLastMinute is how many readers connected to this mount within
	// the current rolling minute — the signal that a file watcher is in a
	// re-read loop with the mount (GAPS.md #47's residual case: a watcher
	// that drains content still re-triggers on the isolation rename).
	// Status uses it to name the loop instead of it burning CPU invisibly.
	ReadsLastMinute int64 `json:"reads_last_minute,omitempty"`
	// LastServe, if set, is the most recent time a reader actually read
	// this mount — and, crucially, whether it got decoy or real content.
	// Before this existed, "my dev server read decoys and nobody could
	// see that from anywhere" was a real point of confusion: the only
	// record was a line in the agent's own log file. Nil when nothing has
	// read the mount since the agent process started (this is in-memory
	// state, not persisted).
	LastServe *MountServeEvent `json:"last_serve,omitempty"`
}

// MountServeEvent describes one read of a mount: when, what kind of
// content was served, and — best-effort, via internal/lineage's audit
// scan (RFC.md §5.1) — who read it. ReaderPID/ReaderPath are zero/empty
// when the scan missed the reader (a fast-closing reader legitimately
// evades it; that's exactly why lineage is audit-only and never gates
// what gets served).
type MountServeEvent struct {
	UnixTime   int64  `json:"unix_time"`
	Decoy      bool   `json:"decoy"`
	ReaderPID  int32  `json:"reader_pid,omitempty"`
	ReaderPath string `json:"reader_path,omitempty"`
	// ReaderLaunchedBy is what launched the reader ("claude", "Code") —
	// "python3 read your credentials" is a fact you can't act on; "python3,
	// launched by claude" is one you can.
	ReaderLaunchedBy string `json:"reader_launched_by,omitempty"`
	// ReaderLikely marks an identity carried over from an earlier scan of this
	// same mount (the reader is still alive and still holding the file open,
	// but this particular scan raced its open and missed it). True means
	// "almost certainly this process"; it must never be displayed as
	// certainty, because it is an inference.
	ReaderLikely bool `json:"reader_likely,omitempty"`
}
