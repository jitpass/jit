// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package agent

// Request is one RPC sent to a running agent over its Unix socket, one
// JSON object per connection (dial, send exactly one Request, read exactly
// one Response, close — no multiplexing needed for this CLI-tool traffic
// pattern).
type Request struct {
	Op string `json:"op"` // "wrap" | "unwrap" | "unlock" | "lock" | "status" | "refresh" | "reveal" | "reveal_pid" | "stop_mount" | "history"
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
	// MountPaths and TargetPID are "reveal_pid"'s arguments: serve real
	// content on each of these mounts to TargetPID's process tree, for as
	// long as that process lives (jit run sends its OWN pid right before
	// execve, which keeps the pid — so this is the target command's pid,
	// known exactly, not guessed). Opaque to Server, same as MountPath:
	// what a grant means, how readers are matched to the tree, and every
	// teardown trigger live entirely in the CLI layer's OnRevealPID.
	MountPaths []string `json:"mount_paths,omitempty"`
	TargetPID  int32    `json:"target_pid,omitempty"`
	// Label is the caller's own description of what a "wrap"/"unwrap" is
	// FOR — the vault path of the secret whose DEK is in Data ("stripe/
	// live-key"), which the agent otherwise cannot know: it only ever sees
	// opaque key bytes. Audit-only and CALLER-REPORTED: unlike every other
	// provenance fact the agent records, this one is what the caller says
	// about itself, so history displays it with that qualifier and it must
	// never reach the Touch ID prompt (challengeReason stays kernel-derived
	// only — a caller could otherwise put a reassuring lie on the one line
	// the human decides by) or gate anything. Optional; empty is fine.
	Label string `json:"label,omitempty"`
}

const (
	OpWrap      = "wrap"
	OpUnwrap    = "unwrap"
	OpUnlock    = "unlock"
	OpLock      = "lock"
	OpStatus    = "status"
	OpRefresh   = "refresh"
	OpReveal    = "reveal"
	OpRevealPID = "reveal_pid"
	OpStopMount = "stop_mount"
	OpHistory   = "history"
)

// SessionEvent.Kind values.
const (
	KindUnlock = "unlock"
	KindLock   = "lock"
	// KindStart marks the agent PROCESS starting, with Cause carrying its
	// build. Server never emits it — the CLI layer writes one per `jit
	// agent run` into the durable history it seeds the ring from — but the
	// ring and the wire carry it like any other event. It's what makes a
	// restored history honest: a session that "just locked" across a
	// launchd restart didn't lock, the process died, and events on either
	// side of a start marker belong to different agent processes.
	KindStart = "start"
	// KindDenied marks a challenge the human (or a timeout) REFUSED, with
	// the same caller provenance an unlock would have carried and Cause
	// naming the failure. It exists because a denied prompt used to leave
	// no trace anywhere: the one event a user most needs to reconstruct —
	// "something asked for my secrets and I said no... what was it?" — was
	// the one event with no record. Denials also arm the re-prompt
	// cooldown (see Server).
	KindDenied = "denied"
	// KindUse marks the session being USED without a fresh challenge — a
	// wrap/unwrap/reveal riding the already-unlocked cache. Unlock events
	// alone could say who OPENED the session but not what flowed through
	// it afterwards, which is most of what an audit wants. Collapsed
	// (Count, Labels) per caller+op over a short window, so a `jit run`
	// resolving a ten-secret profile is one event, not ten.
	KindUse = "use"
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
	// Events answers "history" — every unlock and lock this agent process
	// has seen, plus whatever an earlier process durably recorded and this
	// one was seeded with (SeedHistory), newest first, bounded by
	// MaxSessionEvents. Status deliberately carries only the two latest
	// instead (a status call happens constantly, including from shell
	// prompts; shipping the whole ring each time would be wasteful), so
	// the full sequence needs asking for.
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
	// Kind is "unlock", "lock", "start", "denied", or "use". Callers used
	// to tell unlocks and locks apart by checking whether Cause was set,
	// which worked only because locks happened to be the only events that
	// carried one — a coincidence, not a contract, and one that would have
	// broken silently the first time another kind needed a cause of its
	// own (start and denied events now do).
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
	// Cause is set on lock events (what dropped the session — "15m idle
	// timeout" vs. an explicit lock; "Why am I being asked again?" is
	// usually answered here, not by the unlock at all), on start events
	// (the build), and on denied events (why the challenge failed).
	Cause string `json:"cause,omitempty"`
	// Labels are the caller-reported secret names this event touched
	// (Request.Label) — "what was read", the one fact kernel provenance
	// structurally cannot supply, since the agent only ever sees opaque
	// key bytes. CLAIMED, not verified: any display must say so. On an
	// unlock or denied event there is at most one; on a use event they
	// accumulate across the collapse window, deduplicated and capped, so a
	// long burst names what it touched without growing unboundedly.
	Labels []string `json:"labels,omitempty"`
	// Count, on use events, is how many uses this one event stands for —
	// collapsed per caller+op over Server's use window, the same
	// discipline the mount read-storm logging already applies. Zero/one
	// everywhere else.
	Count int64 `json:"count,omitempty"`
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
	// Grants are the run-scoped reveal grants currently active on this
	// mount (usually zero or one): each names the jit-run target whose
	// process tree gets real content per-read, for that process's
	// lifetime. In-memory like LastServe — a grant never survives the
	// agent process, by design.
	Grants []MountGrantStatus `json:"grants,omitempty"`
}

// MountGrantStatus is one active run-scoped reveal grant as status reports
// it — which process tree may read real content from a mount right now.
// Command is kernel-derived at grant time (internal/lineage), not
// caller-reported, matching SessionEvent.By's convention.
type MountGrantStatus struct {
	PID       int32  `json:"pid"`
	Command   string `json:"command,omitempty"`
	SinceUnix int64  `json:"since_unix"`
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
	// GrantServed marks a REAL serve that was authorized by a run-scoped
	// grant (every attached reader verified inside the granted process
	// tree) rather than by a reveal window. Always false on decoy serves.
	GrantServed bool `json:"grant_served,omitempty"`
}
