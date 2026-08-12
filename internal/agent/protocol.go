// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package agent

// Request is one RPC sent to a running agent over its Unix socket, one
// JSON object per connection (dial, send exactly one Request, read exactly
// one Response, close — no multiplexing needed for this CLI-tool traffic
// pattern).
type Request struct {
	Op string `json:"op"` // "wrap" | "unwrap" | "unlock" | "lock" | "status" | "refresh" | "reveal_pid" | "stop_mount" | "history"
	// Data is the DEK (for "wrap") or the wrapped DEK (for "unwrap").
	// encoding/json base64-encodes a []byte field automatically.
	Data []byte `json:"data,omitempty"`
	// MountPath is "stop_mount"'s argument (which mount to stop serving).
	// Server doesn't interpret it itself (it never imports internal/mount,
	// same one-way dependency OnRefresh already keeps); it's opaque data
	// handed to OnStopMount.
	MountPath string `json:"mount_path,omitempty"`
	// RunMounts and TargetPID are "reveal_pid"'s arguments: for TargetPID's
	// process tree, for as long as that process lives (jit run sends its OWN
	// pid right before execve, which keeps the pid — so this is the target
	// command's pid, known exactly), treat each mount in the run's chosen
	// per-mount MODE. One run can carry several modes at once — swap its
	// .env while granting its .npmrc — which is why this is a list of
	// {path, mode}, not a single flag. Opaque to Server: what a mode means,
	// how readers are matched to the tree, and every teardown trigger live
	// entirely in the CLI layer's OnRevealPID.
	RunMounts []RunMount `json:"run_mounts,omitempty"`
	TargetPID int32      `json:"target_pid,omitempty"`
	// Disclose, set on "reveal_pid" only, forces a FRESH challenge naming a
	// global credential even when the session is already unlocked — the
	// disclosed-grant gate for machine-wide file-delivered mounts (gcloud ADC,
	// sops, ~/.npmrc) that `jit run --with` grants. Without it, a global-mount
	// grant would ride the session silently, so a `jit run --with gcp` a script
	// (not the human) put in a Makefile could hand out your gcloud credentials
	// with no prompt. False for every ordinary run.
	//
	// Deliberately a FLAG, not the prompt's wording. The wording is derived by
	// the agent from the mounts it is about to grant (Server.OnDescribeGrant),
	// for the same reason Label may never reach a prompt: the one line a human
	// decides by must not be a string the caller chose. It used to be
	// caller-supplied (DiscloseReason below), which let any same-user process
	// put a reassuring lie — "unlock the vault for profile dev" — on a prompt
	// that was actually granting away the gcloud ADC.
	Disclose bool `json:"disclose,omitempty"`
	// DiscloseReason is the pre-Disclose spelling of the flag above, honored
	// ONLY as a trigger and never as text: an in-flight older client mid-upgrade
	// must still get the disclosed gate (with the agent's own wording), rather
	// than silently skipping it. Never set by this version's Client.
	//
	// Deprecated: send Disclose.
	DiscloseReason string `json:"disclose_reason,omitempty"`
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
	// Class is the secret's provenance Class (a vault.Class* value) for a
	// "wrap"/"unwrap". Unlike Label it is NOT merely advisory: the agent binds
	// it into the DEK-wrap as AES-GCM additional authenticated data, so an
	// unwrap that names the wrong class fails the auth tag. That is what lets
	// the agent gate consent on it without a caller being able to lie its way
	// around the gate. Empty for legacy (v1/v2) secrets with no provenance.
	Class string `json:"class,omitempty"`
	// GrantProfiles ("grant_create") names the profiles a process grant should
	// cover. NAMES only, deliberately: the agent resolves them to concrete
	// secrets itself (Server.OnResolveGrant, through jit's own profile store
	// and vault envelopes), so the Touch ID prompt and the granted secret set
	// derive from the same agent-resolved facts — a caller cannot name one
	// profile on the prompt and smuggle a different secret set into the grant,
	// the same reasoning that moved reveal_pid's wording to OnDescribeGrant.
	GrantProfiles []string `json:"grant_profiles,omitempty"`
	// ProjectRoot ("grant_create") is the directory whose project profiles
	// should shadow the global ones during that resolution — the caller's cwd,
	// exactly the layering `jit run` applies. Empty means global-only.
	ProjectRoot string `json:"project_root,omitempty"`
	// GrantID ("grant_revoke"/"grant_extend") names the grant to act on.
	GrantID string `json:"grant_id,omitempty"`
	// TTLSeconds ("grant_create"/"grant_extend") is the requested lifetime.
	// The server clamps and validates; a client cannot mint a longer grant
	// than MaxGrantTTL by inflating this field.
	TTLSeconds int64 `json:"ttl_seconds,omitempty"`
}

// RunMount is one mount's requested run-scoped treatment in a reveal_pid
// request: which mount, and how jit run wants it handled for this run.
// Mode is a string (not a bool) so the set can grow — swap, grant, and
// later a disclosed global grant — without another protocol break.
type RunMount struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
}

// RunMount.Mode values.
const (
	// MountModeSwap replaces the mount with an inert compatibility file for
	// the run (jit run default) — guards pass, re-reads set nothing, real
	// values arrive via the injected environment.
	MountModeSwap = "swap"
	// MountModeGrant keeps the live mount and serves real content to the
	// run's process tree, per read (jit run --live, and project template
	// mounts like .npmrc that a tool reads from the file itself).
	MountModeGrant = "grant"
)

const (
	OpWrap      = "wrap"
	OpUnwrap    = "unwrap"
	OpUnlock    = "unlock"
	OpLock      = "lock"
	OpStatus    = "status"
	OpRefresh   = "refresh"
	OpRevealPID = "reveal_pid"
	OpStopMount = "stop_mount"
	OpHistory   = "history"
	// OpTrust registers the CALLER's own process (the kernel peer pid) as a
	// consent trust root: `jit run --trust` marks its run so any credential a
	// process in that run's tree reaches for is auto-allowed without a
	// per-process consent prompt. The agent records the peer's fork-time stamp
	// so a recycled pid can't inherit a dead run's trust; the grant is dropped
	// on the next re-lock.
	OpTrust = "trust"
	// OpGrantCreate creates a process grant (`jit grant`): after one disclosed
	// challenge, TargetPID's process tree may unwrap the covered profiles'
	// secrets until the grant expires — without further prompts, and across
	// re-locks (the one authorization state that deliberately survives them;
	// see Server's grant fields). OpGrantExtend re-prompts for more time on an
	// existing grant; OpGrantRevoke ends one with no prompt at all (reducing
	// access is always free); OpGrantList reads the current set, prompt-free
	// for the same reason OpHistory is.
	OpGrantCreate = "grant_create"
	OpGrantList   = "grant_list"
	OpGrantRevoke = "grant_revoke"
	OpGrantExtend = "grant_extend"
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
	// KindApproved marks a DISCLOSED challenge the human approved: a `jit run
	// --with` global grant, a per-process consent prompt, or a `jit run
	// --trust` registration. Distinct from KindUnlock because no session
	// transition happened — a disclosed challenge is a standalone confirmation
	// that leaves the cached session exactly as it found it.
	//
	// It exists because the audit trail used to record only the refusals: a
	// declined consent prompt became a KindDenied line, an APPROVED one became
	// nothing at all. "At 14:03 you approved gcloud reaching your gcp
	// credential" — the single line the whole consent feature exists to be able
	// to show you afterwards — was the one thing it never wrote down. Cause
	// carries the same wording the human read on the prompt.
	KindApproved = "approved"
	// KindUse marks the session being USED without a fresh challenge — a
	// wrap/unwrap/reveal riding the already-unlocked cache. Unlock events
	// alone could say who OPENED the session but not what flowed through
	// it afterwards, which is most of what an audit wants. Collapsed
	// (Count, Labels) per caller+op over a short window, so a `jit run`
	// resolving a ten-secret profile is one event, not ten.
	KindUse = "use"
	// KindError marks something the service itself got wrong or refused at
	// the socket: a rejected peer (a process the kernel says isn't this
	// user's — someone else probing the agent socket), a malformed request,
	// or the accept loop failing. Op names which ("reject", "decode",
	// "accept") and Cause carries the detail. These used to exist only as
	// prose in agent.log, invisible to `jit audit` and unshippable to a
	// SIEM; as a structured event a rejected peer is now a first-class,
	// greppable line in the same trail as every unlock. Enriched with the
	// peer's provenance (By/ByPID/LaunchedBy) when the kernel still names it.
	KindError = "error"
	// KindServe marks one mount read reaching its content decision: a reader
	// opened a live mount and got either the decoy or the real value. Op is
	// OpServeDecoy or OpServeReal, Cause says WHY that verdict, Labels names
	// the credential, and By/ByPID/LaunchedBy carry internal/lineage's
	// best-effort answer to who read it.
	//
	// The decoy half is the point: a process with no business reading a
	// credential file, quietly handed a fake one, is a honeytoken-shaped
	// signal — and until this existed jit produced that signal on every
	// single read and then discarded it, keeping only the newest one per
	// mount, in memory, gone at the next service restart. The real half
	// closes the other end of the same question: a KindApproved event
	// proves a grant was AUTHORIZED, never that the credential was actually
	// read, and those are different facts on the day one matters.
	//
	// Necessarily collapsed before it is ever written (see the CLI's
	// serveAuditor): the serve path runs once per reader rendezvous and a
	// file-watcher loop re-reads a mount continuously, so an uncollapsed
	// serve event would be an eviction primitive against this very ring —
	// the same hazard recordRejectedClass defends against, arrived at from
	// the other direction.
	KindServe = "serve"
	// KindGrantEnd marks a process grant ending, with Cause naming which way:
	// "expired" (its TTL ran out), "revoked" (jit grant revoke, with the
	// revoker's provenance on By/LaunchedBy), or "process exited" (the root
	// process the grant was anchored to is gone). Its creation needs no kind
	// of its own — a grant is born as a KindApproved event, like every other
	// disclosed challenge — but its END is the moment unattended access
	// stopped, and a trail that records when standing access began and not
	// when it ceased can't answer "was the grant still live at the time?",
	// which is the first question an incident asks. Labels carries the
	// covered vault paths; Op carries the grant id.
	KindGrantEnd = "grant_end"
)

// The Op values a KindServe event carries: which content the reader got.
// They are the serve's outcome, so `jit audit` renders them on the status
// axis (--status decoy / --status real) rather than inventing a new one.
const (
	OpServeDecoy = "decoy"
	OpServeReal  = "real"
)

// OpGrantUse is the Op a KindUse event carries when the unwrap was answered
// from a process grant's DEK cache instead of the session — the audit
// distinction between "rode an unlock you gave moments ago" and "rode a
// standing grant you gave this morning". Exported like the serve ops above:
// it is part of the trail's vocabulary, and the CLI renderer must name it
// without restating the string.
const OpGrantUse = "grant_use"

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
	// ExecutablePath is the serving agent process's own os.Executable(), set
	// on "status" beside Build and Version, and answering the question
	// neither of them can: WHERE the running service's binary is.
	//
	// Build and Version compare what the service IS against what the CLI is,
	// which catches an agent left behind by a rebuild. It cannot catch an
	// agent whose binary MOVED at the same version — and that is the case
	// that breaks the vault outright. A jit install migrating from the
	// release tarball (/usr/local/bin/jit) to the Homebrew cask
	// (/opt/homebrew/bin/jit) leaves launchd's KeepAlive holding a process
	// whose executable has been deleted; macOS then cannot validate its code
	// signature against the on-disk file, and every keychain read fails with
	// a POSIX ENOENT (see internal/keychainwrap's kwPOSIXENOENT). Both
	// builds report 0.82.0, so the existing mismatch check stays silent
	// while nothing can be unlocked (measured on a real machine 2026-08-09).
	//
	// Empty when talking to an agent older than this field, which callers
	// must render as unknown rather than as agreement.
	ExecutablePath string `json:"executable_path,omitempty"`
	// Grants answers "grant_list" (and "grant_create"/"grant_extend" echo the
	// affected grant back the same way, so a client can render the result
	// without a second round trip). Empty on every other Op. In-memory state:
	// a process grant never survives the agent process, by design.
	Grants []GrantStatus `json:"grants,omitempty"`
}

// GrantStatus is one process grant as the agent reports it — deliberately
// plain strings/ints like every other wire type here. Name and Command are
// kernel-derived at grant creation (internal/lineage), never caller-reported,
// matching MountGrantStatus's convention.
type GrantStatus struct {
	ID  string `json:"id"`
	PID int32  `json:"pid"`
	// Name is the root process's display name ("claude"); Command its full
	// invocation for a wide terminal.
	Name    string `json:"name,omitempty"`
	Command string `json:"command,omitempty"`
	// Profiles are the profile names the grant was created from; Secrets the
	// concrete vault paths it actually covers (resolved at creation — a later
	// profile edit never widens a standing grant).
	Profiles []string `json:"profiles"`
	Secrets  []string `json:"secrets"`
	// CreatedUnix/ExpiresUnix bound the grant's life; Serves counts unwraps
	// served under it and LastServeUnix stamps the newest (zero when unused).
	CreatedUnix   int64 `json:"created_unix"`
	ExpiresUnix   int64 `json:"expires_unix"`
	Serves        int64 `json:"serves,omitempty"`
	LastServeUnix int64 `json:"last_serve_unix,omitempty"`
	// RootAlive reports whether the anchored process (pid + fork time) still
	// exists at the time of the status read. A dead root is pruned lazily, so
	// a listing can catch one mid-flight; render it as ending, not live.
	RootAlive bool `json:"root_alive"`
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
	// Kind is "unlock", "lock", "start", "denied", "approved", "use", or
	// "error". Callers used
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
	// ByLikely marks By/ByPID as an identity carried over from an earlier
	// scan rather than observed for THIS event — true on a mount serve whose
	// lineage scan raced the reader's open but found the same process still
	// alive and still holding the mount (internal/cli's identifyReader). It
	// means "almost certainly this process" and must never be rendered as
	// certainty; an audit trail that lies is worse than one that admits it
	// doesn't know.
	ByLikely bool `json:"by_likely,omitempty"`
	// LaunchedBy is the nearest ancestor that explains the call — "claude",
	// "Code" — with the shells that merely relayed it skipped. Empty when a
	// human ran jit at a prompt themselves, because then there is nothing to
	// explain.
	LaunchedBy string `json:"launched_by,omitempty"`
	// Cause is set on lock events (what dropped the session — "15m idle
	// timeout" vs. an explicit lock; "Why am I being asked again?" is
	// usually answered here, not by the unlock at all), on start events
	// (the build), on denied events (why the challenge failed), and on
	// approved events (the wording the human read on the prompt).
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
	// AuthMethod, on the events that involved a FRESH local-auth challenge
	// (unlock and denied), is a best-effort description of how the user was
	// asked: "Touch ID or device passcode" when biometry is enrolled on this
	// Mac, "device passcode" when it isn't. It is deliberately not more
	// precise than that: jit challenges with LAPolicyDeviceOwnerAuthentication,
	// which lets macOS accept EITHER a fingerprint or the passcode, and the
	// LocalAuthentication reply does not report which one the user actually
	// used — so claiming "authenticated by fingerprint" would be a fabrication.
	// Empty on events that rode an already-unlocked session (no challenge
	// happened) and on events restored from a jit version that predates this
	// field.
	AuthMethod string `json:"auth_method,omitempty"`
}

// MountRevealStatus is one currently-served mount's state — deliberately
// plain strings/bools/ints, not a type from internal/mount, since this
// package never imports internal/mount (mountManager, the CLI layer,
// populates this via Server.OnMountStatus). A mount serves decoys unless a
// run-scoped grant (Grants) is currently authorizing real reads for its own
// process tree; there is no reveal window.
type MountRevealStatus struct {
	Path string `json:"path"`
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
	//
	// Deliberately still only the LATEST, and still not persisted: this
	// answers "what is happening to this mount right now", which is the
	// question `jit service status` is open to answer. Every serve is ALSO
	// recorded durably as a KindServe event (collapsed — see the CLI's
	// serveAuditor), and that is what answers "what happened last Tuesday".
	// Neither substitutes for the other, so don't collapse them into one.
	LastServe *MountServeEvent `json:"last_serve,omitempty"`
	// Grants are the run-scoped reveal grants currently active on this
	// mount (usually zero or one): each names the jit-run target whose
	// process tree gets real content per-read, for that process's
	// lifetime. In-memory like LastServe — a grant never survives the
	// agent process, by design.
	Grants []MountGrantStatus `json:"grants,omitempty"`
	// Swapped is true while this mount is a compatibility pointer file
	// (the jit run default) rather than the decoy FIFO — for the lifetime
	// of the run(s) in Grants. A swapped mount isn't "served" in the FIFO
	// sense; Revealed/LastServe don't apply while it's a plain file.
	Swapped bool `json:"swapped,omitempty"`
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
