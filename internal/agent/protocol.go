// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package agent

import (
	"github.com/jitpass/jit/internal/auditlog"
	"github.com/jitpass/jit/internal/job"
)

// Protocol is this build's socket-protocol revision. It exists because
// version skew across the socket degrades by SILENT JSON FIELD DROPPING,
// and that is fail-open for any field whose presence is what enforces
// something: an old agent that has never heard of Request.Disclose simply
// ignores it and performs the reveal with no disclosed challenge at all —
// exactly the machine-wide silent credential grant that flag exists to
// prevent. Vault-side skew already fails CLOSED and loudly ("envelope
// version 4, newer than this jit understands"); the socket had no
// equivalent.
//
// Two mechanisms use it, in opposite directions:
//
//   - Request.MinProtocol lets a client REQUIRE enforcement it cannot
//     verify from the outside: an agent whose own Protocol is lower
//     refuses the request instead of silently doing less than was asked.
//     This protects a future client talking to today's agent.
//   - Response.Protocol (on status) lets a client check BEFORE it sends
//     anything security-relevant, which is what protects a new client
//     talking to a genuinely old agent — one that predates MinProtocol
//     and would ignore that too. An absent field reads as 0.
//
// Bump this when adding a field whose absence would weaken a gate, and
// name the new value in the client check that requires it.
const Protocol = 1

// protocolDisclosedGate is the Protocol at which the agent is known to
// honor Request.Disclose. Below it, a disclosed grant cannot be proven to
// have prompted anyone, so the client refuses to ask.
const protocolDisclosedGate = 1

// Request is one RPC sent to a running agent over its Unix socket, one
// JSON object per connection (dial, send exactly one Request, read exactly
// one Response, close — no multiplexing needed for this CLI-tool traffic
// pattern).
type Request struct {
	// MinProtocol is the lowest agent Protocol that can serve this request
	// AS ASKED. Set it whenever dropping one of this request's fields would
	// silently weaken a gate rather than merely losing a nicety; an agent
	// below it fails the request closed. Zero (absent) means any agent will
	// do, which is the truth for ordinary wrap/unwrap/status traffic.
	MinProtocol int    `json:"min_protocol,omitempty"`
	Op          string `json:"op"` // "wrap" | "unwrap" | "unlock" | "lock" | "status" | "refresh" | "reveal_pid" | "stop_mount" | "history"
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
	// AuditRecord is "audit_append"'s payload: one finished invocation for
	// the agent to write to the application audit log. A pointer so an absent
	// record is distinguishable from a zero one, which the handler refuses
	// rather than writing an empty line into the trail.
	AuditRecord *auditlog.Record `json:"audit_record,omitempty"`
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
	// Broker, on "subscribe", asks to be shown disclosed challenges before
	// they prompt (OpConsentList). An agent that predates it ignores the
	// field and the stream simply never carries a pending request.
	Broker bool `json:"broker,omitempty"`
	// ConsentID and Decision are "consent_answer"'s arguments: the pending
	// event's ConsentID, and DecisionAllow or DecisionDeny.
	ConsentID string `json:"consent_id,omitempty"`
	Decision  string `json:"decision,omitempty"`
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
	// GrantProfileRoots ("grant_create") is GrantProfiles with a folder per
	// name instead of one ProjectRoot for all of them — what a client that
	// lists every profile on the Mac needs, since two ticked profiles may
	// live beside two different projects. Same rule as GrantProfiles: names
	// and folders only, the agent resolves them itself. When set it
	// replaces GrantProfiles/ProjectRoot; an agent older than this field
	// ignores it and refuses the create for having no profiles, which is
	// the safe answer.
	GrantProfileRoots []GrantProfile `json:"grant_profile_roots,omitempty"`
	// Standing ("grant_create") asks for a grant with no deadline
	// (design/standing-grants.md): it holds its own key in the keychain,
	// survives a service restart and a reboot, and ends only on
	// grant_revoke. Tree mode only (GrantName set): a pid dies with the
	// boot, so an exact-process grant always keeps a TTL. Exclusive with
	// TTLSeconds — sending both is an error, so omitting --for can never
	// mint a permanent grant by accident.
	Standing bool `json:"standing,omitempty"`
	// GrantName ("grant_create") switches the grant from exact-process to
	// tree-scoped: TargetPID is then the SESSION ROOT to anchor under (the
	// caller's own terminal app or tmux server — the agent verifies it is
	// genuinely the caller's ancestor), and the grant serves any process at
	// or below that root whose ancestry passes through a process with this
	// display name — including ones started after creation, which is the
	// point. The name is the human's own typed word about their intent and
	// only ever NARROWS the kernel-verified tree (lineage.AncestryNamedWithin);
	// it never widens anything, so the "identity never decides" doctrine
	// holds. Empty means the exact-process grant TargetPID has always meant.
	GrantName string `json:"grant_name,omitempty"`
	// AnchorExplicit ("grant_create", tree mode) says the caller is NOT
	// inside the tree it names and is choosing the anchor deliberately: a
	// menu bar app asking for "any claude under iTerm2" has no terminal
	// above it to anchor to. The agent then requires TargetPID to be a
	// session root in its own right (launchd's direct child: a terminal
	// app, an editor, a tmux server — lineage.IsSessionRoot), never an
	// interior process and never launchd, and the disclosed prompt names
	// the requesting program alongside the tree, so the human sees who is
	// asking to hang a grant under which app. Everything else about a tree
	// grant is unchanged: the name only narrows, the fork-time anchor and
	// per-read ancestry check decide membership, and the human on the
	// prompt is the decision. An agent older than this field ignores it and
	// refuses the request on the ancestry check, which is the safe answer.
	AnchorExplicit bool `json:"anchor_explicit,omitempty"`
	// GrantID ("grant_revoke"/"grant_extend") names the grant to act on.
	GrantID string `json:"grant_id,omitempty"`
	// TTLSeconds ("grant_create"/"grant_extend") is the requested lifetime.
	// The server clamps and validates; a client cannot mint a longer grant
	// than MaxGrantTTL by inflating this field.
	TTLSeconds int64 `json:"ttl_seconds,omitempty"`

	// JobName names the AI job a "job_*" op acts on (design/agent-jobs.md).
	JobName string `json:"job_name,omitempty"`
	// JobSpec is "job_allow"'s proposal: what to run, where, with which
	// profile. It is a PROPOSAL, the same footing as GrantProfiles: the agent
	// resolves the executable, the profile's secrets and the fingerprint
	// itself, and the human approves what the agent resolved, never a
	// resolution the caller claims.
	JobSpec *JobSpec `json:"job_spec,omitempty"`
	// JobNamesOnly ("job_list") skips the fingerprint and rotation checks
	// and returns names and settings only, for shell completion, which must
	// not re-hash every job folder on each Tab. An agent that predates it
	// ignores it and answers in full, which is only slower.
	JobNamesOnly bool `json:"job_names_only,omitempty"`
	// Why ("job_request") is the proposer's one sentence for the human. It
	// is the model's own words: shown labelled as unchecked, never used to
	// decide anything, and never on a Touch ID prompt.
	Why string `json:"why,omitempty"`
	// ProposalID ("job_allow", "job_dismiss") names the proposal being
	// approved or dismissed, so it stops waiting.
	ProposalID string `json:"proposal_id,omitempty"`
}

// JobSpec is a job as the approving client describes it.
type JobSpec struct {
	Dir  string   `json:"dir"`
	Argv []string `json:"argv"`
	// Profile names the profile whose secrets the job gets, and the folder
	// it resolves from, exactly as a grant names one. Nil means no secrets.
	Profile *GrantProfile `json:"profile,omitempty"`
	Ask     string        `json:"ask,omitempty"`
	// Shown lists variables whose values may appear in the output.
	Shown   []string `json:"shown,omitempty"`
	Outputs []string `json:"outputs,omitempty"`
	// PathEnv and Home are the approving shell's, captured so the service
	// (which runs with launchd's environment) runs the command the way it
	// ran when the human read it.
	PathEnv     string `json:"path_env"`
	Home        string `json:"home"`
	Description string `json:"description,omitempty"`
	// Replace approves a job over an existing one of the same name: how a
	// job that changed is approved again.
	Replace bool `json:"replace,omitempty"`
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
	// OpSubscribe is the one streaming op: the agent answers with a single
	// Response{OK: true} line and then keeps the connection open, writing one
	// SessionEvent JSON document per line as each is recorded (the same
	// events "history" returns, in the order they enter the ring), until the
	// client closes or the agent shuts down. It carries nothing "history"
	// does not — no new information, only no polling — and needs no unlock,
	// for the reason OpHistory gives. A subscriber that stops reading is
	// disconnected rather than buffered without bound (see subscribeBuffer);
	// it re-syncs with a "history" call, which is what `jit audit -f` and
	// the menu bar app do on reconnect.
	OpSubscribe = "subscribe"
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
	// see Server's grant fields). With GrantName set the tree is the caller's
	// own session root and the name narrows it — the shape that also covers
	// processes started after creation. OpGrantExtend re-prompts for more time on an
	// existing grant; OpGrantRevoke ends one with no prompt at all (reducing
	// access is always free); OpGrantList reads the current set, prompt-free
	// for the same reason OpHistory is.
	OpGrantCreate = "grant_create"
	OpGrantList   = "grant_list"
	OpGrantRevoke = "grant_revoke"
	OpGrantExtend = "grant_extend"
	// OpConsentList and OpConsentAnswer are consent brokering
	// (consentbroker.go): a subscriber that set Request.Broker is shown each
	// disclosed challenge as a KindPending event before its Touch ID appears,
	// and answers with a Decision. "consent_list" returns the requests waiting
	// right now (a broker that just connected re-syncs from it), prompt-free
	// for OpHistory's reason. An "allow" only lets the agent's own Touch ID
	// proceed; "deny" refuses without one. Neither op needs an unlock.
	OpConsentList   = "consent_list"
	OpConsentAnswer = "consent_answer"
	// OpAuditAppend hands the application audit log one finished invocation
	// for the agent to write, instead of the CLI appending to audit.jsonl
	// itself. It exists for callers that can REACH the agent but cannot write
	// its config directory — a sandboxed shell, where the direct append fails
	// with EPERM and the event is simply lost. Those are precisely the
	// invocations most worth having in the trail, and the alternative fix
	// (granting the sandbox write access to the vault root) buys the trail
	// back by handing the sandboxed process the rest of jit's state.
	//
	// Needs no unlock, for OpHistory's reason: recording that a command ran
	// must never itself raise a prompt.
	//
	// The agent RE-STAMPS the three fields the kernel vouches for — uid (the
	// peercred gate has already proved it), pid (the socket peer) and the
	// timestamp (its own clock, at receipt). Everything else is the caller's
	// account of itself, exactly as it was when the caller wrote the file
	// directly: this op is about reaching the log, not about trusting its
	// contents more than before. A same-uid process could always append
	// whatever it liked to a file it owned.
	OpAuditAppend = "audit_append"
	// OpJobAllow, OpJobList, OpJobRemove and OpJobRun are AI Jobs
	// (design/agent-jobs.md): a command the human approved, run BY THE
	// SERVICE for any caller that names it, with the output returned and the
	// secret values hidden in it. job_allow takes a disclosed Touch ID;
	// job_remove takes none (reducing access is always free); job_list is
	// prompt-free for OpHistory's reason; job_run asks each time unless the
	// job was approved to run without asking.
	OpJobAllow  = "job_allow"
	OpJobList   = "job_list"
	OpJobRemove = "job_remove"
	OpJobRun    = "job_run"
	// OpJobRequest is an agent PROPOSING a job (MCP request_job): the
	// service keeps it for the app to show, and creates nothing. Refused
	// when no app (broker) is connected, so the proposer can fall back to
	// printing the `jit job allow` line. OpJobProposals lists what waits;
	// OpJobDismiss drops one. Approving a proposal is an ordinary job_allow
	// carrying its ProposalID, under the ordinary Touch ID.
	OpJobRequest   = "job_request"
	OpJobProposals = "job_proposals"
	OpJobDismiss   = "job_dismiss"
	// OpJobPreview runs every check job_allow makes before its prompt and
	// reports what it resolved, without prompting or keeping anything: what
	// the app's New AI Job sheet shows before the human spends a Touch ID,
	// and what `jit job allow --dry-run` prints.
	OpJobPreview = "job_preview"
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
	// KindPending is a disclosed challenge waiting on a consent broker
	// (consentbroker.go): the same snapshot the status line's PendingUnlock
	// shows, with ConsentID set so it can be answered. Streamed to brokers
	// only and never recorded — the KindApproved or KindDenied that follows,
	// carrying the same ConsentID, is the durable half.
	KindPending = "pending"
	// KindServeStart is the first read of a new KindServe aggregate: the
	// same fields, Count 1, sent the moment a reader, mount and verdict
	// first meet. Streamed live to every subscriber and never recorded.
	// The KindServe event that closes the aggregate, carrying the full
	// Count, is the durable half.
	//
	// It exists because that durable half is late by design: serves
	// collapse over serveAuditWindow (an hour) before they are written, so
	// a lone decoy probe reaches the trail an hour after it happened. A
	// renderer that says "something just read a decoy" needs it now, and
	// the collapse must stay, because the trail it protects evicts
	// oldest-first. One notice per aggregate keeps the stream exactly as
	// bounded as the trail.
	KindServeStart = "serve_start"
	// KindJobProposal is an agent's job proposal, streamed to brokers only
	// (the app), with ConsentID carrying the proposal's id and Job its name.
	// The request itself is recorded in the trail as a use of job_request.
	KindJobProposal = "job_proposal"
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
	// KeyNote answers "grant_revoke" and "job_remove" when the grant or job
	// is gone but its key could not be deleted: from this copy of jit (a
	// Secure Enclave key, from a jit without the entitlement), or because
	// the delete failed, which it names. A sentence to show, so no one is
	// told the key was deleted. Empty otherwise.
	KeyNote string `json:"key_note,omitempty"`
	// Protocol is the answering agent's own socket-protocol revision (see
	// Protocol). Set on every response, so a client can check what the
	// running agent enforces before it sends a request whose safety depends
	// on that enforcement. Zero from any agent predating the field, which is
	// precisely the "too old to trust with this" signal.
	Protocol int `json:"protocol,omitempty"`
	// Data is the wrapped/unwrapped result for "wrap"/"unwrap".
	Data []byte `json:"data,omitempty"`
	// Unlocked and ExpiresInSeconds answer "status" (and are also set on
	// "unlock"/"lock" so a client can confirm the resulting state without
	// a second round trip).
	Unlocked         bool  `json:"unlocked,omitempty"`
	ExpiresInSeconds int64 `json:"expires_in_seconds,omitempty"`
	// CeilingInSeconds, TTLSeconds and ConsentEnabled answer "status" only,
	// for a client that renders the session rather than merely checking it
	// (the menu bar app, design/menu-bar-app.md). ExpiresInSeconds is the
	// nearer of the idle expiry and the hard ceiling, which is the right
	// single number for "locks in"; CeilingInSeconds is the ceiling on its
	// own, so a renderer can say "locks in 4:12, and no later than 17:58"
	// without re-deriving DefaultMaxSessionAge. Zero while locked, like
	// ExpiresInSeconds. TTLSeconds is the configured inactivity TTL, and
	// ConsentEnabled whether per-process consent gates credential classes —
	// both were previously only knowable from the launchd plist.
	CeilingInSeconds int64 `json:"ceiling_in_seconds,omitempty"`
	TTLSeconds       int64 `json:"ttl_seconds,omitempty"`
	ConsentEnabled   bool  `json:"consent_enabled,omitempty"`
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
	// Jobs answers job_allow (the one approved) and job_list.
	Jobs []JobStatus `json:"jobs,omitempty"`
	// JobResult answers job_run.
	JobResult *JobResult `json:"job_result,omitempty"`
	// Proposals answers job_proposals, and job_request with the one kept.
	Proposals []JobProposal `json:"proposals,omitempty"`
	// Preview answers job_preview.
	Preview *JobPreview `json:"preview,omitempty"`
}

// GrantStatus is one process grant as the agent reports it — deliberately
// plain strings/ints like every other wire type here. Name and Command are
// GrantProfile names one profile a grant covers and the folder it is read
// from: Root is the project directory whose .jit/profiles holds the manifest
// (or "" for the global store), exactly the root profile.Load takes. Names
// and folders only, never secrets or paths — the agent resolves them.
type GrantProfile struct {
	Name string `json:"name"`
	Root string `json:"root,omitempty"`
}

// JobStatus is one AI job as a client renders it. It carries no value and no
// wrapped key, only names and state.
type JobStatus struct {
	Name    string   `json:"name"`
	Dir     string   `json:"dir"`
	Argv    []string `json:"argv"`
	Exe     string   `json:"exe"`
	Profile string   `json:"profile,omitempty"`
	// ProfileGlobal says Profile is read from ~/.jit/profiles rather than
	// the job's folder, so a client approving the job again (an edit, a
	// stopped job) can send the same GrantProfile the job was made from.
	ProfileGlobal bool `json:"profile_global,omitempty"`
	// ProfileRoot is the folder the profile is read from when it is not
	// global. It differs from Dir when the job runs in a folder inside the
	// profile's project.
	ProfileRoot string            `json:"profile_root,omitempty"`
	Secrets     []JobSecretStatus `json:"secrets,omitempty"`
	Ask         string            `json:"ask"`
	Outputs     []string          `json:"outputs,omitempty"`
	Description string            `json:"description,omitempty"`
	Files       int               `json:"files"`
	// State is JobReady, JobChanged or JobRotated; Changes names what
	// changed, capped at maxJobChanges.
	State        string       `json:"state"`
	Changes      []job.Change `json:"changes,omitempty"`
	ApprovedUnix int64        `json:"approved_unix"`
	Runs         int64        `json:"runs,omitempty"`
	LastRunUnix  int64        `json:"last_run_unix,omitempty"`
	LastExit     int          `json:"last_exit,omitempty"`
	LastCaller   string       `json:"last_caller,omitempty"`
	LastRefusal  string       `json:"last_refusal,omitempty"`
	LastHidden   int          `json:"last_hidden,omitempty"`
	// Stopped says the job won't run until it is approved again: it was
	// stopped, or a check that stops it (a changed file, a rotated secret)
	// already fails. Always present, so a client never infers it from
	// State or LastRefusal's words.
	Stopped bool `json:"stopped"`
	// Outcome is where the job stands, in SessionEvent.JobOutcome's words:
	// JobOutcomeStop when Stopped; else JobOutcomePersistingSkip once a
	// streak of skipped runs has been told; else JobOutcomeSkip while one
	// is on; empty for a job that runs.
	Outcome string `json:"outcome,omitempty"`
	// Skips is how many runs in a row were skipped (JobOutcomeSkip), and
	// SkippingSinceUnix when the first of them was; zero once a run runs.
	Skips             int   `json:"skips,omitempty"`
	SkippingSinceUnix int64 `json:"skipping_since_unix,omitempty"`
}

// JobPreview is what approving a job WOULD do, from the same checks
// job_allow runs before its prompt. Refusal, when set, is approval's own
// reason, word for word; nothing else is meaningful then.
type JobPreview struct {
	Refusal string            `json:"refusal,omitempty"`
	Dir     string            `json:"dir,omitempty"`
	Exe     string            `json:"exe,omitempty"`
	Program string            `json:"program,omitempty"`
	Files   int               `json:"files,omitempty"`
	Extra   []string          `json:"extra,omitempty"`
	Secrets []JobSecretStatus `json:"secrets,omitempty"`
	Ask     string            `json:"ask,omitempty"`
	// Exists says approving would replace a job of the same name.
	Exists bool `json:"exists,omitempty"`
	// Prompt is the Touch ID sentence approval will show, exactly.
	Prompt string `json:"prompt,omitempty"`
}

// JobProposal is a job an agent proposed and the human has not answered.
// Nothing in it has been resolved or approved: the app shows it, and the
// human's own job_allow is what resolves, fingerprints and prompts.
type JobProposal struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Spec       JobSpec `json:"spec"`
	Why        string  `json:"why,omitempty"`
	By         string  `json:"by,omitempty"`
	LaunchedBy string  `json:"launched_by,omitempty"`
	UnixTime   int64   `json:"unix_time"`
}

// JobSecretStatus is one secret a job injects: its variable and vault path,
// whether its value may appear in output, and whether it was rotated since
// approval (which stops the job).
type JobSecretStatus struct {
	Var     string `json:"var"`
	Path    string `json:"path"`
	Shown   bool   `json:"shown,omitempty"`
	Rotated bool   `json:"rotated,omitempty"`
}

// JobStatus.State values.
const (
	JobReady   = "ready"
	JobChanged = "changed"
	JobRotated = "rotated"
)

// JobResult is one run's outcome as the caller receives it. Stdout and Stderr
// have every hidden value replaced with [hidden: NAME] before they leave the
// service; Hidden counts the replacements.
type JobResult struct {
	Exit       int            `json:"exit"`
	Stdout     string         `json:"stdout"`
	Stderr     string         `json:"stderr"`
	Truncated  bool           `json:"truncated,omitempty"`
	TimedOut   bool           `json:"timed_out,omitempty"`
	DurationMS int64          `json:"duration_ms"`
	Hidden     map[string]int `json:"hidden,omitempty"`
	// NewFiles are files created or changed under the job's outputs, as
	// absolute paths. Paths only: the caller is never handed their contents.
	NewFiles []string `json:"new_files,omitempty"`
	// Notes are facts the caller should repeat, e.g. a value too short to hide.
	Notes []string `json:"notes,omitempty"`
}

// kernel-derived at grant creation (internal/lineage), never caller-reported,
// matching MountGrantStatus's convention.
type GrantStatus struct {
	ID  string `json:"id"`
	PID int32  `json:"pid"`
	// Name is what the grant covers: the root process's display name for an
	// exact-process grant ("claude"), or the name filter for a tree-scoped
	// one (also "claude" — the list reads the same either way). Command is
	// the root's full invocation for a wide terminal.
	Name    string `json:"name,omitempty"`
	Command string `json:"command,omitempty"`
	// Anchor is set on tree-scoped grants only: the display name of the
	// session root the grant is anchored under ("iTerm2", "tmux_server"),
	// whose pid is PID. Empty means an exact-process grant.
	Anchor string `json:"anchor,omitempty"`
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
	// For a standing grant it reports whether the anchor app is running
	// right now: informational, since the grant outlives it.
	RootAlive bool `json:"root_alive"`
	// Standing marks a grant with no deadline (design/standing-grants.md).
	// ExpiresUnix is zero, PID is zero (there is no anchored process: the
	// anchor is AnchorPath, matched by executable on every serve), and it
	// ends only on revoke.
	Standing bool `json:"standing,omitempty"`
	// AnchorPath is a standing grant's anchor: the executable path of the
	// app the covered program must run under ("/Applications/iTerm.app/
	// Contents/MacOS/iTerm2"). Anchor carries its display name.
	AnchorPath string `json:"anchor_path,omitempty"`
	// ProfileRoots is Profiles with each name's folder, so a listing can
	// tell two same-named profiles apart. Empty for grants created before
	// the field existed.
	ProfileRoots []GrantProfile `json:"profile_roots,omitempty"`
	// Rotated lists the covered vault paths whose secret has changed since
	// the grant was made (standing grants only, checked at list time). A
	// rotated secret is not served — its wrapped bytes no longer match —
	// so the caller prompts for it as if there were no grant; this is what
	// lets the list say so instead of leaving a silent gap.
	Rotated []string `json:"rotated,omitempty"`
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
	// By is the caller's full command line as the kernel reports it — with
	// any secret the caller carried on it masked (caller.command routes argv
	// through auditlog.RedactCommandLine before a By ever exists) — and
	// ByPID its pid: the "what asked for this", for a terminal wide enough
	// to print it. The Touch ID prompt gets a much shorter phrasing (see
	// challengeReason); this is the investigative version, durable in
	// agent-history.jsonl, which is exactly why it must never hold a
	// plaintext secret.
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
	// Undelivered, on serve events, marks a cycle whose reader received
	// NOTHING: the write hit EPIPE, proof that zero processes held the read
	// end by the time content was sent. The verdict (Op) still records what
	// WOULD have been served — but a touch-and-go reader (a backup tool, an
	// indexer, a VM file-sharing sweep) that opens and closes without
	// reading used to be logged as "decoy served", overstating exposure.
	// False (the default, and the value on every event from before this
	// field) means content reached the pipe with a reader attached.
	Undelivered bool `json:"undelivered,omitempty"`
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
	// ConsentID links a brokered challenge's events: set on the KindPending
	// request a broker is shown and on the KindApproved/KindDenied outcome
	// that answers it, so a renderer can close the one with the other.
	// Empty on every challenge that went straight to the screen.
	ConsentID string `json:"consent_id,omitempty"`
	// Job names the AI job a job_allow or job_run event is about, so a broker
	// rendering the pending request can show that job's command, folder and
	// secrets from job_list (design/agent-jobs.md, step 4). Empty otherwise.
	Job string `json:"job,omitempty"`
	// JobOutcome, on a job_run event whose run did not happen, says what
	// that means for the job, so a client decides from this and never from
	// Cause's words: JobOutcomeStop, JobOutcomeStillStopped, JobOutcomeSkip
	// or JobOutcomePersistingSkip. Empty on every other event.
	JobOutcome string `json:"job_outcome,omitempty"`
}

// The job outcomes (SessionEvent.JobOutcome, JobStatus.Outcome).
const (
	// JobOutcomeStop: this run stopped the job. It won't run until it is
	// approved again. The one to announce.
	JobOutcomeStop = "stop"
	// JobOutcomeStillStopped: a run of a job already stopped was refused.
	// Nothing new: the stop was announced when it happened.
	JobOutcomeStillStopped = "still-stopped"
	// JobOutcomeSkip: this run didn't happen for a cause outside the job
	// (its key couldn't be used right now). NOT a stop: the next run tries
	// again. Not worth an announcement on its own.
	JobOutcomeSkip = "skip"
	// JobOutcomePersistingSkip: a skip that has gone on (jobSkipsToTell in a
	// row, or jobSkipTimeToTell since the first), recorded once per streak.
	// Still not a stop, but worth announcing: the owner should learn the
	// job hasn't been running.
	JobOutcomePersistingSkip = "persisting-skip"
)

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
	// Undelivered marks a cycle whose reader received nothing (the write
	// hit EPIPE — zero readers held the pipe). Decoy still records the
	// verdict that was decided; this records that it never arrived.
	Undelivered bool `json:"undelivered,omitempty"`
}
