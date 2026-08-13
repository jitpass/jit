// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

// ErrNotRunning marks a dial failure: nothing answered the agent socket at
// all. Wrapped into every Client method's connect error so a caller can
// tell "no agent" (an expected state, usually deserving a friendly install
// hint) from a real RPC failure with errors.Is — WITHOUT pre-flighting via
// Reachable(), which costs a second dial per command just to learn what
// the real call was about to report anyway.
var ErrNotRunning = errors.New("agent is not running")

// ErrPromptUnanswered is a bounded-wait client giving up on a call that was
// almost certainly sitting behind a human-in-the-loop prompt (session unlock,
// per-process consent) that no human was there to answer. Only a client
// configured via WithResponseTimeout returns it; the default client waits out
// the challenge's own ceiling instead.
var ErrPromptUnanswered = errors.New("approval prompt not answered")

// dialTimeout bounds only "is an agent even listening" — fast, since a
// closed/nonexistent socket fails near-instantly either way.
//
// responseTimeout bounds waiting for an actual reply, and has to be
// generous: a wrap/unwrap/unlock request can legitimately sit behind an
// in-progress Touch ID/passcode challenge (kw_challenge waits up to 120s
// for a human response — see internal/keychainwrap/keychain.m), and
// Server.ensureUnlocked holds its lock for the whole challenge, so even a
// concurrent status/lock request queues behind it. A real run surfaced
// exactly this: a 5-second response timeout gave up on a wrap request (and
// the unlock request queued right behind it) while the user was still in
// the middle of approving Touch ID — the underlying unlock succeeded a
// moment later, but both callers had already reported a spurious timeout
// error. responseTimeout must clear the challenge's own ceiling with room
// to spare, not just be "generous."
const (
	dialTimeout     = 5 * time.Second
	responseTimeout = 130 * time.Second
)

// Client talks to a running Server over its Unix socket. Implements
// vault.KeyWrapper and vault.LabeledKeyWrapper (structurally — this
// package doesn't import internal/vault) so other jit commands can reuse
// an already-unlocked agent's session instead of prompting for their own
// independent Touch ID challenge.
type Client struct {
	socketPath  string
	dialRetry   time.Duration
	waitNotify  func()
	respTimeout time.Duration
	// bounded records that respTimeout was deliberately shortened below the
	// challenge ceiling (WithResponseTimeout), which changes what a timeout
	// MEANS: not a stuck agent, but a prompt nobody was present to answer.
	bounded bool
}

// NewClient returns a Client for the agent socket at socketPath.
func NewClient(socketPath string) *Client {
	return &Client{socketPath: socketPath, respTimeout: responseTimeout}
}

// WithResponseTimeout lowers how long a call may sit unanswered before the
// client gives up, and marks the resulting timeout as ErrPromptUnanswered.
//
// It exists for launches where no human can see (or answer) an approval
// prompt: an MCP host starting a jit-wrapped server at login, a launchd job,
// a shim invoked from a script. The default 130s clears the Touch ID
// challenge ceiling on purpose — right when someone is at the keyboard, and
// exactly wrong headless, where it reads as a silent hang that an MCP host's
// own ~30s startup timeout then kills mid-handshake with no explanation. A
// bounded client fails first, with a message that names the actual problem.
//
// The server-side challenge is NOT cancelled by the client giving up; it
// runs to its own ceiling. That is deliberate: approving the dialog after
// this client has exited still unlocks the session, so the very next
// launch succeeds without prompting again.
func (c *Client) WithResponseTimeout(d time.Duration) *Client {
	if d > 0 && d < responseTimeout {
		c.respTimeout = d
		c.bounded = true
	}
	return c
}

// waitNotifyDelay is how long a single RPC may sit unanswered before we
// conclude the agent is blocked on a human-in-the-loop Touch ID/passcode
// prompt and fire the wait notifier. A cached wrap/unwrap/unlock returns
// over the local socket in well under this; the only thing that makes a
// call take longer is a person standing at the OS prompt. High enough that
// an ordinarily-not-instant reply on a loaded machine won't false-fire,
// low enough to beat a human reading the terminal.
const waitNotifyDelay = 400 * time.Millisecond

// WithWaitNotifier registers a callback fired (at most once per RPC, from a
// timer goroutine) when a call has been blocked for waitNotifyDelay — i.e.
// the agent is almost certainly sitting on a Touch ID/passcode prompt right
// now. It exists to answer the one question a surprise prompt raises from a
// silently-hung terminal: "why did my command stop?" The notifier never
// fires when the reply comes back promptly (no prompt appeared), so it can't
// lie about a challenge that isn't happening. Returns c for chaining.
func (c *Client) WithWaitNotifier(fn func()) *Client {
	c.waitNotify = fn
	return c
}

// WithDialRetry makes this Client keep retrying a failed dial for up to d
// before concluding ErrNotRunning — for callers that KNOW an agent is
// supposed to be there (the launchd plist is installed), where a dial
// failure is usually the 1–2s respawn gap of `jit agent restart` or the
// agent's own stale-binary self-retirement, not a missing agent. Without
// it, a `jit run` landing in that gap silently falls back to an
// independent Touch ID prompt — a surprise prompt caused by the agent's
// own restart. Callers with no such knowledge should not set it: an
// uninstalled agent would just cost every command d of pointless waiting.
// Returns c for chaining.
func (c *Client) WithDialRetry(d time.Duration) *Client {
	c.dialRetry = d
	return c
}

// dialRetryInterval paces WithDialRetry's re-dials. 100ms matches the
// poll the CLI's own install/restart wait uses; a respawning agent binds
// its socket within a couple of these.
const dialRetryInterval = 100 * time.Millisecond

// Reachable reports whether an agent is listening at all — used to decide
// between using the agent's shared session and falling back to an
// independent unlock when no agent is running. Honors WithDialRetry, so a
// caller that knows the agent is installed keeps that decision stable
// across the agent's own restart gap.
func (c *Client) Reachable() bool {
	conn, err := c.dial()
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// dial connects to the agent socket, retrying for up to dialRetry (see
// WithDialRetry) when set.
func (c *Client) dial() (net.Conn, error) {
	conn, err := net.DialTimeout("unix", c.socketPath, dialTimeout)
	if err == nil || c.dialRetry <= 0 {
		return conn, err
	}
	deadline := time.Now().Add(c.dialRetry)
	for time.Now().Before(deadline) {
		time.Sleep(dialRetryInterval)
		conn, err = net.DialTimeout("unix", c.socketPath, dialTimeout)
		if err == nil {
			return conn, nil
		}
	}
	return nil, err
}

func (c *Client) call(req Request) (Response, error) {
	conn, err := c.dial()
	if err != nil {
		return Response{}, fmt.Errorf("connecting to agent: %w: %v", ErrNotRunning, err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(c.respTimeout)); err != nil {
		return Response{}, fmt.Errorf("setting deadline: %w", err)
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return Response{}, fmt.Errorf("sending request: %w", err)
	}
	// A reply that doesn't come back within waitNotifyDelay almost always
	// means the agent is blocked on a Touch ID/passcode prompt (see the
	// const): fire the notifier so a hung terminal can explain itself. The
	// timer is cancelled the moment Decode returns, so a prompt-free call
	// that just happens to be quick still never notifies.
	if c.waitNotify != nil {
		t := time.AfterFunc(waitNotifyDelay, c.waitNotify)
		defer t.Stop()
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		if c.bounded && errors.Is(err, os.ErrDeadlineExceeded) {
			return Response{}, fmt.Errorf(
				"%w within %s: the service is most likely waiting on a Touch ID/consent prompt, and this launch has no terminal for anyone to see it from. Run `jit unlock` in a terminal (or approve the prompt still on screen), then relaunch",
				ErrPromptUnanswered, c.respTimeout)
		}
		return Response{}, fmt.Errorf("reading response: %w", err)
	}
	if !resp.OK {
		return Response{}, fmt.Errorf("agent: %s", resp.Error)
	}
	return resp, nil
}

// WrapKey implements vault.KeyWrapper by asking the agent to wrap dek
// using its cached MEK — challenging (Touch ID/passcode) first if the
// agent's session is currently locked.
func (c *Client) WrapKey(dek []byte) ([]byte, error) {
	return c.WrapKeyLabeled(dek, "", "")
}

// UnwrapKey implements vault.KeyWrapper.
func (c *Client) UnwrapKey(wrapped []byte) ([]byte, error) {
	return c.UnwrapKeyLabeled(wrapped, "", "")
}

// WrapKeyLabeled implements vault.LabeledKeyWrapper: WrapKey plus the
// vault path of the secret whose DEK this is, sent as Request.Label so
// the agent's history can say WHAT was stored/read, not just who asked —
// the one provenance fact the agent cannot learn from the kernel, since
// it only ever sees opaque key bytes. Audit-only on the agent side, and
// recorded there as caller-reported (see Request.Label).
func (c *Client) WrapKeyLabeled(dek []byte, label, class string) ([]byte, error) {
	resp, err := c.call(Request{Op: OpWrap, Data: dek, Label: label, Class: class})
	if err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// UnwrapKeyLabeled implements vault.LabeledKeyWrapper — see WrapKeyLabeled.
func (c *Client) UnwrapKeyLabeled(wrapped []byte, label, class string) ([]byte, error) {
	resp, err := c.call(Request{Op: OpUnwrap, Data: wrapped, Label: label, Class: class})
	if err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// Trust registers this process (the kernel-identified peer pid) as a consent
// trust root: any credential a process in this run's tree reaches for is then
// auto-allowed without a per-process consent prompt. Used by `jit run
// --trust`. Best-effort — a failure just means the run prompts per credential
// as usual, so callers proceed regardless.
func (c *Client) Trust() error {
	_, err := c.call(Request{Op: OpTrust})
	return err
}

// Unlock asks the agent to unlock now (challenging if not already
// unlocked), so a caller can pre-warm the session before running several
// commands in a row that would otherwise each trigger their own prompt.
func (c *Client) Unlock() (unlocked bool, remaining time.Duration, err error) {
	resp, err := c.call(Request{Op: OpUnlock})
	if err != nil {
		return false, 0, err
	}
	return resp.Unlocked, time.Duration(resp.ExpiresInSeconds) * time.Second, nil
}

// Lock asks the agent to drop its cached MEK immediately, without waiting
// for the TTL — for a user stepping away from their desk right now.
func (c *Client) Lock() error {
	_, err := c.call(Request{Op: OpLock})
	return err
}

// Refresh asks the agent to notice any newly-registered mount right now,
// ensuring the session is unlocked first — for a caller (jit migrate)
// that just added a mount and needs it served immediately rather than
// waiting for the next full lock/unlock cycle.
func (c *Client) Refresh() error {
	_, err := c.call(Request{Op: OpRefresh})
	return err
}

// RevealForPID asks the agent to serve real content on each of mountPaths
// to pid's process tree for as long as that process lives (ensuring the
// session is unlocked first, challenging if needed). jit run calls this
// with its OWN pid immediately before execve — which keeps the pid — so
// the grant lands on exactly the command being run. Matching readers to
// the tree, fail-closed gating, and teardown (target exit, lock, hard cap)
// are all agent-side; Client makes no assumptions about any of them.
func (c *Client) RevealForPID(mountPaths []string, pid int32) error {
	return c.RunForPID(RunMounts(mountPaths, MountModeGrant), pid)
}

// SwapForPID is RevealForPID's compatibility-swap variant (the jit run
// default): for pid's lifetime, each mount becomes a regular comment-only
// pointer file instead of the decoy FIFO, so regular-file guards pass and
// re-reads parse to nothing. Same lifecycle and teardown as a grant; the
// difference is what the mount IS during the run.
func (c *Client) SwapForPID(mountPaths []string, pid int32) error {
	return c.RunForPID(RunMounts(mountPaths, MountModeSwap), pid)
}

// RunForPID is the general form: attach pid's process tree to a set of
// mounts, each in its own mode (swap or grant), for the run's lifetime.
// One call can mix modes — swap the project .env while granting its .npmrc.
func (c *Client) RunForPID(mounts []RunMount, pid int32) error {
	_, err := c.call(Request{Op: OpRevealPID, RunMounts: mounts, TargetPID: pid})
	return err
}

// GrantGlobalForPID grants pid's process tree a set of GLOBAL, file-delivered
// mounts (jit run --with), gated by a fresh disclosed challenge — even when
// the session is already unlocked. A declined challenge returns an error; the
// caller drops just these global mounts and lets the rest of the run proceed.
// Sent as its own call so a decline never takes the run's ordinary .env swap
// down with it.
//
// It deliberately sends no wording for that challenge. The agent derives what
// the prompt says from the mounts themselves, because a prompt authorizing a
// machine-wide credential must not be phrased by the process asking for it —
// and "the process asking" is only ever `jit run` when nothing malicious is
// on the machine.
func (c *Client) GrantGlobalForPID(mounts []RunMount, pid int32) error {
	_, err := c.call(Request{Op: OpRevealPID, RunMounts: mounts, TargetPID: pid, Disclose: true})
	return err
}

// GrantCreate asks the agent to create a process grant: after one disclosed
// challenge (agent-worded, like every prompt), pid's process tree may unwrap
// the named profiles' secrets until now+ttl, unattended, across re-locks.
// With name set the grant is tree-scoped: pid must be the caller's own
// session root (the agent verifies the ancestry) and name narrows which of
// its descendants — current and future — are served. The client sends
// profile NAMES and its project root only — the agent resolves them to
// concrete secrets itself, so the prompt and the granted set cannot disagree
// (see Server.OnResolveGrant). Returns the created grant's status for
// rendering.
func (c *Client) GrantCreate(pid int32, name string, profiles []string, projectRoot string, ttl time.Duration) (GrantStatus, error) {
	resp, err := c.call(Request{
		Op:            OpGrantCreate,
		TargetPID:     pid,
		GrantName:     name,
		GrantProfiles: profiles,
		ProjectRoot:   projectRoot,
		TTLSeconds:    int64(ttl / time.Second),
	})
	if err != nil {
		return GrantStatus{}, err
	}
	if len(resp.Grants) != 1 {
		return GrantStatus{}, fmt.Errorf("agent: grant created but not reported back")
	}
	return resp.Grants[0], nil
}

// GrantList reads the live process grants — prompt-free, like History.
func (c *Client) GrantList() ([]GrantStatus, error) {
	resp, err := c.call(Request{Op: OpGrantList})
	if err != nil {
		return nil, err
	}
	return resp.Grants, nil
}

// GrantRevoke ends a grant now. No challenge, by design: reducing access is
// always free, and the kill switch must be the easiest thing in the feature.
func (c *Client) GrantRevoke(id string) error {
	_, err := c.call(Request{Op: OpGrantRevoke, GrantID: id})
	return err
}

// GrantExtend moves a grant's deadline to now+ttl, behind a fresh disclosed
// challenge — more time is a new decision.
func (c *Client) GrantExtend(id string, ttl time.Duration) (GrantStatus, error) {
	resp, err := c.call(Request{Op: OpGrantExtend, GrantID: id, TTLSeconds: int64(ttl / time.Second)})
	if err != nil {
		return GrantStatus{}, err
	}
	if len(resp.Grants) != 1 {
		return GrantStatus{}, fmt.Errorf("agent: grant extended but not reported back")
	}
	return resp.Grants[0], nil
}

// RunMounts labels each of paths with a single mode — the common shape when
// every mount in a group shares one treatment (all grants, or all swaps).
// One helper so the paths->[]RunMount transform lives in exactly one place.
func RunMounts(paths []string, mode string) []RunMount {
	out := make([]RunMount, len(paths))
	for i, p := range paths {
		out[i] = RunMount{Path: p, Mode: mode}
	}
	return out
}

// StopMount asks the agent to stop serving mountPath specifically —
// unlike Lock, every other mount keeps being served undisturbed. `jit
// unmount` uses this right before physically replacing the FIFO with a
// regular file, so nothing races that swap (GAPS.md #35's per-mount
// stop, replacing the old "lock the whole agent first" workaround).
// Works even while the agent is locked — stopping a mount needs no
// vault access at all.
func (c *Client) StopMount(mountPath string) error {
	_, err := c.call(Request{Op: OpStopMount, MountPath: mountPath})
	return err
}

// Status is everything the agent can say about itself in one round trip.
//
// A struct rather than the return tuple this used to be: the tuple had
// reached five values, callers were writing `unlocked, _, _, _, err :=` to
// reach past the ones they didn't want, and the two provenance fields below
// would have made it seven. Named fields also let a caller take only what it
// needs without silently depending on positional order.
type Status struct {
	Unlocked bool
	// Remaining is how long until the idle auto-lock, zero when locked.
	Remaining time.Duration
	// Mounts is every currently-served mount's reveal state (GAPS.md #37) —
	// "is X revealed, and for how long" used to have no answer anywhere short
	// of reading mountManager's in-process state directly, which a separate
	// `jit status` invocation can't do.
	Mounts []MountRevealStatus
	// LastUnlock and LastLock are who moved the session to its current state,
	// and why (GAPS.md #75). Nil until this agent process has actually
	// unlocked (or locked) once.
	LastUnlock *SessionEvent
	LastLock   *SessionEvent
	// PendingUnlock is the challenge currently on the user's screen (nil
	// when none): who triggered it and when the prompt appeared. The
	// answer to "why is there a Touch ID prompt right now?", available
	// while it's still being asked.
	PendingUnlock *SessionEvent
	// Build is the agent process's own BuildID (GAPS.md #49), for the caller
	// to compare against its own and notice a stale, launchd-kept-alive agent
	// that predates the binary on disk.
	Build string
	// Version is the agent process's own Version() — the release-scale
	// counterpart to Build. Empty when the agent predates the field.
	Version string
	// ExecutablePath is the agent process's own binary path. See
	// Response.ExecutablePath: it answers the question Build and Version
	// cannot, which is whether that binary still exists. Empty when the
	// agent predates the field.
	ExecutablePath string
}

// History asks for every unlock and lock the agent knows of, newest first
// — the running process's own events plus what it was seeded with from the
// durable history file (SeedHistory), so the answer survives the launchd
// restarts that happen at every login. Bounded by MaxSessionEvents; agent
// restarts appear as "start" events.
//
// Never triggers a challenge — asking why you keep being prompted must not
// prompt you.
func (c *Client) History() ([]SessionEvent, error) {
	resp, err := c.call(Request{Op: OpHistory})
	if err != nil {
		return nil, err
	}
	return resp.Events, nil
}

// Status asks the running agent for that snapshot.
func (c *Client) Status() (Status, error) {
	resp, err := c.call(Request{Op: OpStatus})
	if err != nil {
		return Status{}, err
	}
	return Status{
		Unlocked:       resp.Unlocked,
		Remaining:      time.Duration(resp.ExpiresInSeconds) * time.Second,
		Mounts:         resp.Mounts,
		LastUnlock:     resp.LastUnlock,
		LastLock:       resp.LastLock,
		PendingUnlock:  resp.PendingUnlock,
		Build:          resp.Build,
		Version:        resp.Version,
		ExecutablePath: resp.ExecutablePath,
	}, nil
}
