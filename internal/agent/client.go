// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"
)

// ErrNotRunning marks a dial failure: nothing answered the agent socket at
// all. Wrapped into every Client method's connect error so a caller can
// tell "no agent" (an expected state, usually deserving a friendly install
// hint) from a real RPC failure with errors.Is — WITHOUT pre-flighting via
// Reachable(), which costs a second dial per command just to learn what
// the real call was about to report anyway.
var ErrNotRunning = errors.New("agent is not running")

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
// vault.KeyWrapper (structurally — this package doesn't import
// internal/vault) so other jit commands can reuse an already-unlocked
// agent's session instead of prompting for their own independent Touch ID
// challenge.
type Client struct {
	socketPath string
}

// NewClient returns a Client for the agent socket at socketPath.
func NewClient(socketPath string) *Client {
	return &Client{socketPath: socketPath}
}

// Reachable reports whether an agent is listening at all — used to decide
// between using the agent's shared session and falling back to an
// independent unlock when no agent is running.
func (c *Client) Reachable() bool {
	conn, err := net.DialTimeout("unix", c.socketPath, dialTimeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (c *Client) call(req Request) (Response, error) {
	conn, err := net.DialTimeout("unix", c.socketPath, dialTimeout)
	if err != nil {
		return Response{}, fmt.Errorf("connecting to agent: %w: %v", ErrNotRunning, err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(responseTimeout)); err != nil {
		return Response{}, fmt.Errorf("setting deadline: %w", err)
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return Response{}, fmt.Errorf("sending request: %w", err)
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
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
	resp, err := c.call(Request{Op: OpWrap, Data: dek})
	if err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// UnwrapKey implements vault.KeyWrapper.
func (c *Client) UnwrapKey(wrapped []byte) ([]byte, error) {
	resp, err := c.call(Request{Op: OpUnwrap, Data: wrapped})
	if err != nil {
		return nil, err
	}
	return resp.Data, nil
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

// Reveal asks the agent to serve mountPath's real content for the next
// duration (ensuring the session is unlocked first, challenging if
// needed) — the explicit half of GAPS.md #2's decoy-by-default gate,
// alongside the automatic post-unlock reveal window OnUnlock/OnRefresh
// trigger. The agent-side handler (internal/cli/agent.go's mountManager)
// clamps duration to a maximum; Client makes no assumption about what
// that maximum is.
func (c *Client) Reveal(mountPath string, duration time.Duration) error {
	_, err := c.call(Request{Op: OpReveal, MountPath: mountPath, RevealSeconds: int64(duration.Seconds())})
	return err
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
		Unlocked:      resp.Unlocked,
		Remaining:     time.Duration(resp.ExpiresInSeconds) * time.Second,
		Mounts:        resp.Mounts,
		LastUnlock:    resp.LastUnlock,
		LastLock:      resp.LastLock,
		PendingUnlock: resp.PendingUnlock,
		Build:         resp.Build,
		Version:       resp.Version,
	}, nil
}
