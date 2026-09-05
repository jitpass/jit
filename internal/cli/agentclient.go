// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"golang.org/x/term"

	"github.com/jitpass/jit/internal/agent"
)

// This file is how every OTHER command reaches the service: the configured
// client (dial retry across a restart gap, the Touch ID wait notifier, the
// bounded wait a headless launch needs) and the single source of what to SAY
// when it cannot be reached.
//
// That single-sourcing is load-bearing. The installed-but-not-running advice
// appears on `jit status`, `jit service status`, `jit doctor`, migrate's
// trailer and every dial-failure hint; it drifted once when a change to what
// restart recovers updated only one of them. It is also the wording the
// 2026-08-17 incident proved wrong on both halves ("may have crashed or be
// mid-restart" for a job launchd had simply never started), which is why the
// state it describes now comes from launchd's own job record.

// agentRestartGrace is how long a dial keeps retrying when the service is
// INSTALLED but not answering — the launchd respawn gap of `jit service
// restart` or the service's own stale-binary self-retirement, observed at
// 1–2s. Only applied when the plist exists (see agentClient): when it
// doesn't, "not answering" means "not installed" and waiting is pure
// delay.
const agentRestartGrace = 2 * time.Second

// agentClient returns a Client for this machine's agent socket without
// probing it first — Client's own calls wrap agent.ErrNotRunning when
// nothing is listening (see notRunningHint), so a Reachable() pre-flight
// would just dial the socket twice per command. When the service is
// installed, the client rides out launchd's respawn gap (see
// agentRestartGrace) instead of misreporting a restarting agent as absent.
// SessionUnlocked reports whether the service is up with an unlocked session,
// prompt-free and without the restart-grace dial retry agentClient adds —
// main.go asks this on a shim's completion invocation to decide between the
// wrapped path and wrap.ShimExecReal, and a TAB press cannot wait out a
// restart gap the way a typed command can. Any failure to answer is "locked":
// the caller's fallback (complete unwrapped) is the one that can never raise
// a prompt, so uncertainty must land there.
func SessionUnlocked() bool {
	root, err := vaultRootDir()
	if err != nil {
		return false
	}
	st, err := agent.NewClient(agent.SocketPath(root)).Status()
	return err == nil && st.Unlocked
}

func agentClient() (*agent.Client, error) {
	return configuredAgentClient(true)
}

// agentClientNoHeal is agentClient for the surfaces that must never SPAWN
// the service as a side effect of asking about it: the health reporters
// (`jit service status`) and the session reducers (`jit lock`, rekey's
// lock bracket). A reporter that quietly revived what it was reporting on
// would erase the very state its advice describes, and locking a service
// that isn't running means the goal — no session — is already true; a
// demand-start there trades an honest "already locked" for a pointless
// spawn. Everything that NEEDS the broker up takes agentClient and heals.
func agentClientNoHeal() (*agent.Client, error) {
	return configuredAgentClient(false)
}

func configuredAgentClient(heal bool) (*agent.Client, error) {
	root, err := vaultRootDir()
	if err != nil {
		return nil, err
	}
	c := agent.NewClient(agent.SocketPath(root))
	if agentInstalled() {
		c = c.WithDialRetry(agentRestartGrace)
		if heal {
			c = c.WithDialFailedHook(healDeadService)
		}
	}
	c = c.WithWaitNotifier(announceTouchIDWait)
	// A LAUNCH with no terminal on stderr is one where nobody can see the
	// wait notice above, let alone the OS prompt behind it — an MCP host
	// starting a wrapped server at login, a launchd job, a shim inside a
	// script. There the default 130s (sized to clear the Touch ID ceiling
	// for someone AT the keyboard) is a silent hang that the MCP host's own
	// ~30s startup timeout kills mid-handshake first, blaming the server.
	// Bounded, jit fails before the host does, and the message that lands in
	// the host's captured-stderr log names the real problem and the fix.
	//
	// stderr, not stdin/stdout: those are pipes in an ordinary terminal
	// pipeline (`jit run ... | grep`) where the user IS present and the full
	// wait is right. stderr-is-a-TTY is precisely "a human can see jit's
	// explanation of the pause."
	if boundedPromptWait && !term.IsTerminal(int(os.Stderr.Fd())) {
		c = c.WithResponseTimeout(headlessPromptWait)
	}
	return c, nil
}

// boundedPromptWait scopes the shortened wait above to `jit run`, which sets
// it before touching the vault. Only a LAUNCH has something else timing it
// out; every other command is one a human typed and is waiting on, and
// bounding those broke a real workflow: `jit migrate` invoked from a script
// that captured its output gave up mid-migration after 20s, on a machine
// whose owner was sitting right there. A package var because cobra runs one
// command per process, matching how this package carries its other flags.
var boundedPromptWait bool

// headlessPromptWait bounds how long a terminal-less launch waits on a
// human-in-the-loop prompt. Under Claude Code's default 30s MCP startup
// timeout with room to spare, so the host reports jit's own message from the
// server log instead of killing jit mid-handshake and blaming the server.
const headlessPromptWait = 20 * time.Second

// healDeadService is the dial-failed hook every healing agentClient carries:
// a command that finds the socket dead while the launchd plist is installed
// demands a start instead of failing with restart advice the user must type
// themselves. It is the client half of the 2026-08-17 incident fix
// (design/service-reliability.md): the service-side kickstart only acts once
// a fixed build is already running, so the upgrade that DELIVERS a fix — and
// any broker already sitting dead — still needed a human to notice and run
// `jit service restart`. This demand lives in the client binary the user's
// next command runs, so it works for the very upgrade that ships it, and
// retroactively for a broker launchd already pended.
//
// Plain kickstart, never -k and never bootstrap. On a running job kickstart
// merely reports it running, which is what makes concurrent healers (a burst
// of wrap shims hitting a dead broker) cost one spawn and no kills; on a
// dropped job it fails and the command falls through to
// installedNotRunningAdvice, which already tells that state apart.
// Re-registering a dropped job stays `jit service restart`'s work. Build
// skew is deliberately NOT healed here: the service's own self-retire owns
// it, behind the quiescent gate that keeps an upgrade from killing a live
// session — a client-side demand would bypass that gate.
//
// Returns agentStartWait when the demand went out, so the dial waits out a
// cold spawn (agentRestartGrace is sized for a respawn already in flight,
// not a fresh exec), and 0 when it didn't — the dial keeps its ordinary
// grace and the existing advice paths do their work.
func healDeadService() time.Duration {
	var window time.Duration
	agentHealOnce.Do(func() {
		fmt.Fprintln(os.Stderr, serviceHealNotice)
		if _, err := launchctlRun("kickstart", agentServiceTarget()); err != nil {
			return
		}
		by := invocationCommandPath
		if by == "" {
			by = "jit"
		}
		// The heal must stay visible after it succeeds: a surface that
		// quietly fixes the dead-broker state would also erase the field
		// evidence of how often launchd pends spawns — the signal that
		// decides whether the parked Sockets-activation work is ever needed.
		// Args mimic argv words, not prose: commandEntry renders (and --grep
		// matches) "jit " + args, so prose here made the line lose "heal".
		recordSideEffect("jit service heal",
			[]string{"service", "heal", "(was not running; demanded start)"}, by)
		window = agentStartWait
	})
	return window
}

// serviceHealNotice is the one stderr line healDeadService prints, so the
// seconds the demand-spawn takes read as jit doing something rather than a
// silent hang — the same job announceTouchIDWait does for a prompt wait.
// stderr, like every transient notice, so it never corrupts stdout output.
const serviceHealNotice = "the background service isn't running; starting it..."

// agentHealOnce bounds healDeadService to one demand per process: if the
// service cannot come up, the command should fail with the honest advice,
// not churn launchd with repeated demands. Tests reset it.
var agentHealOnce sync.Once

// announceTouchIDWait is the wait notifier every CLI agent client carries: it
// prints one line to stderr when a request has been blocked long enough to
// mean the service is sitting on a Touch ID/passcode prompt. Without it the
// terminal just hangs mid-command while the OS challenge waits offscreen, and
// a user (or a demo viewer) has no way to connect the pause to the prompt on
// their Mac — the same silent-prompt confusion internal/keychainwrap already
// documents. stderr, so it never corrupts a --format json payload on stdout;
// json/status commands don't challenge, so it won't fire for them anyway.
//
// Once per process. The client's timer is per RPC, and a command like
// migrate issues several slow RPCs after its one real unlock (a mount
// refresh that re-serves every registered mount, a store behind the
// service's own housekeeping), each of which crossed the 400ms line and
// printed the notice again — three or four "Touch ID required" lines for
// one prompt (seen live 2026-09-05, the audit log showing a single
// unlock). The line's job is to explain the first hang; the audit log,
// not this notice, is the record of prompts.
func announceTouchIDWait() {
	touchIDNotice.mu.Lock()
	defer touchIDNotice.mu.Unlock()
	if touchIDNotice.shown {
		return
	}
	touchIDNotice.shown = true
	fmt.Fprintln(touchIDNotice.out, glyphLock+" Touch ID required: approve the prompt on your Mac to continue...")
}

// touchIDNotice is announceTouchIDWait's once-per-process state; the
// writer is a field so tests can capture the line and reset the guard.
var touchIDNotice = struct {
	mu    sync.Mutex
	shown bool
	out   io.Writer
}{out: os.Stderr}

// installedNotRunningParts is the SINGLE source of the "installed but not
// running" guidance, shared by `jit status`, `jit service status`, doctor,
// migrate's trailer and the notRunningHint agent subcommands print on a dial
// failure — so the wording can't drift across the surfaces. It did drift
// once: a change to what restart recovers updated only `jit service status`,
// leaving `jit status` (the first place a user sees this) and notRunningHint
// on stale advice. The state half and the action half return separately
// because doctor renders them as Detail and Action; flat surfaces join them
// (installedNotRunningAdvice). subject is the caller's noun phrase ("the
// service", "jit's background service") so each surface keeps its own voice
// while the sentences stay identical.
func installedNotRunningParts(subject string) (detail, action string) {
	st, known := queryLaunchdJobState()
	switch {
	case known && st.loaded && st.runs == 0:
		return subject + " is installed and launchd accepted it, but never started it.",
			"`jit service restart` demands a start directly; `jit service log` shows recent output."
	case known && st.loaded && st.hasLastExit:
		return fmt.Sprintf("%s stopped (last exit code %d) and launchd has not brought it back.", subject, st.lastExit),
			"`jit service restart` restarts it; `jit service log` shows recent output."
	case known && !st.loaded:
		return subject + " is installed but launchd has dropped it.",
			"`jit service restart` re-registers and starts it; `jit service log` shows recent output."
	default:
		return subject + " is installed but not running.",
			"`jit service restart` restarts it; `jit service log` shows recent output."
	}
}

func installedNotRunningAdvice(subject string) string {
	detail, action := installedNotRunningParts(subject)
	return detail + " " + action
}

// statusServiceRow is the dashboard-width version of
// installedNotRunningParts: one clause for `jit status`'s service row, with
// the action rendered separately as the row's → line.
func statusServiceRow() string {
	st, known := queryLaunchdJobState()
	switch {
	case known && st.loaded && st.runs == 0:
		return "installed, but launchd never started it (runs 0)"
	case known && st.loaded && st.hasLastExit:
		return fmt.Sprintf("stopped (last exit code %d), launchd has not brought it back", st.lastExit)
	case known && !st.loaded:
		return "installed, but launchd has dropped it"
	default:
		return "installed but not running"
	}
}

// agentStartFailure is the error restart returns when the just-reloaded
// service never answered: what launchd says happened, and what to do. This
// replaced "still starting up in the background" + exit 0, which audited
// success: true for a permanently dead service — the incident's second
// half. A timeout here is a failure, in the exit code and the audit record.
func agentStartFailure() error {
	st, known := queryLaunchdJobState()
	switch {
	case known && st.loaded && st.runs == 0:
		return fmt.Errorf("reloaded, but the service never started (launchd: loaded, runs 0 after %s); retry, and `jit service log` shows recent output", agentStartWait)
	case known && st.loaded && st.hasLastExit:
		return fmt.Errorf("the service started but exited (last exit code %d) and has not come back; `jit service log` shows its output", st.lastExit)
	case known && !st.loaded:
		return errors.New("launchd no longer shows the service after the reload; `jit service log` shows recent output")
	default:
		return fmt.Errorf("the service did not answer within %s; `jit service status` may catch it late, `jit service log` shows output", agentStartWait)
	}
}

// restartedServiceClause is ttl/consent's version of agentStartFailure: their
// setting IS saved, so the sentence blames only the restart half.
func restartedServiceClause() string {
	st, known := queryLaunchdJobState()
	switch {
	case known && st.loaded && st.runs == 0:
		return "the restarted service never started (launchd: loaded, runs 0)"
	case known && st.loaded && st.hasLastExit:
		return fmt.Sprintf("the restarted service exited (last exit code %d)", st.lastExit)
	case known && !st.loaded:
		return "launchd no longer shows the service"
	default:
		return "the restarted service has not answered yet"
	}
}

func notRunningHint(err error) error {
	if !errors.Is(err, agent.ErrNotRunning) {
		return err
	}
	if agentInstalled() {
		return errors.New(installedNotRunningAdvice("the service"))
	}
	return errors.New("the background service isn't running; run `jit service restart` to start it")
}
