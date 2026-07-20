// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/keychainwrap"
	"github.com/jitpass/jit/internal/screenlock"
)

var agentTTL time.Duration

// agentInstallTTL is baked into the installed launchd plist's own
// ProgramArguments (GAPS.md #18) — separate var from agentTTL (agentRunCmd's
// flag) since they're read at different times: agentTTL when `agent run`
// actually starts, agentInstallTTL when `agent install` writes the plist
// that will later invoke `agent run --ttl <value>`.
var agentInstallTTL time.Duration

// agentInstallYes skips agentInstallCmd's confirmation prompt — same
// --yes/-y convention as migrate/vault rm/vault import, for scripting.
var agentInstallYes bool

// revealForDuration is jit agent reveal's --for flag, parsed once at command
// registration and re-read on each run.
var revealForDuration time.Duration
var revealQuiet bool

// agentStatusFormat is agentStatusCmd's --format flag (GAPS.md #22).
var agentStatusFormat string

var agentCmd = &cobra.Command{
	Use:     "agent",
	GroupID: groupAgent,
	Short:   "Run a background helper so you only unlock once, not once per command",
	Long: "jit agent is a small background helper that keeps one unlocked session\n" +
		"other jit commands share, instead of each one prompting Touch ID\n" +
		"separately, and that serves any live-mounted .env files jit migrate has\n" +
		"created.\n\n" +
		"`jit agent install` sets it up to start automatically every time you log\n" +
		"in (and restart itself if it crashes). The helper process itself needs no\n" +
		"Touch ID just to keep running, only your unlocked session inside it locks\n" +
		"after --ttl of inactivity (default 15m), prompting again on next use.\n\n" +
		"A live-mounted file shows fake-looking values until revealed, and real values\n" +
		"only during a short window, opened automatically right after unlock/\n" +
		"refresh, or explicitly via `jit agent reveal`.",
}

// agentRunCmd is what the installed LaunchAgent's plist actually executes.
// Running it directly (not via launchd) works too, in the foreground.
var agentRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the agent in the foreground (normally started by launchd, not by hand)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateAgentTTL(agentTTL); err != nil {
			return fmt.Errorf("jit agent run: %w", err)
		}
		root, err := vaultRootDir()
		if err != nil {
			return fmt.Errorf("jit agent run: %w", err)
		}

		// launchd creates the StandardOutPath/StandardErrorPath log 0644;
		// tighten it to 0600 on every start (covering both a fresh log and
		// one an older build already left world-readable). It records reader
		// lineage — pids, executable paths, mount paths — that no other local
		// user should read. Best-effort: the enclosing dir is already 0700,
		// so this is defense-in-depth, and the file may not exist yet on the
		// very first start before anything is written.
		logPath := filepath.Join(root, "agent.log")
		_ = os.Chmod(logPath, 0o600)

		// Everything this long-lived process prints lands in one agent.log
		// (the plist points both streams there) — timestamp every line, or
		// the log can't answer "when," which is most of what a log of a
		// weeks-lived process is for (GAPS.md #48). Both stamped streams
		// share ONE mutex (lockedWriter) so the mid-run rotation below can
		// hold it across its copy-then-truncate and never lose a line
		// written in between.
		var logMu sync.Mutex
		stdout := newStampedWriter(&lockedWriter{mu: &logMu, w: cmd.OutOrStdout()})
		stderr := newStampedWriter(&lockedWriter{mu: &logMu, w: cmd.ErrOrStderr()})

		// Cap the log before this run's first write. The log otherwise
		// grows for the machine's lifetime — a single watcher-loop
		// afternoon once produced 635k lines (GAPS.md #47), and launchd
		// keeps appending to the same file across every restart forever.
		// Under launchd this is re-checked periodically too
		// (rotateAgentLogPeriodically): a startup-only cap left a storm
		// free to grow the log unboundedly until the NEXT restart, which
		// can be weeks away.
		if err := rotateAgentLog(logPath, agentLogMaxBytes); err != nil {
			fmt.Fprintf(stderr, "jit agent: rotating %s: %v\n", logPath, err)
		}

		server := agent.NewServer(agent.SocketPath(root), func() agent.MEKFetcher { return keychainwrap.New() }, agentTTL)
		mounts := &mountManager{root: root, keyWrapper: server, stdout: stdout, stderr: stderr}
		server.OnUnlock = mounts.start
		server.OnUnlockForReveal = mounts.startForReveal
		server.OnLock = mounts.stop
		server.OnRefresh = mounts.start
		server.OnReveal = mounts.revealMount
		server.OnRevealPID = mounts.revealForPID
		server.OnCanGrant = mounts.canGrantAll
		server.OnStopMount = mounts.stopMount
		server.OnMountStatus = mounts.mountRevealStatuses

		// Durable session history: every event goes to agent-history.jsonl
		// as well as the prose log, and the previous processes' events are
		// seeded back into the ring — so `jit agent history` can answer for
		// prompts that happened before the most recent launchd restart,
		// which is exactly when the question gets asked (restarts happen at
		// login; the question is asked the next morning, about yesterday).
		// The start marker is what keeps the restored sequence honest: a
		// session that "just locked" across a restart didn't lock, the
		// process died.
		hist := newHistoryLog(root, stderr)
		hist.trim()
		hist.append(agent.SessionEvent{
			UnixTime: time.Now().Unix(),
			Kind:     agent.KindStart,
			Cause:    fmt.Sprintf("build %s", agent.BuildID()),
		})
		server.SeedHistory(hist.load(agent.MaxSessionEvents))
		server.OnSessionEvent = func(e agent.SessionEvent) {
			logSessionEvent(stdout, e)
			hist.append(e)
		}

		if err := server.Listen(); err != nil {
			return fmt.Errorf("jit agent run: %w", err)
		}
		defer func() {
			mounts.shutdown()
			_ = server.Close()
		}()

		// Decoy serving needs no vault access at all (GAPS.md #35), so —
		// unlike real-content resolution — it's safe to start right here,
		// before anyone has unlocked anything. This is what makes opening
		// a mount never hang: a RunAtLoad launchd agent that just started,
		// or one sitting locked, still has a writer behind every
		// registered mount's pipe from this point on.
		mounts.startDecoyOnly()

		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		// runCtx additionally ends when the agent retires ITSELF — the
		// stale-binary watcher below — with everything downstream (Serve,
		// the run loop) shutting down exactly as it would on a signal.
		runCtx, endRun := context.WithCancel(ctx)
		defer endRun()

		// Lock the moment the human demonstrably leaves — the screen
		// locking or the machine going to sleep — instead of holding the
		// session for the remainder of the idle TTL after they're gone.
		// Best-effort: a watch failure is logged and the TTL still covers
		// everything, just later.
		if err := screenlock.Watch(func(cause string) { server.LockWithCause(cause) }); err != nil {
			fmt.Fprintf(stderr, "jit agent: screen-lock/sleep watch unavailable (%v), sessions will lock on the idle TTL alone\n", err)
		}

		// Self-retire when the jit binary on disk is replaced (see
		// agentbinary.go for the gates), but only under launchd — its
		// KeepAlive restarts what exits; a foreground run has no such net.
		// The periodic log-rotation check shares the gate: a foreground
		// run's streams are a terminal, not agent.log, and truncating the
		// file out from under a concurrently-installed agent's O_APPEND fd
		// is exactly the cross-process interference to avoid.
		if os.Getppid() == 1 {
			if exePath, exeErr := os.Executable(); exeErr == nil {
				go watchOwnBinary(runCtx, exePath, agentBinaryCheckInterval, server.Quiescent, func() {
					fmt.Fprintf(stdout, "jit agent: the jit binary on disk changed (this process is build %s), exiting while the session is locked so launchd restarts the agent on the current build\n", agent.BuildID())
					endRun()
				})
			}
			go rotateAgentLogPeriodically(runCtx, logPath, &logMu, stderr)
		}

		fmt.Fprintf(stdout, "jit agent listening on %s (session TTL %s, build %s)\n", agent.SocketPath(root), agentTTL, agent.BuildID())

		// Serve from a goroutine so THIS goroutine — locked to the main OS
		// thread by cmd/jit's init — can park in the main run loop, the
		// only place macOS delivers the screen-lock/sleep notifications
		// (see screenlock.RunMain). Serve ending for any reason must also
		// unpark the loop, or a listener failure would leave the process
		// alive doing nothing.
		loopCtx, loopCancel := context.WithCancel(runCtx)
		defer loopCancel()
		serveErr := make(chan error, 1)
		go func() {
			serveErr <- server.Serve(runCtx)
			loopCancel()
		}()
		if err := screenlock.RunMain(loopCtx); err != nil {
			// Not on the main thread (an embedding or test arrangement):
			// screen-lock events won't be delivered, but serving is
			// unaffected — say so and keep running.
			fmt.Fprintf(stderr, "jit agent: screen-lock/sleep events disabled: %v\n", err)
		}
		err = <-serveErr
		if err != nil && !errors.Is(err, context.Canceled) {
			return fmt.Errorf("jit agent run: %w", err)
		}
		fmt.Fprintln(stdout, "jit agent stopped.")
		return nil
	},
}

var agentInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Start jit agent automatically at every login (survives reboots)",
	Long: "Sets up jit agent to start automatically every time you log in, and to\n" +
		"restart itself if it crashes, until you run `jit agent uninstall`.\n" +
		"Under the hood this writes and loads a launchd LaunchAgent plist that\n" +
		"runs `jit agent run`.\n\n" +
		"--ttl controls how long a session stays unlocked after your last Touch ID\n" +
		"prompt (default 15m, same meaning as `jit agent run --ttl`), baked into\n" +
		"the installed service so it applies from every future login, not just\n" +
		"this one.\n\n" +
		"Safe to run again to change --ttl later: an already-installed instance is\n" +
		"unloaded first, so the new value takes effect immediately rather than\n" +
		"only on the next login.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Validated HERE, not just in `agent run`, because install bakes
		// the value into the plist: a bad --ttl would otherwise install a
		// service that fails validation on every launchd start, forever,
		// with the error visible only in the agent log.
		if err := validateAgentTTL(agentInstallTTL); err != nil {
			return fmt.Errorf("jit agent install: %w", err)
		}
		// Writing a LaunchAgent plist is a system-persistence action — it
		// runs code automatically at every login, beyond this one
		// invocation, until explicitly uninstalled. Confirm before
		// doing it, the same way vault
		// rm/import gate their own less-reversible actions, rather than
		// treating this as a routine, silent setup step.
		if !agentInstallYes && !confirmPrompt(cmd, fmt.Sprintf(
			"Set up jit agent to start automatically at every login (and restart itself if it crashes), staying unlocked for up to %s after each Touch ID prompt, until you run `jit agent uninstall`? [y/N] ",
			agentInstallTTL)) {
			fmt.Fprintln(cmd.OutOrStdout(), "Aborted. Nothing was installed.")
			return nil
		}

		exePath, err := os.Executable()
		if err != nil {
			return fmt.Errorf("jit agent install: %w", err)
		}
		exePath, err = filepath.EvalSymlinks(exePath)
		if err != nil {
			return fmt.Errorf("jit agent install: %w", err)
		}

		plistPath, err := agentPlistPath()
		if err != nil {
			return fmt.Errorf("jit agent install: %w", err)
		}
		root, err := vaultRootDir()
		if err != nil {
			return fmt.Errorf("jit agent install: %w", err)
		}
		logPath := filepath.Join(root, "agent.log")

		// Boot out any previously-running instance first — bootstrap on an
		// already-loaded label fails outright, and a re-install to change
		// --ttl must take effect now, not at next login. Best-effort:
		// nothing to boot out on a first-ever install, and a failure here
		// still leaves the bootstrap below to report the real error if
		// something's actually wrong. (bootstrap/bootout are the modern
		// verbs; load/unload have been deprecated since 10.11 and their
		// errors are famously unhelpful.)
		_ = exec.Command("launchctl", "bootout", agentServiceTarget()).Run() // #nosec G204 -- fixed subcommand, jit's own label

		// exePath/logPath are filesystem paths and can legally contain XML
		// metacharacters (& is common in directory names) — splicing one
		// into the plist unescaped produces a file launchctl rejects, or
		// worse, silently misparses.
		plist := fmt.Sprintf(agentPlistTemplate, agentPlistLabel, xmlEscape(exePath), agentInstallTTL.String(), xmlEscape(logPath), xmlEscape(logPath))
		if err := os.MkdirAll(filepath.Dir(plistPath), 0o700); err != nil {
			return fmt.Errorf("jit agent install: %w", err)
		}
		if err := os.WriteFile(plistPath, []byte(plist), 0o600); err != nil {
			return fmt.Errorf("jit agent install: %w", err)
		}

		out, err := exec.Command("launchctl", "bootstrap", agentDomainTarget(), plistPath).CombinedOutput() // #nosec G204 -- fixed subcommand, plistPath is a file jit itself just wrote
		if err != nil {
			return fmt.Errorf("jit agent install: launchctl bootstrap failed: %w (%s)", err, strings.TrimSpace(string(out)))
		}
		// launchctl bootstrap returns before the agent process has spawned
		// and bound its socket — a real, observed first-run confusion: `jit
		// agent status` typed right after a successful install said "not
		// running — run `jit agent install` to set it up" for the ~2s
		// launchd took to actually start it. Wait briefly until the socket
		// answers so "Installed" also means "running"; if it still isn't
		// up after the timeout, say what's actually happening rather than
		// letting status contradict this command a moment later.
		running := waitForAgentSocket(root, 5*time.Second)
		fmt.Fprintf(cmd.OutOrStdout(),
			"Installed, jit agent now starts automatically every time you log in (survives reboots) and stays unlocked for up to %s after your last Touch ID prompt.\nRun `jit agent uninstall` to remove it. (%s)\n",
			agentInstallTTL, plistPath)
		if !running {
			fmt.Fprintln(cmd.OutOrStdout(), "The agent is still starting up in the background, give `jit agent status` a few seconds.")
		}
		return nil
	},
}

var agentUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Stop jit agent and remove it from login startup",
	Long: "Stops the background helper and removes it from login startup, it will\n" +
		"no longer start automatically. Any files it was live-mounting stop being\n" +
		"served (they don't disappear; they just go quiet until you run\n" +
		"`jit agent install` again). Doesn't touch the vault or any secrets\n" +
		"already stored, only the background helper itself.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		plistPath, err := agentPlistPath()
		if err != nil {
			return fmt.Errorf("jit agent uninstall: %w", err)
		}

		if _, statErr := os.Stat(plistPath); statErr == nil {
			out, unloadErr := exec.Command("launchctl", "bootout", agentServiceTarget()).CombinedOutput() // #nosec G204 -- fixed subcommand, jit's own label
			if unloadErr != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "warning: launchctl bootout failed (%v): %s\n", unloadErr, strings.TrimSpace(string(out)))
			}
		}
		if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("jit agent uninstall: %w", err)
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Uninstalled jit agent.")
		return nil
	},
}

var agentRestartCmd = &cobra.Command{
	Use:   "restart",
	Short: "Restart the agent process (picks up a newly built or updated jit binary)",
	Long: "Kills and restarts the launchd-managed agent process, the immediate fix\n" +
		"when `jit agent status` warns that the running agent predates the jit\n" +
		"binary on disk. (The agent also retires itself onto the new binary\n" +
		"automatically, but only once its session is locked and no prompt is\n" +
		"pending; restart is for wanting it now.)\n\n" +
		"The in-memory session is lost, so the next vault use prompts Touch ID\n" +
		"again, and live-mounted files serve placeholder values until then.\n" +
		"Session history survives, it's durable. Requires `jit agent install`.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		plistPath, err := agentPlistPath()
		if err != nil {
			return fmt.Errorf("jit agent restart: %w", err)
		}
		if _, err := os.Stat(plistPath); err != nil {
			return errors.New("jit agent restart: the agent isn't installed, run `jit agent install` first")
		}
		// kickstart -k kills a running instance and starts a fresh one in
		// a single verb; it also starts one that wasn't running at all — but
		// only while the service is still bootstrapped into the domain.
		// launchd drops a service outright when it gives up on a crash loop,
		// on an explicit bootout, or when an upgrade unloaded the old one; the
		// plist file is still on disk (so status/agentInstalled report
		// "installed"), yet kickstart fails with "Could not find service"
		// because launchd has no live record to kick. That state is
		// recoverable only by re-bootstrapping the plist — exactly what `jit
		// agent install` does, minus rewriting it — so fall back to that
		// rather than dead-ending on an error whose only fix was a command
		// this one is supposed to stand in for.
		out, err := exec.Command("launchctl", "kickstart", "-k", agentServiceTarget()).CombinedOutput() // #nosec G204 -- fixed subcommand, jit's own label
		if err != nil {
			if !serviceNotLoaded(out) {
				return fmt.Errorf("jit agent restart: launchctl kickstart failed: %w (%s)", err, strings.TrimSpace(string(out)))
			}
			bootOut, bootErr := exec.Command("launchctl", "bootstrap", agentDomainTarget(), plistPath).CombinedOutput() // #nosec G204 -- fixed subcommand, plistPath is jit's own plist that os.Stat above confirmed exists
			if bootErr != nil {
				return fmt.Errorf("jit agent restart: launchd had dropped the agent's service and re-bootstrapping it failed: %w (%s); run `jit agent install` to reinstall it", bootErr, strings.TrimSpace(string(bootOut)))
			}
		}
		root, err := vaultRootDir()
		if err != nil {
			return fmt.Errorf("jit agent restart: %w", err)
		}
		// Same wait as install, same reason: "Restarted" must mean the new
		// process is actually answering, or status contradicts us moments
		// later.
		if !waitForAgentSocket(root, 5*time.Second) {
			fmt.Fprintln(cmd.OutOrStdout(), "Restart requested, the agent is still starting up in the background; give `jit agent status` a few seconds.")
			return nil
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Restarted, the agent is now running the current binary. The next vault use will prompt Touch ID.")
		return nil
	},
}

var agentUnlockCmd = &cobra.Command{
	Use:   "unlock",
	Short: "Unlock the running agent's session now (prompts Touch ID if needed)",
	Long:  "Pre-warms the shared session so a run of jit run/vault get/export right after doesn't prompt.",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := agentClient()
		if err != nil {
			return fmt.Errorf("jit agent unlock: %w", err)
		}
		_, remaining, err := c.Unlock()
		if err != nil {
			return fmt.Errorf("jit agent unlock: %w", notRunningHint(err))
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Unlocked, locks automatically after %s of inactivity (or `jit agent lock` sooner).\n", remaining.Round(time.Second))
		return nil
	},
}

var agentLockCmd = &cobra.Command{
	Use:   "lock",
	Short: "Lock the running agent's session immediately, without waiting for the TTL",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := agentClient()
		if err != nil {
			return fmt.Errorf("jit agent lock: %w", err)
		}
		if err := c.Lock(); err != nil {
			return fmt.Errorf("jit agent lock: %w", notRunningHint(err))
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Locked.")
		return nil
	},
}

var agentRevealCmd = &cobra.Command{
	Use:   "reveal <mount-path>",
	Short: "Temporarily show real secret values in a live-mounted file",
	Long: "A live-mounted file (the kind jit migrate creates for .env/npmrc) shows\n" +
		"fake-looking values by default and only its real ones while \"revealed\".\n" +
		"Every unlock/refresh already reveals every mount for a short default\n" +
		"window automatically; this command is for when that's not enough (a\n" +
		"dev server that reads .env well after the window closed).\n" +
		"Requires the agent to be unlocked, prompting Touch ID/passcode if it isn't.\n\n" +
		"Meant to be embedded in a pre-run hook (jit migrate wires this up\n" +
		"automatically for direnv/npm projects) as well as run by hand.",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// mounts.yaml stores absolute paths (DiscoverEnvFiles walks an
		// absolute root), so a relative arg here — the common case, typed
		// from inside the project directory — must be resolved the same
		// way before being sent, or it silently matches nothing server-side
		// (a real bug: OpReveal used to report success regardless).
		mountPath, err := filepath.Abs(args[0])
		if err != nil {
			return fmt.Errorf("jit agent reveal: %w", err)
		}
		duration := revealForDuration
		if duration <= 0 {
			duration = 5 * time.Minute
		}
		if duration > revealMaxWindow {
			duration = revealMaxWindow
		}

		c, err := agentClient()
		if err != nil {
			return fmt.Errorf("jit agent reveal: %w", err)
		}
		if err := c.Reveal(mountPath, duration); err != nil {
			return fmt.Errorf("jit agent reveal: %w", notRunningHint(err))
		}
		if !revealQuiet {
			fmt.Fprintf(cmd.OutOrStdout(), "Revealed %s for %s.\n", mountPath, duration.Round(time.Second))
		}
		return nil
	},
}

// agentStatusResult is `jit agent status`'s --format json shape
// (GAPS.md #22). LocksInSeconds is only meaningful (and only nonzero) when
// Running && Unlocked — omitted rather than zero-valued-but-misleading
// when the agent isn't running at all or is already locked.
type agentStatusResult struct {
	Running bool `json:"running"`
	// Installed is whether the launchd plist exists — with Running false,
	// it's what separates "crashed or mid-restart" (launchd should be
	// respawning it; `jit agent restart` forces it) from "never set up"
	// (only `jit agent install` helps). A script alerting on dead agents
	// needs exactly this distinction.
	Installed      bool  `json:"installed"`
	Unlocked       bool  `json:"unlocked"`
	LocksInSeconds int64 `json:"locks_in_seconds,omitempty"`
	// Mounts is GAPS.md #37's per-mount reveal snapshot — empty when nothing
	// is registered/served, never omitted outright, so a script parsing
	// this doesn't need to special-case "field missing" vs "empty list."
	Mounts []agent.MountRevealStatus `json:"mounts"`
	// LastUnlock/LastLock are GAPS.md #75's session provenance — who unlocked
	// this agent, what launched them, and what dropped the session since.
	// Omitted (not zero-valued) when the agent has never unlocked: "no
	// provenance" and "unlocked by nobody at the epoch" must not look alike
	// to a script.
	LastUnlock *agent.SessionEvent `json:"last_unlock,omitempty"`
	LastLock   *agent.SessionEvent `json:"last_lock,omitempty"`
	// PendingUnlock is the challenge currently sitting on the user's screen,
	// omitted when none is — status answers during a challenge (reads never
	// queue behind it), so a script polling this sees the prompt the human
	// is being asked to approve, while they're being asked.
	PendingUnlock *agent.SessionEvent `json:"pending_unlock,omitempty"`
	// Build is the running agent PROCESS's build (GAPS.md #49) — compare
	// against this CLI's own to catch a launchd-kept-alive agent that
	// predates the binary on disk. Empty when the agent isn't running.
	Build string `json:"build,omitempty"`
	// Version is the running agent PROCESS's release version — Build's
	// release-scale counterpart. Empty when the agent isn't running or
	// predates the field.
	Version string `json:"version,omitempty"`
}

var agentStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show whether the agent is running, and whether its session is unlocked",
	Long: "Reports whether jit agent is running and, if so, whether its session is\n" +
		"unlocked. --format json prints a machine-readable snapshot instead of the\n" +
		"default text summary.",
	Args: cobra.NoArgs,
	// See doctor.go's SilenceUsage comment for why: a --format json
	// snapshot must never have cobra's usage text appended to it.
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateOutputFormat(agentStatusFormat); err != nil {
			return fmt.Errorf("jit agent status: %w", err)
		}

		client, err := agentClient()
		if err != nil {
			return fmt.Errorf("jit agent status: %w", err)
		}
		st, err := client.Status()
		if errors.Is(err, agent.ErrNotRunning) {
			installed := agentInstalled()
			if agentStatusFormat == "json" {
				return writeJSON(cmd.OutOrStdout(), agentStatusResult{Installed: installed})
			}
			if installed {
				// An installed agent that isn't answering is a different
				// situation from one that was never set up — launchd was
				// supposed to keep this one alive, so "run install" is the
				// wrong advice and hides that something actually failed.
				fmt.Fprintln(cmd.OutOrStdout(), "jit agent is installed but not running, it may have crashed or be mid-restart.")
				fmt.Fprintln(cmd.OutOrStdout(), "Try `jit agent restart` (it reloads the service if launchd dropped it); if that doesn't bring it back, `jit agent install` reinstalls it. `jit agent log` shows recent output.")
				return nil
			}
			fmt.Fprintln(cmd.OutOrStdout(), "jit agent is not running. Run `jit agent install` to set it up.")
			return nil
		}
		if err != nil {
			return fmt.Errorf("jit agent status: %w", err)
		}

		if agentStatusFormat == "json" {
			result := agentStatusResult{Running: true, Installed: agentInstalled(), Unlocked: st.Unlocked, Mounts: st.Mounts, LastUnlock: st.LastUnlock, LastLock: st.LastLock, PendingUnlock: st.PendingUnlock, Build: st.Build, Version: st.Version}
			if st.Unlocked {
				result.LocksInSeconds = int64(st.Remaining.Round(time.Second).Seconds())
			}
			return writeJSON(cmd.OutOrStdout(), result)
		}
		if st.Unlocked {
			fmt.Fprintf(cmd.OutOrStdout(), "jit agent is running and unlocked (locks in %s).\n", st.Remaining.Round(time.Second))
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), "jit agent is running and locked.")
		}
		printPendingUnlock(cmd.OutOrStdout(), st.PendingUnlock)
		fmt.Fprintf(cmd.OutOrStdout(), "Versions: agent %s; CLI %s.\n", versionBuild(st.Version, st.Build), versionBuild(agent.Version(), agent.BuildID()))
		printSessionProvenance(cmd.OutOrStdout(), st)
		printMountStatuses(cmd.OutOrStdout(), st.Mounts)
		if warning := agentBuildMismatch(st.Build); warning != "" {
			_, _ = color.New(color.FgYellow).Fprintf(cmd.OutOrStdout(), "%s\n", warning)
		}
		return nil
	},
}

// agentHistoryFormat is agentHistoryCmd's --format flag, matching `jit agent
// status`'s own.
var agentHistoryFormat string

var agentHistoryCmd = &cobra.Command{
	Use:   "history",
	Short: "List every unlock, lock, denial, and use this agent has seen, and what caused them",
	Long: "Prints the agent's session history, most recent first: every Touch ID prompt\n" +
		"that succeeded (with the command that triggered it and what launched that\n" +
		"command), every prompt that was DECLINED (same provenance, plus why it\n" +
		"failed), every lock (with its cause, an idle timeout, the screen locking,\n" +
		"or an explicit `jit agent lock`), every use of the already-unlocked session\n" +
		"(what flowed through it, collapsed per caller, with the secret names the\n" +
		"caller reported), and every agent start.\n\n" +
		"This is the answer to \"why does it keep asking me?\", a question the agent\n" +
		"previously had no way to answer, since only locks were ever recorded and the\n" +
		"unlocks that did the prompting left no trace at all.\n\n" +
		"Survives restarts: events are also written to agent-history.jsonl alongside\n" +
		"the vault, and each new agent process picks the newest back up, so asking\n" +
		"about yesterday's prompts works even though logging in this morning restarted\n" +
		"the agent. Agent starts appear in the list, marking where one process's\n" +
		"events end and the previous one's begin.",
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateOutputFormat(agentHistoryFormat); err != nil {
			return fmt.Errorf("jit agent history: %w", err)
		}
		client, err := agentClient()
		if err != nil {
			return fmt.Errorf("jit agent history: %w", err)
		}
		events, err := client.History()
		if errors.Is(err, agent.ErrNotRunning) {
			if agentHistoryFormat == "json" {
				return writeJSON(cmd.OutOrStdout(), []agent.SessionEvent{})
			}
			fmt.Fprintln(cmd.OutOrStdout(), "jit agent is not running. Run `jit agent install` to set it up.")
			return nil
		}
		if err != nil {
			return fmt.Errorf("jit agent history: %w", err)
		}
		if agentHistoryFormat == "json" {
			if events == nil {
				events = []agent.SessionEvent{} // an empty list, never a bare null
			}
			return writeJSON(cmd.OutOrStdout(), events)
		}
		printSessionHistory(cmd.OutOrStdout(), events)
		return nil
	},
}

// agentLogLines and agentLogFollow are `jit agent log`'s flags.
var agentLogLines int
var agentLogFollow bool

// agentLogPollInterval paces --follow's growth checks — comfortably
// under a human's "is it live?" threshold without hammering stat.
const agentLogPollInterval = 500 * time.Millisecond

var agentLogCmd = &cobra.Command{
	Use:   "log",
	Short: "Show the agent's own log (session events, mount reads, serve errors)",
	Long: "Prints the tail of the agent's log file, the durable, timestamped record\n" +
		"of session events, mount reads (with who read them), and serve errors that\n" +
		"outlives the in-memory snapshot `jit agent status` reports.\n\n" +
		"The file lives alongside the vault as agent.log (the previous generation\n" +
		"is kept as agent.log.1 after rotation). This command exists because the\n" +
		"investigations that need the log are exactly the ones where hunting down\n" +
		"its path is one obstacle too many.",
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		root, err := vaultRootDir()
		if err != nil {
			return fmt.Errorf("jit agent log: %w", err)
		}
		logPath := filepath.Join(root, "agent.log")
		out := cmd.OutOrStdout()

		data, err := os.ReadFile(logPath) // #nosec G304 -- jit's own log file under its config root
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("jit agent log: %w", err)
		}
		if os.IsNotExist(err) && !agentLogFollow {
			// Not an error: an empty history is a normal state on a machine
			// where the agent hasn't run, and the useful output is what
			// would make one exist.
			fmt.Fprintf(out, "No agent log yet at %s, it's written once the agent runs (`jit agent install` sets that up).\n", displayLogPath(logPath))
			return nil
		}
		_, _ = out.Write(tailLines(data, agentLogLines))

		if !agentLogFollow {
			return nil
		}
		// Follow by polling for growth. A rotation truncates in place (see
		// rotateAgentLog), which reads as the file shrinking — restart from
		// the top of the now-small file rather than waiting for it to grow
		// past a stale offset that may be megabytes away.
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		offset := int64(len(data))
		ticker := time.NewTicker(agentLogPollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
			}
			fi, err := os.Stat(logPath)
			if err != nil {
				continue // mid-rotation or not yet created; try again next tick
			}
			if fi.Size() < offset {
				offset = 0
			}
			if fi.Size() == offset {
				continue
			}
			f, err := os.Open(logPath) // #nosec G304 -- jit's own log file under its config root
			if err != nil {
				continue
			}
			if _, err := f.Seek(offset, io.SeekStart); err == nil {
				n, _ := io.Copy(out, f)
				offset += n
			}
			_ = f.Close()
		}
	},
}

// tailLines returns the last n lines of data, newline-terminated — the
// whole file when it has fewer.
func tailLines(data []byte, n int) []byte {
	trimmed := bytes.TrimSuffix(data, []byte("\n"))
	if n <= 0 || len(trimmed) == 0 {
		return nil
	}
	lines := bytes.Split(trimmed, []byte("\n"))
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return append(bytes.Join(lines, []byte("\n")), '\n')
}

// displayLogPath ~-shortens the log path for a message, same courtesy as
// every other path this file prints.
func displayLogPath(logPath string) string {
	home, _ := os.UserHomeDir()
	return displayPath(home, logPath)
}

// printSessionHistory renders `jit agent history` — the same bullet shape as
// the Session block in `jit agent status`, just without the two-event limit.
func printSessionHistory(w io.Writer, events []agent.SessionEvent) {
	if len(events) == 0 {
		fmt.Fprintln(w, "No unlocks or locks recorded since the agent started.")
		return
	}
	home, _ := os.UserHomeDir()

	fmt.Fprintln(w, "Session history (most recent first):")
	for _, e := range events {
		switch e.Kind {
		case agent.KindLock:
			cause := e.Cause
			if cause == "" {
				cause = "unknown cause"
			}
			fmt.Fprintf(w, "  • %s, %s\n", sessionWhen("locked", e.UnixTime), cause)
		case agent.KindStart:
			// The process boundary: everything below this line happened in
			// an earlier agent process (restored from the durable history).
			line := sessionWhen("started", e.UnixTime)
			if e.Cause != "" {
				line += fmt.Sprintf(", agent process started (%s)", e.Cause)
			} else {
				line += ", agent process started"
			}
			fmt.Fprintf(w, "  • %s\n", line)
		case agent.KindDenied:
			// The prompt the human refused — in red, because among a page of
			// routine unlocks it's the line an investigation is looking for,
			// and the one event that used to leave no trace at all.
			line := sessionWhen("denied", e.UnixTime)
			if e.LaunchedBy != "" {
				line += fmt.Sprintf(", launched by %s", e.LaunchedBy)
			}
			_, _ = color.New(color.FgRed).Fprintf(w, "  • %s\n", line)
			if e.By != "" {
				fmt.Fprintf(w, "      %s\n", shortenCommand(home, e.By))
			}
			if e.Cause != "" {
				fmt.Fprintf(w, "      %s\n", e.Cause)
			}
		case agent.KindUse:
			line := fmt.Sprintf("  • %s, %s", sessionWhen("used", e.UnixTime), agent.DescribeUse(e.Op))
			if e.Count > 1 {
				line += fmt.Sprintf(" ×%d", e.Count)
			}
			if e.LaunchedBy != "" {
				line += fmt.Sprintf(", launched by %s", e.LaunchedBy)
			}
			fmt.Fprintln(w, line)
			if e.By != "" {
				fmt.Fprintf(w, "      %s\n", shortenCommand(home, e.By))
			}
			printEventLabels(w, e.Labels)
		default:
			line := fmt.Sprintf("  • %s", sessionWhen("unlocked", e.UnixTime))
			if e.LaunchedBy != "" {
				line += fmt.Sprintf(", launched by %s", e.LaunchedBy)
			}
			fmt.Fprintln(w, line)
			if e.By != "" {
				fmt.Fprintf(w, "      %s\n", shortenCommand(home, e.By))
			}
			printEventLabels(w, e.Labels)
		}
	}
}

// printEventLabels renders an event's caller-reported secret names, always
// with the qualifier: unlike everything else on these lines, the labels
// are what the CALLER said about itself (agent.Request.Label), not a fact
// the kernel supplied — displaying them bare would launder a claim into
// an observation.
func printEventLabels(w io.Writer, labels []string) {
	if len(labels) == 0 {
		return
	}
	fmt.Fprintf(w, "      secrets (caller-reported): %s\n", strings.Join(labels, ", "))
}

// logSessionEvent writes an unlock or a lock to the agent's log, with the
// provenance that made it happen.
//
// The log used to record every lock and no unlock at all — so the one event a
// user ever asks about (the prompt that just interrupted them) was the one
// event with no line anywhere. Reconstructing a single unlock meant reading
// this log against the user's own shell history to guess which command had
// run when. Both halves are written now, and unlike `jit agent status`'s
// in-memory snapshot, these survive the launchd restarts that happen at every
// login and every rebuild.
//
// The full command goes in untruncated: a log file is not a modal dialog, and
// the whole point of the line is to still be useful weeks later.
func logSessionEvent(w io.Writer, e agent.SessionEvent) {
	if e.Kind == agent.KindLock { // a lock: the cause IS the news ("why was I asked again?")
		cause := e.Cause
		if cause == "" {
			cause = "unknown cause"
		}
		fmt.Fprintf(w, "jit agent: session locked, %s\n", cause)
		return
	}

	verb := "session unlocked"
	switch e.Kind {
	case agent.KindDenied:
		// The refused prompt gets the same full provenance an approved one
		// would have — it used to be the one event with no line anywhere.
		verb = "unlock DENIED"
	case agent.KindUse:
		verb = "session used"
	}
	line := "jit agent: " + verb
	if e.Op != "" {
		op := e.Op
		if e.Count > 1 {
			op += fmt.Sprintf(" ×%d", e.Count)
		}
		line += fmt.Sprintf(" (%s)", op)
	}
	if e.By != "" {
		line += fmt.Sprintf(" by %s", e.By)
		if e.ByPID != 0 {
			line += fmt.Sprintf(" [pid %d]", e.ByPID)
		}
	}
	if e.LaunchedBy != "" {
		line += fmt.Sprintf(", launched by %s", e.LaunchedBy)
	}
	if len(e.Labels) > 0 {
		line += fmt.Sprintf(", secrets (caller-reported): %s", strings.Join(e.Labels, ", "))
	}
	if e.Kind == agent.KindDenied && e.Cause != "" {
		line += fmt.Sprintf(", %s", e.Cause)
	}
	fmt.Fprintln(w, line)
}

// maxCommandLen bounds the unlocking command on a status line. A
// jit-launched MCP server's real argv runs to ~170 characters of absolute
// paths — it wraps twice in a terminal and buries the part that matters
// (`jit run --profile mcp-jamf`) in the middle of the wreckage. The full,
// untruncated command stays in --format json, which is where a script (or a
// human who genuinely wants the child's arguments) should be looking.
const maxCommandLen = 72

// shortenCommand makes a kernel-reported command line fit a status line:
// $HOME collapses to ~ (the same courtesy printMountStatuses already extends
// to paths), and what's still too long is cut. jit's own arguments come
// first in the string, so a cut tail costs the child command's arguments —
// the least interesting part — rather than the profile name.
func shortenCommand(home, cmd string) string {
	if home != "" {
		cmd = strings.ReplaceAll(cmd, home+"/", "~/")
	}
	r := []rune(cmd)
	if len(r) <= maxCommandLen {
		return cmd
	}
	return string(r[:maxCommandLen-1]) + "…"
}

// printPendingUnlock names the Touch ID/passcode prompt that is on the
// user's screen RIGHT NOW, if one is. This is the situation the whole
// provenance effort exists for, caught in the act: the user typed `jit
// agent status` because an unexplained prompt is sitting in front of them,
// and status can answer only because reads no longer queue behind the
// in-flight challenge itself. Yellow, because it's the one line that
// demands a decision rather than describing the past.
func printPendingUnlock(w io.Writer, p *agent.SessionEvent) {
	if p == nil {
		return
	}
	line := fmt.Sprintf("A Touch ID/passcode prompt is up right now (appeared %s ago)", humanAgo(time.Since(time.Unix(p.UnixTime, 0))))
	if p.LaunchedBy != "" {
		line += fmt.Sprintf(", triggered by a command launched by %s", p.LaunchedBy)
	}
	_, _ = color.New(color.FgYellow).Fprintf(w, "%s\n", line)
	if p.By != "" {
		home, _ := os.UserHomeDir()
		fmt.Fprintf(w, "      %s\n", shortenCommand(home, p.By))
	}
}

// printSessionProvenance is the "who put the session in this state" lines
// under `jit agent status`'s headline (GAPS.md #75).
//
// The motivating report: a Touch ID prompt appeared unbidden while the user
// was doing something entirely unrelated, and reconstructing why took
// cross-referencing the agent's log against shell history — the answer being
// "Claude Code started, and two of the MCP servers it boots are `jit run
// --profile ...`". The agent knew every one of those facts at the moment it
// prompted and stored none of them. It does now, so status can just say it.
//
// Prints nothing when this agent process has never unlocked: a freshly
// installed agent has no history to explain, and inventing lines that say
// "unknown" is worse than silence.
// Reads as a "Session" group in the same bulleted shape as Mounts below,
// NEWEST EVENT FIRST — and says so in its own heading. An unlock and the lock
// that ends it routinely land in the same second (an unlock, then a `jit
// vault` command locking on its way out), so two bare timestamped lines gave
// a reader no way to tell which came last; "2m ago" on both, in an order
// nothing declared, is not a history. Stating the order in the heading costs
// three words and removes the guess.
func printSessionProvenance(w io.Writer, st agent.Status) {
	if st.LastUnlock == nil {
		return
	}

	// While unlocked, the headline already says when the session WILL lock. A
	// "locked ..." bullet from the previous cycle would sit right under it,
	// flatly contradicting it — so the lock only appears once it's the truth.
	showLock := !st.Unlocked && st.LastLock != nil

	heading := "\nSession:"
	if showLock {
		heading = "\nSession (most recent first):"
	}
	fmt.Fprintln(w, heading)

	if showLock {
		l := st.LastLock
		cause := l.Cause
		if cause == "" {
			cause = "unknown cause"
		}
		fmt.Fprintf(w, "  • %s, %s\n", sessionWhen("locked", l.UnixTime), cause)
	}

	u := st.LastUnlock
	line := fmt.Sprintf("  • %s", sessionWhen("unlocked", u.UnixTime))
	if u.LaunchedBy != "" {
		// The half that answers "why now" — and the half nobody could get at
		// before, since a process's parent is gone from every log jit keeps.
		line += fmt.Sprintf(", launched by %s", u.LaunchedBy)
	}
	fmt.Fprintln(w, line)

	// The command goes on its own indented line, like a mount's last-read
	// detail: on the bullet it pushed the line past 120 characters, where it
	// wrapped and stopped being read at all.
	if u.By != "" {
		home, _ := os.UserHomeDir()
		fmt.Fprintf(w, "      %s\n", shortenCommand(home, u.By))
	}
}

// sessionWhen renders one event's verb and time — "locked    2m ago
// (12:58:59)" — padding the verb so the times line up under each other, which
// is what makes two bullets scan as a sequence rather than as two unrelated
// sentences.
func sessionWhen(verb string, unixTime int64) string {
	at := time.Unix(unixTime, 0)
	return fmt.Sprintf("%-8s %s ago (%s)", verb, humanAgo(time.Since(at)), at.Format("15:04:05"))
}

// printMountStatuses renders the per-mount section of `jit agent status`
// (GAPS.md #37/#48): a "Mounts:" group with one sorted bullet per mount —
// reveal state on the bullet line, the most recent read (what was served, to
// whom, when) on one indented line under it. It used to print a flat
// stream of "Revealed:"/"Last read:" lines in map iteration order, which
// read like a raw event log — a real, reported complaint: dense,
// randomly ordered between runs, the full absolute path repeated on
// every single line. Paths are ~-shortened for display only (the JSON
// snapshot keeps absolute paths, per this package's convention). A decoy
// read stays yellow with the fixing command inline — "my dev server got
// decoy values and nothing anywhere said so" was its own real, reported
// confusion — and the watcher-loop heads-up (GAPS.md #47) rides under
// its mount the same way, since excluding the file from the watcher is
// the one fix jit can't apply itself.
func printMountStatuses(w io.Writer, mounts []agent.MountRevealStatus) {
	if len(mounts) == 0 {
		return
	}
	sorted := make([]agent.MountRevealStatus, len(mounts))
	copy(sorted, mounts)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })

	home, _ := os.UserHomeDir()

	fmt.Fprintln(w, "\nMounts:")
	for _, m := range sorted {
		path := displayPath(home, m.Path)
		// A swapped mount is a plain compatibility file for the run(s)
		// listed below it — the FIFO, and so the whole reveal/decoy
		// vocabulary, doesn't apply while it's swapped, so this replaces
		// the revealed/not-revealed line rather than adding to it.
		if m.Swapped {
			fmt.Fprintf(w, "  • %s, compatibility file (real values are in the run's environment; the file is inert)\n", path)
			for _, g := range m.Grants {
				cmd := g.Command
				if cmd == "" {
					cmd = "unknown command"
				}
				fmt.Fprintf(w, "      swapped for jit run pid %d (%s) since %s ago, decoy mount returns when it exits\n", g.PID, cmd, humanAgo(time.Since(time.Unix(g.SinceUnix, 0))))
			}
			continue
		}
		switch {
		case m.Revealed:
			fmt.Fprintf(w, "  • %s, revealed, %s left\n", path, time.Duration(m.RevealedForSeconds)*time.Second)
		case m.RevealEndedUnix != 0:
			// Reveal expiry is lazy — nothing fires when a window ends — so
			// this line is the only place "the timer ended" is visible at
			// all; without it the revealed line just silently disappeared,
			// which read as "it never switched to hidden" (GAPS.md #48).
			fmt.Fprintf(w, "  • %s, not revealed (window ended %s ago)\n", path, humanAgo(time.Since(time.Unix(m.RevealEndedUnix, 0))))
		default:
			fmt.Fprintf(w, "  • %s, not revealed\n", path)
		}
		for _, g := range m.Grants {
			// A live run-scoped grant is the narrow counterpart of the
			// revealed line above it: real values, but only to one run's
			// process tree, only while that run lives.
			cmd := g.Command
			if cmd == "" {
				cmd = "unknown command"
			}
			fmt.Fprintf(w, "      serving real values to jit run pid %d (%s) since %s ago, until it exits\n", g.PID, cmd, humanAgo(time.Since(time.Unix(g.SinceUnix, 0))))
		}
		if ls := m.LastServe; ls != nil {
			reader := describeReader(ls)
			ago := humanAgo(time.Since(time.Unix(ls.UnixTime, 0)))
			switch {
			case ls.Decoy:
				_, _ = color.New(color.FgYellow).Fprintf(w, "      read %s ago by %s: decoy values, if that was your app, reveal and retry: jit agent reveal %s\n", ago, reader, path)
			case ls.GrantServed:
				fmt.Fprintf(w, "      read %s ago by %s: real values (run-scoped grant)\n", ago, reader)
			default:
				fmt.Fprintf(w, "      read %s ago by %s: real values\n", ago, reader)
			}
			if m.ReadsLastMinute >= readStormThreshold {
				_, _ = color.New(color.FgYellow).Fprintf(w, "      read %d times in the last minute, usually an editor or file watcher re-reading it in a loop; excluding this file from it stops the churn\n", m.ReadsLastMinute)
			}
		}
	}
}

// describeReader names whoever last read a mount, as precisely as jit can
// honestly claim — and no more.
//
// Three tiers, because there really are three states. A reader the scan caught
// outright is named flatly. One carried over from this mount's previous scan
// (still alive, still holding the file open, but this scan raced its open) is
// named as "likely", because it is an inference, and an audit line that
// overstates its confidence is worse than one that admits doubt. Only a reader
// jit has genuinely never seen falls back to "an unidentified process" — which
// used to be the answer even for an editor jit had identified by name seconds
// earlier.
//
// The launcher rides along for the same reason it does on an unlock line:
// "python3 read your Wiz credentials" is a fact you can't act on, and
// "python3, launched by claude" is one you can.
func describeReader(ls *agent.MountServeEvent) string {
	if ls.ReaderPath == "" {
		return "an unidentified process"
	}
	who := fmt.Sprintf("%s (pid %d)", filepath.Base(ls.ReaderPath), ls.ReaderPID)
	if ls.ReaderLikely {
		who = "likely " + who
	}
	if ls.ReaderLaunchedBy != "" {
		who += fmt.Sprintf(", launched by %s", ls.ReaderLaunchedBy)
	}
	return who
}

// humanAgo renders an elapsed duration at the precision a human scanning
// a status or plan line wants ("37s", "2m", "3h", "12d") — never "2m0s".
// Shared with jit migrate undo's backup ages, where "3d" vs "2m" is what
// tells a human whether edits-since-backup are plausible.
func humanAgo(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// validateAgentTTL rejects a --ttl the session logic can't honor: zero or
// negative makes every touchSession see an already-expired session, so
// EVERY operation re-prompts Touch ID — an agent that is all cost and no
// session, installed with no error message anywhere near the mistake.
func validateAgentTTL(ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("--ttl must be positive, got %s (a zero or negative TTL would re-prompt Touch ID on every single use)", ttl)
	}
	return nil
}

// agentRestartGrace is how long a dial keeps retrying when the agent is
// INSTALLED but not answering — the launchd respawn gap of `jit agent
// restart` or the agent's own stale-binary self-retirement, observed at
// 1–2s. Only applied when the plist exists (see agentClient): when it
// doesn't, "not answering" means "not installed" and waiting is pure
// delay.
const agentRestartGrace = 2 * time.Second

// agentClient returns a Client for this machine's agent socket without
// probing it first — Client's own calls wrap agent.ErrNotRunning when
// nothing is listening (see notRunningHint), so a Reachable() pre-flight
// would just dial the socket twice per command. When the agent is
// installed, the client rides out launchd's respawn gap (see
// agentRestartGrace) instead of misreporting a restarting agent as absent.
func agentClient() (*agent.Client, error) {
	root, err := vaultRootDir()
	if err != nil {
		return nil, err
	}
	c := agent.NewClient(agent.SocketPath(root))
	if agentInstalled() {
		c = c.WithDialRetry(agentRestartGrace)
	}
	return c, nil
}

// notRunningHint rewrites a Client call's dial failure into the actionable
// message the agent commands print — the raw error says the socket didn't
// answer, but the thing a human can DO about that differs: an installed
// agent that isn't answering wants a restart (and its log), one that was
// never installed wants installing.
func notRunningHint(err error) error {
	if !errors.Is(err, agent.ErrNotRunning) {
		return err
	}
	if agentInstalled() {
		return errors.New("the agent is installed but isn't answering, it may have crashed or be mid-restart; try `jit agent restart`, and `jit agent log` for its recent output")
	}
	return errors.New("no agent is running, run `jit agent install` first")
}

// xmlEscape escapes the five XML metacharacters for splicing a string
// into a plist <string> element.
func xmlEscape(s string) string {
	return xmlEscaper.Replace(s)
}

var xmlEscaper = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	`"`, "&quot;",
	"'", "&apos;",
)

// agentLogMaxBytes caps agent.log. 5MB is months of ordinary lines and
// still small enough to open casually; the previous generation is kept in
// agent.log.1, so a rotation never costs the recent past.
const agentLogMaxBytes = 5 << 20

// rotateAgentLog copies an over-cap agent.log aside to agent.log.1 and
// truncates the original IN PLACE. In place is the load-bearing part:
// launchd opened this file (StandardOutPath, O_APPEND) and that open fd IS
// this process's stdout — a rename would strand every future write on the
// rotated file, silently ending the live log. Truncating under an O_APPEND
// fd is safe: the next write lands at the new EOF. Called once per agent
// start, before this run's first log write, so the copy can't race a
// writer — this process is the only one and it hasn't written yet.
func rotateAgentLog(path string, maxBytes int64) error {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() <= maxBytes {
		return nil // missing (first ever start) or under cap
	}
	src, err := os.Open(path) // #nosec G304 -- jit's own log file under its config root
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()
	dst, err := os.OpenFile(path+".1", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) // #nosec G304 -- jit's own log path under its config root, not external input
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		return err
	}
	if err := dst.Close(); err != nil {
		return err
	}
	return os.Truncate(path, 0)
}

// lockedWriter serializes writes through a SHARED mutex — unlike
// stampedWriter's per-writer one — so `jit agent run` can put both its
// streams and the mid-run log rotation behind the same lock: the
// rotation's copy-then-truncate loses any line written between those two
// steps, and holding this mutex across both is what rules that out.
type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// agentLogRotateCheckInterval paces the mid-run cap re-check. One stat
// per ten minutes is nothing, and the worst case between checks (a
// watcher storm at GAPS.md #47's observed rate, already collapsed by the
// log-suppression there) stays far from filling a disk.
const agentLogRotateCheckInterval = 10 * time.Minute

// rotateAgentLogPeriodically re-applies the agent.log cap for the life of
// the agent process. The startup-only rotation left a hole: launchd keeps
// one process alive for weeks, so a mid-run storm had nothing to trim the
// log until the NEXT restart. Caller gates on running under launchd —
// see the gate's comment in agentRunCmd. mu is the shared writer mutex;
// the failure line is printed outside it because stderr writes back
// through that same mutex.
func rotateAgentLogPeriodically(ctx context.Context, logPath string, mu *sync.Mutex, stderr io.Writer) {
	ticker := time.NewTicker(agentLogRotateCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		mu.Lock()
		err := rotateAgentLog(logPath, agentLogMaxBytes)
		mu.Unlock()
		if err != nil {
			fmt.Fprintf(stderr, "jit agent: rotating %s: %v\n", logPath, err)
		}
	}
}

// agentPlistPath and agentInstalled live in agentinstalled.go (un-gated),
// so status.go's portable agent section can share them.

// agentDomainTarget and agentServiceTarget name the agent to launchctl's
// modern verbs (bootstrap/bootout/kickstart): the per-user GUI domain, and
// the agent's service inside it.
func agentDomainTarget() string {
	return fmt.Sprintf("gui/%d", os.Getuid())
}

func agentServiceTarget() string {
	return agentDomainTarget() + "/" + agentPlistLabel
}

// serviceNotLoaded reports whether a launchctl failure was specifically
// "this service isn't bootstrapped into the domain" — the exit-113 case
// kickstart/kill hit when the plist exists on disk but launchd has no live
// record of it. It is the one launchctl failure a bootstrap recovers, so it
// gates `jit agent restart`'s fallback; every other failure (a malformed
// plist, a permissions problem) is a real error to surface, not to paper
// over with a bootstrap that would fail the same way. Matched on the message
// text rather than the exit code because launchctl's numeric codes are
// undocumented and have shifted across macOS releases, while this wording
// has been stable.
func serviceNotLoaded(launchctlOutput []byte) bool {
	return bytes.Contains(bytes.ToLower(launchctlOutput), []byte("could not find service"))
}

// waitForAgentSocket polls until an agent answers the socket, or gives up.
// install/restart use it so their success message never races launchd's
// actual spawn of the process.
func waitForAgentSocket(root string, timeout time.Duration) bool {
	client := agent.NewClient(agent.SocketPath(root))
	for deadline := time.Now().Add(timeout); time.Now().Before(deadline); {
		if client.Reachable() {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

const agentPlistTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>agent</string>
		<string>run</string>
		<string>--ttl</string>
		<string>%s</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>%s</string>
	<key>StandardErrorPath</key>
	<string>%s</string>
</dict>
</plist>
`

func init() {
	agentRunCmd.Flags().DurationVar(&agentTTL, "ttl", 15*time.Minute, "how long an unlocked session stays cached before auto-locking")
	agentInstallCmd.Flags().DurationVar(&agentInstallTTL, "ttl", 15*time.Minute, "how long an unlocked session stays cached before auto-locking, baked into the installed plist")
	agentInstallCmd.Flags().BoolVarP(&agentInstallYes, "yes", "y", false, "skip the confirmation prompt and install immediately")
	agentRevealCmd.Flags().DurationVar(&revealForDuration, "for", 5*time.Minute, "how long to serve real content (clamped to 10m)")
	agentRevealCmd.Flags().BoolVarP(&revealQuiet, "quiet", "q", false, "suppress the success message, for embedding in a pre-run hook")
	agentStatusCmd.Flags().StringVar(&agentStatusFormat, "format", "text", `output format: "text" (default) or "json"`)
	agentHistoryCmd.Flags().StringVar(&agentHistoryFormat, "format", "text", `output format: "text" (default) or "json"`)
	agentLogCmd.Flags().IntVarP(&agentLogLines, "lines", "n", 50, "how many trailing lines to print")
	agentLogCmd.Flags().BoolVarP(&agentLogFollow, "follow", "f", false, "keep printing new lines as the agent writes them (Ctrl-C to stop)")
	agentCmd.AddCommand(agentRunCmd, agentInstallCmd, agentUninstallCmd, agentRestartCmd, agentUnlockCmd, agentLockCmd, agentStatusCmd, agentHistoryCmd, agentLogCmd, agentRevealCmd)
	rootCmd.AddCommand(agentCmd)
}
