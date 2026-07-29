// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

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

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/consent"
	"github.com/jitpass/jit/internal/keychainwrap"
	"github.com/jitpass/jit/internal/screenlock"
	"github.com/jitpass/jit/internal/termtext"
)

// The agent releases each fetcher's cached MEK as soon as it has copied the
// key out, via a runtime type assertion (agent.closeFetcher). This is the
// compile-time half: if Wrapper's Close ever changes shape, the build breaks
// here instead of the assertion quietly failing to match and restoring a
// plaintext master key that outlives every lock, screen-lock and sleep wipe.
var _ agent.ClosableFetcher = (*keychainwrap.Wrapper)(nil)

var agentTTL time.Duration

// agentConsent turns on per-process credential consent in the running service
// (design/per-process-credential-consent.md). ON by default (the flag's default
// is true, and every installed plist bakes its state explicitly); a user turns
// it off with `jit service consent off`, which writes `--consent=false`.
var agentConsent bool

// agentStatusFormat is agentStatusCmd's --format flag (GAPS.md #22).
var agentStatusFormat string

var serviceCmd = &cobra.Command{
	Use:     "service",
	GroupID: groupService,
	// See runCommandGroup: without a Run of its own, `jit service consnt
	// off` printed help and exited 0, leaving per-process consent silently
	// ON when a script believed it had turned it off.
	RunE:        runCommandGroup,
	Annotations: commandGroupAnnotations(),
	Short:       "Manage jit's background service (the daemon that holds your session and serves mounts)",
	Long: "jit runs a small background service: a login-time daemon that keeps one\n" +
		"unlocked session other jit commands share, instead of each one prompting\n" +
		"Touch ID separately, and that serves any live-mounted .env files jit migrate\n" +
		"has created.\n\n" +
		"It is a solid part of jit, not an optional add-on: it sets itself up the\n" +
		"first time a command needs it (a `jit run` that serves a mount, a `jit\n" +
		"migrate`, or `jit unlock`), starts at every login, and restarts itself if it\n" +
		"crashes. There is no install step. These subcommands are for the rare times\n" +
		"you want to manage it by hand: `jit service ttl` shows or changes how long a\n" +
		"session stays unlocked, `jit service status` reports its health, `jit service\n" +
		"restart` restarts it (and brings it back if it ever stopped), and `jit\n" +
		"service log` shows its own output. It goes away when you remove jit itself.\n" +
		"The service process itself needs no Touch ID just to keep running, only your\n" +
		"unlocked session inside it locks after the TTL of inactivity (default 5m),\n" +
		"prompting again on next use.\n\n" +
		"To control the session itself, use the top-level `jit unlock` and `jit lock`.\n" +
		"To see what the service has done (unlocks, denials, mount reads), use\n" +
		"`jit audit`.\n\n" +
		"A live-mounted file shows fake-looking values by default. Real values flow\n" +
		"only to a `jit run` grant's own process tree: `jit run --live` for a project\n" +
		"mount, `jit run --with` for a global credential. Unlocking the vault never\n" +
		"makes a mount serve real values on its own.",
}

// agentRunCmd is what the installed LaunchAgent's plist actually executes.
// Running it directly (not via launchd) works too, in the foreground.
var agentRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the service in the foreground (normally started by launchd, not by hand)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateAgentTTL(agentTTL); err != nil {
			return fmt.Errorf("jit service run: %w", err)
		}
		root, err := vaultRootDir()
		if err != nil {
			return fmt.Errorf("jit service run: %w", err)
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

		// A TTL this process cannot run with at all fails loudly above; one it
		// can merely not honor in full is clamped here and said out loud. The
		// difference matters at startup specifically: this command is what an
		// installed plist executes, and a plist written before the hard
		// session ceiling existed can legitimately carry `--ttl 24h`. Refusing
		// that would leave the agent silently not running after an upgrade,
		// with the only symptom a line in a log nobody is watching — a worse
		// outcome than a session that locks earlier than a stale config asked
		// for. Setting a too-long TTL by hand is still rejected outright, at
		// the one moment there is a person there to read the reason
		// (validateAgentTTLSetting).
		if agentTTL > agent.DefaultMaxSessionAge {
			fmt.Fprintf(stderr, "jit service: --ttl %s exceeds the %s maximum session age; using %s instead (a session ends at that ceiling however actively it is used)\n",
				agentTTL, agent.DefaultMaxSessionAge, agent.DefaultMaxSessionAge)
			agentTTL = agent.DefaultMaxSessionAge
		}

		// Cap the log before this run's first write. The log otherwise
		// grows for the machine's lifetime — a single watcher-loop
		// afternoon once produced 635k lines (GAPS.md #47), and launchd
		// keeps appending to the same file across every restart forever.
		// Under launchd this is re-checked periodically too
		// (rotateAgentLogPeriodically): a startup-only cap left a storm
		// free to grow the log unboundedly until the NEXT restart, which
		// can be weeks away.
		if err := rotateAgentLog(logPath, agentLogMaxBytes); err != nil {
			fmt.Fprintf(stderr, "jit service: rotating %s: %v\n", logPath, err)
		}

		server := agent.NewServer(agent.SocketPath(root), func() agent.MEKFetcher { return keychainwrap.New() }, agentTTL)
		home, _ := os.UserHomeDir()
		mounts := &mountManager{root: root, home: home, keyWrapper: server, stdout: stdout, stderr: stderr}
		if agentConsent {
			// Align the consent cache lifetime with the unlock session's, so an
			// approval never outlives the session it rode in on. mounts.consent
			// routes the FIFO credential mounts (gcp/npm/netrc) through the same
			// engine, best-effort.
			server.Consent = consent.New(agentTTL)
			mounts.consent = server
			fmt.Fprintln(stdout, "jit service: per-process credential consent ENABLED (prompting on credential reads)")
		}
		server.OnUnlock = mounts.start
		server.OnLock = mounts.stop
		server.OnRefresh = mounts.start
		server.OnRevealPID = mounts.revealForPID
		server.OnCanGrant = mounts.canGrantAll
		server.OnDescribeGrant = mounts.describeGrant
		server.OnStopMount = mounts.stopMount
		server.OnMountStatus = mounts.mountRevealStatuses
		// Best-effort "how were you asked" for the audit trail: probe once per
		// fresh challenge whether Touch ID is currently usable, so a denial or
		// unlock records "Touch ID or device passcode" on a Mac with biometry
		// and "device passcode" on one without. Never an auth decision — the OS
		// challenge (LAPolicyDeviceOwnerAuthentication) accepts either anyway.
		server.AuthMethodFn = func() string {
			if keychainwrap.BiometryAvailable() {
				return "Touch ID or device passcode"
			}
			return "device passcode"
		}

		// Durable session history: every event goes to agent-history.jsonl,
		// the one structured trail `jit audit` reads (merged with the command
		// log), and the previous processes' events are seeded back into the
		// ring — so `jit audit` can answer for prompts that happened before the
		// most recent launchd restart, which is exactly when the question gets
		// asked (restarts happen at login; the question is asked the next
		// morning, about yesterday). The start marker is what keeps the
		// restored sequence honest: a session that "just locked" across a
		// restart didn't lock, the process died.
		//
		// This file is now the SOLE home of session events: they used to be
		// double-written here and as prose into agent.log, so the same unlock
		// sat in two places and agent.log doubled as an event log. It doesn't
		// anymore — agent.log is the raw operational output (startup, mount
		// notes, serve-error prose, panics) that `jit service log` tails, and
		// `jit audit` is the one place the events themselves are read, filtered,
		// and followed.
		hist := newHistoryLog(root, stderr)
		hist.trim()
		hist.append(agent.SessionEvent{
			UnixTime: time.Now().Unix(),
			Kind:     agent.KindStart,
			Cause:    fmt.Sprintf("build %s", agent.BuildID()),
		})
		server.SeedHistory(hist.load(agent.MaxSessionEvents))
		server.OnSessionEvent = func(e agent.SessionEvent) {
			hist.append(e)
		}
		// Socket-boundary failures (a rejected peer, a malformed request, the
		// accept loop dying) become durable KindError events in the same trail,
		// so `jit audit` sees them and a SIEM can ship them — a rejected peer in
		// particular used to be logged nowhere. A prose line still goes to the
		// raw operational log so `jit service log` shows it in context too.
		server.OnServeError = func(e agent.SessionEvent) {
			hist.append(e)
			fmt.Fprintf(stderr, "jit service: %s\n", e.Cause)
		}

		if err := server.Listen(); err != nil {
			return fmt.Errorf("jit service run: %w", err)
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
		// runCtx additionally ends when the service retires ITSELF — the
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
			fmt.Fprintf(stderr, "jit service: screen-lock/sleep watch unavailable (%v), sessions will lock on the idle TTL alone\n", err)
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
					fmt.Fprintf(stdout, "jit service: the jit binary on disk changed (this process is build %s), exiting while the session is locked so launchd restarts the service on the current build\n", agent.BuildID())
					endRun()
				})
			}
			go rotateAgentLogPeriodically(runCtx, logPath, &logMu, stderr)
		}

		fmt.Fprintf(stdout, "jit service listening on %s (session TTL %s, build %s)\n", agent.SocketPath(root), agentTTL, agent.BuildID())

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
			fmt.Fprintf(stderr, "jit service: screen-lock/sleep events disabled: %v\n", err)
		}
		err = <-serveErr
		if err != nil && !errors.Is(err, context.Canceled) {
			return fmt.Errorf("jit service run: %w", err)
		}
		fmt.Fprintln(stdout, "jit service stopped.")
		return nil
	},
}

// serviceTTLCmd shows or changes the session TTL. It replaces the old
// `jit service install --ttl`: there is no "install" step anymore (the service
// is a solid part of the app and sets itself up on first use, GAPS.md #18), so
// the one thing the install command uniquely offered — picking the session
// length — lives here as its own discoverable verb. Setting a value also
// creates the login item if it somehow wasn't there yet, so this doubles as
// "make sure the service exists, with this TTL."
var serviceTTLCmd = &cobra.Command{
	Use:   "ttl [duration]",
	Short: "Show or change how long a session stays unlocked before it auto-locks",
	Long: "With no argument, prints the session TTL the background service is currently\n" +
		"configured with. With a duration (e.g. 30s, 10m, 1h), changes it.\n\n" +
		"The TTL is how long an unlocked session stays cached after your last Touch\n" +
		"ID prompt before it locks itself, so the next use prompts again (default\n" +
		"5m). It is baked into the service's login item, so a change persists across\n" +
		"logins and reboots, not just this one.\n\n" +
		"It is an INACTIVITY timeout, so use pushes it back — and a session also ends\n" +
		"8 hours after the unlock that started it, however busy it has been. Values\n" +
		"above that ceiling are refused rather than accepted and quietly ignored: an\n" +
		"idle timeout longer than the maximum session age could never be reached.\n\n" +
		"Changing it restarts the background service, so the current session is\n" +
		"dropped and the next vault use prompts Touch ID once. Your vault and the\n" +
		"session history are untouched.",
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			ttl, ok := configuredAgentTTL()
			if !ok {
				fmt.Fprintf(cmd.OutOrStdout(), "The background service isn't running yet, so no TTL is set; the default %s applies once it starts (it starts on its own the first time you use jit).\n", agentInstallDefaultTTL)
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Session TTL: %s (a session locks this long after your last Touch ID prompt).\n", ttl)
			return nil
		}
		d, err := time.ParseDuration(args[0])
		if err != nil {
			return fmt.Errorf("jit service ttl: %q is not a duration, try 30s, 10m, or 1h: %w", args[0], err)
		}
		// Validated before it reaches the plist: a zero or negative TTL bakes a
		// service that re-prompts on every use, and the error would otherwise
		// surface only in the service log at the next launchd start.
		if err := validateAgentTTLSetting(d); err != nil {
			return fmt.Errorf("jit service ttl: %w", err)
		}
		// installAgentService writes the plist with the new --ttl and reloads
		// it, creating the login item if it wasn't there yet. Preserve the
		// consent setting across the TTL change.
		_, running, err := installAgentService(d, configuredAgentConsent())
		if err != nil {
			return fmt.Errorf("jit service ttl: %w", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Session TTL set to %s. The background service restarted, so the next vault use prompts Touch ID once.\n", d)
		if !running {
			fmt.Fprintln(cmd.OutOrStdout(), hlCmds("It's still starting up in the background; give `jit service status` a few seconds."))
		}
		return nil
	},
}

// configuredAgentTTL reads the session TTL baked into the installed launchd
// plist's ProgramArguments (the `--ttl <value>` pair installAgentService
// wrote). Returns ok=false when the service isn't installed or the plist has no
// readable --ttl, so a caller can tell "not set up" from a real value rather
// than reporting a misleading zero.
func configuredAgentTTL() (time.Duration, bool) {
	plistPath, err := agentPlistPath()
	if err != nil {
		return 0, false
	}
	data, err := os.ReadFile(plistPath) // #nosec G304 -- jit's own launchd plist under the user's LaunchAgents dir
	if err != nil {
		return 0, false
	}
	values := plistStringValues(data)
	for i := 0; i+1 < len(values); i++ {
		if values[i] == "--ttl" {
			if d, perr := time.ParseDuration(values[i+1]); perr == nil {
				return d, true
			}
			return 0, false
		}
	}
	return 0, false
}

// configuredAgentConsent reports whether per-process consent is baked into the
// installed plist. Consent is ON by default, so this returns true unless the
// plist EXPLICITLY carries `--consent=false` (what `jit service consent off`
// writes). An absent flag — a fresh install, or a plist written before consent
// existed — reads as the default: on. Callers use it to preserve a user's
// explicit choice across a TTL change or an upgrade.
func configuredAgentConsent() bool {
	plistPath, err := agentPlistPath()
	if err != nil {
		return true
	}
	data, err := os.ReadFile(plistPath) // #nosec G304 -- jit's own launchd plist under the user's LaunchAgents dir
	if err != nil {
		return true
	}
	for _, v := range plistStringValues(data) {
		switch v {
		case "--consent=false":
			return false
		case "--consent", "--consent=true":
			return true
		}
	}
	return true
}

// serviceConsentCmd shows or sets per-process credential consent. Like
// serviceTTLCmd it reinstalls the plist (preserving the TTL) so the setting
// survives restarts and logins, then reloads the service so it takes effect now.
var serviceConsentCmd = &cobra.Command{
	Use:   "consent [on|off]",
	Short: "Show or set per-process credential consent",
	Long: "Per-process credential consent (on by default): the background service\n" +
		"prompts a fresh Touch ID the first time each tool reaches for a credential\n" +
		"(AWS, git, docker, kube, gcloud/sops/npm/netrc keys), naming who is asking,\n" +
		"and remembers your answer for the session. It closes the window where any\n" +
		"process running as you can use a migrated credential silently while your\n" +
		"vault is unlocked.\n\n" +
		"Saying no is meant to be cheap. A refused prompt is not remembered as a\n" +
		"lasting \"no\" — it can't be, since a decline and a keychain failure look the\n" +
		"same from here — so instead it pauses that caller for a few seconds, then\n" +
		"longer if it keeps asking, and the prompt tells you how many times it has\n" +
		"already been refused. Nothing is locked out: the next genuine attempt still\n" +
		"asks, and an approval (or a fresh `jit unlock`) clears the pause.\n\n" +
		"With no argument, prints whether it's on. `on`/`off` set it and restart the\n" +
		"service; turning it OFF requires a fresh Touch ID/passcode, since disabling\n" +
		"the guard reopens the window it closes. Use `jit run --trust -- <cmd>` to\n" +
		"pre-authorize a whole run's tree so it isn't prompted.",
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			if configuredAgentConsent() {
				fmt.Fprintln(cmd.OutOrStdout(), "Per-process credential consent is ON.")
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), hlCmds("Per-process credential consent is OFF. Turn it on with `jit service consent on`."))
			}
			return nil
		}
		var on bool
		switch strings.ToLower(args[0]) {
		case "on", "true", "enable", "enabled":
			on = true
		case "off", "false", "disable", "disabled":
			on = false
		default:
			return fmt.Errorf("jit service consent: expected 'on' or 'off', got %q", args[0])
		}
		// Turning consent OFF reopens the exact window the feature exists to
		// close, so it must prove a human is present — never ride an unlocked
		// agent session. Turning it ON (or reading state) only strengthens the
		// guard and needs no gate. Auth BEFORE writing the plist: a declined
		// gesture must leave the setting untouched.
		if !on {
			if err := requireConsentOffPresence(); err != nil {
				return fmt.Errorf("jit service consent off: %w", err)
			}
		}
		ttl, ok := configuredAgentTTL()
		if !ok {
			ttl = agentInstallDefaultTTL
		}
		if _, _, err := installAgentService(ttl, on); err != nil {
			return fmt.Errorf("jit service consent: %w", err)
		}
		if on {
			fmt.Fprintln(cmd.OutOrStdout(), "Per-process credential consent is now ON. The service restarted; the next credential use prompts Touch ID.")
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), "Per-process credential consent is now OFF. The service restarted.")
		}
		return nil
	},
}

// requireConsentOffPresence forces a fresh Touch ID/passcode gesture before
// per-process consent can be DISABLED. Disabling consent reopens the exact
// window it exists to close — any process running as you using a migrated
// credential silently while the vault is unlocked — so flipping it off must
// prove a human is present, not merely inherit an unlocked agent session.
// Mirrors requireUninstallPresence: challenge through the vault's
// biometric-gated MEK fetch when there are secrets to protect (which also
// audit-stamps the fresh auth), falling back to a bare LocalAuthentication
// prompt when the vault is empty or unreadable.
//
// Honest limit: this gates the `jit service consent off` COMMAND, not the plist
// it writes. An attacker with code execution as you could rewrite the LaunchAgent
// plist and reload it directly, exactly as they could `rm` the files uninstall
// guards — the gate is anti-footgun and defense-in-depth over a scripted flip,
// not a hard boundary (RFC.md B6/GAPS.md #1 already concede that adversary).
func requireConsentOffPresence() error {
	const reason = "authorize turning off per-process credential consent"
	if vaultSecretCount() > 0 {
		v, err := openVaultFreshAuth()
		if err != nil {
			return err
		}
		return requireFreshUserPresence(v, reason)
	}
	return keychainwrap.Challenge(reason)
}

// plistStringValues returns the text of every <string>…</string> element in a
// plist, in order — enough to walk ProgramArguments without a full XML parser.
// The values it's used to match (the literal "--ttl" and a duration) carry no
// XML entities, so it deliberately does not unescape.
func plistStringValues(data []byte) []string {
	const open, closing = "<string>", "</string>"
	var out []string
	s := string(data)
	for {
		i := strings.Index(s, open)
		if i < 0 {
			return out
		}
		s = s[i+len(open):]
		j := strings.Index(s, closing)
		if j < 0 {
			return out
		}
		out = append(out, s[:j])
		s = s[j+len(closing):]
	}
}

// agentInstallDefaultTTL is the session TTL used whenever the service is set
// up without a TTL chosen explicitly: the silent first-use auto-install
// (ensureAgentInstalled) and `jit service restart` recreating a missing login
// item. `jit service ttl <d>` overrides it. One constant so those paths can't
// drift on the default.
const agentInstallDefaultTTL = 5 * time.Minute

// installAgentService writes the launchd LaunchAgent plist that runs
// `jit service run --ttl <ttl>` and (re)loads it, returning the plist path and
// whether the socket answered within a short wait. It is the shared core of
// every path that creates or reconfigures the service — the silent first-use
// auto-install (ensureAgentInstalled), `jit service ttl` changing the session
// length, and `jit service restart` recreating a missing login item — so none
// of them can drift on how the service is written or bootstrapped. It performs
// NO consent prompt of its own: the service is a solid part of the app that
// sets itself up on first use, and the plist is a low-privilege, fully
// reversible user LaunchAgent.
func installAgentService(ttl time.Duration, consent bool) (plistPath string, running bool, err error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", false, err
	}
	// Resolve the /usr/local/bin install symlink (or any shim) to the real
	// binary: launchd re-execs this exact path at every login, and a path that
	// later moves out from under it would leave the service pointing at nothing.
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return "", false, err
	}
	plistPath, err = agentPlistPath()
	if err != nil {
		return "", false, err
	}
	root, err := vaultRootDir()
	if err != nil {
		return plistPath, false, err
	}
	logPath := filepath.Join(root, "agent.log")

	// exePath/logPath are filesystem paths and can legally contain XML
	// metacharacters (& is common in directory names) — splicing one into the
	// plist unescaped produces a file launchctl rejects, or worse, misparses.
	// Consent is ON by default, so its state is baked into ProgramArguments
	// EXPLICITLY (`--consent` on, `--consent=false` off) — that's what lets a
	// user who turned it off keep it off across a reinstall/upgrade, instead of
	// an absent flag being ambiguous between "off" and "never set". A plist with
	// neither (one written before consent existed) reads as the default: on.
	consentArg := "\n\t\t<string>--consent</string>"
	if !consent {
		consentArg = "\n\t\t<string>--consent=false</string>"
	}
	plist := fmt.Sprintf(agentPlistTemplate, agentPlistLabel, xmlEscape(exePath), ttl.String(), consentArg, xmlEscape(logPath), xmlEscape(logPath))
	if err := os.MkdirAll(filepath.Dir(plistPath), 0o700); err != nil {
		return plistPath, false, err
	}
	if err := os.WriteFile(plistPath, []byte(plist), 0o600); err != nil {
		return plistPath, false, err
	}

	// reloadAgentService boots out any previously-running instance before
	// bootstrapping the just-written plist — bootstrap on an already-loaded
	// label fails outright, and a re-install to change --ttl must take effect
	// now, not at next login. The same helper `jit service restart` uses, so
	// so those callers can't drift on how they (re)load.
	out, err := reloadAgentService(plistPath)
	if err != nil {
		return plistPath, false, fmt.Errorf("launchctl bootstrap failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	// launchctl bootstrap returns before the service process has spawned and
	// bound its socket — a real, observed confusion where `jit service status`
	// typed right after a successful install said "not running" for the ~2s
	// launchd took to actually start it. Wait briefly so "installed" also
	// means "answering."
	running = waitForAgentSocket(root, 5*time.Second)
	return plistPath, running, nil
}

// ensureAgentInstalled silently sets up and starts the launchd agent the first
// time a command that actually needs a live agent finds none installed — so
// the service is always just there. It is a solid part of "the app" (the same
// jit binary in daemon mode), not a separate setup step, so this path does NOT
// prompt: the caller already ran something (a `jit run` that needs a mount
// served, a `jit migrate` that just produced one, `jit unlock`) that can't
// proceed without it, and the plist is a low-privilege user LaunchAgent that
// goes away when jit itself is removed.
//
// Best-effort and idempotent. An already-installed agent is left untouched
// (didInstall false): running/crashed/mid-restart is the callers' existing
// territory — dial retry, restart advice — not ours. Any install failure is
// swallowed so the caller falls back to its own no-agent path (an independent
// unlock, or notRunningHint's advice) rather than failing the user's real
// command because a background convenience didn't take. Returns whether it just
// installed the service, and whether the service is answering now.
func ensureAgentInstalled() (didInstall, running bool) {
	if agentInstalled() {
		return false, false
	}
	_, running, err := installAgentService(agentInstallDefaultTTL, true)
	if err != nil {
		return false, false
	}
	return true, running
}

var agentRestartCmd = &cobra.Command{
	Use:   "restart",
	Short: "Restart the background service (picks up a new binary, or brings a stopped one back)",
	Long: "Restarts jit's background service. Two uses: the immediate fix when\n" +
		"`jit service status` warns that the running service predates the jit binary\n" +
		"on disk (the service also retires itself onto the new binary automatically,\n" +
		"but only once its session is locked and no prompt is pending; restart is for\n" +
		"wanting it now), and the way to bring the service back if it stopped.\n\n" +
		"If the login item is missing entirely (it was never started, or was\n" +
		"removed), this recreates it — jit keeps the service installed as a matter of\n" +
		"course, so there is no separate install step.\n\n" +
		"The in-memory session is lost, so the next vault use prompts Touch ID\n" +
		"again, and live-mounted files serve placeholder values until then.\n" +
		"Session history survives, it's durable.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		plistPath, err := agentPlistPath()
		if err != nil {
			return fmt.Errorf("jit service restart: %w", err)
		}
		if _, statErr := os.Stat(plistPath); os.IsNotExist(statErr) {
			// No login item yet (never started, or uninstalled). Rather than
			// dead-end, create it: restart is the single "get the service
			// running" command, and the service is meant to always be present.
			// Default TTL and default (on) consent, since a missing plist has no
			// configured value to preserve — `jit service ttl <d>` and
			// `jit service consent off` change them afterward.
			root, rerr := vaultRootDir()
			if rerr != nil {
				return fmt.Errorf("jit service restart: %w", rerr)
			}
			if _, _, ierr := installAgentService(agentInstallDefaultTTL, true); ierr != nil {
				return fmt.Errorf("jit service restart: %w", ierr)
			}
			if !waitForAgentSocket(root, 5*time.Second) {
				fmt.Fprintln(cmd.OutOrStdout(), hlCmds("Started the background service; it's still coming up, give `jit service status` a few seconds."))
				return nil
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Started the background service. The next vault use will prompt Touch ID.")
			return nil
		} else if statErr != nil {
			return fmt.Errorf("jit service restart: %w", statErr)
		}
		// bootout + bootstrap (reloadAgentService) restarts a running agent
		// AND recovers one launchd has dropped (the plist on disk with no live
		// service, e.g. after a crash loop launchd gave up on or an upgrade
		// that unloaded the old one) in a single unconditional sequence. It
		// replaced a kickstart -k that only worked while the service was still
		// bootstrapped and otherwise dead-ended on "Could not find service" —
		// and it needs no fragile parsing of launchctl's undocumented,
		// localizable error text to decide which state we're in.
		if out, err := reloadAgentService(plistPath); err != nil {
			return fmt.Errorf("jit service restart: reloading the launchd service failed: %w (%s); `jit service log` shows recent output", err, strings.TrimSpace(string(out)))
		}
		root, err := vaultRootDir()
		if err != nil {
			return fmt.Errorf("jit service restart: %w", err)
		}
		// Same wait as install, same reason: "Restarted" must mean the new
		// process is actually answering, or status contradicts us moments
		// later.
		if !waitForAgentSocket(root, 5*time.Second) {
			fmt.Fprintln(cmd.OutOrStdout(), hlCmds("Restart requested, the service is still starting up in the background; give `jit service status` a few seconds."))
			return nil
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Restarted, the service is now running the current binary. The next vault use will prompt Touch ID.")
		return nil
	},
}

var unlockCmd = &cobra.Command{
	Use:     "unlock",
	GroupID: groupService,
	Short:   "Unlock jit's session now (prompts Touch ID if needed)",
	Long: "Unlocks the shared session jit's background service holds, prompting Touch ID\n" +
		"or your device passcode if it isn't already unlocked. Pre-warms it so a\n" +
		"following jit run / vault get / export doesn't stop to prompt. It locks\n" +
		"itself again after the session --ttl of inactivity, at the 8-hour maximum\n" +
		"session age whichever comes first, or on `jit lock` sooner.\n\n" +
		"An unlock that actually prompts you also clears any consent pauses: a\n" +
		"refused credential prompt holds that caller off for a few seconds, and you\n" +
		"standing at the keyboard is exactly the \"now\" that refusal withheld. An\n" +
		"unlock while the session is already open prompts nobody, so it clears\n" +
		"nothing — otherwise any process could reset the pause by asking for one.\n\n" +
		"If the background service isn't set up yet, this sets it up first: `unlock`\n" +
		"is the \"get me a session\" intent, so there's nothing extra to run by hand.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		// No service yet? Set one up silently rather than erroring with "run
		// starting the service first — `unlock` IS the "get me a session"
		// intent, so absence is a setup step to do, not a failure to report.
		ensureAgentInstalled()
		c, err := agentClient()
		if err != nil {
			return fmt.Errorf("jit unlock: %w", err)
		}
		_, remaining, err := c.Unlock()
		if err != nil {
			return fmt.Errorf("jit unlock: %w", notRunningHint(err))
		}
		fmt.Fprint(cmd.OutOrStdout(), hlCmds(fmt.Sprintf("Unlocked, locks automatically after %s of inactivity (or `jit lock` sooner).\n", remaining.Round(time.Second))))
		return nil
	},
}

var lockCmd = &cobra.Command{
	Use:     "lock",
	GroupID: groupService,
	Short:   "Lock jit's session immediately, without waiting for the TTL",
	Long: "Locks the shared session jit's background service holds, right now, instead\n" +
		"of waiting out whichever bound would end it first — the idle --ttl or the\n" +
		"8-hour maximum session age. The next vault use prompts Touch ID again, and\n" +
		"live-mounted files serve placeholder values until then.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := agentClient()
		if err != nil {
			return fmt.Errorf("jit lock: %w", err)
		}
		if err := c.Lock(); err != nil {
			return fmt.Errorf("jit lock: %w", notRunningHint(err))
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Locked.")
		return nil
	},
}

// agentStatusResult is `jit service status`'s --format json shape
// (GAPS.md #22). LocksInSeconds is only meaningful (and only nonzero) when
// Running && Unlocked — omitted rather than zero-valued-but-misleading
// when the service isn't running at all or is already locked.
type agentStatusResult struct {
	Running bool `json:"running"`
	// Installed is whether the launchd plist exists — with Running false,
	// it's what separates "crashed or mid-restart" (launchd should be
	// respawning it; `jit service restart` forces it) from "never set up"
	// (only jit reinstalling it, via any use or `jit service restart`, helps). A script alerting on dead agents
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
	// Omitted (not zero-valued) when the service has never unlocked: "no
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
	// predates the binary on disk. Empty when the service isn't running.
	Build string `json:"build,omitempty"`
	// Version is the running agent PROCESS's release version — Build's
	// release-scale counterpart. Empty when the service isn't running or
	// predates the field.
	Version string `json:"version,omitempty"`
}

var agentStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show whether the service is running, and whether its session is unlocked",
	Long: "Reports whether jit's background service is running and, if so, whether its session is\n" +
		"unlocked. --format json prints a machine-readable snapshot instead of the\n" +
		"default text summary.",
	Args: cobra.NoArgs,
	// See doctor.go's SilenceUsage comment for why: a --format json
	// snapshot must never have cobra's usage text appended to it.
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateOutputFormat(agentStatusFormat); err != nil {
			return fmt.Errorf("jit service status: %w", err)
		}

		client, err := agentClient()
		if err != nil {
			return fmt.Errorf("jit service status: %w", err)
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
				fmt.Fprintln(cmd.OutOrStdout(), installedNotRunningAdvice("jit's background service is"))
				return nil
			}
			fmt.Fprintln(cmd.OutOrStdout(), hlCmds("jit's background service is not running. Run `jit service restart` to start it (or just use jit and it starts on its own)."))
			return nil
		}
		if err != nil {
			return fmt.Errorf("jit service status: %w", err)
		}

		if agentStatusFormat == "json" {
			result := agentStatusResult{Running: true, Installed: agentInstalled(), Unlocked: st.Unlocked, Mounts: st.Mounts, LastUnlock: st.LastUnlock, LastLock: st.LastLock, PendingUnlock: st.PendingUnlock, Build: st.Build, Version: st.Version}
			if st.Unlocked {
				result.LocksInSeconds = int64(st.Remaining.Round(time.Second).Seconds())
			}
			return writeJSON(cmd.OutOrStdout(), result)
		}
		if st.Unlocked {
			fmt.Fprintf(cmd.OutOrStdout(), "jit's background service is running and unlocked (locks in %s).\n", st.Remaining.Round(time.Second))
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), "jit's background service is running and locked.")
		}
		printPendingUnlock(cmd.OutOrStdout(), st.PendingUnlock)
		fmt.Fprintf(cmd.OutOrStdout(), "Versions: service %s; CLI %s.\n", versionBuild(st.Version, st.Build), versionBuild(agent.Version(), agent.BuildID()))
		printSessionProvenance(cmd.OutOrStdout(), st)
		printMountStatuses(cmd.OutOrStdout(), st.Mounts)
		if warning := agentBuildMismatchLine(st.Build); warning != "" {
			_, _ = cWarn.Fprintf(cmd.OutOrStdout(), "%s\n", hlCmds(warning))
		}
		return nil
	},
}

// agentLogLines and agentLogFollow are `jit service log`'s flags.
var agentLogLines int
var agentLogFollow bool

// agentLogRaw prints the log file's bytes exactly as written, skipping the
// human rendering. The formatted view drops repeated prefixes and shortens
// paths, which is what makes it readable and also what would break a grep or
// a pasted bug report — so the untouched bytes stay one flag away.
var agentLogRaw bool

// agentLogPollInterval paces --follow's growth checks — comfortably
// under a human's "is it live?" threshold without hammering stat.
const agentLogPollInterval = 500 * time.Millisecond

var agentLogCmd = &cobra.Command{
	Use:   "log",
	Short: "Show the service's raw operational output (startup, mount notes, serve errors)",
	Long: "Prints the tail of the service's raw output log: the timestamped operational\n" +
		"lines the daemon prints as it runs, startup and shutdown, mount notes (with\n" +
		"who read them), serve-error detail, and anything a crash leaves behind.\n\n" +
		"This is the low-level debug view, not the audit trail. The session events\n" +
		"themselves, every unlock, denial, lock, use, and refused peer, live in the\n" +
		"structured trail that `jit audit` reads, filters, and follows; they are no\n" +
		"longer duplicated as prose here. Reach for `jit audit` for \"what happened and\n" +
		"who did it\", and for this when a serve error or a startup problem needs its\n" +
		"raw context.\n\n" +
		"The file lives alongside the vault as agent.log (the previous generation\n" +
		"is kept as agent.log.1 after rotation). This command exists because the\n" +
		"investigations that need the log are exactly the ones where hunting down\n" +
		"its path is one obstacle too many.",
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		root, err := vaultRootDir()
		if err != nil {
			return fmt.Errorf("jit service log: %w", err)
		}
		logPath := filepath.Join(root, "agent.log")
		out := cmd.OutOrStdout()

		data, err := os.ReadFile(logPath) // #nosec G304 -- jit's own log file under its config root
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("jit service log: %w", err)
		}
		if os.IsNotExist(err) && !agentLogFollow {
			// Not an error: an empty history is a normal state on a machine
			// where the service hasn't run, and the useful output is what
			// would make one exist.
			fmt.Fprint(out, hlCmds(fmt.Sprintf("No service log yet at %s, it's written once the service runs; it starts on its own the first time you use jit, or run `jit service restart`.\n", displayLogPath(logPath))))
			return nil
		}
		writeAgentLogTail(out, tailLines(data, agentLogLines))

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
				// --follow renders each appended chunk through the same
				// formatter as the initial tail, so a live stream and a
				// static read look identical rather than the stream
				// reverting to raw lines partway down the screen.
				chunk, _ := io.ReadAll(f)
				writeAgentLogTail(out, chunk)
				offset += int64(len(chunk))
			}
			_ = f.Close()
		}
	},
}

// writeAgentLogTail prints a slice of the log, formatted for reading unless
// --raw asked for the bytes as written.
func writeAgentLogTail(out io.Writer, data []byte) {
	if agentLogRaw {
		_, _ = out.Write(data)
		return
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = ""
	}
	writeAgentLog(out, data, home)
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

// maxCommandLen bounds the unlocking command on a status line. A
// jit-launched MCP server's real argv runs to ~170 characters of absolute
// paths — it wraps twice in a terminal and buries the part that matters
// (`jit run --profile mcp-jamf`) in the middle of the wreckage. The full,
// untruncated command stays in --format json, which is where a script (or a
// human who genuinely wants the child's arguments) should be looking.
// It is derived from the window rather than fixed: 72 was chosen for an
// 80-column terminal, and in a 50-column one it produces exactly the
// double-wrapped wreckage it was added to prevent.
func maxCommandLen() int {
	return max(32, termtext.Width()-8)
}

// shortenCommand makes a kernel-reported command line fit a status line:
// $HOME collapses to ~ (the same courtesy printMountStatuses already extends
// to paths), and what's still too long is cut. jit's own arguments come
// first in the string, so a cut tail costs the child command's arguments —
// the least interesting part — rather than the profile name.
func shortenCommand(home, cmd string) string {
	if home != "" {
		cmd = strings.ReplaceAll(cmd, home+"/", "~/")
	}
	return termtext.TruncTail(cmd, maxCommandLen())
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
	_, _ = cWarn.Fprintf(w, "%s\n", line)
	if p.By != "" {
		home, _ := os.UserHomeDir()
		fmt.Fprintf(w, "      %s\n", shortenCommand(home, p.By))
	}
}

// printSessionProvenance is the "who put the session in this state" lines
// under `jit service status`'s headline (GAPS.md #75).
//
// The motivating report: a Touch ID prompt appeared unbidden while the user
// was doing something entirely unrelated, and reconstructing why took
// cross-referencing the service's log against shell history — the answer being
// "Claude Code started, and two of the MCP servers it boots are `jit run
// --profile ...`". The service knew every one of those facts at the moment it
// prompted and stored none of them. It does now, so status can just say it.
//
// Prints nothing when this service process has never unlocked: a freshly
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

// printMountStatuses renders the per-mount section of `jit service status`
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

	// State the decoy rule ONCE, in the header, instead of tailing the same
	// "(real values flow through a jit run grant or an approved consent prompt)"
	// onto every mount line — that parenthetical, repeated per mount, was most of
	// the noise. Each mount then reads as a glyph plus its path: ○ decoy (the
	// default), ● real-to-a-grant.
	fmt.Fprint(w, "\n")
	_, _ = cBold.Fprint(w, "Mounts:")
	_, _ = cDim.Fprintf(w, " %d · decoy by default; real values flow through a jit run grant, or an approved consent prompt for a global credential file\n", len(sorted))
	decoyReads := 0
	for _, m := range sorted {
		path := displayPath(home, m.Path)
		// A swapped mount is a plain compatibility file for the run(s)
		// listed below it — the FIFO, and so the whole reveal/decoy
		// vocabulary, doesn't apply while it's swapped.
		if m.Swapped {
			_, _ = cOK.Fprint(w, "  "+glyphOK+" ")
			fmt.Fprint(w, path)
			_, _ = cDim.Fprintln(w, "  compatibility file (real values are in the run's environment; the file is inert)")
			for _, g := range m.Grants {
				cmd := grantCommand(g)
				_, _ = cDim.Fprintf(w, "      swapped for jit run pid %d (%s) since %s ago, decoy mount returns when it exits\n", g.PID, cmd, humanAgo(time.Since(time.Unix(g.SinceUnix, 0))))
			}
			continue
		}
		if len(m.Grants) > 0 {
			_, _ = cOK.Fprint(w, "  "+glyphOK+" ")
			fmt.Fprint(w, path)
			_, _ = cDim.Fprintf(w, "  real to %s, decoy to everything else\n", countWord(len(m.Grants), "active grant", "active grants"))
		} else {
			_, _ = cWarn.Fprint(w, "  "+glyphWarn+" ")
			fmt.Fprintln(w, path)
		}
		for _, g := range m.Grants {
			cmd := grantCommand(g)
			_, _ = cDim.Fprintf(w, "      serving real values to jit run pid %d (%s) since %s ago, until it exits\n", g.PID, cmd, humanAgo(time.Since(time.Unix(g.SinceUnix, 0))))
		}
		if ls := m.LastServe; ls != nil {
			reader := describeReader(ls)
			ago := humanAgo(time.Since(time.Unix(ls.UnixTime, 0)))
			switch {
			case ls.Decoy:
				decoyReads++
				_, _ = cDim.Fprintf(w, "      read %s ago by %s · decoy\n", ago, reader)
			case ls.GrantServed:
				_, _ = cDim.Fprintf(w, "      read %s ago by %s · real (run-scoped grant)\n", ago, reader)
			default:
				_, _ = cDim.Fprintf(w, "      read %s ago by %s · real\n", ago, reader)
			}
			if m.ReadsLastMinute >= readStormThreshold {
				_, _ = cWarn.Fprintf(w, "      read %d times in the last minute, usually an editor or file watcher re-reading it in a loop; excluding this file from it stops the churn\n", m.ReadsLastMinute)
			}
		}
	}
	// The "if that was your app, run it through jit run --live" advice used to
	// ride on every decoy read line. State it once, at the end, when any mount
	// actually served a decoy to a reader — the one place the reader can act.
	if decoyReads > 0 {
		_, _ = cWarn.Fprint(w, "  If one of those decoy reads was your own app, run it through: ")
		_, _ = cPath.Fprintln(w, "jit run --live -- <command>")
	}
}

// grantCommand names the command behind a grant, falling back to a stable
// placeholder when the record didn't capture one.
func grantCommand(g agent.MountGrantStatus) string {
	if g.Command == "" {
		return "unknown command"
	}
	return g.Command
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
	case d < 0:
		// An event stamped ahead of the reader's clock (durable history
		// crossing an NTP step-back) would otherwise render as "-3s ago".
		return "0s"
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

// validateAgentTTL rejects a --ttl the session logic cannot honor at all:
// zero or negative makes every touchSession see an already-expired session,
// so EVERY operation re-prompts Touch ID — an agent that is all cost and no
// session, installed with no error message anywhere near the mistake.
//
// Deliberately NOT an opinion about the upper bound. This runs at startup,
// against whatever an already-installed plist happens to say, and a config
// that merely asks for more than the session ceiling can deliver is clamped
// there instead — refusing to boot over it would turn an upgrade into a
// silently missing agent.
func validateAgentTTL(ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("--ttl must be positive, got %s (a zero or negative TTL would re-prompt Touch ID on every single use)", ttl)
	}
	return nil
}

// validateAgentTTLSetting is validateAgentTTL for a value a human just typed,
// where the upper bound belongs.
//
// An inactivity timeout above the hard session ceiling is a number that can
// never be reached: the session ends at the ceiling however actively it is
// used, so `jit service ttl 720h` would report a month-long session and
// deliver eight hours. Saying so at the moment it is typed is very different
// from silently clamping a value someone chose on purpose — and it is the
// only moment there is a person present to tell.
func validateAgentTTLSetting(ttl time.Duration) error {
	if err := validateAgentTTL(ttl); err != nil {
		return err
	}
	if ttl > agent.DefaultMaxSessionAge {
		return fmt.Errorf("--ttl must not exceed %s, got %s (a session ends at that hard ceiling no matter how actively it is used, so a longer idle timeout could never be reached)", agent.DefaultMaxSessionAge, ttl)
	}
	return nil
}

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
func agentClient() (*agent.Client, error) {
	root, err := vaultRootDir()
	if err != nil {
		return nil, err
	}
	c := agent.NewClient(agent.SocketPath(root))
	if agentInstalled() {
		c = c.WithDialRetry(agentRestartGrace)
	}
	c = c.WithWaitNotifier(announceTouchIDWait)
	return c, nil
}

// announceTouchIDWait is the wait notifier every CLI agent client carries: it
// prints one line to stderr when a request has been blocked long enough to
// mean the service is sitting on a Touch ID/passcode prompt. Without it the
// terminal just hangs mid-command while the OS challenge waits offscreen, and
// a user (or a demo viewer) has no way to connect the pause to the prompt on
// their Mac — the same silent-prompt confusion internal/keychainwrap already
// documents. stderr, so it never corrupts a --format json payload on stdout;
// json/status commands don't challenge, so it won't fire for them anyway.
func announceTouchIDWait() {
	fmt.Fprintln(os.Stderr, "🔐 Touch ID required: approve the prompt on your Mac to continue...")
}

// notRunningHint rewrites a Client call's dial failure into the actionable
// message the service commands print — the raw error says the socket didn't
// answer, but the thing a human can DO about that differs: an installed
// agent that isn't answering wants a restart (and its log), one that was
// never installed wants installing.
// installedNotRunningAdvice is the SINGLE source of the "installed but not
// running" guidance, shared by `jit status`, `jit service status`, and the
// notRunningHint agent subcommands print on a dial failure — so the wording
// can't drift across the three. It did drift once: a change to what restart
// recovers updated only `jit service status`, leaving `jit status` (the first
// place a user sees this) and notRunningHint on stale advice. subject is the
// caller's sentence opener ("Service:", "jit's background service is", "the service is") so each
// surface keeps its own voice while the actionable half stays identical.
func installedNotRunningAdvice(subject string) string {
	return subject + " installed but not running, it may have crashed or be mid-restart. Try `jit service restart` (it reloads the service, recovering even one launchd has dropped, and recreates the login item if it was removed). `jit service log` shows recent output."
}

func notRunningHint(err error) error {
	if !errors.Is(err, agent.ErrNotRunning) {
		return err
	}
	if agentInstalled() {
		return errors.New(installedNotRunningAdvice("the service is"))
	}
	return errors.New("the background service isn't running; run `jit service restart` to start it")
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
// stampedWriter's per-writer one — so `jit service run` can put both its
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

// rotateAgentLogPeriodically re-applies the service.log cap for the life of
// the service process. The startup-only rotation left a hole: launchd keeps
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
			fmt.Fprintf(stderr, "jit service: rotating %s: %v\n", logPath, err)
		}
	}
}

// agentPlistPath and agentInstalled live in agentinstalled.go (un-gated),
// so status.go's portable agent section can share them.

// agentDomainTarget and agentServiceTarget name the service to launchctl's
// modern verbs (bootstrap/bootout/kickstart): the per-user GUI domain, and
// the service's service inside it.
func agentDomainTarget() string {
	return fmt.Sprintf("gui/%d", os.Getuid())
}

func agentServiceTarget() string {
	return agentDomainTarget() + "/" + agentPlistLabel
}

// launchctlRun runs launchctl with fixed, jit-controlled arguments and
// returns its combined output. A package var (not a direct exec) purely so
// tests can substitute a fake and drive install/restart's recovery logic
// without spawning real launchd — the exec'd path was otherwise untestable.
var launchctlRun = func(args ...string) ([]byte, error) {
	return exec.Command("launchctl", args...).CombinedOutput() // #nosec G204 -- fixed subcommands with jit's own label/domain/plist path, never external input
}

// reloadAgentService (re)loads the service's launchd service from plistPath:
// boot out any currently-loaded instance, then bootstrap the plist back in.
// This one unconditional sequence recovers EVERY installed-but-not-running
// state without having to detect which it is — a healthy running agent
// (booted out, then restarted onto the current binary), a crash loop launchd
// gave up on, or a service launchd dropped entirely (the plist on disk with
// no live record, where the old kickstart -k dead-ended on "Could not find
// service"). The bootout is best-effort: nothing to boot out on a first-ever
// load or an already-dropped service, and its failure there is expected, so
// only bootstrap's result decides success. bootout/bootstrap are the modern
// verbs; load/unload have been deprecated since 10.11.
//
// bootout returns before launchd has finished tearing the old service down,
// and a bootstrap that lands in that window fails with "Input/output error"
// (EIO, launchctl exit 5) — observed on real hardware. The previous install
// code happened to dodge it by writing the plist between bootout and
// bootstrap, which gave launchd that beat; doing the two back-to-back exposed
// it. So retry the bootstrap through the teardown window rather than
// surfacing a transient race as a hard failure. A non-transient error (bad
// plist, permissions) is returned on the first try.
func reloadAgentService(plistPath string) ([]byte, error) {
	_, _ = launchctlRun("bootout", agentServiceTarget())
	var out []byte
	var err error
	for attempt := 0; attempt < 15; attempt++ {
		out, err = launchctlRun("bootstrap", agentDomainTarget(), plistPath)
		if err == nil || !bootstrapRaceError(out) {
			return out, err
		}
		time.Sleep(200 * time.Millisecond)
	}
	return out, err
}

// bootstrapRaceError reports whether a failed bootstrap is the transient
// "the service this is replacing is still being torn down" state that a
// retry clears — EIO right after a bootout, or launchd still reporting the
// old instance as loaded. Anything else is a real error to surface.
func bootstrapRaceError(launchctlOutput []byte) bool {
	l := bytes.ToLower(launchctlOutput)
	return bytes.Contains(l, []byte("input/output error")) ||
		bytes.Contains(l, []byte("already loaded")) ||
		bytes.Contains(l, []byte("service already bootstrapped"))
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
		<string>service</string>
		<string>run</string>
		<string>--ttl</string>
		<string>%s</string>%s
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

// agentCompatCmd is a hidden, deprecated alias for the pre-rename `jit agent`
// command tree. It exists for exactly one reason: an already-installed launchd
// plist written before the rename has `agent run` baked into its
// ProgramArguments (see agentPlistTemplate's history), and launchd re-execs
// that verbatim at every login. Without this alias those deployed agents would
// silently fail to start on the new binary until something rewrote their plist.
// New plists use `service run`; every `jit service ttl`/`restart` rewrites
// an old plist to match, so this is a migration bridge to delete a release
// later, not a permanent second name. Hidden (and off tab-completion) so it
// never re-introduces the "agent" noun to anyone reading help.
var agentCompatCmd = &cobra.Command{
	Use:     "agent",
	Hidden:  true,
	GroupID: groupPlumbing, // never rendered (Hidden, no help-visible annotation); GroupID only satisfies the every-top-level-command-has-a-group rule
	Short:   "Deprecated alias for jit service (kept only so old login items keep starting)",
}

// agentCompatRunCmd mirrors the installed plist's `agent run --ttl <d>`. It
// delegates to the real service-run command rather than duplicating its body,
// so the two can't drift. The closure defers the lookup to call time, so it
// doesn't depend on package-var initialization order.
var agentCompatRunCmd = &cobra.Command{
	Use:    "run",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return agentRunCmd.RunE(cmd, args)
	},
}

func init() {
	agentRunCmd.Flags().DurationVar(&agentTTL, "ttl", 5*time.Minute, "how long an unlocked session stays cached before auto-locking (values above the 8h maximum session age are clamped to it)")
	agentRunCmd.Flags().BoolVar(&agentConsent, "consent", true, "prompt for per-process consent (Touch ID) the first time each tool reaches for a credential (on by default; use --consent=false to disable)")
	agentStatusCmd.Flags().StringVar(&agentStatusFormat, "format", "text", `output format: "text" (default) or "json"`)
	agentLogCmd.Flags().IntVarP(&agentLogLines, "lines", "n", 50, "how many trailing lines to print")
	agentLogCmd.Flags().BoolVarP(&agentLogFollow, "follow", "f", false, "keep printing new lines as the service writes them (Ctrl-C to stop)")
	agentLogCmd.Flags().BoolVar(&agentLogRaw, "raw", false, "print the log file's bytes exactly as written, without the formatted view")
	serviceCmd.AddCommand(agentRunCmd, serviceTTLCmd, serviceConsentCmd, agentRestartCmd, agentStatusCmd, agentLogCmd)

	// The old plist's `agent run --ttl <d>` needs the same --ttl flag bound to
	// the same target var; only one of the two run commands executes per
	// process, so sharing agentTTL is safe.
	agentCompatRunCmd.Flags().DurationVar(&agentTTL, "ttl", 5*time.Minute, "how long an unlocked session stays cached before auto-locking (values above the 8h maximum session age are clamped to it)")
	agentCompatCmd.AddCommand(agentCompatRunCmd)

	rootCmd.AddCommand(serviceCmd, unlockCmd, lockCmd, agentCompatCmd)
}
