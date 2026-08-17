// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/consent"
	"github.com/jitpass/jit/internal/keychainwrap"
	"github.com/jitpass/jit/internal/onepassword"
	"github.com/jitpass/jit/internal/screenlock"
)

// This file is `jit service run`: the daemon mode itself — what the installed
// launchd plist actually executes. It owns the process's lifetime (signal and
// self-retirement contexts, the main-thread run loop macOS requires for
// screen-lock delivery), its log discipline (every line timestamped through
// one mutex so the mid-run rotation can hold it across a copy-then-truncate),
// and the TTL validation a plist's stored value has to survive.
//
// Split from the service SUBCOMMANDS (servicecmds.go) on purpose: everything
// here runs in the long-lived background process, and everything there runs
// in a short-lived CLI invocation talking to it.

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

		// A foreground run must not steal the socket from a live agent:
		// Listen unconditionally replaces the socket file, so a second agent
		// silently splits the world — the first keeps the session and every
		// FIFO mount's writer while new clients dial this one, and this one's
		// exit then removes the socket out from under the first's listener,
		// leaving a healthy process every command reports as crashed. Only
		// the foreground case checks: under launchd (ppid 1) the reload's
		// bootout guarantees the singleton, and a mid-teardown predecessor
		// still answering the socket would turn this probe into a crash loop.
		if os.Getppid() != 1 && agent.NewClient(agent.SocketPath(root)).Reachable() {
			// "the background service", not "an agent": this is the only
			// surface a user would meet the word, and every other one
			// (help, status, doctor) says service.
			return fmt.Errorf("jit service run: the background service is already running and answering on %s; use `jit service restart` to restart it", agent.SocketPath(root))
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
		mounts := &mountManager{root: root, home: home, keyWrapper: server, refResolver: onepassword.New(), stdout: stdout, stderr: stderr}
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
		// Process grants (design/process-grants.md): the service resolves a
		// grant's profile names to concrete secrets itself, through the same
		// stores `jit run` reads — see resolveGrantSecrets for why that
		// agent-side resolution is what makes the grant prompt trustworthy.
		server.OnResolveGrant = resolveGrantSecrets(root)
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
		// One-time rewrite masking any By a pre-fix agent recorded raw —
		// this is what removes a legacy line's plaintext from DISK; the
		// readers' scrub only keeps it off the screen. Same single-writer
		// startup window as trim, so it can't race an append.
		hist.scrubLegacy()
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
		// Mount reads join the same trail: which reader got a decoy, which got
		// the real value, and why. Collapsed by the auditor before they reach
		// here — a watcher loop must not be able to evict the history it is
		// being written into — and started only now that there is somewhere
		// durable to put them.
		mounts.serveAudit.emit = hist.append
		mounts.serveAudit.labelFn = mounts.serveAuditLabel
		mounts.serveAudit.start()

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
			// Watch the STABLE path (the same one the plist names), not the raw
			// os.Executable(): a versioned Caskroom exec path is deleted whole
			// by `brew upgrade`, and a vanished file deliberately reads as "no
			// change yet" forever — a watcher pointed there would never fire,
			// leaving the old build running with only the status mismatch
			// warning saying why: the exact trap this watcher exists to end.
			if exePath, exeErr := agentBinaryPath(); exeErr == nil {
				go watchOwnBinary(runCtx, exePath, agentBinaryCheckInterval, server.Quiescent, func() {
					fmt.Fprintf(stdout, "jit service: the jit binary on disk changed (this process is build %s), demanding a launchd restart onto the current build while the session is locked\n", agent.BuildID())
					// The restart is DEMANDED, not hoped for. A clean exit
					// trusting KeepAlive was how the 2026-08-17 incident
					// happened: launchd pended the respawn ("pended nondemand
					// spawn = inefficient") and the broker stayed dead for 71
					// minutes. kickstart -k has launchd kill this process and
					// spawn the new binary, re-reading the plist on the way (so
					// an upgraded --ttl/--consent takes effect); it cannot hit
					// the exit-113 dead end because a running service is by
					// definition bootstrapped. If launchctl itself errors,
					// endRun's clean exit still happens and KeepAlive remains
					// the (unreliable) backstop it always was.
					_, _ = launchctlRun("kickstart", "-k", agentServiceTarget())
					endRun()
				})
			}
			go rotateAgentLogPeriodically(runCtx, logPath, &logMu, stderr)
			go trimHistoryPeriodically(runCtx, hist, agentLogRotateCheckInterval)
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
		// No "--ttl" in the message: the human who reaches this typed a
		// POSITIONAL argument to `jit service ttl`, and --ttl is a flag only
		// `jit service run` takes. Naming it sent people looking for a flag
		// they never used.
		return fmt.Errorf("the session TTL must not exceed %s, got %s (a session ends at that hard ceiling no matter how actively it is used, so a longer idle timeout could never be reached)", agent.DefaultMaxSessionAge, ttl)
	}
	return nil
}

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
