// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
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
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/keychainwrap"
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

const agentPlistLabel = "com.jitpass.agent"

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
		"Touch ID just to keep running — only your unlocked session inside it locks\n" +
		"after --ttl of inactivity (default 15m), prompting again on next use.\n\n" +
		"A live-mounted file shows fake-looking values until revealed, and real values\n" +
		"only during a short window — opened automatically right after unlock/\n" +
		"refresh, or explicitly via `jit agent reveal`.",
}

// agentRunCmd is what the installed LaunchAgent's plist actually executes.
// Running it directly (not via launchd) works too, in the foreground.
var agentRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the agent in the foreground (normally started by launchd, not by hand)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
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
		_ = os.Chmod(filepath.Join(root, "agent.log"), 0o600)

		// Everything this long-lived process prints lands in one agent.log
		// (the plist points both streams there) — timestamp every line, or
		// the log can't answer "when," which is most of what a log of a
		// weeks-lived process is for (GAPS.md #48).
		stdout := newStampedWriter(cmd.OutOrStdout())
		stderr := newStampedWriter(cmd.ErrOrStderr())

		server := agent.NewServer(agent.SocketPath(root), func() agent.MEKFetcher { return keychainwrap.New() }, agentTTL)
		mounts := &mountManager{root: root, keyWrapper: server, stdout: stdout, stderr: stderr}
		server.OnUnlock = mounts.start
		server.OnUnlockForReveal = mounts.startForReveal
		server.OnLock = mounts.stop
		server.OnRefresh = mounts.start
		server.OnReveal = mounts.revealMount
		server.OnStopMount = mounts.stopMount
		server.OnMountStatus = mounts.mountRevealStatuses
		server.OnSessionEvent = func(e agent.SessionEvent) { logSessionEvent(stdout, e) }

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

		fmt.Fprintf(stdout, "jit agent listening on %s (session TTL %s, build %s)\n", agent.SocketPath(root), agentTTL, agent.BuildID())
		err = server.Serve(ctx)
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
		"restart itself if it crashes — until you run `jit agent uninstall`.\n" +
		"Under the hood this writes and loads a launchd LaunchAgent plist that\n" +
		"runs `jit agent run`.\n\n" +
		"--ttl controls how long a session stays unlocked after your last Touch ID\n" +
		"prompt (default 15m, same meaning as `jit agent run --ttl`) — baked into\n" +
		"the installed service so it applies from every future login, not just\n" +
		"this one.\n\n" +
		"Safe to run again to change --ttl later: an already-installed instance is\n" +
		"unloaded first, so the new value takes effect immediately rather than\n" +
		"only on the next login.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
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

		// Unload any previously-installed instance first — launchctl load on
		// an already-loaded label doesn't restart it with new arguments, so
		// a re-install to change --ttl would otherwise silently keep running
		// with the old value until next login. Best-effort: nothing to
		// unload on a first-ever install (plistPath doesn't exist yet), and
		// an unload failure here still leaves the load below to report the
		// real error if something's actually wrong.
		if _, statErr := os.Stat(plistPath); statErr == nil {
			_ = exec.Command("launchctl", "unload", plistPath).Run() // #nosec G204 -- fixed subcommand, jit's own previously-written plist
		}

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

		out, err := exec.Command("launchctl", "load", plistPath).CombinedOutput() // #nosec G204 -- fixed subcommand, plistPath is a file jit itself just wrote
		if err != nil {
			return fmt.Errorf("jit agent install: launchctl load failed: %w (%s)", err, strings.TrimSpace(string(out)))
		}
		// launchctl load returns before the agent process has spawned and
		// bound its socket — a real, observed first-run confusion: `jit
		// agent status` typed right after a successful install said "not
		// running — run `jit agent install` to set it up" for the ~2s
		// launchd took to actually start it. Wait briefly until the socket
		// answers so "Installed" also means "running"; if it still isn't
		// up after the timeout, say what's actually happening rather than
		// letting status contradict this command a moment later.
		running := false
		client := agent.NewClient(agent.SocketPath(root))
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
			if client.Reachable() {
				running = true
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		fmt.Fprintf(cmd.OutOrStdout(),
			"Installed — jit agent now starts automatically every time you log in (survives reboots) and stays unlocked for up to %s after your last Touch ID prompt.\nRun `jit agent uninstall` to remove it. (%s)\n",
			agentInstallTTL, plistPath)
		if !running {
			fmt.Fprintln(cmd.OutOrStdout(), "The agent is still starting up in the background — give `jit agent status` a few seconds.")
		}
		return nil
	},
}

var agentUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Stop jit agent and remove it from login startup",
	Long: "Stops the background helper and removes it from login startup — it will\n" +
		"no longer start automatically. Any files it was live-mounting stop being\n" +
		"served (they don't disappear; they just go quiet until you run\n" +
		"`jit agent install` again). Doesn't touch the vault or any secrets\n" +
		"already stored — only the background helper itself.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		plistPath, err := agentPlistPath()
		if err != nil {
			return fmt.Errorf("jit agent uninstall: %w", err)
		}

		if _, statErr := os.Stat(plistPath); statErr == nil {
			out, unloadErr := exec.Command("launchctl", "unload", plistPath).CombinedOutput() // #nosec G204 -- fixed subcommand, jit's own previously-written plist
			if unloadErr != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "warning: launchctl unload failed (%v): %s\n", unloadErr, strings.TrimSpace(string(out)))
			}
		}
		if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("jit agent uninstall: %w", err)
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Uninstalled jit agent.")
		return nil
	},
}

var agentUnlockCmd = &cobra.Command{
	Use:   "unlock",
	Short: "Unlock the running agent's session now (prompts Touch ID if needed)",
	Long:  "Pre-warms the shared session so a run of jit run/vault get/export right after doesn't prompt.",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := dialAgent()
		if err != nil {
			return fmt.Errorf("jit agent unlock: %w", err)
		}
		_, remaining, err := c.Unlock()
		if err != nil {
			return fmt.Errorf("jit agent unlock: %w", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Unlocked — locks automatically after %s of inactivity (or `jit agent lock` sooner).\n", remaining.Round(time.Second))
		return nil
	},
}

var agentLockCmd = &cobra.Command{
	Use:   "lock",
	Short: "Lock the running agent's session immediately, without waiting for the TTL",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := dialAgent()
		if err != nil {
			return fmt.Errorf("jit agent lock: %w", err)
		}
		if err := c.Lock(); err != nil {
			return fmt.Errorf("jit agent lock: %w", err)
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

		c, err := dialAgent()
		if err != nil {
			return fmt.Errorf("jit agent reveal: %w", err)
		}
		if err := c.Reveal(mountPath, duration); err != nil {
			return fmt.Errorf("jit agent reveal: %w", err)
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
	Running        bool  `json:"running"`
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

		root, err := vaultRootDir()
		if err != nil {
			return fmt.Errorf("jit agent status: %w", err)
		}
		client := agent.NewClient(agent.SocketPath(root))
		if !client.Reachable() {
			if agentStatusFormat == "json" {
				return writeJSON(cmd.OutOrStdout(), agentStatusResult{})
			}
			fmt.Fprintln(cmd.OutOrStdout(), "jit agent is not running. Run `jit agent install` to set it up.")
			return nil
		}
		st, err := client.Status()
		if err != nil {
			return fmt.Errorf("jit agent status: %w", err)
		}

		if agentStatusFormat == "json" {
			result := agentStatusResult{Running: true, Unlocked: st.Unlocked, Mounts: st.Mounts, LastUnlock: st.LastUnlock, LastLock: st.LastLock, Build: st.Build, Version: st.Version}
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
	Short: "List every unlock and lock this agent has seen, and what caused them",
	Long: "Prints the agent's session history, most recent first: every Touch ID prompt\n" +
		"that succeeded (with the command that triggered it and what launched that\n" +
		"command) and every lock (with its cause — an idle timeout, or an explicit\n" +
		"`jit agent lock`).\n\n" +
		"This is the answer to \"why does it keep asking me?\" — a question the agent\n" +
		"previously had no way to answer, since only locks were ever recorded and the\n" +
		"unlocks that did the prompting left no trace at all.\n\n" +
		"In-memory and bounded, so a restart (launchd restarts the agent at every\n" +
		"login) empties it. The same events are also appended to the agent's log file,\n" +
		"which is the durable record.",
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateOutputFormat(agentHistoryFormat); err != nil {
			return fmt.Errorf("jit agent history: %w", err)
		}
		root, err := vaultRootDir()
		if err != nil {
			return fmt.Errorf("jit agent history: %w", err)
		}
		client := agent.NewClient(agent.SocketPath(root))
		if !client.Reachable() {
			if agentHistoryFormat == "json" {
				return writeJSON(cmd.OutOrStdout(), []agent.SessionEvent{})
			}
			fmt.Fprintln(cmd.OutOrStdout(), "jit agent is not running. Run `jit agent install` to set it up.")
			return nil
		}

		events, err := client.History()
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
			fmt.Fprintf(w, "  • %s — %s\n", sessionWhen("locked", e.UnixTime), cause)
		default:
			line := fmt.Sprintf("  • %s", sessionWhen("unlocked", e.UnixTime))
			if e.LaunchedBy != "" {
				line += fmt.Sprintf(" — launched by %s", e.LaunchedBy)
			}
			fmt.Fprintln(w, line)
			if e.By != "" {
				fmt.Fprintf(w, "      %s\n", shortenCommand(home, e.By))
			}
		}
	}
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
		fmt.Fprintf(w, "jit agent: session locked — %s\n", cause)
		return
	}

	line := "jit agent: session unlocked"
	if e.Op != "" {
		line += fmt.Sprintf(" (%s)", e.Op)
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
		fmt.Fprintf(w, "  • %s — %s\n", sessionWhen("locked", l.UnixTime), cause)
	}

	u := st.LastUnlock
	line := fmt.Sprintf("  • %s", sessionWhen("unlocked", u.UnixTime))
	if u.LaunchedBy != "" {
		// The half that answers "why now" — and the half nobody could get at
		// before, since a process's parent is gone from every log jit keeps.
		line += fmt.Sprintf(" — launched by %s", u.LaunchedBy)
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
		switch {
		case m.Revealed:
			fmt.Fprintf(w, "  • %s — revealed, %s left\n", path, time.Duration(m.RevealedForSeconds)*time.Second)
		case m.RevealEndedUnix != 0:
			// Reveal expiry is lazy — nothing fires when a window ends — so
			// this line is the only place "the timer ended" is visible at
			// all; without it the revealed line just silently disappeared,
			// which read as "it never switched to hidden" (GAPS.md #48).
			fmt.Fprintf(w, "  • %s — not revealed (window ended %s ago)\n", path, humanAgo(time.Since(time.Unix(m.RevealEndedUnix, 0))))
		default:
			fmt.Fprintf(w, "  • %s — not revealed\n", path)
		}
		if ls := m.LastServe; ls != nil {
			reader := describeReader(ls)
			ago := humanAgo(time.Since(time.Unix(ls.UnixTime, 0)))
			if ls.Decoy {
				_, _ = color.New(color.FgYellow).Fprintf(w, "      read %s ago by %s: decoy values — if that was your app, reveal and retry: jit agent reveal %s\n", ago, reader, path)
			} else {
				fmt.Fprintf(w, "      read %s ago by %s: real values\n", ago, reader)
			}
			if m.ReadsLastMinute >= readStormThreshold {
				_, _ = color.New(color.FgYellow).Fprintf(w, "      read %d times in the last minute — usually an editor or file watcher re-reading it in a loop; excluding this file from it stops the churn\n", m.ReadsLastMinute)
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

func dialAgent() (*agent.Client, error) {
	root, err := vaultRootDir()
	if err != nil {
		return nil, err
	}
	c := agent.NewClient(agent.SocketPath(root))
	if !c.Reachable() {
		return nil, fmt.Errorf("no agent is running — run `jit agent install` first")
	}
	return c, nil
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

func agentPlistPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", agentPlistLabel+".plist"), nil
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
	agentRevealCmd.Flags().BoolVarP(&revealQuiet, "quiet", "q", false, "suppress the success message — for embedding in a pre-run hook")
	agentStatusCmd.Flags().StringVar(&agentStatusFormat, "format", "text", `output format: "text" (default) or "json"`)
	agentHistoryCmd.Flags().StringVar(&agentHistoryFormat, "format", "text", `output format: "text" (default) or "json"`)
	agentCmd.AddCommand(agentRunCmd, agentInstallCmd, agentUninstallCmd, agentUnlockCmd, agentLockCmd, agentStatusCmd, agentHistoryCmd, agentRevealCmd)
	rootCmd.AddCommand(agentCmd)
}
