// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/termtext"
)

// This file is `jit service status`: its --format json shape and the
// renderers for the text one — session provenance, per-mount reveal state,
// who is reading a mount, and the bounded command strings all of that
// displays. The health VOCABULARY it draws on (what to say and advise when
// the service is installed but not answering) is single-sourced in
// agentclient.go, so every surface says the same thing.

// agentStatusFormat is agentStatusCmd's --format flag (GAPS.md #22).
var agentStatusFormat string

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
	// Protocol is the running service's socket-protocol revision
	// (agent.Protocol). It decides real behaviour — a service below
	// protocolDisclosedGate cannot enforce the disclosed-credential prompt,
	// so the client refuses to ask it for a machine-wide grant — and this is
	// the only machine-readable surface that reports it. Zero when the
	// service isn't running or predates the field, which is itself the
	// "too old to trust with that" answer.
	Protocol int `json:"protocol,omitempty"`
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
				// Mounts is [] rather than null, as its own doc comment
				// promises: "never omitted outright, so a script parsing
				// this doesn't need to special-case field-missing vs empty
				// list". A nil slice marshals to null and broke that.
				return writeJSON(cmd.OutOrStdout(), agentStatusResult{Installed: installed, Mounts: []agent.MountRevealStatus{}})
			}
			if installed {
				// An installed agent that isn't answering is a different
				// situation from one that was never set up — launchd was
				// supposed to keep this one alive, so "run install" is the
				// wrong advice and hides that something actually failed.
				fmt.Fprintln(cmd.OutOrStdout(), hlCmds(installedNotRunningAdvice("jit's background service")))
				return nil
			}
			fmt.Fprintln(cmd.OutOrStdout(), hlCmds("jit's background service is not running. Run `jit service restart` to start it (or just use jit and it starts on its own)."))
			return nil
		}
		if err != nil {
			return fmt.Errorf("jit service status: %w", err)
		}

		if agentStatusFormat == "json" {
			result := agentStatusResult{Running: true, Installed: agentInstalled(), Unlocked: st.Unlocked, Mounts: st.Mounts, LastUnlock: st.LastUnlock, LastLock: st.LastLock, PendingUnlock: st.PendingUnlock, Build: st.Build, Version: st.Version, Protocol: st.Protocol}
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
		fmt.Fprintf(w, "  "+glyphBullet+" %s, %s\n", sessionWhen("locked", l.UnixTime), cause)
	}

	u := st.LastUnlock
	line := fmt.Sprintf("  "+glyphBullet+" %s", sessionWhen("unlocked", u.UnixTime))
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
	_, _ = fmt.Fprintf(w, " %d · decoy by default; real values flow through a jit run grant, or an approved consent prompt for a global credential file\n", len(sorted))
	decoyReads := 0
	for _, m := range sorted {
		path := displayPath(home, m.Path)
		// A swapped mount is a plain compatibility file for the run(s)
		// listed below it — the FIFO, and so the whole reveal/decoy
		// vocabulary, doesn't apply while it's swapped.
		if m.Swapped {
			_, _ = cOK.Fprint(w, "  "+glyphOK+" ")
			fmt.Fprint(w, path)
			_, _ = fmt.Fprintln(w, "  compatibility file (real values are in the run's environment; the file is inert)")
			for _, g := range m.Grants {
				cmd := grantCommand(g)
				_, _ = fmt.Fprintf(w, "      swapped for jit run pid %d (%s) since %s ago, decoy mount returns when it exits\n", g.PID, cmd, humanAgo(time.Since(time.Unix(g.SinceUnix, 0))))
			}
			continue
		}
		if len(m.Grants) > 0 {
			_, _ = cOK.Fprint(w, "  "+glyphOK+" ")
			fmt.Fprint(w, path)
			_, _ = fmt.Fprintf(w, "  real to %s, decoy to everything else\n", countWord(len(m.Grants), "active grant", "active grants"))
		} else {
			_, _ = cWarn.Fprint(w, "  "+glyphWarn+" ")
			fmt.Fprintln(w, path)
		}
		for _, g := range m.Grants {
			cmd := grantCommand(g)
			_, _ = fmt.Fprintf(w, "      serving real values to jit run pid %d (%s) since %s ago, until it exits\n", g.PID, cmd, humanAgo(time.Since(time.Unix(g.SinceUnix, 0))))
		}
		if ls := m.LastServe; ls != nil {
			reader := describeReader(ls)
			ago := humanAgo(time.Since(time.Unix(ls.UnixTime, 0)))
			switch {
			case ls.Decoy:
				decoyReads++
				_, _ = fmt.Fprintf(w, "      read %s ago by %s · decoy\n", ago, reader)
			case ls.GrantServed:
				_, _ = fmt.Fprintf(w, "      read %s ago by %s · real (run-scoped grant)\n", ago, reader)
			default:
				_, _ = fmt.Fprintf(w, "      read %s ago by %s · real\n", ago, reader)
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
