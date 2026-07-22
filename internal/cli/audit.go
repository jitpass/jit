// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/auditlog"
)

var (
	auditFormat string
	auditLimit  int
)

// auditTimeLayout is an absolute local timestamp, an audit log spans days and
// launchd restarts, so "5m ago" (what the session-history view uses for a
// live, single-session question) is the wrong axis here; you want the wall
// clock a line can be cross-referenced against.
const auditTimeLayout = "2006-01-02 15:04:05"

var auditCmd = &cobra.Command{
	Use:     "audit",
	GroupID: groupWorkflow,
	Short:   "Show the audit log: what jit commands ran, when, by whom, and every unlock",
	Long: "jit audit prints the application audit trail, most recent first: one line for\n" +
		"every jit command that ran (what, when, which user and parent process, and\n" +
		"whether it succeeded), interleaved with every local-auth event the agent saw\n" +
		"(each unlock and each DECLINED prompt, with how you were asked, what triggered\n" +
		"it, and the secret names each one touched).\n\n" +
		"Together they answer \"what happened on this machine, and who did it\": the\n" +
		"command lines are the actions, the auth lines are the approvals those actions\n" +
		"needed. Command arguments are recorded with any secret-looking value masked, so\n" +
		"the log records that a command ran, never the secret it may have carried.\n\n" +
		"On the auth method: jit challenges with a single macOS prompt that accepts\n" +
		"either a fingerprint or the device passcode, and the OS does not report which\n" +
		"one you used. So a line says \"Touch ID or device passcode\" (biometry is\n" +
		"available on this Mac) or \"device passcode\" (it isn't), never a claim macOS\n" +
		"can't back.\n\n" +
		"Survives restarts and logouts: both halves are durable files alongside the\n" +
		"vault (audit.jsonl and agent-history.jsonl), so this answers for last week as\n" +
		"readily as for the last hour. To scan for plaintext secrets on disk instead,\n" +
		"that command is now `jit scan`.",
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateOutputFormat(auditFormat); err != nil {
			return fmt.Errorf("jit audit: %w", err)
		}
		root, err := vaultRootDir()
		if err != nil {
			return fmt.Errorf("jit audit: %w", err)
		}

		// Read both durable logs directly rather than asking the running agent:
		// the audit trail must read the same whether or not the agent happens
		// to be up, and the agent appends every event to the same file it would
		// serve, so nothing recent is missed. A limit <= 0 means "everything";
		// otherwise pull the newest `limit` from each source, since the global
		// newest N can only come from the per-source newest N.
		perSource := auditLimit
		if perSource <= 0 {
			perSource = 0 // auditlog.Load: all
		}
		commands := auditlog.New(root, io.Discard).Load(perSource)
		histMax := auditLimit
		if histMax <= 0 {
			histMax = 1 << 30 // effectively all
		}
		events := newHistoryLog(root, io.Discard).load(histMax)

		if auditFormat == "json" {
			if commands == nil {
				commands = []auditlog.Record{}
			}
			if events == nil {
				events = []agent.SessionEvent{}
			}
			return writeJSON(cmd.OutOrStdout(), auditJSON{Commands: commands, AuthEvents: events})
		}

		printAuditLog(cmd.OutOrStdout(), commands, events, auditLimit)
		return nil
	},
}

// auditJSON is the shape of `jit audit --format json`: the two logs side by
// side, each in its native record shape, rather than flattened into one lossy
// stream. A consumer that wants a merged timeline sorts on unix_nano /
// unix_time itself; one that wants only the commands (or only the auth events)
// reads one array and ignores the other.
type auditJSON struct {
	Commands   []auditlog.Record    `json:"commands"`
	AuthEvents []agent.SessionEvent `json:"auth_events"`
}

// auditEntry is one merged, rendered timeline row: its wall-clock time (for
// the merge sort) and the already-formatted lines to print under a bullet.
type auditEntry struct {
	t     time.Time
	lines []string
}

// printAuditLog merges command records and auth events into one reverse-
// chronological view. limit, when positive, caps the merged output; the per-
// source reads already trimmed to roughly this, so this is the exact final cut.
func printAuditLog(w io.Writer, commands []auditlog.Record, events []agent.SessionEvent, limit int) {
	if len(commands) == 0 && len(events) == 0 {
		fmt.Fprintln(w, "No audit log yet. It fills in as you run jit commands; if the agent has never run, there are no unlocks to show either.")
		return
	}
	home, _ := os.UserHomeDir()

	entries := make([]auditEntry, 0, len(commands)+len(events))
	for _, r := range commands {
		entries = append(entries, commandEntry(r))
	}
	for _, e := range events {
		entries = append(entries, authEntry(home, e))
	}
	// Newest first. Stable so that a command and the unlock it triggered, which
	// can share a whole-second timestamp, keep the order they were appended in.
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].t.After(entries[j].t) })
	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
	}

	fmt.Fprintln(w, "Audit log (most recent first):")
	for _, e := range entries {
		for _, line := range e.lines {
			fmt.Fprintln(w, line)
		}
	}
}

// commandEntry renders one recorded jit invocation.
func commandEntry(r auditlog.Record) auditEntry {
	t := time.Unix(0, r.UnixNano)
	invocation := "jit"
	if len(r.Args) > 0 {
		invocation = "jit " + strings.Join(r.Args, " ")
	}
	outcome := fmt.Sprintf("ok · %dms", r.DurationMS)
	if !r.Success {
		outcome = fmt.Sprintf("FAILED · %dms", r.DurationMS)
	}
	head := fmt.Sprintf("  • %s  %s  (%s)", t.Format(auditTimeLayout), invocation, outcome)
	if !r.Success {
		head = color.New(color.FgRed).Sprint(head)
	}
	lines := []string{head}

	who := "  ran by " + r.User
	if r.PID != 0 {
		who += fmt.Sprintf(" (pid %d)", r.PID)
	}
	if r.LaunchedBy != "" {
		who += ", launched by " + r.LaunchedBy
	} else if r.Parent != "" {
		who += ", from " + r.Parent
	}
	lines = append(lines, "    "+who)
	if r.Error != "" {
		lines = append(lines, "    "+color.New(color.FgRed).Sprint("error: "+r.Error))
	}
	return auditEntry{t: t, lines: lines}
}

// authEntry renders one agent session event (unlock, denial, use, lock, or
// agent start) into the same bullet shape, reusing the session-history phrasing
// but on an absolute-time axis and surfacing the recorded auth method.
func authEntry(home string, e agent.SessionEvent) auditEntry {
	t := time.Unix(e.UnixTime, 0)
	ts := t.Format(auditTimeLayout)
	var lines []string

	switch e.Kind {
	case agent.KindLock:
		cause := e.Cause
		if cause == "" {
			cause = "unknown cause"
		}
		lines = append(lines, fmt.Sprintf("  • %s  session locked, %s", ts, cause))
	case agent.KindStart:
		line := fmt.Sprintf("  • %s  agent process started", ts)
		if e.Cause != "" {
			line += fmt.Sprintf(" (%s)", e.Cause)
		}
		lines = append(lines, line)
	case agent.KindDenied:
		head := fmt.Sprintf("  • %s  unlock DENIED, via %s", ts, authMethodPhrase(e))
		lines = append(lines, color.New(color.FgRed).Sprint(head))
		if e.LaunchedBy != "" {
			lines = append(lines, "    launched by "+e.LaunchedBy)
		}
		if e.By != "" {
			lines = append(lines, "    "+shortenCommand(home, e.By))
		}
		if e.Cause != "" {
			lines = append(lines, "    "+e.Cause)
		}
		lines = append(lines, authLabelLines(e.Labels)...)
	case agent.KindUse:
		line := fmt.Sprintf("  • %s  session used, %s", ts, agent.DescribeUse(e.Op))
		if e.Count > 1 {
			line += fmt.Sprintf(" ×%d", e.Count)
		}
		if e.LaunchedBy != "" {
			line += ", launched by " + e.LaunchedBy
		}
		lines = append(lines, line)
		if e.By != "" {
			lines = append(lines, "    "+shortenCommand(home, e.By))
		}
		lines = append(lines, authLabelLines(e.Labels)...)
	default: // unlock
		line := fmt.Sprintf("  • %s  unlock via %s", ts, authMethodPhrase(e))
		if e.LaunchedBy != "" {
			line += ", launched by " + e.LaunchedBy
		}
		lines = append(lines, line)
		if e.By != "" {
			lines = append(lines, "    "+shortenCommand(home, e.By))
		}
		lines = append(lines, authLabelLines(e.Labels)...)
	}
	return auditEntry{t: t, lines: lines}
}

// authMethodPhrase is the recorded "how were you asked" for a challenge event,
// falling back to the honest policy description for events restored from a jit
// version that predates the field.
func authMethodPhrase(e agent.SessionEvent) string {
	if e.AuthMethod != "" {
		return e.AuthMethod
	}
	return "Touch ID or device passcode"
}

func authLabelLines(labels []string) []string {
	if len(labels) == 0 {
		return nil
	}
	return []string{"    secrets (caller-reported): " + strings.Join(labels, ", ")}
}

func init() {
	auditCmd.Flags().StringVar(&auditFormat, "format", "text", `output format: "text" (default) or "json"`)
	auditCmd.Flags().IntVar(&auditLimit, "limit", 50, "show at most this many recent entries (0 for all)")
	rootCmd.AddCommand(auditCmd)
}
