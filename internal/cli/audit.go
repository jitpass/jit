// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
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
		"Output is logfmt: one key=value line per event, newest first, so it reads and\n" +
		"greps like a real service log (filter with grep 'kind=unlock', 'status=denied',\n" +
		"and the like). For a machine-parseable dump of the same data use --format json.\n\n" +
		"On the auth method: jit challenges with a single macOS prompt that accepts\n" +
		"either a fingerprint or the device passcode, and the OS does not report which\n" +
		"one you used. So the method reads touchid-or-passcode (biometry is available on\n" +
		"this Mac) or passcode (it isn't), never a claim macOS can't back.\n\n" +
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
// the merge sort) and the already-formatted logfmt line to print.
type auditEntry struct {
	t    time.Time
	line string
}

// printAuditLog merges command records and auth events into one reverse-
// chronological logfmt stream: one `key=value` line per event, the shape a
// real service log takes, so the output is scan- and grep-friendly and reads
// as a log rather than a report. limit, when positive, caps the merged output;
// the per-source reads already trimmed to roughly this, so this is the exact
// final cut.
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

	for _, e := range entries {
		fmt.Fprintln(w, e.line)
	}
}

// kv is one logfmt field. Emitted in slice order so the eye finds the same
// fact in the same place on every line.
type kv struct{ k, v string }

// logfmtLine joins fields into a `key=value key="quoted value"` line.
func logfmtLine(pairs []kv) string {
	var b strings.Builder
	for i, p := range pairs {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(p.k)
		b.WriteByte('=')
		b.WriteString(logfmtValue(p.v))
	}
	return b.String()
}

// logfmtValue quotes a value only when it must — empty, or containing a space,
// tab, quote, or the `=` that separates fields — and escapes backslashes and
// quotes inside the quotes, so a parser round-trips it.
func logfmtValue(v string) string {
	if v == "" {
		return `""`
	}
	if !strings.ContainsAny(v, " \t\"=") {
		return v
	}
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	return `"` + v + `"`
}

// logfmtDur renders a duration the way service logs do: milliseconds under a
// second, one-decimal seconds above, so a 13-second unlock reads as 13.3s.
func logfmtDur(ms int64) string {
	if ms >= 1000 {
		return fmt.Sprintf("%.1fs", float64(ms)/1000)
	}
	return fmt.Sprintf("%dms", ms)
}

// commandEntry renders one recorded jit invocation as a logfmt line.
func commandEntry(r auditlog.Record) auditEntry {
	t := time.Unix(0, r.UnixNano)
	invocation := "jit"
	if len(r.Args) > 0 {
		invocation = "jit " + strings.Join(r.Args, " ")
	}
	level, status := "info", "ok"
	if !r.Success {
		level, status = "error", "failed"
	}
	pairs := []kv{
		{"time", t.Format(auditTimeLayout)},
		{"level", level},
		{"kind", "cmd"},
		{"status", status},
		{"dur", logfmtDur(r.DurationMS)},
		{"cmd", invocation},
	}
	if r.User != "" {
		pairs = append(pairs, kv{"user", r.User})
	}
	if r.PID != 0 {
		pairs = append(pairs, kv{"pid", strconv.Itoa(r.PID)})
	}
	if parent := launcher(r.LaunchedBy, r.Parent); parent != "" {
		pairs = append(pairs, kv{"parent", parent})
	}
	if r.Error != "" {
		pairs = append(pairs, kv{"err", r.Error})
	}
	line := logfmtLine(pairs)
	if !r.Success {
		line = color.New(color.FgRed).Sprint(line)
	}
	return auditEntry{t: t, line: line}
}

// authEntry renders one agent session event (unlock, denial, use, lock, or
// agent start) as a logfmt line, on an absolute-time axis and surfacing the
// recorded auth method.
func authEntry(home string, e agent.SessionEvent) auditEntry {
	t := time.Unix(e.UnixTime, 0)
	pairs := []kv{{"time", t.Format(auditTimeLayout)}}
	var lineColor *color.Color

	switch e.Kind {
	case agent.KindLock:
		cause := e.Cause
		if cause == "" {
			cause = "unknown"
		}
		pairs = append(pairs, kv{"level", "info"}, kv{"kind", "lock"}, kv{"reason", cause})
	case agent.KindStart:
		pairs = append(pairs, kv{"level", "info"}, kv{"kind", "agent"}, kv{"msg", "process started"})
		if b := strings.TrimPrefix(e.Cause, "build "); b != e.Cause {
			pairs = append(pairs, kv{"build", b})
		} else if e.Cause != "" {
			pairs = append(pairs, kv{"note", e.Cause})
		}
	case agent.KindDenied:
		pairs = append(pairs,
			kv{"level", "warn"}, kv{"kind", "unlock"}, kv{"status", "denied"},
			kv{"method", authMethodSlug(e)})
		if e.Cause != "" {
			pairs = append(pairs, kv{"reason", e.Cause})
		}
		pairs = appendAuthContext(pairs, home, e)
		lineColor = color.New(color.FgYellow)
	case agent.KindUse:
		pairs = append(pairs, kv{"level", "info"}, kv{"kind", "use"}, kv{"op", agent.DescribeUse(e.Op)})
		if e.Count > 1 {
			pairs = append(pairs, kv{"count", strconv.FormatInt(e.Count, 10)})
		}
		pairs = appendAuthContext(pairs, home, e)
	default: // unlock
		pairs = append(pairs,
			kv{"level", "info"}, kv{"kind", "unlock"}, kv{"status", "ok"},
			kv{"method", authMethodSlug(e)})
		pairs = appendAuthContext(pairs, home, e)
	}

	line := logfmtLine(pairs)
	if lineColor != nil {
		line = lineColor.Sprint(line)
	}
	return auditEntry{t: t, line: line}
}

// appendAuthContext adds the provenance fields shared by unlock, denied, and
// use events: the caller command line, the ancestor that explains it, and the
// caller-reported secret names. Each is best-effort and omitted when empty.
func appendAuthContext(pairs []kv, home string, e agent.SessionEvent) []kv {
	if e.By != "" {
		pairs = append(pairs, kv{"cmd", shortenCommand(home, e.By)})
	}
	if e.LaunchedBy != "" {
		pairs = append(pairs, kv{"parent", e.LaunchedBy})
	}
	if len(e.Labels) > 0 {
		pairs = append(pairs, kv{"secrets", strings.Join(e.Labels, ", ")})
	}
	return pairs
}

// launcher picks the best "who explains this call" for a command record:
// the resolved ancestor if we have one, else the immediate parent process.
func launcher(launchedBy, parent string) string {
	if launchedBy != "" {
		return launchedBy
	}
	return parent
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

// authMethodSlug turns the human auth-method phrase into a bare logfmt token,
// so the common cases read as method=touchid-or-passcode rather than a quoted
// sentence; anything unrecognized falls through to be quoted verbatim.
func authMethodSlug(e agent.SessionEvent) string {
	switch authMethodPhrase(e) {
	case "Touch ID or device passcode":
		return "touchid-or-passcode"
	case "device passcode":
		return "passcode"
	default:
		return authMethodPhrase(e)
	}
}

func init() {
	auditCmd.Flags().StringVar(&auditFormat, "format", "text", `output format: "text" (default) or "json"`)
	auditCmd.Flags().IntVar(&auditLimit, "limit", 50, "show at most this many recent entries (0 for all)")
	rootCmd.AddCommand(auditCmd)
}
