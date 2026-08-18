// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/auditlog"
)

var (
	auditFormat string
	auditLimit  int
	auditFollow bool
	auditKinds  []string
	auditSince  string
	auditUntil  string
	auditStatus string
	auditUser   string
	auditParent string
	auditSecret string
	auditGrep   string
)

// auditFilter is the compiled form of the narrowing flags. A zero value keeps
// everything; each set field is one AND-ed predicate. Compiling once (kinds
// into a set, since/until into instants, grep into a regexp) keeps keep() a
// cheap per-entry test, which --follow calls on every appended line.
type auditFilter struct {
	kinds  map[string]bool // empty = every kind
	since  time.Time       // zero = no lower bound
	until  time.Time       // zero = no upper bound
	status string          // "" = any
	user   string          // substring, case-insensitive
	parent string          // substring, case-insensitive
	secret string          // substring against the caller-reported labels
	grep   *regexp.Regexp  // nil = no content filter
}

// auditKindAliases maps forgiving spellings to the logfmt kind token a line
// actually renders, so `--kind command` and `--kind start` do what a reader
// means rather than silently matching nothing.
var auditKindAliases = map[string]string{
	"cmd":      "cmd",
	"command":  "cmd",
	"unlock":   "unlock",
	"use":      "use",
	"lock":     "lock",
	"service":  "service",
	"start":    "service",
	"error":    "error",
	"grant":    "grant",
	"approve":  "grant",
	"approved": "grant",
	"revoked":  "grant",
	"ended":    "grant",
	"serve":    "serve",
	"read":     "serve",
	"mount":    "serve",
}

// auditStatuses is every value --status accepts, in the order tab offers
// them. decoy/real are a mount serve's outcome, so they belong on this axis
// rather than on a flag of their own: --status decoy is the tripwire query
// ("what read a credential file and got a fake"), --status real its
// counterpart ("what actually received the value"). One slice, so the check,
// the error message and the completion cannot drift apart.
var auditStatuses = []string{"ok", "failed", "denied", "approved", "decoy", "real"}

// auditKindHelp is the kind vocabulary as tab offers it: the canonical tokens
// of auditKindAliases (the forgiving spellings are accepted but not offered,
// they would read as eight more kinds), each with what it records.
// TestAuditKindCompletionCoversEveryKind pins it to the alias map.
var auditKindHelp = []string{
	"cmd\ta jit command that ran",
	"unlock\ta session unlock (Touch ID, passcode, or the service)",
	"use\ta secret handed to a process",
	"grant\ta process grant approved, extended, revoked or ended",
	"serve\ta live mount read, decoy or real",
	"lock\tthe session locked",
	"service\tthe background service started or stopped",
	"error\ta rejected peer, or a failure jit recorded",
}

// completeAuditKinds offers the kinds --kind accepts. Denials are reached
// with --status denied rather than a kind of their own, which the flag's own
// error says too, so the active help says it here as well.
func completeAuditKinds(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	comps := cobra.AppendActiveHelp(filterValues(auditKindHelp, toComplete),
		"comma-separate to combine; denials are --status denied")
	return comps, cobra.ShellCompDirectiveNoFileComp
}

// completeAuditStatuses offers --status from the same slice compileAuditFilter
// validates against.
func completeAuditStatuses(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	desc := map[string]string{
		"ok":       "the operation succeeded",
		"failed":   "it errored",
		"denied":   "the Touch ID or consent prompt was refused",
		"approved": "the prompt was approved",
		"decoy":    "a mount read got the fake value",
		"real":     "a mount read got the real value",
	}
	values := make([]string, 0, len(auditStatuses))
	for _, s := range auditStatuses {
		values = append(values, s+"\t"+desc[s])
	}
	return filterValues(values, toComplete), cobra.ShellCompDirectiveNoFileComp
}

// completeAuditTimes offers common ages for --since/--until. parseAuditTime
// also takes absolute dates, so a bare list of ages would misrepresent the
// grammar as closed — hence the active help, as with --for on a grant.
func completeAuditTimes(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	return completeValuesWithHelp(
		`an age (90m, 2h, 3d) or a date ("2026-08-12", "2026-08-12 09:00")`,
		"1h", "6h", "24h", "3d", "7d")(cmd, args, toComplete)
}

// completeAuditEntry rides the bare command's positional completion, which
// cobra otherwise answers with the user's filenames. `jit audit` takes no
// arguments at all: everything that makes it the one filterable surface is a
// flag, and none of them was discoverable at the moment someone double-taps
// to find out. Same shape as completeGrantCreateEntry.
func completeAuditEntry(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	comps := dropTypedFlags(cmd, []string{
		"--kind\tonly these kinds: " + strings.Join(auditCanonicalKinds(), ", "),
		"--since\tonly entries after an age or a date",
		"--status\tonly this status: " + strings.Join(auditStatuses, ", "),
		"--secret\tonly events that touched a secret whose name contains this",
		"--follow\tprint the matching tail, then stream new entries live",
	})
	comps = cobra.AppendActiveHelp(comps, "audit takes filters, not arguments: jit audit --kind use --since 2h")
	return comps, cobra.ShellCompDirectiveNoFileComp
}

// auditCanonicalKinds is the kind tokens in auditKindHelp's order, for the
// one-line summaries that name them inside a description.
func auditCanonicalKinds() []string {
	out := make([]string, 0, len(auditKindHelp))
	for _, k := range auditKindHelp {
		out = append(out, k[:strings.IndexByte(k, '\t')])
	}
	return out
}

// compileAuditFilter turns the raw flags into an auditFilter, rejecting an
// unknown --kind or an unparseable --since/--until/--grep with a message that
// names what was expected. Denials are reached with --status denied, not a
// kind, because in the output they render as kind=unlock status=denied.
func compileAuditFilter() (auditFilter, error) {
	var f auditFilter
	if len(auditKinds) > 0 {
		f.kinds = map[string]bool{}
		for _, raw := range auditKinds {
			for _, k := range strings.Split(raw, ",") {
				k = strings.ToLower(strings.TrimSpace(k))
				if k == "" {
					continue
				}
				canon, ok := auditKindAliases[k]
				if !ok {
					return f, fmt.Errorf("unknown --kind %q: choose from cmd, unlock, use, grant, serve, lock, service, error (denials are --status denied)", k)
				}
				f.kinds[canon] = true
			}
		}
	}
	if auditStatus != "" {
		s := strings.ToLower(auditStatus)
		if !slices.Contains(auditStatuses, s) {
			return f, fmt.Errorf("unknown --status %q: choose from %s", auditStatus, strings.Join(auditStatuses, ", "))
		}
		f.status = s
	}
	var err error
	if f.since, err = parseAuditTime(auditSince); err != nil {
		return f, fmt.Errorf("--since %q: %w", auditSince, err)
	}
	if f.until, err = parseAuditTime(auditUntil); err != nil {
		return f, fmt.Errorf("--until %q: %w", auditUntil, err)
	}
	f.user = auditUser
	f.parent = auditParent
	f.secret = auditSecret
	if auditGrep != "" {
		if f.grep, err = regexp.Compile(auditGrep); err != nil {
			return f, fmt.Errorf("--grep %q: %w", auditGrep, err)
		}
	}
	return f, nil
}

// keep reports whether an entry survives every active predicate.
func (f auditFilter) keep(e auditEntry) bool {
	if f.kinds != nil && !f.kinds[e.kind] {
		return false
	}
	if !f.since.IsZero() && e.t.Before(f.since) {
		return false
	}
	if !f.until.IsZero() && e.t.After(f.until) {
		return false
	}
	if f.status != "" && e.status != f.status {
		return false
	}
	// --user narrows to command records: auth events carry no user because
	// they are always this machine's one user, so an events-only view under
	// --user would be empty in a confusing way. Excluding them is the honest
	// reading of "commands this user ran".
	if f.user != "" && !containsFold(e.user, f.user) {
		return false
	}
	if f.parent != "" && !containsFold(e.parent, f.parent) {
		return false
	}
	if f.secret != "" && !labelsContain(e.labels, f.secret) {
		return false
	}
	if f.grep != nil && !f.grep.MatchString(e.match) {
		return false
	}
	return true
}

// active reports whether any narrowing predicate is set — used to decide
// whether an empty result is "nothing happened" or "nothing matched".
func (f auditFilter) active() bool {
	return f.kinds != nil || !f.since.IsZero() || !f.until.IsZero() ||
		f.status != "" || f.user != "" || f.parent != "" || f.secret != "" || f.grep != nil
}

// containsFold is a case-insensitive substring test; empty needle matches.
func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

// labelsContain reports whether any caller-reported secret name contains the
// needle (case-insensitive), so --secret stripe finds stripe/live-key.
func labelsContain(labels []string, needle string) bool {
	for _, l := range labels {
		if containsFold(l, needle) {
			return true
		}
	}
	return false
}

// parseAuditTime accepts a relative age (2h, 90m, 3d, 1w — interpreted as
// "that long ago") or an absolute local timestamp (2006-01-02, with an
// optional time, or RFC3339). Empty is the zero time, meaning "no bound".
func parseAuditTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	if d, ok := parseFlexDuration(s); ok {
		// A duration here is read as "that long ago"; a negative one would
		// resolve into the future and silently match nothing. Reject it with a
		// message that names the fix rather than leaving an empty result.
		if d < 0 {
			return time.Time{}, fmt.Errorf("a duration here means %q ago; drop the leading '-'", strings.TrimPrefix(s, "-"))
		}
		return time.Now().Add(-d), nil
	}
	for _, layout := range []string{auditTimeLayout, "2006-01-02 15:04", "2006-01-02", time.RFC3339} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("not a duration (like 2h, 90m, 3d) or a date (like 2006-01-02 or %q)", auditTimeLayout)
}

// parseFlexDuration extends time.ParseDuration with day and week suffixes,
// which it lacks but a log reader reaches for constantly ("--since 3d").
func parseFlexDuration(s string) (time.Duration, bool) {
	if d, err := time.ParseDuration(s); err == nil {
		return d, true
	}
	if len(s) >= 2 {
		num, unit := s[:len(s)-1], s[len(s)-1]
		if v, err := strconv.ParseFloat(num, 64); err == nil {
			switch unit {
			case 'd':
				return time.Duration(v * float64(24*time.Hour)), true
			case 'w':
				return time.Duration(v * float64(7*24*time.Hour)), true
			}
		}
	}
	return 0, false
}

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
		"whether it succeeded), interleaved with every local-auth event the service saw\n" +
		"(each unlock, each APPROVED disclosed grant, and each DECLINED prompt, with how\n" +
		"you were asked, what triggered it, and the secret names each one touched).\n\n" +
		"Together they answer \"what happened on this machine, and who did it\": the\n" +
		"command lines are the actions, the auth lines are the approvals those actions\n" +
		"needed. Command arguments are recorded with any secret-looking value masked, so\n" +
		"the log records that a command ran, never the secret it may have carried.\n\n" +
		"It also records what the service refused at its socket: a rejected peer (a\n" +
		"process the kernel says isn't yours, probing the agent), a malformed request, an\n" +
		"unwrap whose claimed credential class doesn't match the ciphertext it sent\n" +
		"(op=class-mismatch — a caller with no vault data trying to summon a prompt), or\n" +
		"the accept loop failing, each as a kind=error line with the peer's provenance.\n" +
		"Repeated rejections collapse into one line carrying a count; a collapsed line\n" +
		"names the first caller of that window, because keying them per caller would let\n" +
		"a flood of throwaway processes push every real event out of the history.\n\n" +
		"Mount reads are here too, as kind=serve: every time a reader opened a live\n" +
		"mount, whether it got the decoy (--status decoy) or the real value (--status\n" +
		"real), why, and — best-effort, from the kernel — which program read it and what\n" +
		"launched that program. A decoy read is jit working as designed, and it is also\n" +
		"the one signal that names a process reading a credential file it has no business\n" +
		"in. Same-mount, same-reader, same-verdict reads inside a short window collapse\n" +
		"into one line carrying a count, because a file watcher re-reads a mount\n" +
		"continuously and an uncollapsed read would push every unlock out of the log.\n\n" +
		"Output is a grouped text timeline, newest first. --format logfmt prints one\n" +
		"key=value line per event instead, so it reads and greps like a real service\n" +
		"log. Narrow either without grep using the flags: --kind\n" +
		"cmd,unlock,use,grant,serve,lock,service,error, --status\n" +
		"ok|failed|denied|approved|decoy|real,\n" +
		"--since and --until\n" +
		"(an age like 2h/3d or a date), --parent (the launching ancestor, e.g. claude),\n" +
		"--secret (a secret name an unlock touched), --user, and --grep (a regexp over the\n" +
		"line). --limit caps how many of the newest MATCHING entries print. Add --follow\n" +
		"(-f) to print the matching tail and then stream new entries live, like tail -f.\n" +
		"For a machine-parseable dump of the same, filtered, data use --format json.\n\n" +
		"On the auth method: jit challenges with a single macOS prompt that accepts\n" +
		"either a fingerprint or the device passcode, and the OS does not report which\n" +
		"one you used. So the method reads touchid-or-passcode (biometry is available on\n" +
		"this Mac) or passcode (it isn't), never a claim macOS can't back.\n\n" +
		"Survives restarts and logouts: both halves are durable files alongside the\n" +
		"vault (audit.jsonl and agent-history.jsonl), so this answers for last week as\n" +
		"readily as for the last hour. To scan for plaintext secrets on disk instead,\n" +
		"that command is now `jit scan`. For the service's raw operational output\n" +
		"(startup, mount notes, panics) rather than the event trail, see `jit service log`.",
	// Eleven filters and no example composing any of them: the flags are
	// documented one by one, and what this command is FOR is the combination.
	Example: "  jit audit                                  # the recent log\n" +
		"  jit audit --kind use --since 2h            # what read a secret, lately\n" +
		"  jit audit --status denied                  # refused prompts\n" +
		"  jit audit --parent claude --kind serve     # what one tool's tree read\n" +
		"  jit audit --follow                         # stream new entries live",
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateAuditOutputFormat(auditFormat); err != nil {
			return fmt.Errorf("jit audit: %w", err)
		}
		if auditFollow && auditFormat == "json" {
			return fmt.Errorf("jit audit: --follow streams the text log; it can't be combined with --format json")
		}
		filter, err := compileAuditFilter()
		if err != nil {
			return fmt.Errorf("jit audit: %w", err)
		}
		root, err := vaultRootDir()
		if err != nil {
			return fmt.Errorf("jit audit: %w", err)
		}

		// Read both durable logs directly rather than asking the running
		// service: the audit trail must read the same whether or not the agent
		// happens to be up, and the agent appends every event to the same file
		// it would serve, so nothing recent is missed. Load ALL of each (the
		// files are bounded, a few hundred KB to ~2MB) and filter in memory, so
		// --limit means "the newest N that MATCH" rather than "matches within
		// the newest N" — the former is what a reader narrowing with a filter
		// actually wants.
		// --follow reads the files itself, starting the stream from the exact
		// offset its initial tail consumed, so it never double-reads nor skips
		// a line across the load; it does not share this snapshot.
		if auditFollow {
			return followAuditLog(cmd.Context(), cmd.OutOrStdout(), root, filter, auditLimit)
		}

		commands := auditlog.New(root, io.Discard).Load(0)
		events := newHistoryLog(root, io.Discard).load(1 << 30)

		// Page the snapshot views on a terminal. --follow stays direct: it
		// streams live, and a pager buffering an endless tail shows nothing.
		out, donePaging := pageableOutput(cmd)
		defer donePaging()

		if auditFormat == "json" {
			keptCmds, keptEvents := filterSources(commands, events, filter, auditLimit)
			return writeJSON(out, auditJSON{Commands: keptCmds, AuthEvents: keptEvents})
		}

		printAuditLog(out, commands, events, filter, auditLimit)
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
// the merge sort), the metadata the filters test against, and the rendered
// line. match is the uncolored logfmt line (what --grep runs against and what
// --follow re-reads), line is the display form that may carry ANSI color.
type auditEntry struct {
	t      time.Time
	kind   string   // logfmt kind token: cmd | unlock | use | grant | lock | service | error
	status string   // ok | failed | denied, where the kind carries one; else ""
	user   string   // command records only (auth events are all this machine's user)
	parent string   // the ancestor that explains the call (launched-by)
	labels []string // caller-reported secret names an auth event touched
	match  string   // uncolored logfmt line, for --grep and content matching
	line   string   // display line, may carry ANSI color

	// The fields below drive the human report. They hold the same facts the
	// logfmt line encodes, kept apart so the report can lay them out in
	// columns instead of re-parsing its own output: subject is what happened
	// (the command, or "session unlocked"), detail an error or note that
	// belongs under it, and action a fix the reader can run.
	subject string
	detail  string
	action  string

	// undelivered marks a serve row whose reader received nothing (EPIPE
	// before the write) — the header counts those apart from decoy reads,
	// because an empty touch and a delivered decoy are different findings.
	undelivered bool
}

// printAuditLog merges command records and auth events into one reverse-
// chronological logfmt stream: one `key=value` line per event, the shape a
// real service log takes, so the output is scan- and grep-friendly and reads
// as a log rather than a report. Entries are filtered first; limit, when
// positive, then caps to the newest that survived.
func printAuditLog(w io.Writer, commands []auditlog.Record, events []agent.SessionEvent, filter auditFilter, limit int) {
	home, _ := os.UserHomeDir()
	entries := buildEntries(home, commands, events, filter)
	if len(entries) == 0 {
		printAuditEmpty(w, filter.active())
		return
	}
	// Newest first. Stable so that a command and the unlock it triggered, which
	// can share a whole-second timestamp, keep the order they were appended in.
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].t.After(entries[j].t) })
	// Measure the whole match set BEFORE the limit cuts it: the header
	// describes what the query matched, the cap only decides what prints.
	scale := auditScaleOf(entries)
	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
	}

	if auditFormat == "logfmt" {
		for _, e := range entries {
			fmt.Fprintln(w, e.line)
		}
		return
	}
	printAuditReport(w, entries, filter.active(), scale)
}

// buildEntries renders every command and event that survives the filter into a
// merged, still-unsorted slice of timeline rows.
func buildEntries(home string, commands []auditlog.Record, events []agent.SessionEvent, filter auditFilter) []auditEntry {
	entries := make([]auditEntry, 0, len(commands)+len(events))
	for _, r := range commands {
		if e := commandEntry(r); filter.keep(e) {
			entries = append(entries, e)
		}
	}
	for _, ev := range events {
		if e := authEntry(home, ev); filter.keep(e) {
			entries = append(entries, e)
		}
	}
	return entries
}

// filterSources applies the same predicates for --format json, returning the
// surviving records and events in their native shapes (never nil, so the JSON
// renders [] not null) each capped to the newest `limit`. The filter is tested
// against the rendered entry so text and json narrow identically.
func filterSources(commands []auditlog.Record, events []agent.SessionEvent, filter auditFilter, limit int) ([]auditlog.Record, []agent.SessionEvent) {
	home, _ := os.UserHomeDir()
	// Choose the newest `limit` over the MERGED timeline — exactly the set the
	// text and logfmt views show — rather than the newest `limit` of each
	// source independently, which would return up to 2*limit rows and a
	// different set than text for the same flags.
	type ref struct {
		t     time.Time
		isCmd bool
		idx   int
	}
	var refs []ref
	for i, r := range commands {
		if filter.keep(commandEntry(r)) {
			refs = append(refs, ref{t: time.Unix(0, r.UnixNano), isCmd: true, idx: i})
		}
	}
	for i, ev := range events {
		if filter.keep(authEntry(home, ev)) {
			refs = append(refs, ref{t: time.Unix(ev.UnixTime, 0), isCmd: false, idx: i})
		}
	}
	// Newest first — same stable order buildEntries+sort uses (commands appended
	// before events, so a tie keeps that order) — then cap the merged stream.
	sort.SliceStable(refs, func(i, j int) bool { return refs[i].t.After(refs[j].t) })
	if limit > 0 && len(refs) > limit {
		refs = refs[:limit]
	}
	cmdSel, evtSel := map[int]bool{}, map[int]bool{}
	for _, r := range refs {
		if r.isCmd {
			cmdSel[r.idx] = true
		} else {
			evtSel[r.idx] = true
		}
	}
	// Restore each array to its native oldest-first order. Never nil, so the
	// JSON renders [] not null.
	keptCmds := []auditlog.Record{}
	for i, r := range commands {
		if cmdSel[i] {
			keptCmds = append(keptCmds, r)
		}
	}
	keptEvents := []agent.SessionEvent{}
	for i, ev := range events {
		if evtSel[i] {
			keptEvents = append(keptEvents, ev)
		}
	}
	return keptCmds, keptEvents
}

// auditFollowPollInterval paces --follow's growth checks — comfortably under a
// human's "is it live?" threshold without hammering stat, the same cadence
// `jit service log --follow` uses.
const auditFollowPollInterval = 500 * time.Millisecond

// followAuditLog prints the newest matching tail, then streams every later
// matching line as it lands in either durable log. Unlike the one-shot view
// (newest-first), the follow stream is chronological — the initial tail oldest-
// first and each new line after it — so a live watch reads like `tail -f`
// rather than scrolling backwards. Ends on ctrl-C / SIGTERM.
func followAuditLog(ctx context.Context, w io.Writer, root string, filter auditFilter, limit int) error {
	home, _ := os.UserHomeDir()

	auditPath := filepath.Join(root, auditlog.FileName)
	histPath := filepath.Join(root, historyFileName)
	// Read each file once for the opening tail, keeping the exact byte offset
	// that read consumed, and begin the live stream from precisely there. Using
	// the same read to produce both the tail and the follow offset (rather than
	// a later stat) closes the window in which a line appended between the two
	// is neither shown in the tail nor picked up as new.
	offA, commands := readNewCommands(auditPath, 0)
	offH, events := readNewEvents(histPath, 0)

	entries := buildEntries(home, commands, events, filter)
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].t.Before(entries[j].t) })
	if limit > 0 && len(entries) > limit {
		entries = entries[len(entries)-limit:]
	}
	// --follow streams a timeline that has no end, so it can't precompute
	// columns over entries it hasn't seen. It sizes them from the opening
	// tail and holds them steady, which is what keeps a live feed's columns
	// from jumping every time a longer command scrolls past.
	cols := auditFollowColumns(entries)
	for _, e := range entries {
		writeAuditFollowRow(w, e, cols)
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	ticker := time.NewTicker(auditFollowPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		var fresh []auditEntry
		var newCmds []auditlog.Record
		offA, newCmds = readNewCommands(auditPath, offA)
		for _, r := range newCmds {
			if e := commandEntry(r); filter.keep(e) {
				fresh = append(fresh, e)
			}
		}
		var newEvents []agent.SessionEvent
		offH, newEvents = readNewEvents(histPath, offH)
		for _, ev := range newEvents {
			if e := authEntry(home, ev); filter.keep(e) {
				fresh = append(fresh, e)
			}
		}
		if len(fresh) == 0 {
			continue
		}
		// Interleave a command and the unlock it triggered by time. Stable, so
		// two lines sharing a whole second keep their append order.
		sort.SliceStable(fresh, func(i, j int) bool { return fresh[i].t.Before(fresh[j].t) })
		for _, e := range fresh {
			writeAuditFollowRow(w, e, cols)
		}
	}
}

// readNewCommands returns command records appended to path since off and the
// advanced offset; readAppended handles trims and partial trailing lines.
func readNewCommands(path string, off int64) (int64, []auditlog.Record) {
	data, newOff, ok := readAppended(path, off)
	if !ok {
		return newOff, nil
	}
	var out []auditlog.Record
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var r auditlog.Record
		if err := json.Unmarshal(line, &r); err != nil || r.Command == "" {
			continue
		}
		out = append(out, r)
	}
	return newOff, out
}

// readNewEvents is readNewCommands' twin for the session-history file.
func readNewEvents(path string, off int64) (int64, []agent.SessionEvent) {
	data, newOff, ok := readAppended(path, off)
	if !ok {
		return newOff, nil
	}
	var out []agent.SessionEvent
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var e agent.SessionEvent
		if err := json.Unmarshal(line, &e); err != nil || e.Kind == "" {
			continue
		}
		// Same legacy scrub historyLog.load applies: a line written before the
		// agent masked By at the source can hold a caller's raw secret, and
		// this reader feeds `jit audit` (text and JSON alike).
		e.By = auditlog.RedactCommandLine(e.By)
		out = append(out, e)
	}
	return newOff, out
}

// readAppended returns the bytes of path from off up to its last complete line
// and the offset advanced to that newline. ok is false (with a sensible new
// offset) when there is nothing complete to read: the file is unchanged, not
// there, or was trimmed smaller — in which case the offset resets to the new
// end so the trimmed-away prefix is never reprinted, at the cost of possibly
// missing a line or two written during that rare trim, which a live tail can
// afford.
func readAppended(path string, off int64) ([]byte, int64, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, off, false
	}
	size := fi.Size()
	if size < off {
		return nil, size, false
	}
	if size == off {
		return nil, off, false
	}
	f, err := os.Open(path) // #nosec G304 -- jit's own bookkeeping file under its config root
	if err != nil {
		return nil, off, false
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, off, false
	}
	buf := make([]byte, size-off)
	n, _ := io.ReadFull(f, buf)
	buf = buf[:n]
	nl := bytes.LastIndexByte(buf, '\n')
	if nl < 0 {
		return nil, off, false // no complete line yet
	}
	return buf[:nl+1], off + int64(nl+1), true
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
	if !strings.ContainsAny(v, " \t\r\n\"=") {
		return v
	}
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	// Escape newlines and carriage returns to their two-character forms so one
	// event never splits across physical lines — the whole promise of "one
	// key=value line per event". Done after the backslash pass above so the
	// backslash this inserts is not itself doubled.
	v = strings.ReplaceAll(v, "\r", `\r`)
	v = strings.ReplaceAll(v, "\n", `\n`)
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
	// A command that forced its own fresh Touch ID/passcode (jit migrate
	// undo/remove) surfaces it here — the audit trail should show a
	// plaintext-restoring or destructive action was gated by a live
	// fingerprint, not a cached session.
	if r.Auth != "" {
		pairs = append(pairs, kv{"auth", r.Auth})
	}
	if r.Error != "" {
		pairs = append(pairs, kv{"err", r.Error})
	}
	plain := logfmtLine(pairs)
	line := plain
	if !r.Success {
		line = cRisk.Sprint(plain)
	}
	detail, action := splitAuditError(r.Error)
	return auditEntry{
		t:       t,
		kind:    "cmd",
		status:  status,
		user:    r.User,
		parent:  launcher(r.LaunchedBy, r.Parent),
		match:   plain,
		line:    line,
		subject: invocation,
		detail:  detail,
		action:  action,
	}
}

// auditFixRe lifts a suggested command out of an error message. jit's errors
// end with "run `some command` to ..." by convention, which in logfmt is
// buried mid-value inside a quoted string — on the report it becomes the
// arrow line, the last thing on screen because it is the thing to type.
var auditFixRe = regexp.MustCompile("(?i)(?:[,;—-]|\\.)?\\s*run `([^`]+)`")

// splitAuditError separates an error into the sentence that says what went
// wrong and the command that might fix it. The command's own prefix
// ("jit clisso-capture: ") goes too — the row above already names it.
func splitAuditError(err string) (detail, action string) {
	if err == "" {
		return "", ""
	}
	detail = auditCmdPrefixRe.ReplaceAllString(err, "")
	if m := auditFixRe.FindStringSubmatchIndex(detail); m != nil {
		action = detail[m[2]:m[3]]
		detail = strings.TrimRight(detail[:m[0]], " ,;—-.")
	}
	return detail, action
}

// auditCmdPrefixRe strips the "jit <subcommand>: " an error carries so it can
// stand alone as a message; the row it hangs under already names the command.
var auditCmdPrefixRe = regexp.MustCompile(`^jit [a-z-]+(?: [a-z-]+)?: `)

// authEntry renders one agent session event (unlock, denial, use, lock, or
// agent start) as a logfmt line, on an absolute-time axis and surfacing the
// recorded auth method.
func authEntry(home string, e agent.SessionEvent) auditEntry {
	t := time.Unix(e.UnixTime, 0)
	pairs := []kv{{"time", t.Format(auditTimeLayout)}}
	var lineColor *color.Color
	// kind/status mirror the logfmt tokens this line renders, so the filters
	// test against exactly what the user greps.
	var kind, status string
	// subject/detail are the human report's fields; the logfmt pairs above
	// stay the machine form. Both are built in one pass so the two views can
	// never describe the same event differently.
	var subject, detail string

	switch e.Kind {
	case agent.KindLock:
		kind = "lock"
		cause := e.Cause
		if cause == "" {
			cause = "unknown"
		}
		pairs = append(pairs, kv{"level", "info"}, kv{"kind", "lock"}, kv{"reason", cause})
		subject = "session locked (" + cause + ")"
	case agent.KindStart:
		kind = "service"
		pairs = append(pairs, kv{"level", "info"}, kv{"kind", "service"}, kv{"msg", "process started"})
		subject = "service process started"
		if b := strings.TrimPrefix(e.Cause, "build "); b != e.Cause {
			pairs = append(pairs, kv{"build", b})
		} else if e.Cause != "" {
			pairs = append(pairs, kv{"note", e.Cause})
		}
	case agent.KindDenied:
		kind, status = "unlock", "denied"
		pairs = append(pairs,
			kv{"level", "warn"}, kv{"kind", "unlock"}, kv{"status", "denied"},
			kv{"method", authMethodSlug(e)})
		subject = "unlock DENIED (" + authMethodLabel(e) + ")"
		detail = e.Cause
		if e.Cause != "" {
			pairs = append(pairs, kv{"reason", e.Cause})
		}
		pairs = appendAuthContext(pairs, home, e)
		lineColor = cWarn
	case agent.KindApproved:
		// The counterpart to KindDenied: a disclosed challenge — a --with
		// grant, a per-process consent prompt, a --trust registration — that
		// the human APPROVED. Its own kind rather than an unlock, because no
		// session transition happened; reason carries the exact sentence they
		// read on the dialog, which is the point of recording it at all.
		kind, status = "grant", "approved"
		pairs = append(pairs,
			kv{"level", "info"}, kv{"kind", "grant"}, kv{"status", "approved"},
			kv{"method", authMethodSlug(e)})
		subject = "grant approved (" + authMethodLabel(e) + ")"
		detail = e.Cause
		if e.Cause != "" {
			pairs = append(pairs, kv{"reason", e.Cause})
		}
		pairs = appendAuthContext(pairs, home, e)
	case agent.KindUse:
		kind = "use"
		pairs = append(pairs, kv{"level", "info"}, kv{"kind", "use"}, kv{"op", agent.DescribeUse(e.Op)})
		subject = agent.DescribeUse(e.Op)
		if e.Count > 1 {
			subject = fmt.Sprintf("%s ×%d", subject, e.Count)
		}
		if e.Count > 1 {
			pairs = append(pairs, kv{"count", strconv.FormatInt(e.Count, 10)})
		}
		pairs = appendAuthContext(pairs, home, e)
	case agent.KindServe:
		// One mount read, collapsed. status carries the verdict (decoy | real)
		// rather than a new axis, because that IS the serve's outcome and
		// --status is where a reader already looks for one. The decoy rows are
		// the tripwire — amber, and counted in the header — while the real ones
		// answer the question a grant approval never could: not "was this
		// authorized" but "was it actually read".
		kind = "serve"
		status = agent.OpServeDecoy
		if e.Op == agent.OpServeReal {
			status = agent.OpServeReal
		}
		level := "info"
		if status == agent.OpServeDecoy {
			level = "warn"
			lineColor = cWarn
		}
		reader := serveReaderName(e)
		switch {
		case e.Undelivered:
			// The reader was gone before the write: it received nothing, and
			// saying "served" here is exactly the overstatement this field
			// exists to retire. The verdict still rides in status, so
			// --status decoy keeps matching these rows.
			subject = "opened by " + reader + ", nothing read"
		case status == agent.OpServeDecoy:
			subject = "decoy served to " + reader
		default:
			subject = "real value served to " + reader
		}
		if e.Count > 1 {
			subject = fmt.Sprintf("%s ×%d", subject, e.Count)
		}
		pairs = append(pairs,
			kv{"level", level}, kv{"kind", "serve"}, kv{"status", status})
		if e.Undelivered {
			pairs = append(pairs, kv{"undelivered", "true"})
		}
		if len(e.Labels) > 0 {
			pairs = append(pairs, kv{"mount", strings.Join(e.Labels, ", ")})
		}
		if e.Count > 1 {
			pairs = append(pairs, kv{"count", strconv.FormatInt(e.Count, 10)})
		}
		if e.By != "" {
			pairs = append(pairs, kv{"reader", shortenCommand(home, e.By)})
		}
		if e.ByPID != 0 {
			pairs = append(pairs, kv{"reader_pid", strconv.FormatInt(int64(e.ByPID), 10)})
		}
		// The inference marker travels with the identity it qualifies, in both
		// views: a carried-over reader is "almost certainly" this process, and
		// a trail that renders that as certainty is worse than one that says
		// less (identifyReader's own doctrine).
		if e.ByLikely {
			pairs = append(pairs, kv{"reader_likely", "true"})
		}
		if e.LaunchedBy != "" {
			pairs = append(pairs, kv{"parent", e.LaunchedBy})
		}
		detail = e.Cause
		if e.Cause != "" {
			pairs = append(pairs, kv{"reason", e.Cause})
		}
	case agent.KindGrantEnd:
		// A process grant ending — expiry, revoke, or its root process
		// exiting. Same kind token as the approval that created it, so
		// `--kind grant` shows a grant's whole life; status carries which
		// ending it was. Op is the grant id, Labels the covered vault paths.
		kind, status = "grant", "ended"
		pairs = append(pairs, kv{"level", "info"}, kv{"kind", "grant"}, kv{"status", "ended"})
		subject = "grant ended"
		if e.Cause != "" {
			subject = e.Cause
		}
		if e.Op != "" {
			pairs = append(pairs, kv{"grant", e.Op})
		}
		if e.Cause != "" {
			pairs = append(pairs, kv{"reason", e.Cause})
		}
		pairs = appendAuthContext(pairs, home, e)
	case agent.KindError:
		// A socket-boundary failure the service refused or hit: a rejected
		// peer, a malformed request, the accept loop dying. op names which and
		// reason carries the detail; the caller provenance (when the kernel
		// still named the peer) is exactly what makes a rejected-peer line
		// worth having. Yellow — it sits with the denials as the lines an
		// investigation scans for.
		kind = "error"
		pairs = append(pairs, kv{"level", "error"}, kv{"kind", "error"})
		subject = "service refused a request"
		if e.Op != "" {
			subject = "service refused: " + e.Op
		}
		detail = e.Cause
		if e.Op != "" {
			pairs = append(pairs, kv{"op", e.Op})
		}
		// Rejections that repeat are collapsed into one event carrying how
		// many there were (see recordRejectedClass). Without printing it, a
		// flood of hundreds reads exactly like a single stray request — and
		// the count is the whole reason the line is interesting.
		if e.Count > 1 {
			pairs = append(pairs, kv{"count", strconv.FormatInt(e.Count, 10)})
		}
		if e.Cause != "" {
			pairs = append(pairs, kv{"reason", e.Cause})
		}
		pairs = appendAuthContext(pairs, home, e)
		lineColor = cWarn
	default: // unlock
		kind, status = "unlock", "ok"
		pairs = append(pairs,
			kv{"level", "info"}, kv{"kind", "unlock"}, kv{"status", "ok"},
			kv{"method", authMethodSlug(e)})
		subject = "session unlocked (" + authMethodLabel(e) + ")"
		pairs = appendAuthContext(pairs, home, e)
	}

	plain := logfmtLine(pairs)
	line := plain
	if lineColor != nil {
		line = lineColor.Sprint(plain)
	}
	return auditEntry{
		t:           t,
		kind:        kind,
		status:      status,
		parent:      e.LaunchedBy,
		labels:      e.Labels,
		match:       plain,
		line:        line,
		subject:     subject,
		detail:      detail,
		undelivered: e.Kind == agent.KindServe && e.Undelivered,
	}
}

// serveReaderName names who read a mount, for the human report's subject.
//
// Three honest states, never four: the program's own name when lineage saw it
// open the mount, the same name marked "likely" when the identity is carried
// over from an earlier scan of that mount, and an explicit admission when the
// scan missed it outright. A fast-closing reader legitimately evades the scan
// (which is exactly why lineage is audit-only and gates nothing), so the third
// case is normal rather than exceptional and must read that way.
func serveReaderName(e agent.SessionEvent) string {
	if e.By == "" {
		return "an unidentified reader"
	}
	name := filepath.Base(e.By)
	if e.ByLikely {
		return name + " (likely)"
	}
	return name
}

// authMethodLabel names the local-auth method the way the dialog does, for
// the human report; authMethodSlug keeps the stable token logfmt and --grep
// match against.
func authMethodLabel(e agent.SessionEvent) string {
	switch authMethodSlug(e) {
	case "touchid-or-passcode":
		return "Touch ID"
	case "passcode":
		return "passcode"
	default:
		return authMethodSlug(e)
	}
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
	auditCmd.Flags().StringVar(&auditFormat, "format", "text", `output format: "text" (default), "logfmt" (one key=value line per event), or "json"`)
	auditCmd.Flags().IntVar(&auditLimit, "limit", 50, "show at most this many recent matching entries (0 for all)")
	auditCmd.Flags().BoolVarP(&auditFollow, "follow", "f", false, "print the matching tail, then stream new entries live (text only)")
	auditCmd.Flags().StringSliceVar(&auditKinds, "kind", nil, "only these kinds (comma-separated): cmd, unlock, use, grant, serve, lock, service, error")
	auditCmd.Flags().StringVar(&auditSince, "since", "", `only entries at or after this time: an age (2h, 90m, 3d) or a date ("2026-07-23" or "2026-07-23 09:00")`)
	auditCmd.Flags().StringVar(&auditUntil, "until", "", "only entries at or before this time (same forms as --since)")
	auditCmd.Flags().StringVar(&auditStatus, "status", "", "only this status: ok, failed, denied, approved, decoy, or real")
	auditCmd.Flags().StringVar(&auditUser, "user", "", "only commands this user ran (auth events carry no user)")
	auditCmd.Flags().StringVar(&auditParent, "parent", "", "only entries whose launched-by ancestor contains this (e.g. claude)")
	auditCmd.Flags().StringVar(&auditSecret, "secret", "", "only auth events that touched a secret whose name contains this")
	auditCmd.Flags().StringVar(&auditGrep, "grep", "", "only entries whose rendered line matches this regular expression")
	registerPagerFlag(auditCmd)

	// `jit audit` is the one filterable surface, and every filter is a flag:
	// tab offered a directory listing for all eleven of them, and nothing at
	// all for the bare command. See completeAuditEntry.
	auditCmd.ValidArgsFunction = completeAuditEntry
	_ = auditCmd.RegisterFlagCompletionFunc("format", completeValues(
		"text\thuman-readable (default)",
		"logfmt\tone key=value line per event",
		"json\tone JSON object per event"))
	_ = auditCmd.RegisterFlagCompletionFunc("kind", completeAuditKinds)
	_ = auditCmd.RegisterFlagCompletionFunc("status", completeAuditStatuses)
	_ = auditCmd.RegisterFlagCompletionFunc("since", completeAuditTimes)
	_ = auditCmd.RegisterFlagCompletionFunc("until", completeAuditTimes)
	// --parent matches the launched-by chain, which is exactly the set
	// `jit grant --process` already computes from the same two logs.
	_ = auditCmd.RegisterFlagCompletionFunc("parent", completeGrantProcessNames)
	_ = auditCmd.RegisterFlagCompletionFunc("secret", completeVaultPaths)
	_ = auditCmd.RegisterFlagCompletionFunc("limit", completeCounts(20, 50, 200, 0))
	rootCmd.AddCommand(auditCmd)
}
