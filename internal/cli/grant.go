// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/auditlog"
	"github.com/jitpass/jit/internal/lineage"
	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

// jit grant — process grants (design/process-grants.md): pre-approve a
// RUNNING process tree to use one or more profiles' secrets unattended, for
// a bounded time, with one Touch ID given while you are still at the
// keyboard. The bare command creates; list/revoke/extend manage what exists.
// All state lives in the service's memory — the CLI here is a thin client
// over the grant_* RPCs, plus the name-to-pid resolution and completion
// that need a terminal-side view.

var (
	grantProcess      string
	grantPIDFlag      int32
	grantProfileNames []string
	grantFor          string
	grantListFormat   string
	grantExtendFor    string
)

var grantCmd = &cobra.Command{
	Use:     "grant --process NAME --profile NAME --for DURATION",
	GroupID: groupSecrets,
	Short:   "Pre-approve a running process to use profiles unattended",
	Long: `Create a process grant: with one Touch ID now, allow a process that is
already running (and everything it launches) to use the named profiles'
secrets without further prompts, until the grant expires - including while
the screen is locked or you are away.

The grant is anchored to the live process you name, not to its name: a new
process called the same thing tomorrow inherits nothing. It covers exactly
the secrets the named profiles resolve to at creation time, ends at its
deadline (or when the process exits, or on 'jit grant revoke'), and every
serve under it is recorded in 'jit audit'.

Grants live in the service's memory: they survive screen lock by design,
and do not survive a service restart or reboot.`,
	Example: `  # let the running claude session use the jamf profile for 8 hours
  jit grant --process claude --profile jamf --for 8h

  # several profiles in one grant, anchored by pid when the name is ambiguous
  jit grant --pid 4211 --profile jamf --profile aws-ci --for 1d

  # see, shorten, or end what is open
  jit grant list
  jit grant revoke g-7f3a
  jit grant extend g-7f3a --for 24h`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := runGrantCreate(cmd.OutOrStdout()); err != nil {
			return fmt.Errorf("jit grant: %w", err)
		}
		return nil
	},
}

var grantListCmd = &cobra.Command{
	Use:   "list",
	Short: "Show the active process grants",
	Long: `List every live process grant: who holds it, which profiles it covers,
when it expires, and how many serves have ridden it. Reading this never
prompts.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := runGrantList(cmd.OutOrStdout()); err != nil {
			return fmt.Errorf("jit grant list: %w", err)
		}
		return nil
	},
}

var grantRevokeCmd = &cobra.Command{
	Use:   "revoke ID",
	Short: "End a process grant now",
	Long: `End a grant immediately. No authentication: reducing access is always
free, and the kill switch is deliberately the easiest command in the
feature. The ending is recorded in 'jit audit'.`,
	Args:              requireGrantID,
	ValidArgsFunction: completeGrantIDs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := runGrantRevoke(cmd.OutOrStdout(), args[0]); err != nil {
			return fmt.Errorf("jit grant revoke: %w", err)
		}
		return nil
	},
}

var grantExtendCmd = &cobra.Command{
	Use:   "extend ID --for DURATION",
	Short: "Give an existing grant more time (re-prompts Touch ID)",
	Long: `Move a grant's deadline to now plus the new duration. More time is a new
decision, so this puts the same disclosed prompt in front of you that
creating the grant did. Shortening needs no command of its own: revoke and
re-create, and neither step re-asks for what you already have.`,
	Args:              requireGrantID,
	ValidArgsFunction: completeGrantIDs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := runGrantExtend(cmd.OutOrStdout(), args[0]); err != nil {
			return fmt.Errorf("jit grant extend: %w", err)
		}
		return nil
	},
}

// requireGrantID is ExactArgs(1) with the argument named in the error, so a
// bare `jit grant revoke` says what is missing instead of counting.
func requireGrantID(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("expects a grant id (see `jit grant list`)")
	}
	return nil
}

// grantCreateUsage is the one-line shape of a create, quoted wherever a user
// lands without it: the bare command, an empty completion, a missing flag.
const grantCreateUsage = "jit grant --process <name> --profile <profile> --for <duration>"

func runGrantCreate(out io.Writer) error {
	// A bare `jit grant` is someone discovering the command, not someone who
	// forgot one flag: answer with the whole shape, not the first missing
	// piece of it.
	if grantProcess == "" && grantPIDFlag == 0 && len(grantProfileNames) == 0 && grantFor == "" {
		return fmt.Errorf("create a grant with %s\n(list / revoke / extend manage existing grants - see `jit grant --help`)", grantCreateUsage)
	}
	if grantProcess == "" && grantPIDFlag == 0 {
		return fmt.Errorf("--process is required (the running program to grant to; tab-completes from recent callers)")
	}
	if len(grantProfileNames) == 0 {
		return fmt.Errorf("--profile is required (repeat it for several: --profile jamf --profile aws-ci)")
	}
	if grantFor == "" {
		return fmt.Errorf("--for is required (how long the grant lasts, like 45m, 8h, 3d - max %s)", formatFlexDuration(agent.MaxGrantTTL))
	}
	ttl, err := parseGrantFor(grantFor)
	if err != nil {
		return err
	}

	// Validate the profiles HERE, where the error can name the files checked —
	// the service re-resolves authoritatively, but a typo should fail before
	// any RPC, let alone a prompt.
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, name := range grantProfileNames {
		if seen[name] {
			return fmt.Errorf("--profile %s given twice", name)
		}
		seen[name] = true
		if _, err := profile.Load(cwd, name); err != nil {
			return err
		}
	}

	target, err := resolveGrantTarget()
	if err != nil {
		return err
	}

	ac, err := agentClient()
	if err != nil {
		return err
	}
	st, err := ac.GrantCreate(target.PID, grantProfileNames, cwd, ttl)
	if err != nil {
		return notRunningHint(err)
	}
	printGrantCreated(out, st)
	return nil
}

// resolveGrantTarget turns --process/--pid into the live process the grant
// anchors to. A name that matches several running processes is an error that
// lists them — the human picks with --pid; jit never guesses which claude
// they meant.
func resolveGrantTarget() (lineage.Process, error) {
	if grantPIDFlag != 0 && grantProcess != "" {
		return lineage.Process{}, fmt.Errorf("give --process or --pid, not both")
	}
	if grantPIDFlag != 0 {
		p, ok := lineage.Describe(grantPIDFlag)
		if !ok {
			return lineage.Process{}, fmt.Errorf("no process with pid %d (it may have exited)", grantPIDFlag)
		}
		return p, nil
	}
	if grantProcess == "" {
		return lineage.Process{}, fmt.Errorf("--process is required (the running program to grant to; tab-completes from recent callers)")
	}
	procs := lineage.ProcessesNamed(grantProcess)
	switch len(procs) {
	case 0:
		return lineage.Process{}, fmt.Errorf("nothing named %q is running - a grant anchors to a live process, start it first", grantProcess)
	case 1:
		return procs[0], nil
	}
	lines := make([]string, 0, len(procs))
	for _, p := range procs {
		lines = append(lines, fmt.Sprintf("  --pid %-6d %s", p.PID, truncateEnd(p.Command(), 60)))
	}
	return lineage.Process{}, fmt.Errorf("%d processes are named %q, pick one with --pid:\n%s",
		len(procs), grantProcess, strings.Join(lines, "\n"))
}

func printGrantCreated(out io.Writer, st agent.GrantStatus) {
	_, _ = cOKBold.Fprint(out, glyphDone+" granted "+st.ID)
	fmt.Fprintf(out, "   %s %s %s   until %s\n",
		st.Name, glyphAction, strings.Join(st.Profiles, ", "), grantClock(st.ExpiresUnix))
	fmt.Fprintf(out, "  %s %s: %s\n", glyphBranch,
		countWord(len(st.Secrets), "secret", "secrets"), truncateEnd(strings.Join(st.Secrets, ", "), 58))
	fmt.Fprintf(out, "  %s end it early: %s\n", glyphBranch, cPath.Sprint("jit grant revoke "+st.ID))
}

func runGrantList(out io.Writer) error {
	if err := validateOutputFormat(grantListFormat); err != nil {
		return err
	}
	ac, err := agentClient()
	if err != nil {
		return err
	}
	grants, err := ac.GrantList()
	if err != nil {
		return notRunningHint(err)
	}
	if grantListFormat == "json" {
		if grants == nil {
			grants = []agent.GrantStatus{}
		}
		return writeJSON(out, grants)
	}
	renderGrantRows(out, grants)
	return nil
}

// renderGrantRows is the text half of `jit grant list`: a [Grants] report
// whose rows carry state in the leading glyph (live ● / ending ✗), the id in
// bold (it is what revoke/extend take), and everything else plain.
func renderGrantRows(out io.Writer, grants []agent.GrantStatus) {
	fmt.Fprintf(out, "[Grants] %d\n", len(grants))
	if len(grants) == 0 {
		fmt.Fprintln(out, "  no process grants are active")
		return
	}
	who := make([]string, len(grants))
	widest := 0
	for i, g := range grants {
		who[i] = fmt.Sprintf("%s %s %s", g.Name, glyphAction, strings.Join(g.Profiles, ", "))
		if len(who[i]) > widest {
			widest = len(who[i])
		}
	}
	if widest > 34 {
		widest = 34
	}
	for i, g := range grants {
		glyph, ink := glyphOK, cOK
		state := fmt.Sprintf("expires %s (%s left)", grantClock(g.ExpiresUnix), grantRemaining(g.ExpiresUnix))
		if !g.RootAlive {
			glyph, ink = glyphRisk, cRisk
			state = "process exited, ending"
		}
		serves := "unused"
		if g.Serves > 0 {
			serves = countWord(int(g.Serves), "serve", "serves")
		}
		fmt.Fprint(out, "  ")
		_, _ = ink.Fprint(out, glyph)
		fmt.Fprint(out, " ")
		_, _ = cBold.Fprint(out, g.ID)
		fmt.Fprintf(out, "  %-*s  %s · %s\n", widest, truncateEnd(who[i], widest), state, serves)
	}
}

func runGrantRevoke(out io.Writer, id string) error {
	ac, err := agentClient()
	if err != nil {
		return err
	}
	// Best-effort name lookup first, so the confirmation can say what ended
	// rather than echoing an opaque id. The revoke itself decides existence.
	var who string
	if grants, err := ac.GrantList(); err == nil {
		for _, g := range grants {
			if g.ID == id {
				who = fmt.Sprintf("   %s %s %s", g.Name, glyphAction, strings.Join(g.Profiles, ", "))
				break
			}
		}
	}
	if err := ac.GrantRevoke(id); err != nil {
		return notRunningHint(err)
	}
	_, _ = cOKBold.Fprint(out, glyphDone+" revoked "+id)
	fmt.Fprintln(out, who)
	return nil
}

func runGrantExtend(out io.Writer, id string) error {
	if grantExtendFor == "" {
		return fmt.Errorf("--for is required (the new lifetime from now, like 8h or 1d)")
	}
	ttl, err := parseGrantFor(grantExtendFor)
	if err != nil {
		return err
	}
	ac, err := agentClient()
	if err != nil {
		return err
	}
	st, err := ac.GrantExtend(id, ttl)
	if err != nil {
		return notRunningHint(err)
	}
	_, _ = cOKBold.Fprint(out, glyphDone+" extended "+st.ID)
	fmt.Fprintf(out, "   %s %s %s   until %s\n",
		st.Name, glyphAction, strings.Join(st.Profiles, ", "), grantClock(st.ExpiresUnix))
	return nil
}

// parseGrantFor reads a --for duration with the audit log's forgiving grammar
// (45m, 8h, 3d) and bounds it the same way the service will, so the friendly
// error happens before any RPC.
func parseGrantFor(s string) (time.Duration, error) {
	d, ok := parseFlexDuration(s)
	if !ok {
		return 0, fmt.Errorf("--for %q is not a duration (like 45m, 8h, 3d)", s)
	}
	if d < time.Minute {
		return 0, fmt.Errorf("--for %s is under the 1m minimum", s)
	}
	if d > agent.MaxGrantTTL {
		return 0, fmt.Errorf("--for %s exceeds the %s maximum for an unattended grant", s, formatFlexDuration(agent.MaxGrantTTL))
	}
	return d, nil
}

// formatFlexDuration renders a duration the way --for reads one ("7d", "8h"),
// for error messages that quote the limits.
func formatFlexDuration(d time.Duration) string {
	if d >= 24*time.Hour && d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	}
	if d >= time.Hour && d%time.Hour == 0 {
		return fmt.Sprintf("%dh", d/time.Hour)
	}
	return d.String()
}

// grantClock renders an expiry instant on the axis a human plans by: clock
// time today, day + clock time within the week the TTL cap allows.
func grantClock(unix int64) string {
	t := time.Unix(unix, 0)
	now := time.Now()
	if t.YearDay() == now.YearDay() && t.Year() == now.Year() {
		return t.Format("15:04")
	}
	if t.YearDay() == now.AddDate(0, 0, 1).YearDay() && t.Year() == now.AddDate(0, 0, 1).Year() {
		return t.Format("tomorrow 15:04")
	}
	return t.Format("Mon 15:04")
}

// grantRemaining renders time left in at most two units ("6h12m", "3d2h",
// "45m"), matching how --for was typed rather than time.Duration's seconds.
func grantRemaining(expiresUnix int64) string {
	d := time.Until(time.Unix(expiresUnix, 0))
	if d <= 0 {
		return "0m"
	}
	d = d.Round(time.Minute)
	days := d / (24 * time.Hour)
	hours := (d % (24 * time.Hour)) / time.Hour
	mins := (d % time.Hour) / time.Minute
	switch {
	case days > 0 && hours > 0:
		return fmt.Sprintf("%dd%dh", days, hours)
	case days > 0:
		return fmt.Sprintf("%dd", days)
	case hours > 0 && mins > 0:
		return fmt.Sprintf("%dh%02dm", hours, mins)
	case hours > 0:
		return fmt.Sprintf("%dh", hours)
	default:
		return fmt.Sprintf("%dm", mins)
	}
}

// truncateEnd cuts s to max runes with a trailing ellipsis — variable content
// is truncated rather than wrapped (house rule), and these are process
// command lines and secret lists, whose tail is the expendable half.
func truncateEnd(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max <= 1 {
		return string(r[:max])
	}
	return string(r[:max-1]) + "…"
}

// resolveGrantSecrets is the service-side OnResolveGrant hook (wired in
// runAgent): profile names in, concrete grant secrets out — vault path,
// wrapped DEK bytes, AAD-bound class — resolved through jit's OWN profile
// store and vault envelopes. This being agent-side is what makes the grant
// prompt trustworthy: the caller sends names, and the set those names cover
// is decided by the same code path `jit run` resolves them with (project
// store shadowing global), never by anything the caller listed.
func resolveGrantSecrets(root string) func(profiles []string, projectRoot string) ([]agent.GrantSecret, error) {
	return func(profiles []string, projectRoot string) ([]agent.GrantSecret, error) {
		deviceID, err := vault.EnsureDeviceID(root)
		if err != nil {
			return nil, fmt.Errorf("determining device recipient ID: %w", err)
		}
		// No KeyWrapper: WrappedDEK reads envelopes without decrypting, so
		// resolution can never prompt on its own.
		v := &vault.Vault{Root: root, RecipientID: deviceID}
		loadRoot := projectRoot
		if loadRoot == "" {
			if home, err := profile.GlobalRoot(); err == nil {
				loadRoot = home
			}
		}
		seen := map[string]bool{}
		var out []agent.GrantSecret
		for _, name := range profiles {
			p, err := profile.Load(loadRoot, name)
			if err != nil {
				return nil, err
			}
			paths := make([]string, 0, len(p))
			for _, secretPath := range p {
				paths = append(paths, secretPath)
			}
			sort.Strings(paths)
			for _, secretPath := range paths {
				if seen[secretPath] {
					continue
				}
				seen[secretPath] = true
				wrapped, class, err := v.WrappedDEK(secretPath)
				if err != nil {
					return nil, fmt.Errorf("profile %s: %w", name, err)
				}
				out = append(out, agent.GrantSecret{Path: secretPath, Wrapped: wrapped, Class: class})
			}
		}
		return out, nil
	}
}

// completeGrantProcessNames offers --process candidates from the audit
// trails: the programs that actually asked for secrets recently, annotated
// with whether a live process currently carries the name. Reads the two
// JSONL files directly and scans the process table once — no agent RPC, no
// prompt, no state mutation (completeVaultPaths' discipline).
func completeGrantProcessNames(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	root, err := vaultRootDir()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	cutoff := time.Now().Add(-24 * time.Hour)
	last := map[string]time.Time{}
	note := func(name string, t time.Time) {
		if name == "" || name == "jit" || t.Before(cutoff) {
			return
		}
		if t.After(last[name]) {
			last[name] = t
		}
	}
	for _, r := range auditlog.New(root, io.Discard).Load(0) {
		t := time.Unix(0, r.UnixNano)
		note(r.LaunchedBy, t)
		note(r.Parent, t)
	}
	for _, e := range newHistoryLog(root, io.Discard).load(4096) {
		note(e.LaunchedBy, time.Unix(e.UnixTime, 0))
	}
	if len(last) == 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	running := map[string]int32{}
	for _, p := range lineage.VisibleProcesses() {
		if n := p.Name(); n != "" {
			running[n] = p.PID
		}
	}

	names := make([]string, 0, len(last))
	for n := range last {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool { return last[names[i]].After(last[names[j]]) })
	out := make([]string, 0, len(names))
	for _, n := range names {
		desc := fmt.Sprintf("asked %s ago", grantAgo(time.Since(last[n])))
		if pid, ok := running[n]; ok {
			desc += fmt.Sprintf(" · running (pid %d)", pid)
		} else {
			desc += " · not running"
		}
		out = append(out, n+"\t"+desc)
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}

// grantAgo renders an age in one coarse unit for a completion description.
func grantAgo(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "moments"
	case d < time.Hour:
		return fmt.Sprintf("%dm", d/time.Minute)
	default:
		return fmt.Sprintf("%dh", d/time.Hour)
	}
}

// completeGrantCreateEntry rides the parent command's positional completion:
// cobra offers the subcommands (list/revoke/extend) on its own, and without
// this the CREATE form - the whole point of the command - was invisible at
// exactly the moment a user double-tabs to discover it. Offering the
// --process flag as a candidate plus an active-help line puts the create
// shape on the same screen as the subcommands.
func completeGrantCreateEntry(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	comps := []string{"--process\tcreate: grant a running program (then --profile, --for)"}
	comps = cobra.AppendActiveHelp(comps, "create a grant: "+grantCreateUsage)
	return comps, cobra.ShellCompDirectiveNoFileComp
}

// completeGrantFor offers --for values: common picks up to the 7d cap, with
// an active-help line saying the grammar is free-form - a fixed list alone
// read as "these four are the only options", which a real user reported.
func completeGrantFor(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	comps := []string{"1h", "8h", "24h", "3d", "7d"}
	comps = cobra.AppendActiveHelp(comps,
		fmt.Sprintf("any duration up to %s works: 45m, 12h, 5d, ...", formatFlexDuration(agent.MaxGrantTTL)))
	return comps, cobra.ShellCompDirectiveNoFileComp
}

// completeGrantIDs offers live grant ids for revoke/extend. It does ask the
// service (grant_list is prompt-free and instant); an unreachable service or
// an empty grant set completes to an active-help line naming the way forward
// rather than to dead silence - a tab that produces nothing, explains
// nothing, and leaves the user stuck was a real report.
func completeGrantIDs(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	ac, err := agentClient()
	if err != nil {
		return cobra.AppendActiveHelp(nil, "the jit service is not reachable"), cobra.ShellCompDirectiveNoFileComp
	}
	grants, err := ac.GrantList()
	if err != nil {
		msg := "could not list grants (is the service on an older jit?)"
		if errors.Is(err, agent.ErrNotRunning) {
			msg = "the jit service is not running"
		}
		return cobra.AppendActiveHelp(nil, msg), cobra.ShellCompDirectiveNoFileComp
	}
	if len(grants) == 0 {
		return cobra.AppendActiveHelp(nil, "no active grants - create one: "+grantCreateUsage), cobra.ShellCompDirectiveNoFileComp
	}
	out := make([]string, 0, len(grants))
	for _, g := range grants {
		out = append(out, fmt.Sprintf("%s\t%s %s %s · until %s",
			g.ID, g.Name, glyphAction, strings.Join(g.Profiles, ", "), grantClock(g.ExpiresUnix)))
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}

func init() {
	grantCmd.Flags().StringVar(&grantProcess, "process", "", "running program the grant anchors to, by name (tab-completes from recent callers)")
	grantCmd.Flags().Int32Var(&grantPIDFlag, "pid", 0, "running process the grant anchors to, by pid (when --process is ambiguous)")
	grantCmd.Flags().StringArrayVar(&grantProfileNames, "profile", nil, "profile whose secrets the grant covers (repeatable)")
	grantCmd.Flags().StringVar(&grantFor, "for", "", "how long the grant lasts (45m, 8h, 3d - max 7d)")
	_ = grantCmd.RegisterFlagCompletionFunc("process", completeGrantProcessNames)
	_ = grantCmd.RegisterFlagCompletionFunc("profile", completeProfileNames)
	_ = grantCmd.RegisterFlagCompletionFunc("for", completeGrantFor)
	grantCmd.ValidArgsFunction = completeGrantCreateEntry

	grantListCmd.Flags().StringVar(&grantListFormat, "format", "text", "output format: text or json")
	grantExtendCmd.Flags().StringVar(&grantExtendFor, "for", "", "new lifetime from now (45m, 8h, 3d - max 7d)")
	_ = grantExtendCmd.RegisterFlagCompletionFunc("for", completeGrantFor)

	grantCmd.AddCommand(grantListCmd, grantRevokeCmd, grantExtendCmd)
	rootCmd.AddCommand(grantCmd)
}
