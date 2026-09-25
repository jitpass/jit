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
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/auditlog"
	"github.com/jitpass/jit/internal/keychainwrap"
	"github.com/jitpass/jit/internal/keystore"
	"github.com/jitpass/jit/internal/lineage"
	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/secureenclave"
	"github.com/jitpass/jit/internal/vault"
)

// jit grant — process grants (design/process-grants.md): pre-approve a
// process tree to use one or more profiles' secrets unattended, for a
// bounded time, with one Touch ID given while you are still at the
// keyboard. --process NAME is tree-scoped: anchored to the terminal it is
// typed in, covering every NAME under it, running now or started later
// within the window. --pid is the exact-one-running-process mode. The bare
// command creates; list/revoke/extend manage what exists. All state lives
// in the service's memory — the CLI here is a thin client over the grant_*
// RPCs, plus the anchor resolution and completion that need a terminal-side
// view.

var (
	grantProcess      string
	grantPIDFlag      int32
	grantProfileNames []string
	grantFor          string
	grantUntilRevoked bool
	grantListFormat   string
	grantExtendFor    string
)

var grantCmd = &cobra.Command{
	Use:     "grant --process NAME --profile NAME (--for DURATION | --until-revoked)",
	GroupID: groupSecrets,
	Short:   "Pre-approve a program to use profiles unattended",
	Long: `Create a process grant: with one Touch ID now, allow a program (and
everything it launches) to use the named profiles' secrets without further
prompts - including while the screen is locked or you are away.

You choose how it ends, and the two shapes differ in more than duration:

  --for DURATION    until a deadline, at most 7d. The grant lives in the
                    service's memory, so it also ends if the service stops
                    or the terminal it is anchored to quits.
  --until-revoked   until you run 'jit grant revoke'. The grant holds a key
                    of its own, so it survives screen lock, a service
                    restart and a reboot.

--process NAME is scoped to the terminal you type it in: every NAME under
this terminal - running now or started later, in any tab - is covered. The
anchor is the terminal app itself, verified through kernel ancestry, so a
same-named process elsewhere on the machine inherits nothing. --pid grants
one exact running process instead and ends when it exits; it always takes
--for, because one process cannot outlive a reboot.

A grant covers exactly the secrets the named profiles resolve to at
creation time, and every serve under it is recorded in 'jit audit'. If one
of those secrets is rotated it stops being served and 'jit grant list'
says so; the rest keep working.`,
	Example: `  # let claude use the jamf profile for 8 hours - current sessions and
  # any started from this terminal within the window
  jit grant --process claude --profile jamf --for 8h

  # no deadline: until you revoke it, across restarts and reboots
  jit grant --process claude --profile mcp-caido --until-revoked

  # several profiles, for one exact running process only
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
how it ends - at a deadline, or only when you revoke it - and how many
serves have ridden it. A covered secret that has been rotated is flagged
here, because a rotated secret stops being served. Reading this never
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
feature. The ending is recorded in 'jit audit'.

For a grant made with --until-revoked this is the only way it ends, and it
deletes the key that grant holds, so the secrets it covered go back to
asking for Touch ID.`,
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
re-create, and neither step re-asks for what you already have.

A grant made with --until-revoked has no deadline to move, so this refuses
it. Revoke it when you want it to end.`,
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
const grantCreateUsage = "jit grant --process <name> --profile <profile>"

// grantCreateEnding is the choice that completes grantCreateUsage. It is a
// second line rather than a longer usage string: "(--for <d> | --until-revoked)"
// pushed the one-line shape past the width where a reader stops reading it.
const grantCreateEnding = "then --for <duration> for a deadline, or --until-revoked for none"

func runGrantCreate(out io.Writer) error {
	// A bare `jit grant` is someone discovering the command, not someone who
	// forgot one flag: answer with the whole shape, not the first missing
	// piece of it.
	if grantProcess == "" && grantPIDFlag == 0 && len(grantProfileNames) == 0 && grantFor == "" && !grantUntilRevoked {
		return fmt.Errorf("create a grant with %s\n%s\n(list / revoke / extend manage existing grants - see `jit grant --help`)", grantCreateUsage, grantCreateEnding)
	}
	if grantProcess == "" && grantPIDFlag == 0 {
		return fmt.Errorf("--process is required (the running program to grant to; tab-completes from recent callers)")
	}
	if len(grantProfileNames) == 0 {
		return fmt.Errorf("--profile is required (repeat it for several: --profile jamf --profile aws-ci)")
	}
	// A grant lasts until a deadline or until revoked, never both and never
	// neither: --until-revoked is an explicit flag so that omitting --for
	// can never mint a permanent grant by accident (design/standing-grants.md).
	if grantFor == "" && !grantUntilRevoked {
		return fmt.Errorf("say how the grant ends: --for a deadline (45m, 8h, 3d - max %s)\nor --until-revoked for none", formatFlexDuration(agent.MaxGrantTTL))
	}
	if grantFor != "" && grantUntilRevoked {
		return fmt.Errorf("give --for or --until-revoked, not both")
	}
	if grantUntilRevoked && grantProcess == "" {
		return fmt.Errorf("--until-revoked needs --process: one process cannot outlive a reboot\n(--pid grants one exact running process, and always takes --for)")
	}
	var ttl time.Duration
	if grantFor != "" {
		var err error
		ttl, err = parseGrantFor(grantFor)
		if err != nil {
			return err
		}
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
	profiles := make([]agent.GrantProfile, 0, len(grantProfileNames))
	for _, name := range grantProfileNames {
		profiles = append(profiles, agent.GrantProfile{Name: name, Root: cwd})
	}
	st, err := ac.GrantCreateWith(agent.GrantCreateOpts{
		TargetPID: target.anchor.PID, Name: target.name, Profiles: profiles, TTL: ttl, Standing: grantUntilRevoked,
	})
	if err != nil {
		return grantAgentErr("grant_create", err)
	}
	// A service older than tree grants ignores the unknown grant_name field
	// and mints an EXACT grant anchored at the terminal — every process under
	// it, no name filter: strictly wider than what the human just approved.
	// The reply betrays it (no Anchor on a tree request), and reducing access
	// is free, so revoke before reporting anything. The window is real but
	// short: the service swaps itself onto a replaced binary within seconds.
	if target.name != "" && st.Anchor == "" {
		_ = ac.GrantRevoke(st.ID)
		return fmt.Errorf("the running service predates tree grants and granted the whole terminal instead; revoked it - run `jit service restart` and retry")
	}
	printGrantCreated(out, st)
	return nil
}

// grantAgentErr unwraps the framing a grant error collects on its way to the
// screen. The server prefixes its own op ("grant_extend: "), the client adds
// "agent: ", and the command's RunE adds "jit grant extend: " — so the reader
// met three prefixes before the sentence, which is the raw-error-reaching-
// the-user shape the house style rules out. The op is passed rather than
// derived so a rename cannot silently stop the stripping.
func grantAgentErr(op string, err error) error {
	if err == nil {
		return nil
	}
	err = notRunningHint(err)
	msg := strings.TrimPrefix(err.Error(), "agent: ")
	msg = strings.TrimPrefix(msg, op+": ")
	return errors.New(msg)
}

// grantTarget is what a create resolves --process/--pid into: the process
// the grant anchors to, plus (tree mode only) the name that narrows its
// descendants. An empty name is the exact-one-process grant --pid means.
type grantTarget struct {
	anchor lineage.Process
	name   string
}

// resolveGrantTarget turns --process/--pid into the grant's anchor.
// --process needs no live match and no disambiguation: it anchors to THIS
// terminal's session root and covers the name inside it — the sessions
// running now and the ones started later within the window, which is why a
// name that matches nothing yet is fine, not an error. --pid keeps the
// exact-process shape for the times one specific tree is the point.
func resolveGrantTarget() (grantTarget, error) {
	if grantPIDFlag != 0 && grantProcess != "" {
		return grantTarget{}, fmt.Errorf("give --process or --pid, not both")
	}
	if grantPIDFlag != 0 {
		p, ok := lineage.Describe(grantPIDFlag)
		if !ok {
			return grantTarget{}, fmt.Errorf("no process with pid %d (it may have exited)", grantPIDFlag)
		}
		return grantTarget{anchor: p}, nil
	}
	if grantProcess == "" {
		return grantTarget{}, fmt.Errorf("--process is required (the program to grant to; tab-completes from recent callers)")
	}
	root, ok := lineage.SessionRoot(int32(os.Getpid())) // #nosec G115 -- darwin pids fit int32
	if !ok {
		return grantTarget{}, fmt.Errorf("no terminal tree to anchor %q to - run this from your terminal, or anchor one exact process with `--pid`", grantProcess)
	}
	return grantTarget{anchor: root, name: grantProcess}, nil
}

func printGrantCreated(out io.Writer, st agent.GrantStatus) {
	_, _ = cOKBold.Fprint(out, glyphDone+" granted "+st.ID)
	fmt.Fprintf(out, "   %s %s %s   %s\n",
		st.Name, glyphAction, strings.Join(st.Profiles, ", "), grantUntil(st))
	fmt.Fprintf(out, "  %s %s: %s\n", glyphBranch,
		countWord(len(st.Secrets), "secret", "secrets"), truncateEnd(strings.Join(st.Secrets, ", "), 58))
	if st.Standing {
		fmt.Fprintf(out, "  %s every %s under %s, now or later\n", glyphBranch, st.Name, st.Anchor)
		fmt.Fprintf(out, "  %s survives a service restart and a reboot\n", glyphBranch)
		fmt.Fprintf(out, "  %s a rotated secret stops being covered\n", glyphBranch)
	} else if st.Anchor != "" {
		fmt.Fprintf(out, "  %s covers %s under %s: %s, any started before %s\n", glyphBranch,
			st.Name, st.Anchor, grantRunningNow(st.Name, st.PID), grantClock(st.ExpiresUnix))
	}
	fmt.Fprintf(out, "  %s end it early: %s\n", glyphBranch, cPath.Sprint("jit grant revoke "+st.ID))
}

// grantUntil words a grant's end: the deadline, or "until you revoke it"
// for a standing grant, which has none.
func grantUntil(st agent.GrantStatus) string {
	if st.Standing {
		return "until you revoke it"
	}
	return "until " + grantClock(st.ExpiresUnix)
}

// grantRunningNow phrases how many processes a fresh tree grant covers at
// this moment — the reassurance half ("2 running now") or the granting-ahead
// half ("none running yet"), both of which the human should see stated.
func grantRunningNow(name string, anchorPID int32) string {
	n := 0
	for _, p := range lineage.ProcessesNamed(name) {
		if lineage.AncestryContainsPID(p.PID, anchorPID) {
			n++
		}
	}
	if n == 0 {
		return "none running yet"
	}
	return fmt.Sprintf("%d running now", n)
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
		return grantAgentErr("grant_list", err)
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
		// Runes, not bytes: every row carries a multi-byte arrow, so a byte
		// width padded each column two spaces too far.
		if n := len([]rune(who[i])); n > widest {
			widest = n
		}
	}
	if widest > 34 {
		widest = 34
	}
	for i, g := range grants {
		glyph, ink := glyphOK, cOK
		state := fmt.Sprintf("expires %s (%s left)", grantClock(g.ExpiresUnix), grantRemaining(g.ExpiresUnix))
		switch {
		case g.Standing && len(g.Rotated) > 0:
			// The design's one silent failure made loud. The row counts what
			// stopped; the block under the table names each one and prints
			// the command that covers them again, because "re-approve" is
			// not a command anyone can type.
			glyph, ink = glyphWarn, cWarn
			state = fmt.Sprintf("until revoked · %s no longer covered", countWord(len(g.Rotated), "secret", "secrets"))
		case g.Standing:
			state = "until revoked"
		case !g.RootAlive:
			glyph, ink = glyphRisk, cRisk
			state = "process exited, ending"
			if g.Anchor != "" {
				state = "terminal closed, ending"
			}
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
	renderRotatedSecrets(out, grants)
}

// renderRotatedSecrets names the covered secrets a rotation stopped, and the
// one command that covers them again. The row above can only carry a count,
// and a count the reader cannot act on is a count they ignore.
func renderRotatedSecrets(out io.Writer, grants []agent.GrantStatus) {
	for _, g := range grants {
		if len(g.Rotated) == 0 {
			continue
		}
		fmt.Fprintln(out)
		_, _ = cWarn.Fprint(out, "  "+glyphWarn+" ")
		// "rotated" is the common case but not the only one: a secret deleted
		// from the vault reports identically, because the check is whether
		// the vault still holds what the grant covers.
		fmt.Fprintf(out, "%s stopped being served: the value changed, or it left the vault\n",
			countWord(len(g.Rotated), "secret", "secrets"))
		for _, path := range g.Rotated {
			fmt.Fprintf(out, "    %s %s\n", glyphBranch, path)
		}
		fmt.Fprint(out, "    ")
		_, _ = cPath.Fprint(out, glyphAction+" "+regrantCommand(g))
		fmt.Fprintln(out, "   covers them again")
	}
}

// regrantCommand is the create that re-covers a grant's secrets as they are
// now. A standing grant is always tree-scoped, so its whole shape is known.
func regrantCommand(g agent.GrantStatus) string {
	cmd := "jit grant --process " + g.Name
	for _, p := range g.Profiles {
		cmd += " --profile " + p
	}
	if g.Standing {
		return cmd + " --until-revoked"
	}
	return cmd + " --for <duration>"
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
		return grantAgentErr("grant_revoke", err)
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
		return grantAgentErr("grant_extend", err)
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
		return 0, fmt.Errorf("--for %s is over the %s maximum\n(--until-revoked has no deadline at all)", s, formatFlexDuration(agent.MaxGrantTTL))
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
	return remainingUnits(time.Until(time.Unix(expiresUnix, 0)))
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
func resolveGrantSecrets(root string) func(profiles []agent.GrantProfile) ([]agent.GrantSecret, error) {
	return func(profiles []agent.GrantProfile) ([]agent.GrantSecret, error) {
		deviceID, err := vault.EnsureDeviceID(root)
		if err != nil {
			return nil, fmt.Errorf("determining device recipient ID: %w", err)
		}
		// No KeyWrapper: WrappedDEK reads envelopes without decrypting, so
		// resolution can never prompt on its own.
		v := &vault.Vault{Root: root, RecipientID: deviceID}
		home, herr := profile.GlobalRoot()
		seen := map[string]bool{}
		var out []agent.GrantSecret
		for _, gp := range profiles {
			// Each name resolves from ITS folder (project store shadowing
			// global), so two profiles beside two projects can share one
			// grant. An empty folder means the global store alone.
			name, loadRoot := gp.Name, gp.Root
			if loadRoot == "" && herr == nil {
				loadRoot = home
			}
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
					// Name the entry, not just the profile: "profile x: secret
					// not found" leaves the user diffing fourteen manifest
					// lines against `jit vault list` by hand (a real dead end,
					// hit on the first live tree-grant create).
					return nil, fmt.Errorf("profile %s: %s: %w (the profile names it, the vault does not have it - `jit vault list` shows what is stored)", name, secretPath, err)
				}
				out = append(out, agent.GrantSecret{Path: secretPath, Wrapped: wrapped, Class: class})
			}
		}
		return out, nil
	}
}

// wrappedDEKReader is the service-side OnWrappedDEK hook: one path's
// current wrapped DEK bytes, read without decrypting or prompting, so a
// standing grant's listing can say which of its secrets were rotated.
func wrappedDEKReader(root string) func(path string) ([]byte, string, error) {
	return func(path string) ([]byte, string, error) {
		deviceID, err := vault.EnsureDeviceID(root)
		if err != nil {
			return nil, "", err
		}
		v := &vault.Vault{Root: root, RecipientID: deviceID}
		return v.WrappedDEK(path)
	}
}

// grantKeyBackend is one place grant keys live: the login keychain
// (keychainwrap.GrantKeys) or the Secure Enclave (secureenclave.GrantKeys).
type grantKeyBackend interface {
	Create(id string) (agent.GrantKey, error)
	Load(id string) (agent.GrantKey, error)
	Present(id string) (bool, error)
	Delete(id string) error
	List() ([]string, error)
}

// grantKeyStore is the agent's GrantKeyStore over both backends (the agent
// never imports either; the CLI wires them, as it wires the MEK fetcher).
//
// A NEW key goes where the vault's own key is: an enclave vault's grants and
// jobs get enclave keys, which never ask and work while the Mac is locked
// (design/secure-enclave-plan.md, C2). A key is LOADED from wherever that
// grant's key exists, enclave first, so grants made before a vault moved
// keep working until they are moved too (C3). Delete clears both.
type grantKeyStore struct {
	root    string
	keys    grantKeyBackend // the keychain
	enclave grantKeyBackend // the Secure Enclave
}

func newGrantKeyStore(root string) grantKeyStore {
	return grantKeyStore{root: root, keys: keychainGrantKeys{}, enclave: enclaveGrantKeys{}}
}

func (g grantKeyStore) Create(id string) (agent.GrantKey, error) {
	if openKeyStore(g.root).Kind() == keystore.KindSecureEnclave {
		return g.enclave.Create(id)
	}
	return g.keys.Create(id)
}

func (g grantKeyStore) Load(id string) (agent.GrantKey, error) {
	// A jit that cannot reach the enclave (ErrUnavailable) answers false
	// here and loads the keychain key, which is all it could open anyway.
	if ok, err := g.enclave.Present(id); err == nil && ok {
		return g.enclave.Load(id)
	}
	return g.keys.Load(id)
}

func (g grantKeyStore) Delete(id string) error {
	err := g.enclave.Delete(id)
	if errors.Is(err, secureenclave.ErrUnavailable) {
		err = nil // this jit cannot reach the enclave, so made no key there
	}
	return errors.Join(err, g.keys.Delete(id))
}

// The agent.GrantKeyMover half (plan C3): at service start the agent moves
// every existing grant and job key to TargetWrap, the kind the vault's own
// key is.

var _ agent.GrantKeyMover = grantKeyStore{}

func (g grantKeyStore) TargetWrap() string {
	if openKeyStore(g.root).Kind() == keystore.KindSecureEnclave {
		return agent.GrantWrapEnclave
	}
	return agent.GrantWrapKeychain
}

func (g grantKeyStore) backend(wrap string) grantKeyBackend {
	if wrap == agent.GrantWrapEnclave {
		return g.enclave
	}
	return g.keys
}

func (g grantKeyStore) LoadWrap(id, wrap string) (agent.GrantKey, error) {
	return g.backend(wrap).Load(id)
}

// CreateWrap returns the key a crashed move already made rather than
// refusing it: that key sealed nothing that was kept, and the move is
// starting over.
func (g grantKeyStore) CreateWrap(id, wrap string) (agent.GrantKey, error) {
	b := g.backend(wrap)
	if ok, err := b.Present(id); err == nil && ok {
		return b.Load(id)
	}
	return b.Create(id)
}

func (g grantKeyStore) DeleteWrap(id, wrap string) error {
	err := g.backend(wrap).Delete(id)
	if errors.Is(err, secureenclave.ErrUnavailable) {
		return nil
	}
	return err
}

// The agent.GrantKeyLister half (plan C4): every id with a key of either
// kind, for the service's start-up cleanup of keys nothing names.

var _ agent.GrantKeyLister = grantKeyStore{}

func (g grantKeyStore) ListGrantKeyIDs() ([]string, error) {
	ids, err := g.keys.List()
	if err != nil {
		return nil, err
	}
	enc, err := g.enclave.List()
	if err != nil && !errors.Is(err, secureenclave.ErrUnavailable) {
		return nil, err
	}
	return append(ids, enc...), nil
}

type keychainGrantKeys struct{ keys keychainwrap.GrantKeys }

func (k keychainGrantKeys) Create(id string) (agent.GrantKey, error) {
	key, err := k.keys.Create(id)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (k keychainGrantKeys) Load(id string) (agent.GrantKey, error) {
	key, err := k.keys.Load(id)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (k keychainGrantKeys) Present(id string) (bool, error) {
	_, err := k.keys.Load(id)
	return err == nil, nil
}

func (k keychainGrantKeys) Delete(id string) error { return k.keys.Delete(id) }

func (k keychainGrantKeys) List() ([]string, error) { return k.keys.List() }

type enclaveGrantKeys struct{ keys secureenclave.GrantKeys }

func (e enclaveGrantKeys) Create(id string) (agent.GrantKey, error) {
	key, err := e.keys.Create(id)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (e enclaveGrantKeys) Load(id string) (agent.GrantKey, error) {
	key, err := e.keys.Load(id)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (e enclaveGrantKeys) Present(id string) (bool, error) { return e.keys.Present(id) }

func (e enclaveGrantKeys) Delete(id string) error { return e.keys.Delete(id) }

func (e enclaveGrantKeys) List() ([]string, error) { return e.keys.List() }

// completeGrantProcessNames offers --process candidates from the audit
// trails: the programs that actually asked for secrets recently, annotated
// with whether a live process currently carries the name. Reads the two
// JSONL files directly and scans the process table once — no agent RPC, no
// prompt, no state mutation (completeVaultPaths' discipline).
// recentCallerNames is the last-seen time of every program that asked jit for
// a secret in the past 24h, read straight from the two JSONL trails — no
// agent RPC, no prompt, no state mutation. Shared by the --process and --pid
// completions so both mean the same thing by "a caller jit has seen".
func recentCallerNames() (map[string]time.Time, error) {
	root, err := vaultRootDir()
	if err != nil {
		return nil, err
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
	return last, nil
}

func completeGrantProcessNames(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	last, err := recentCallerNames()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	if len(last) == 0 {
		// The sibling of the two completions this file already fixed, missed
		// because it only shows up on a machine that has not used jit yet —
		// exactly the machine that needs telling.
		return cobra.AppendActiveHelp(nil,
				"no recent callers recorded - type any program name (it need not be running yet)"),
			cobra.ShellCompDirectiveNoFileComp
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

// completeGrantPIDs offers the visible processes for --pid, the
// exact-one-process mode — so answering it with filenames left the pick with
// no way to see the candidates it is meant to choose between. Same process
// table --process annotates from.
func completeGrantPIDs(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	// Never the whole process table: a bare list of every visible pid runs to
	// several hundred rows of system daemons, which is a worse answer than the
	// filenames this replaced. The candidates are the processes a grant could
	// plausibly name — a --process already on the line, else the programs that
	// have actually asked jit for a secret.
	want := func(string) bool { return false }
	if grantProcess != "" {
		want = func(name string) bool { return name == grantProcess }
	} else if last, err := recentCallerNames(); err == nil && len(last) > 0 {
		want = func(name string) bool { _, ok := last[name]; return ok }
	}
	var out []string
	for _, p := range lineage.VisibleProcesses() {
		name := p.Name()
		if name == "" || name == "jit" || !want(name) {
			continue
		}
		pid := strconv.FormatInt(int64(p.PID), 10)
		if !strings.HasPrefix(pid, toComplete) {
			continue
		}
		out = append(out, pid+"\t"+name+grantPIDDetail(p.PID))
	}
	if len(out) == 0 {
		if grantProcess != "" {
			return cobra.AppendActiveHelp(nil, "nothing named "+grantProcess+" is running"), cobra.ShellCompDirectiveNoFileComp
		}
		return cobra.AppendActiveHelp(nil, "--pid grants one exact running process (--process covers a name under this terminal)"), cobra.ShellCompDirectiveNoFileComp
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}

// grantPIDDetail annotates one --pid candidate with what tells identical
// names apart: the directory the process runs in (seven rows saying only
// "claude" were a real report — the cwd is which PROJECT each one is) and
// how long it has lived, newest usually being the one meant. Display only,
// like everything lineage answers.
func grantPIDDetail(pid int32) string {
	detail := ""
	if cwd := lineage.ProcessCWD(pid); cwd != "" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			if cwd == home {
				cwd = "~"
			} else if strings.HasPrefix(cwd, home+"/") {
				cwd = "~" + cwd[len(home):]
			}
		}
		detail += " · in " + cwd
	}
	if start, ok := lineage.ProcessStartTime(pid); ok {
		detail += " · started " + grantAgo(time.Since(time.UnixMicro(start))) + " ago"
	}
	return detail
}

// grantAgo renders an age in one coarse unit for a completion description.
func grantAgo(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "moments"
	case d < time.Hour:
		return fmt.Sprintf("%dm", d/time.Minute)
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", d/time.Hour)
	default:
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	}
}

// completeGrantCreateEntry rides the parent command's positional completion:
// cobra offers the subcommands (list/revoke/extend) on its own, and without
// this the CREATE form - the whole point of the command - was invisible at
// exactly the moment a user double-tabs to discover it. It offers the FIRST
// flag the create form still lacks, in the order the usage line reads
// (--process, --profile, --for): cobra has already parsed the typed flags
// into the bound vars by the time this runs, so a tab after `--process bash`
// walks forward to --profile instead of re-offering what is on the line.
func completeGrantCreateEntry(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	switch {
	case grantProcess == "" && grantPIDFlag == 0:
		comps := []string{"--process\tcreate: grant a program by name, future sessions included (then --profile, then --for or --until-revoked)"}
		comps = cobra.AppendActiveHelp(comps, "create a grant: "+grantCreateUsage)
		comps = cobra.AppendActiveHelp(comps, grantCreateEnding)
		return comps, cobra.ShellCompDirectiveNoFileComp
	case len(grantProfileNames) == 0:
		return []string{"--profile\tprofile whose secrets the grant covers (repeatable)"}, cobra.ShellCompDirectiveNoFileComp
	case grantFor == "" && !grantUntilRevoked:
		return []string{
			"--for\thow long the grant lasts (45m, 8h, 3d - max 7d)",
			"--until-revoked\tno deadline: survives restarts and reboots, ends on jit grant revoke",
		}, cobra.ShellCompDirectiveNoFileComp
	default:
		return cobra.AppendActiveHelp(nil, "all set - press enter to create the grant"), cobra.ShellCompDirectiveNoFileComp
	}
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
	// extend's id is taken; what it still needs is the duration. Answering
	// with nothing at that point is the dead-end tab this function was
	// written to remove, and it had grown one of its own.
	// cmd is nil when a test drives this directly; treat that as the revoke
	// shape, which is the one that offers everything.
	forExtend := cmd != nil && cmd.Name() == "extend"
	if len(args) > 0 {
		if forExtend && grantExtendFor == "" {
			return []string{"--for\tnew lifetime from now (45m, 8h, 3d - max 7d)"}, cobra.ShellCompDirectiveNoFileComp
		}
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	ac, err := agentClient()
	if err != nil {
		return cobra.AppendActiveHelp(nil, "the jit service is not reachable"), cobra.ShellCompDirectiveNoFileComp
	}
	grants, err := ac.GrantList()
	if err != nil {
		msg := "could not list grants (is the service on an older jit?)"
		switch {
		case errors.Is(err, agent.ErrSocketBlocked):
			msg = "this shell can't reach the jit service (sandboxed?)"
		case errors.Is(err, agent.ErrNotRunning):
			msg = "the jit service is not running"
		}
		return cobra.AppendActiveHelp(nil, msg), cobra.ShellCompDirectiveNoFileComp
	}
	if len(grants) == 0 {
		comps := cobra.AppendActiveHelp(nil, "no active grants - create one: "+grantCreateUsage)
		return cobra.AppendActiveHelp(comps, grantCreateEnding), cobra.ShellCompDirectiveNoFileComp
	}
	out := make([]string, 0, len(grants))
	for _, g := range grants {
		// A grant with no deadline has nothing for extend to move, and the
		// server refuses it. Offering it would complete a command that can
		// only fail.
		if forExtend && g.Standing {
			continue
		}
		out = append(out, fmt.Sprintf("%s\t%s %s %s · %s",
			g.ID, g.Name, glyphAction, strings.Join(g.Profiles, ", "), grantUntil(g)))
	}
	if len(out) == 0 && forExtend {
		return cobra.AppendActiveHelp(nil,
			"every live grant runs until revoked - there is no deadline to extend; `jit grant revoke` ends one"), cobra.ShellCompDirectiveNoFileComp
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}

func init() {
	grantCmd.Flags().StringVar(&grantProcess, "process", "", "program to cover, by name: every one under this terminal, running or started later")
	grantCmd.Flags().Int32Var(&grantPIDFlag, "pid", 0, "one exact running process to grant instead (ends when it exits)")
	grantCmd.Flags().StringArrayVar(&grantProfileNames, "profile", nil, "profile whose secrets the grant covers (repeatable)")
	grantCmd.Flags().StringVar(&grantFor, "for", "", "how long the grant lasts (45m, 8h, 3d - max 7d)")
	grantCmd.Flags().BoolVar(&grantUntilRevoked, "until-revoked", false, "no deadline: the grant holds its own key, survives restarts and reboots, and ends on jit grant revoke (--process only)")
	_ = grantCmd.RegisterFlagCompletionFunc("process", completeGrantProcessNames)
	_ = grantCmd.RegisterFlagCompletionFunc("profile", completeProfileNames)
	_ = grantCmd.RegisterFlagCompletionFunc("for", completeGrantFor)
	_ = grantCmd.RegisterFlagCompletionFunc("pid", completeGrantPIDs)
	grantCmd.ValidArgsFunction = completeGrantCreateEntry

	grantListCmd.Flags().StringVar(&grantListFormat, "format", "text", "output format: text or json")
	// After the flag exists, not before: RegisterFlagCompletionFunc fails on
	// an unknown flag and every call site discards that error, so an early
	// registration is a completion that silently never fires.
	_ = grantListCmd.RegisterFlagCompletionFunc("format", completeOutputFormat)
	grantExtendCmd.Flags().StringVar(&grantExtendFor, "for", "", "new lifetime from now (45m, 8h, 3d - max 7d)")
	_ = grantExtendCmd.RegisterFlagCompletionFunc("for", completeGrantFor)

	grantCmd.AddCommand(grantListCmd, grantRevokeCmd, grantExtendCmd)
	rootCmd.AddCommand(grantCmd)
}
