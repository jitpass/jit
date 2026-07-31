// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"errors"
	"fmt"
	"strings"
	"text/template"
	"time"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/agent"
)

// Command-group IDs (cobra.Group) — the root help renders commands under
// these headings instead of one flat alphabetical list, so the three
// protocol plumbing commands (aws-credential-process etc.) stop reading
// as things a human is expected to type. Groups are registered in
// newRootCmd (a package-var initializer, not an init function) because
// Go runs package-level variable initialization before ANY init() in the
// package — every subcommand file's init() calls rootCmd.AddCommand with
// a GroupID, and cobra panics if the group isn't registered yet; init()
// order between files is alphabetical, so registering groups in root.go's
// own init() would come too late for agent.go/audit.go.
const (
	groupWorkflow = "workflow"
	groupSecrets  = "secrets"
	groupService  = "service"
	groupPlumbing = "plumbing"
)

// helpVisibleAnnotation marks a command that is Hidden solely to keep it
// out of shell tab-completion (cobra has exactly one visibility flag, and
// completion ignores command groups, so grouping alone still left the
// plumbing commands in every Tab list). Annotated commands are rendered
// by rootUsageTemplate under their group and get generated docs pages
// (docsgen.go), so they stay discoverable everywhere except completion.
// A Hidden command WITHOUT this annotation (docs-gen) stays invisible
// everywhere.
const helpVisibleAnnotation = "jit-help-visible"

// rootUsageTemplate is cobra v1.10.2's defaultUsageTemplate with one
// change: the per-group command loop also admits Hidden commands carrying
// helpVisibleAnnotation. If a cobra upgrade changes its default template,
// re-diff against defaultUsageTemplate in cobra's command.go.
const rootUsageTemplate = `Usage:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Examples:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}{{$cmds := .Commands}}{{if eq (len .Groups) 0}}

Available Commands:{{range $cmds}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{else}}{{range $group := .Groups}}

{{.Title}}{{range $cmds}}{{if (and (eq .GroupID $group.ID) (or .IsAvailableCommand (eq .Name "help") (index .Annotations "jit-help-visible")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if not .AllChildCommandsHaveGroup}}

Additional Commands:{{range $cmds}}{{if (and (eq .GroupID "") (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

Global Flags:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

Additional help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}
`

var rootCmd = newRootCmd()

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "jit",
		Short: "Local-first developer secret runtime",
		Long: "jit finds plaintext secrets exposed on your machine and gives you a one-command way to fix it, without ever putting them back on disk in plaintext. See https://github.com/jitpass/jit for details.\n\n" +
			"Start with `jit scan` (strictly read-only), then `jit migrate <path> --dry-run` to preview the guided fix for a file it flagged.",
		// Version lives in internal/agent (next to BuildID) because the
		// agent reports it over the socket too — see agent/version.go.
		Version: agent.Version(),
		// cobra's default RunE-error handling prints "Error: <err>" itself,
		// on top of cmd/jit/main.go's own fmt.Fprintln(os.Stderr, err) —
		// every failing command printed its error twice. main.go is the
		// single intended printer (it already gets the correctly wrapped
		// "jit <cmd>: <detail>" error each RunE returns), so cobra's own
		// copy is silenced here instead of per-command.
		SilenceErrors: true,
		// A handful of commands set their own SilenceUsage: true already
		// (doctor, status, agent status, vault list — see doctor.go's
		// comment) specifically so their machine-readable output/exit code
		// isn't followed by a usage dump. That reasoning applies to every
		// command here, not just the --format json ones: cobra's ExecuteC
		// checks `!cmd.SilenceUsage && !rootCmd.SilenceUsage`, so setting it
		// here covers every subcommand's RunE error too (a runtime error
		// like "no secret stored at <path>" or "--profile is required" is
		// never a flag-usage problem, so a usage block after it is just
		// noise burying the actual message). Individual commands can still
		// set their own SilenceUsage redundantly; that's now belt-and-braces,
		// not load-bearing.
		SilenceUsage: true,
		// Bare `jit` (no subcommand) runs the first-run flow instead of
		// dumping help: on a fresh machine it audits and offers the guided
		// setup; an already-configured machine, a non-interactive shell, or
		// an unknown command all fall through to cobra's help/errors exactly
		// as before. This validator is what turns `jit bogus` into an "unknown
		// command" error instead of routing it into RunE with args; it stands
		// in for cobra.NoArgs so the message carries the same "Did you mean
		// this?" block a command group's does (plain NoArgs has none).
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return nil
			}
			return unknownCommandError(cmd, args[0])
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFirstRun(cmd)
		},
	}
	cmd.AddGroup(
		&cobra.Group{ID: groupWorkflow, Title: "Find & fix exposed secrets:"},
		&cobra.Group{ID: groupSecrets, Title: "Vault & profiles:"},
		&cobra.Group{ID: groupService, Title: "Session & background service:"},
		&cobra.Group{ID: groupPlumbing, Title: "Invoked by other tools, not by hand:"},
	)
	cmd.SetUsageTemplate(rootUsageTemplate)
	// --quiet is persistent so it silences the progress trail (see
	// newProgress) uniformly across every long-running command — scan,
	// migrate, vault rekey — rather than each adding its own flag. It only
	// affects the transient stderr spinner; the command's actual result on
	// stdout is never suppressed.
	cmd.PersistentFlags().BoolVar(&quietFlag, "quiet", false, "suppress the progress spinner/status trail (results still print)")
	cmd.AddCommand(newVersionCmd(cmd))
	return cmd
}

// runCommandGroup is the RunE for a pure command GROUP — a command that
// only holds subcommands and does nothing itself (jit vault, jit service).
//
// Such a command needs a Run at all only because of how cobra orders its
// checks: execute() returns flag.ErrHelp for any !Runnable() command BEFORE
// it ever calls ValidateArgs, so `Args: cobra.NoArgs` on a group is dead
// code. Without this, cobra's legacyArgs accepted arbitrary args on any
// non-root parent, and `jit vault clen` printed the help text and exited 0.
// A typo'd destructive subcommand silently "succeeding" is the worst
// failure mode this CLI has: `jit vault export "$f" && echo backed up`
// would report success having backed up nothing, and `jit service consnt
// off` would leave per-process consent ON while a script believed it was
// off.
//
// A bare `jit vault` still prints help and exits 0, matching every other
// command group.
func runCommandGroup(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return cmd.Help()
	}
	return unknownCommandError(cmd, args[0])
}

// annotationCommandGroup marks a command whose RunE is runCommandGroup.
// The audit recorder needs to tell "this group just printed its help" from
// real work, and a cobra.Command carries no way to compare RunE identity.
const annotationCommandGroup = "jit.command_group"

// commandGroupAnnotations is the Annotations value every command group sets,
// alongside RunE: runCommandGroup. Kept as one shared map builder so the two
// can't be wired up inconsistently.
func commandGroupAnnotations() map[string]string {
	return map[string]string{annotationCommandGroup: "true"}
}

// isCommandGroup reports whether cmd is a pure command group (see
// runCommandGroup), i.e. one whose only action is printing its own help.
func isCommandGroup(cmd *cobra.Command) bool {
	return cmd != nil && cmd.Annotations[annotationCommandGroup] == "true"
}

// unknownCommandError builds cobra's own "unknown command" message plus its
// "Did you mean this?" block, for the two places jit rejects an unrecognized
// subcommand itself: the root's Args validator and runCommandGroup. Cobra
// only assembles this text inside its unexported findSuggestions, reached
// via legacyArgs — which jit deliberately bypasses at the root (NoArgs, so
// bare `jit` reaches the first-run flow) and cannot reach on a group at all.
// Sharing it here is what keeps `jit clen` and `jit vault clen` reading
// identically.
func unknownCommandError(cmd *cobra.Command, arg string) error {
	var sb strings.Builder
	fmt.Fprintf(&sb, "unknown command %q for %q", arg, cmd.CommandPath())
	// SuggestionsFor compares against SuggestionsMinimumDistance as-is; the
	// default-to-2 lives in findSuggestions, so calling SuggestionsFor
	// directly with the zero value would reject every edit-distance match
	// ("clen" -> "clean" is distance 1, and 1 <= 0 is false) and only ever
	// suggest prefix matches.
	if cmd.SuggestionsMinimumDistance <= 0 {
		cmd.SuggestionsMinimumDistance = 2
	}
	if suggestions := cmd.SuggestionsFor(arg); len(suggestions) > 0 {
		sb.WriteString("\n\nDid you mean this?\n")
		for _, s := range suggestions {
			fmt.Fprintf(&sb, "\t%v\n", s)
		}
	}
	return errors.New(sb.String())
}

// requirePaths is cobra.MinimumNArgs(1) in jit's own voice, for the commands
// that must be told what to act on. Cobra's stock message is
// "requires at least 1 arg(s), only received 0" — the one error in this CLI
// that reads like a library talking to itself, next to a help text that
// promises "a bare `jit migrate` with no path does nothing". Naming the
// command and what it wants keeps the surface consistent.
func requirePaths(name string) cobra.PositionalArgs {
	return func(_ *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("%s: name at least one file or folder to act on", name)
		}
		return nil
	}
}

// newVersionCmd makes `jit version` a synonym for `jit --version`. Cobra
// gives a Version-bearing command the --version/-v FLAG only, so `jit
// version` — the first thing many people type, and what `git`/`docker`/`go`
// all accept — failed with "unknown command", which the audit log then
// recorded as a status=failed line. It renders the root's OWN version
// template (cobra's tmpl helper is unexported, but that template uses only
// stdlib actions) rather than re-formatting the string here, so the two
// spellings can't drift apart if the template is ever customized.
func newVersionCmd(root *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print jit's version (same as `jit --version`)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			t, err := template.New("version").Parse(root.VersionTemplate())
			if err != nil {
				return err
			}
			return t.Execute(cmd.OutOrStdout(), root)
		},
	}
}

// quietFlag is bound to the root's persistent --quiet flag and read by
// newProgress. A package var (not threaded through every RunE) because it's a
// global display preference, like color, not a per-command argument.
var quietFlag bool

// recordInvocation, when set, writes one line to the application audit log
// for a finished command. It is a hook (nil default) rather than a direct
// call so this portable file never has to import the darwin-only lineage /
// keychainwrap machinery the real recorder needs; auditrecord.go installs the
// implementation on darwin. A nil hook simply means no audit trail — the same
// best-effort posture the recorder itself keeps internally.
var recordInvocation func(cmd *cobra.Command, err error, elapsed time.Duration)

// ExitError carries a specific process exit status out of a command whose
// non-zero exit is a RESULT rather than a failure — `jit scan --fail-on high`
// finding critical secrets is the gate working, not the scan breaking. Scripts
// and CI need to tell those apart: a bad flag or an unreadable vault must not
// look identical to "secrets were found". Everything that is genuinely an
// error keeps the plain exit 1.
//
// Msg, when set, is printed to stderr in place of the wrapped error's text.
type ExitError struct {
	Code int
	Msg  string
}

func (e *ExitError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return fmt.Sprintf("exit status %d", e.Code)
}

// Execute runs the root command. Called from cmd/jit/main.go.
//
// ExecuteC (not Execute) so the audit log can record WHICH command actually
// ran — cobra resolves the args to a concrete *cobra.Command and hands it
// back, which a bare Execute() throws away. The command is recorded whether it
// succeeded or failed: "what ran, when, by whom, and did it work" is exactly
// the question an audit trail exists to answer, and the failures are often the
// interesting half.
func Execute() error {
	start := time.Now()
	cmd, err := rootCmd.ExecuteC()
	if recordInvocation != nil {
		recordInvocation(cmd, err, time.Since(start))
	}
	return err
}
