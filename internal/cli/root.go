// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package cli

import (
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
	groupAgent    = "agent"
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
			"Start with `jit audit` (strictly read-only), then `jit migrate --dry-run` to preview the guided fix for everything it found.",
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
		// as before. NoArgs is what turns `jit bogus` into cobra's "unknown
		// command" error instead of routing it into RunE with args.
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFirstRun(cmd)
		},
	}
	cmd.AddGroup(
		&cobra.Group{ID: groupWorkflow, Title: "Find & fix exposed secrets:"},
		&cobra.Group{ID: groupSecrets, Title: "Vault & profiles:"},
		&cobra.Group{ID: groupAgent, Title: "Background agent:"},
		&cobra.Group{ID: groupPlumbing, Title: "Invoked by other tools, not by hand:"},
	)
	cmd.SetUsageTemplate(rootUsageTemplate)
	return cmd
}

// Execute runs the root command. Called from cmd/jit/main.go.
func Execute() error {
	return rootCmd.Execute()
}
