// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"github.com/spf13/cobra"
)

// version is set at build time via -ldflags "-X github.com/jitpass/jit/internal/cli.version=vX.Y.Z" (see .goreleaser.yml).
var version = "dev"

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

var rootCmd = newRootCmd()

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "jit",
		Short: "Local-first developer secret runtime",
		Long: "jit finds plaintext secrets exposed on your machine and gives you a one-command way to fix it, without ever putting them back on disk in plaintext. See https://github.com/jitpass/jit for details.\n\n" +
			"Start with `jit audit` (strictly read-only), then `jit migrate local --dry-run` to preview the guided fix for the project you're in.",
		Version: version,
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
	}
	cmd.AddGroup(
		&cobra.Group{ID: groupWorkflow, Title: "Find & fix exposed secrets:"},
		&cobra.Group{ID: groupSecrets, Title: "Vault & profiles:"},
		&cobra.Group{ID: groupAgent, Title: "Background agent:"},
		&cobra.Group{ID: groupPlumbing, Title: "Invoked by other tools, not by hand:"},
	)
	return cmd
}

// Execute runs the root command. Called from cmd/jit/main.go.
func Execute() error {
	return rootCmd.Execute()
}
