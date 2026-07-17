// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/profile"
)

// formatProfilePath shortens a profile manifest's path for display —
// relative to cwd for a project-scoped profile (they're always
// underneath it), "~/..."-prefixed for a global one — rather than the
// full absolute path, which is mostly noise once you already know
// whether it's a project or global profile. Falls back to the full path
// if either relative computation fails (e.g. cwd/home unavailable).
func formatProfilePath(cwd string, scope profile.Scope, path string) string {
	switch scope {
	case profile.ScopeProject:
		if rel, err := filepath.Rel(cwd, path); err == nil {
			return rel
		}
	case profile.ScopeGlobal:
		if home, err := os.UserHomeDir(); err == nil {
			// The shared shortener, not filepath.Rel — Rel would render a
			// path OUTSIDE home as ../../..., where every other report in
			// this package shows such a path absolute.
			return displayPath(home, path)
		}
	}
	return path
}

var profileCmd = &cobra.Command{
	Use:     "profile",
	GroupID: groupSecrets,
	Short:   "Inspect profile manifests (names and vault paths only, never secret values)",
	Long: "A profile maps environment variable names to vault secret paths.\n" +
		"jit profile lists and shows these manifests, both project-local ones\n" +
		"under .jit/profiles/ and the home-rooted global ones jit migrate creates\n" +
		"for shell-config/MCP/AWS/kubeconfig/npmrc secrets, without ever decrypting\n" +
		"or printing a secret value. Use jit doctor to also verify a profile's\n" +
		"referenced secrets actually exist in the vault.",
}

var profileListCmd = &cobra.Command{
	Use:   "list",
	Short: "List every profile manifest visible from the current directory",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("jit profile list: %w", err)
		}

		infos, err := profile.ListAll(cwd)
		if err != nil {
			return fmt.Errorf("jit profile list: %w", err)
		}
		if len(infos) == 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "No profiles found under %s/ or the global store.\n", profile.ProfilesDir)
			return nil
		}

		// tabwriter, not raw tabs: one long profile name would otherwise
		// knock its row's columns out of line with every other row.
		tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
		for _, info := range infos {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", info.Name, info.Scope, formatProfilePath(cwd, info.Scope, info.Path))
		}
		// tabwriter buffers every row and only writes on Flush, so this is
		// the one place a write error can surface — wrap it in the same
		// "jit profile list:" voice as every other return above (main.go
		// prints the returned error verbatim).
		if err := tw.Flush(); err != nil {
			return fmt.Errorf("jit profile list: %w", err)
		}
		return nil
	},
}

var profileShowCmd = &cobra.Command{
	Use:   "show <name>",
	Short: "Show a profile's variable-to-vault-path mapping",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("jit profile show: %w", err)
		}

		name := args[0]
		p, scope, path, err := profile.LoadWithScope(cwd, name)
		if err != nil {
			return fmt.Errorf("jit profile show: %w", err)
		}

		vars := make([]string, 0, len(p))
		for varName := range p {
			vars = append(vars, varName)
		}
		sort.Strings(vars)

		fmt.Fprintf(cmd.OutOrStdout(), "%s (%s: %s)\n", name, scope, formatProfilePath(cwd, scope, path))
		for _, varName := range vars {
			fmt.Fprintf(cmd.OutOrStdout(), "  %s -> %s\n", varName, p[varName])
		}
		return nil
	},
}

func init() {
	profileCmd.AddCommand(profileListCmd, profileShowCmd)
	rootCmd.AddCommand(profileCmd)
}
