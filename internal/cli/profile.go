// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
		"jit profile show prints one profile's mapping, both project-local ones\n" +
		"under .jit/profiles/ and the home-rooted global ones jit migrate creates\n" +
		"for shell-config/MCP/AWS/kubeconfig/npmrc secrets, without ever decrypting\n" +
		"or printing a secret value.\n\n" +
		"For the whole picture — which stored secrets are wired to a profile, which\n" +
		"are managed elsewhere, and which are orphaned — use jit status --secrets\n" +
		"(the successor to the deprecated jit profile list). Use jit doctor to also\n" +
		"verify a profile's referenced secrets actually exist in the vault.",
}

var profileListCmd = &cobra.Command{
	Use:   "list",
	Short: "Deprecated: use `jit status --secrets`",
	Long: "Lists the profile manifests visible from the current directory.\n\n" +
		"Deprecated: this only ever shows the manifests in this folder, never the\n" +
		"secrets those manifests don't touch — so a vault full of secrets can look\n" +
		"empty here. `jit status --secrets` reconciles the two: which stored secrets\n" +
		"are wired to a profile, which are managed elsewhere, and which are orphaned.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		// The successor draws the full picture; nudge toward it on stderr so a
		// script still parsing stdout keeps working through the deprecation window.
		fmt.Fprintln(cmd.ErrOrStderr(), "note: `jit profile list` is deprecated; use `jit status --secrets` for the full picture (which secrets are wired, managed elsewhere, or orphaned).")

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
	Use:               "show <name>",
	Short:             "Show a profile's variable-to-vault-path mapping",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeProfileNames,
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

// completeProfileNames offers the profile names visible from the current
// directory — project-local first, then global, exactly the set `jit
// profile list` shows and `Load` resolves. Shared by `jit profile show`'s
// positional argument and every `--profile` flag, so a name the shell
// could never guess becomes tab-completable. Names are deduped (a project
// profile shadows a global one of the same name) and each carries its
// scope as the completion description.
func completeProfileNames(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	infos, err := profile.ListAll(cwd)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	seen := map[string]bool{}
	var out []string
	for _, info := range infos {
		if seen[info.Name] || !strings.HasPrefix(info.Name, toComplete) {
			continue
		}
		seen[info.Name] = true
		out = append(out, fmt.Sprintf("%s\t%s", info.Name, info.Scope))
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}

func init() {
	profileCmd.AddCommand(profileListCmd, profileShowCmd)
	rootCmd.AddCommand(profileCmd)
}
