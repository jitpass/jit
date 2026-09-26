// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

// `jit profile create` exists because every other way a profile comes into
// being is a side effect of something else: `jit migrate` writes one for a
// file it rewrote, `jit wrap` writes one for a tool it shimmed, a capture
// wrap writes one at the first login. None of them can be asked for a
// profile on its own, so a profile that is LOST has no command that brings
// it back — and the vault it referenced survives every kind of restore that
// loses it, since secrets and manifests travel by different mechanisms.
// Recovering one meant reading another project's committed YAML and
// retyping the shape by hand.
//
// The default is that recovery: with no VAR=PATH pairs, the manifest is
// built from the vault group of the same name, one variable per secret,
// named as the secret is named. That is what a migrate-written profile
// looks like, so recreating one is `jit profile create <name>` and nothing
// else.
//
// Prompt-free by construction: it reads the vault's NAMES (List, no
// KeyWrapper) and writes a file of names. No value is decrypted, so there
// is no Touch ID, and a machine whose vault is locked can still rebuild
// every profile it lost.
var (
	profileCreateFrom   string
	profileCreateGlobal bool
	profileCreateForce  bool
	profileCreateDryRun bool
)

var profileCreateCmd = &cobra.Command{
	Use:   "create <name> [VAR=<vault path>]...",
	Short: "Write a profile manifest",
	Long: "Writes a profile manifest: the file mapping environment variable\n" +
		"names to vault paths that `jit run --profile <name>` reads.\n\n" +
		"With no VAR=<vault path> pairs, the variables are taken from the\n" +
		"vault group of the same name — every secret in it becomes a variable\n" +
		"named as the secret is named. That is the shape `jit migrate` writes,\n" +
		"so a profile lost while its secrets survived comes back with just its\n" +
		"name. --from takes them from a differently named group.\n\n" +
		"Writes to ./.jit/profiles by default, so the manifest sits beside the\n" +
		"project it serves and can be committed with it; --global writes to\n" +
		"~/.jit/profiles, where MCP and shell profiles live. An existing\n" +
		"manifest is never overwritten without --force.\n\n" +
		"Only names are read from the vault and only names are written, so no\n" +
		"value is decrypted and no Touch ID is needed.",
	Example: "  jit profile create mcp-sentry\n" +
		"  jit profile create mcp-sentry --global\n" +
		"  jit profile create mcp-sentry --from sentry\n" +
		"  jit profile create deploy AWS_SECRET=aws-prod/SECRET DB_URL=rds/URL",
	Args:              requireArgs(1, -1, "a profile name"),
	ValidArgsFunction: completeProfileCreateArgs,
	SilenceUsage:      true,
	RunE:              runProfileCreate,
}

// completeProfileCreateArgs offers nothing for the name (it is new by
// definition) and vault paths for the VAR=PATH pairs after it.
func completeProfileCreateArgs(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) == 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	name, path, ok := strings.Cut(toComplete, "=")
	if !ok {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	paths, directive := completeVaultPaths(cmd, args, path)
	for i, p := range paths {
		paths[i] = name + "=" + p
	}
	return paths, directive
}

func runProfileCreate(cmd *cobra.Command, args []string) error {
	name := args[0]
	// Path validates the NAME and nothing else here; the root it is joined
	// to is chosen below.
	if _, err := profile.Path("", name); err != nil {
		return fmt.Errorf("jit profile create: %w", err)
	}

	root, err := profileCreateRoot()
	if err != nil {
		return fmt.Errorf("jit profile create: %w", err)
	}
	manifest, err := profile.Path(root, name)
	if err != nil {
		return fmt.Errorf("jit profile create: %w", err)
	}

	v, err := openVaultReadOnly()
	if err != nil {
		return fmt.Errorf("jit profile create: %w", err)
	}

	prof, order, err := profileCreateVars(v, name, args[1:])
	if err != nil {
		return fmt.Errorf("jit profile create: %w", err)
	}

	data, err := profile.MarshalOrdered(prof, order)
	if err != nil {
		return fmt.Errorf("jit profile create: %w", err)
	}

	out := cmd.OutOrStdout()
	if profileCreateDryRun {
		fmt.Fprintf(out, "%s would write %s:\n\n", glyphAction, shortPath(manifest))
		fmt.Fprint(out, string(data))
		return nil
	}
	// Checked immediately before the write rather than earlier, so the
	// window between "it wasn't there" and "so I wrote it" is as small as
	// this can make it. Never a silent overwrite: a manifest is the only
	// record of which secret each variable takes, and rebuilding one from
	// the vault cannot reproduce a hand-edited mapping.
	if !profileCreateForce {
		if _, err := os.Stat(manifest); err == nil {
			return fmt.Errorf("jit profile create: %s already exists; --force to replace it", shortPath(manifest))
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("jit profile create: %s: %w", shortPath(manifest), err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(manifest), 0o700); err != nil {
		return fmt.Errorf("jit profile create: creating the profile directory: %w", err)
	}
	if err := os.WriteFile(manifest, data, 0o600); err != nil {
		return fmt.Errorf("jit profile create: writing %s: %w", shortPath(manifest), err)
	}

	_, _ = cOK.Fprint(out, glyphOK+" ")
	fmt.Fprintf(out, "wrote %s (%s)\n", shortPath(manifest), countWord(len(prof), "variable", "variables"))
	fmt.Fprintln(out, hlCmds(fmt.Sprintf("%s `jit run --profile %s -- <command>`", glyphAction, name)))
	return nil
}

// profileCreateRoot is the store the manifest goes in: the global one under
// --global, else this directory, where it can be committed with the project
// whose tools read it.
func profileCreateRoot() (string, error) {
	if profileCreateGlobal {
		home, err := profile.GlobalRoot()
		if err != nil {
			return "", fmt.Errorf("finding the global profile store: %w", err)
		}
		return home, nil
	}
	return os.Getwd()
}

// profileCreateVars builds the manifest's contents: the VAR=PATH pairs as
// given (their order preserved, which MarshalOrdered keeps), or the vault
// group's secrets when none were given.
func profileCreateVars(v *vault.Vault, name string, pairs []string) (profile.Profile, []string, error) {
	if len(pairs) > 0 {
		return profileCreatePairs(v, pairs)
	}
	group := profileCreateFrom
	if group == "" {
		group = name
	}
	return profileCreateFromGroup(v, group)
}

func profileCreatePairs(v *vault.Vault, pairs []string) (profile.Profile, []string, error) {
	prof := make(profile.Profile, len(pairs))
	order := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		varName, path, ok := strings.Cut(pair, "=")
		if !ok {
			return nil, nil, fmt.Errorf("%q is not VAR=<vault path>", pair)
		}
		varName, path = strings.TrimSpace(varName), strings.TrimSpace(path)
		if _, dup := prof[varName]; dup {
			return nil, nil, fmt.Errorf("%s is given twice", varName)
		}
		// Exists both validates the path's shape and answers whether the
		// secret is there. A path naming nothing is a warning, not a
		// refusal: a profile written before its secrets are stored is a
		// legitimate order to work in, and `jit doctor` reports the gap.
		if _, err := v.Exists(path); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", varName, err)
		}
		prof[varName] = path
		order = append(order, varName)
	}
	// LoadFile rejects a manifest whose keys aren't shell-legal, so writing
	// one that cannot be read back is caught here rather than at first use.
	if err := profileCreateCheckNames(prof); err != nil {
		return nil, nil, err
	}
	return prof, order, nil
}

// profileCreateFromGroup maps every secret in one vault group to a variable
// of the same name: "mcp-jamf/JAMF_URL" becomes JAMF_URL: mcp-jamf/JAMF_URL.
func profileCreateFromGroup(v *vault.Vault, group string) (profile.Profile, []string, error) {
	paths, err := v.List()
	if err != nil {
		return nil, nil, fmt.Errorf("listing the vault: %w", err)
	}
	secrets, _ := splitBackupPaths(paths)

	prof := profile.Profile{}
	for _, p := range secrets {
		g, varName, ok := strings.Cut(p, "/")
		if !ok || g != group || strings.Contains(varName, "/") {
			continue
		}
		prof[varName] = p
	}
	if len(prof) == 0 {
		return nil, nil, fmt.Errorf(
			"the vault has no group %q to build it from; name the variables as VAR=<vault path>, or --from another group", group)
	}
	if err := profileCreateCheckNames(prof); err != nil {
		return nil, nil, err
	}
	// Sorted, so the same vault always produces the same file: a manifest
	// is meant to be committed, and a diff that reorders itself between
	// machines is noise nobody can review.
	order := make([]string, 0, len(prof))
	for varName := range prof {
		order = append(order, varName)
	}
	sort.Strings(order)
	return prof, order, nil
}

// profileCreateCheckNames rejects keys a manifest can hold but `jit run`
// cannot export, naming every one rather than only the first: a group
// rebuilt from the vault can carry several, and fixing them one error at a
// time is a poor way to learn that.
func profileCreateCheckNames(prof profile.Profile) error {
	var bad []string
	for varName := range prof {
		if !profile.ValidVarName(varName) {
			bad = append(bad, varName)
		}
	}
	if len(bad) == 0 {
		return nil
	}
	sort.Strings(bad)
	return fmt.Errorf("%s is not a legal environment variable name: %s",
		pluralWord(len(bad), "this name", "these names"), strings.Join(bad, ", "))
}

func init() {
	profileCreateCmd.Flags().StringVar(&profileCreateFrom, "from", "",
		"take the variables from this vault group instead of <name>")
	profileCreateCmd.Flags().BoolVar(&profileCreateGlobal, "global", false,
		"write to ~/.jit/profiles instead of ./.jit/profiles")
	profileCreateCmd.Flags().BoolVar(&profileCreateForce, "force", false,
		"replace an existing manifest")
	profileCreateCmd.Flags().BoolVar(&profileCreateDryRun, "dry-run", false,
		"print the manifest; write nothing")
	_ = profileCreateCmd.RegisterFlagCompletionFunc("from", completeVaultGroups)

	profileCmd.AddCommand(profileCreateCmd)
}

// completeVaultGroups offers the vault's top-level group names.
func completeVaultGroups(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	v, err := openVaultReadOnly()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	paths, err := v.List()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	secrets, _ := splitBackupPaths(paths)
	seen := map[string]bool{}
	var out []string
	for _, p := range secrets {
		g, _, ok := strings.Cut(p, "/")
		if !ok || seen[g] || !strings.HasPrefix(g, toComplete) {
			continue
		}
		seen[g] = true
		out = append(out, g)
	}
	sort.Strings(out)
	return out, cobra.ShellCompDirectiveNoFileComp
}
