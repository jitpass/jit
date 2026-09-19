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

	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

// `jit profile drop` removes variables from a manifest and nothing else.
//
// It exists because doctor's only answer to a manifest entry the vault has
// no value for was "put a value there" — `jit vault set`, or `jit migrate`
// the file it came from. Both assume the entry is WANTED, and there was no
// supported way to say the other thing: this entry is left over, the tool
// never needed it, drop it. `jit profile rm` deletes the whole profile and
// the secrets nothing else uses; `jit profile create --force` rewrites the
// manifest from scratch, which means retyping every variable that is fine.
// Neither is a proportionate answer to one stale line, so the only route
// was hand-editing YAML — which is exactly what a user hit.
//
// How those entries get there is worth knowing, because it is not a bug the
// user made: `jit migrate` MERGES into an existing manifest rather than
// overwriting it (claimNamespace, so a re-run can never silently drop an
// earlier variable). Migrate a two-variable .env beside a manifest that a
// clone restored with six, and the result claims six — two with values and
// four without. Doctor then calls the profile broken, correctly, and the
// four entries are unreachable by any command jit had.
//
// The guards refuse rather than ask, matching `jit migrate forget`:
//
//   - every named variable must be in the manifest, so a typo cannot
//     silently succeed;
//   - the vault must hold NO value at the variable's path, because then the
//     entry is live and dropping it abandons a real secret with nothing
//     left pointing at it;
//   - the last variable cannot be dropped, because an empty manifest is a
//     profile that resolves to nothing and reports no finding — a trap, not
//     a fix.
//
// The `.pointers` companion beside a live mount is rewritten from the
// trimmed manifest, because nothing else ever does: WritePointerFile has a
// single caller in migrate, and every other reference to that file only
// deletes it. Without this the companion would keep listing the dropped
// variables for good, which is how this class of confusion started.
//
// Only vault NAMES are read, so no value is decrypted and no Touch ID is
// needed.
var (
	profileDropYes    bool
	profileDropDryRun bool
)

var profileDropCmd = &cobra.Command{
	Use:   "drop <name> VAR...",
	Short: "Remove variables from a profile manifest",
	Long: "Removes variables from a profile manifest, keeping the rest. Use it\n" +
		"for an entry the tool does not actually need — the leftovers a\n" +
		"restored or merged manifest carries, which `jit doctor` reports as\n" +
		"[missing] because the vault has no value for them.\n\n" +
		"It refuses to drop a variable whose vault path holds a value: that\n" +
		"entry is live, and dropping it would leave a real secret with\n" +
		"nothing pointing at it (`jit vault rm` is the command that means\n" +
		"that). It refuses to empty a manifest, and it never touches a\n" +
		"secret, a mount or another profile.\n\n" +
		"The `.pointers` companion beside a live mount is rewritten to match.\n\n" +
		"No value is read, so no Touch ID is needed.",
	Example: "  jit profile drop hibob HIBOB_BASE_URL\n" +
		"  jit profile drop hibob HIBOB_BASE_URL HIBOB_FIELDS --dry-run",
	Args:              requireArgs(2, -1, "a profile name and at least one variable"),
	ValidArgsFunction: completeProfileDropArgs,
	SilenceUsage:      true,
	RunE:              runProfileDrop,
}

func runProfileDrop(cmd *cobra.Command, args []string) error {
	name, vars := args[0], args[1:]

	manifest, err := resolveProfileManifest(name)
	if err != nil {
		return fmt.Errorf("jit profile drop: %w", err)
	}
	prof, order, err := profile.LoadFileOrdered(manifest)
	if err != nil {
		return fmt.Errorf("jit profile drop: %w", err)
	}

	v, err := openVaultReadOnly()
	if err != nil {
		return fmt.Errorf("jit profile drop: %w", err)
	}
	if err := profileDropCheck(v, prof, manifest, vars); err != nil {
		return fmt.Errorf("jit profile drop: %w", err)
	}

	drop := map[string]bool{}
	for _, varName := range vars {
		drop[varName] = true
	}
	kept := profile.Profile{}
	keptOrder := make([]string, 0, len(order))
	for _, varName := range order {
		if drop[varName] {
			continue
		}
		kept[varName] = prof[varName]
		keptOrder = append(keptOrder, varName)
	}

	data, err := profile.MarshalOrdered(kept, keptOrder)
	if err != nil {
		return fmt.Errorf("jit profile drop: %w", err)
	}

	out := cmd.OutOrStdout()
	dropped := profileDropNames(order, drop)
	if profileDropDryRun {
		fmt.Fprintf(out, "%s would drop %s from %s, leaving %s\n",
			glyphAction, strings.Join(dropped, ", "), shortPath(manifest),
			countWord(len(kept), "variable", "variables"))
		return nil
	}
	if !profileDropYes {
		if !confirmPrompt(cmd, fmt.Sprintf("Drop %s from %s? The tool will no longer receive %s. [y/N] ",
			strings.Join(dropped, ", "), shortPath(manifest),
			pluralWord(len(dropped), "it", "them"))) {
			fmt.Fprintln(out, "Left alone.")
			return nil
		}
	}
	if err := os.WriteFile(manifest, data, 0o600); err != nil {
		return fmt.Errorf("jit profile drop: writing %s: %w", shortPath(manifest), err)
	}

	_, _ = cOK.Fprint(out, glyphOK+" ")
	fmt.Fprintf(out, "dropped %s from %s (%s left)\n",
		strings.Join(dropped, ", "), shortPath(manifest), countWord(len(kept), "variable", "variables"))

	if companion, err := profileDropRewriteCompanion(manifest, kept, keptOrder); err != nil {
		// The manifest is already correct, which is the fix the user asked
		// for; a companion that could not be rewritten is a stale document,
		// not a broken tool. Reported, never fatal.
		fmt.Fprintf(cmd.ErrOrStderr(), "%s the manifest is updated, but its .pointers companion could not be: %v\n", glyphWarn, err)
	} else if companion != "" {
		fmt.Fprintf(out, "  %s rewritten to match\n", shortPath(companion))
	}
	return nil
}

// profileDropCheck runs every guard before anything is written, so a command
// naming four variables either drops all four or refuses and changes
// nothing. Each failure names the one command that means what the user
// probably meant instead.
func profileDropCheck(v *vault.Vault, prof profile.Profile, manifest string, vars []string) error {
	seen := map[string]bool{}
	var unknown, live []string
	for _, varName := range vars {
		if seen[varName] {
			return fmt.Errorf("%s is given twice", varName)
		}
		seen[varName] = true

		secretPath, ok := prof[varName]
		if !ok {
			unknown = append(unknown, varName)
			continue
		}
		// Exists reads a name, never a value. A vault error here is not a
		// reason to refuse the drop outright, but it IS a reason not to
		// claim the path is empty: treated as live, the safe side.
		exists, err := v.Exists(secretPath)
		if err != nil {
			return fmt.Errorf("checking %s: %w", secretPath, err)
		}
		if exists {
			live = append(live, fmt.Sprintf("%s (%s)", varName, secretPath))
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		have := make([]string, 0, len(prof))
		for varName := range prof {
			have = append(have, varName)
		}
		sort.Strings(have)
		return fmt.Errorf("%s does not list %s; it lists %s",
			shortPath(manifest), strings.Join(unknown, ", "), strings.Join(have, ", "))
	}
	if len(live) > 0 {
		sort.Strings(live)
		return fmt.Errorf(
			"the vault holds a value for %s, so %s live, not left over; `jit vault rm <path>` is the command that deletes a secret",
			strings.Join(live, ", "), pluralWord(len(live), "this entry is", "these entries are"))
	}
	if len(seen) >= len(prof) {
		return fmt.Errorf(
			"that would leave %s with no variables, which resolves to nothing and reports nothing; delete the file itself if the profile is finished",
			shortPath(manifest))
	}
	return nil
}

// profileDropNames renders the dropped variables in the manifest's own
// order rather than the order they were typed, so the confirmation reads
// like the file.
func profileDropNames(order []string, drop map[string]bool) []string {
	out := make([]string, 0, len(drop))
	for _, varName := range order {
		if drop[varName] {
			out = append(out, varName)
		}
	}
	return out
}

// resolveProfileManifest finds the manifest a profile NAME refers to, in the
// order a run resolves it — this project, then the global store — and then
// the mount registry, which is the only place a manifest belonging to some
// other project's tree can be found from here. That last step is what makes
// a doctor action runnable: doctor reaches those manifests through the
// registry (scope "mount"), so an action it prints for one has to resolve
// the same way or the button fails in the one situation it exists for.
func resolveProfileManifest(name string) (string, error) {
	if _, err := profile.Path("", name); err != nil {
		return "", err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	var tried []string
	if _, _, path, err := profile.LoadWithScope(cwd, name); err == nil {
		return path, nil
	} else if !errors.Is(err, profile.ErrNotFound) {
		return "", err
	} else {
		tried = append(tried, profileScopePathsTried(err)...)
	}

	root, rootErr := vaultRootDir()
	if rootErr == nil {
		if entries, lerr := mount.LoadRegistry(mount.RegistryPath(root)); lerr == nil {
			for _, e := range entries {
				clean := filepath.Clean(e.ProfilePath)
				if strings.TrimSuffix(filepath.Base(clean), filepath.Ext(clean)) != name {
					continue
				}
				if _, statErr := os.Stat(clean); statErr == nil {
					return clean, nil
				}
			}
		}
	}
	if len(tried) == 0 {
		return "", fmt.Errorf("profile %q %w", name, profile.ErrNotFound)
	}
	return "", fmt.Errorf("profile %q %w (checked %s, and every registered mount's manifest)",
		name, profile.ErrNotFound, strings.Join(tried, ", "))
}

// profileScopePathsTried pulls the paths out of LoadWithScope's not-found
// error so this command's own error can list them alongside the registry it
// also searched, rather than printing two not-found errors in a row.
func profileScopePathsTried(err error) []string {
	msg := err.Error()
	open := strings.LastIndex(msg, "(checked ")
	if open < 0 || !strings.HasSuffix(msg, ")") {
		return nil
	}
	return strings.Split(msg[open+len("(checked "):len(msg)-1], ", ")
}

// profileDropRewriteCompanion rewrites the `.pointers` file beside a live
// mount this manifest serves, returning the path it wrote (or "" when no
// mount uses this manifest, which is the common case for a profile that
// only ever feeds `jit run`).
func profileDropRewriteCompanion(manifest string, kept profile.Profile, order []string) (string, error) {
	root, err := vaultRootDir()
	if err != nil {
		return "", err
	}
	entries, err := mount.LoadRegistry(mount.RegistryPath(root))
	if err != nil {
		return "", err
	}
	// canonicalPath, not Clean: the registry holds whatever path `jit
	// migrate` recorded, while this manifest path came from resolving a
	// name against cwd. A symlink anywhere above them — /var vs
	// /private/var on macOS, or a project directory reached through one —
	// makes two spellings of the same file compare unequal, and the
	// companion then silently keeps listing a variable that is gone.
	want := canonicalPath(manifest)
	for _, e := range entries {
		if canonicalPath(e.ProfilePath) != want {
			continue
		}
		companion := migrate.PointerFilePath(e.MountPath)
		// Only ever rewritten in place: a mount whose companion was
		// deliberately deleted does not get one back from a drop.
		if _, statErr := os.Stat(companion); statErr != nil {
			continue
		}
		if err := migrate.WritePointerFile(e.MountPath, kept, order); err != nil {
			return "", err
		}
		return companion, nil
	}
	return "", nil
}

// completeProfileDropArgs offers profile names for the first argument and
// that profile's own variables for the rest, so the variables on offer are
// always ones the manifest actually lists.
func completeProfileDropArgs(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) == 0 {
		return completeProfileNames(cmd, args, toComplete)
	}
	manifest, err := resolveProfileManifest(args[0])
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	prof, err := profile.LoadFile(manifest)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	chosen := map[string]bool{}
	for _, a := range args[1:] {
		chosen[a] = true
	}
	var out []string
	for varName := range prof {
		if !chosen[varName] && strings.HasPrefix(varName, toComplete) {
			out = append(out, varName)
		}
	}
	sort.Strings(out)
	return out, cobra.ShellCompDirectiveNoFileComp
}

func init() {
	profileDropCmd.Flags().BoolVarP(&profileDropYes, "yes", "y", false, "skip the confirmation prompt")
	profileDropCmd.Flags().BoolVar(&profileDropDryRun, "dry-run", false, "show what would be dropped; change nothing")
	profileCmd.AddCommand(profileDropCmd)
}
