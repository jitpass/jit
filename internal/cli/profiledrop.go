// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"errors"
	"fmt"
	"io"
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
// A `.pointers` companion still sitting beside a live mount is rewritten
// from the trimmed manifest, because nothing else ever would: migrate
// stopped writing companions, and every other reference to one only deletes
// it. This is legacy-only upkeep — no new companion is ever created — but
// without it the ones already in people's repos would go on listing a
// variable the manifest no longer has, which is the drift that made this
// class of finding confusing in the first place.
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
		"A `.pointers` companion left beside a live mount by an older jit is\n" +
		"rewritten to match; none is created.\n\n" +
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
		// order comes from the raw YAML mapping, prof from the typed
		// unmarshal, and they diverge on a merge key: `<<: *defaults` is in
		// one and not the other. Copying blind would write `"<<": ""`, which
		// MarshalOrdered no longer filters (the key now exists) and
		// LoadFileOrdered then rejects — an unloadable manifest out of a
		// command whose whole job is to leave a loadable one.
		path, ok := prof[varName]
		if drop[varName] || !ok {
			continue
		}
		kept[varName] = path
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
	// Atomic and fsynced, exactly as migrate writes a manifest
	// (writeProfileManifest): os.WriteFile truncates before it writes, and a
	// crash in that window leaves a manifest mapping no variable to any vault
	// path — every secret it covered stranded, with LoadFileOrdered then
	// refusing the file outright. That is the end state the last-variable
	// guard above exists to prevent; reaching it by accident instead would be
	// no better.
	if err := vault.AtomicWriteFile(manifest, data); err != nil {
		return fmt.Errorf("jit profile drop: writing %s: %w", shortPath(manifest), err)
	}

	_, _ = cOK.Fprint(out, glyphOK+" ")
	fmt.Fprintf(out, "dropped %s from %s (%s left)\n",
		strings.Join(dropped, ", "), shortPath(manifest), countWord(len(kept), "variable", "variables"))

	companions, cerr := profileDropRewriteCompanion(manifest, kept, keptOrder)
	for _, c := range companions {
		fmt.Fprintf(out, "  %s rewritten to match\n", shortPath(c))
	}
	if cerr != nil {
		// The manifest is already correct, which is the fix the user asked
		// for; a companion that could not be rewritten is a stale document,
		// not a broken tool. Reported, never fatal.
		fmt.Fprintf(cmd.ErrOrStderr(), "%s the manifest is updated, but a .pointers companion could not be: %v\n", glyphWarn, cerr)
	}
	profileDropServedNote(out, profileDropServedMounts(manifest))
	return nil
}

// profileDropServedMounts is every registered mount this manifest feeds.
func profileDropServedMounts(manifest string) []string {
	root, err := vaultRootDir()
	if err != nil {
		return nil
	}
	entries, err := mount.LoadRegistry(mount.RegistryPath(root))
	if err != nil {
		return nil
	}
	want := canonicalPath(manifest)
	var out []string
	for _, e := range entries {
		if canonicalPath(e.ProfilePath) == want {
			out = append(out, e.MountPath)
		}
	}
	return out
}

// profileDropCheck runs every guard before anything is written, so a command
// naming four variables either drops all four or refuses and changes
// nothing. Each failure names the one command that means what the user
// probably meant instead.
func profileDropCheck(v *vault.Vault, prof profile.Profile, manifest string, vars []string) error {
	seen := map[string]bool{}
	var unknown []string
	for _, varName := range vars {
		if seen[varName] {
			return fmt.Errorf("%s is given twice", varName)
		}
		seen[varName] = true
		if _, ok := prof[varName]; !ok {
			unknown = append(unknown, varName)
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
	if len(seen) >= len(prof) {
		return fmt.Errorf(
			"that would leave %s with no variables, which resolves to nothing and reports nothing; delete the file itself if the profile is finished",
			shortPath(manifest))
	}

	// What the manifest still points at once these are gone. A secret can
	// only be STRANDED by this drop if nothing surviving names it — two
	// variables on one vault path (the usual shape of a rename left
	// half-done, OLD_NAME beside NEW_NAME) is exactly when refusing would be
	// wrong, and exactly the leftover this command is for.
	survives := map[string]bool{}
	for varName, path := range prof {
		if !seen[varName] {
			survives[path] = true
		}
	}

	var live, unsure []string
	for _, varName := range vars {
		secretPath := prof[varName]
		if survives[secretPath] {
			continue
		}
		// Exists reads a name, never a value.
		exists, err := v.Exists(secretPath)
		switch {
		case errors.Is(err, vault.ErrInvalidPath):
			// The path is not one the vault can ever hold anything at, so
			// there is no secret behind this entry to strand. Doctor reports
			// these as [bad path] and offers no action at all, which left
			// them removable by no jit command whatsoever — hand-edited YAML
			// being precisely what this command exists to retire.
			continue
		case err != nil:
			// Not "the path is empty" — that is the one thing this must not
			// assume. A case-variant collision (the manifest says
			// hibob/token, the vault holds hibob/TOKEN) answers this way, and
			// there IS a secret behind it.
			unsure = append(unsure, fmt.Sprintf("%s (%s: %v)", varName, secretPath, err))
		case exists:
			live = append(live, fmt.Sprintf("%s (%s)", varName, secretPath))
		}
	}
	if len(live) > 0 {
		sort.Strings(live)
		return fmt.Errorf(
			"the vault holds a value for %s, so %s live, not left over; `jit vault rm <path>` is the command that deletes a secret",
			strings.Join(live, ", "), pluralWord(len(live), "this entry is", "these entries are"))
	}
	if len(unsure) > 0 {
		sort.Strings(unsure)
		return fmt.Errorf("jit can't tell whether the vault holds a value for %s, so it will not drop %s",
			strings.Join(unsure, ", "), pluralWord(len(unsure), "it", "them"))
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
// A manifest PATH may be given instead of a name, and is the unambiguous
// form: a name can legitimately mean two different files (see below), a path
// never can.
func resolveProfileManifest(name string) (string, error) {
	if looksLikeManifestPath(name) {
		path, err := filepath.Abs(name)
		if err != nil {
			return "", err
		}
		if _, statErr := os.Stat(path); statErr != nil {
			return "", fmt.Errorf("%s: %w", shortPath(path), statErr)
		}
		return path, nil
	}
	if _, err := profile.Path("", name); err != nil {
		return "", err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	var scoped string
	if _, _, path, lerr := profile.LoadWithScope(cwd, name); lerr == nil {
		scoped = path
	} else if !errors.Is(lerr, profile.ErrNotFound) {
		return "", lerr
	}
	mounted := profileManifestsInRegistry(name)

	// Refuse rather than guess, the rule every other guard in this command
	// follows. `jit doctor` names a mount-scope profile by its manifest's
	// BASENAME, so the action it prints for some other project's tree is a
	// bare name — and resolving cwd first would edit the local manifest of
	// the same name instead. Two projects each owning an `api` profile is
	// not exotic, and the two failures compound: the unknown-variable guard
	// only saves you when the names differ. Several registered mounts can
	// also share a basename, where "first in the registry" is no answer at
	// all.
	candidates := map[string]bool{}
	if scoped != "" {
		candidates[canonicalPath(scoped)] = true
	}
	for _, m := range mounted {
		candidates[canonicalPath(m)] = true
	}
	switch len(candidates) {
	case 0:
		return "", fmt.Errorf("profile %q %w (checked %s, and every registered mount's manifest)",
			name, profile.ErrNotFound, strings.Join(profileScopePaths(cwd, name), ", "))
	case 1:
		if scoped != "" {
			return scoped, nil
		}
		return mounted[0], nil
	default:
		paths := make([]string, 0, len(candidates))
		for p := range candidates {
			paths = append(paths, shortPath(p))
		}
		sort.Strings(paths)
		return "", fmt.Errorf("%q names more than one manifest (%s); give the path of the one you mean instead of the name",
			name, strings.Join(paths, ", "))
	}
}

// looksLikeManifestPath distinguishes a path argument from a profile NAME.
// Names are validated by profile.Path and can hold neither a separator nor a
// file extension, so neither test can swallow a legal name.
func looksLikeManifestPath(arg string) bool {
	return strings.ContainsRune(arg, filepath.Separator) || filepath.Ext(arg) != ""
}

// profileScopePaths is where LoadWithScope would have looked, built rather
// than scraped back out of its error string: that message's shape is a
// display decision, not a contract, and a directory containing ", " alone
// was enough to turn the scrape into nonsense.
func profileScopePaths(cwd, name string) []string {
	var out []string
	if p, err := profile.Path(cwd, name); err == nil {
		out = append(out, shortPath(p))
	}
	// When cwd IS home, LoadWithScope resolves one path, not two; listing it
	// twice would read as a bug in the search rather than a fact about it.
	if home, err := profile.GlobalRoot(); err == nil {
		if p, perr := profile.Path(home, name); perr == nil && (len(out) == 0 || shortPath(p) != out[0]) {
			out = append(out, shortPath(p))
		}
	}
	return out
}

// profileManifestsInRegistry returns every registered mount's manifest whose
// basename is name, deduplicated, in registry order.
func profileManifestsInRegistry(name string) []string {
	root, err := vaultRootDir()
	if err != nil {
		return nil
	}
	entries, err := mount.LoadRegistry(mount.RegistryPath(root))
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		clean := filepath.Clean(e.ProfilePath)
		if strings.TrimSuffix(filepath.Base(clean), filepath.Ext(clean)) != name {
			continue
		}
		if _, statErr := os.Stat(clean); statErr != nil || seen[canonicalPath(clean)] {
			continue
		}
		seen[canonicalPath(clean)] = true
		out = append(out, clean)
	}
	return out
}

// profileDropRewriteCompanion rewrites the `.pointers` file beside a live
// mount this manifest serves, returning the path it wrote (or "" when no
// mount uses this manifest, which is the common case for a profile that
// only ever feeds `jit run`).
func profileDropRewriteCompanion(manifest string, kept profile.Profile, order []string) ([]string, error) {
	root, err := vaultRootDir()
	if err != nil {
		return nil, err
	}
	entries, err := mount.LoadRegistry(mount.RegistryPath(root))
	if err != nil {
		return nil, err
	}
	// canonicalPath, not Clean: the registry holds whatever path `jit
	// migrate` recorded, while this manifest path came from resolving a
	// name against cwd. A symlink anywhere above them — /var vs
	// /private/var on macOS, or a project directory reached through one —
	// makes two spellings of the same file compare unequal, and the
	// companion then silently keeps listing a variable that is gone.
	// EVERY matching mount, not the first: the registry is keyed on mount
	// path, so nothing stops several mounts sharing one manifest. Returning
	// at the first match left the rest naming the dropped variable for good
	// while the command reported the single path it did fix — the exact
	// drift this function exists to prevent, now stated falsely.
	want := canonicalPath(manifest)
	var written []string
	for _, e := range entries {
		if canonicalPath(e.ProfilePath) != want {
			continue
		}
		companion := migrate.PointerFilePath(e.MountPath)
		// Only ever rewritten in place: a mount whose companion was
		// deliberately deleted does not get one back from a drop, and
		// migrate no longer writes them at all.
		if _, statErr := os.Stat(companion); statErr != nil {
			continue
		}
		if err := migrate.WritePointerFile(e.MountPath, kept, order); err != nil {
			return written, err
		}
		written = append(written, companion)
	}
	return written, nil
}

// profileDropServedNote warns that a mount already being served keeps
// handing out the OLD variable list until the service restarts.
//
// Nothing in jit reloads a changed manifest into a live mount: ensureServing
// skips any mount already in m.served, and Refresh routes to the same place,
// so the decoy content built from the manifest's keys at first serve is
// never rebuilt. Real values are unaffected (resolveReal re-reads the
// manifest per grant) and `jit run --profile` reads it directly, so the tool
// itself is correct immediately — it is the file anyone OPENS that lags.
// Pre-existing, and invisible while editing a manifest meant editing YAML by
// hand; a one-click button makes it something users will now actually hit,
// so it gets said rather than discovered.
func profileDropServedNote(w io.Writer, mounts []string) {
	if len(mounts) == 0 {
		return
	}
	fmt.Fprint(w, hlCmds(fmt.Sprintf("  note: %s already being served still %s the old variable list until `jit service restart`\n",
		countWord(len(mounts), "mount", "mounts"),
		pluralWord(len(mounts), "shows", "show"))))
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
