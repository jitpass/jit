// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/projectrecord"
)

// `jit mount` is the two repairs a project record makes possible
// (design/project-relocation.md): re-pointing a registration at the project
// that moved, and serving one a copy or a clone brought with it.
//
// Both write exactly one thing — the machine-local mount registry — and
// nothing else: no secret is read or written, no manifest is touched, no file
// is created or deleted. That is what keeps the project record in the class
// it has to stay in: it can make jit RECOGNISE a project and make a finding
// appear, and a human still decides whether this Mac serves it. Repo content
// never enlarges what a machine does on its own.
var mountCmd = &cobra.Command{
	Use:     "mount",
	GroupID: groupSecrets,
	Short:   "Re-point or register a project's live mounts",
	Long: "Repairs the machine-local mount registry when a project has moved or\n" +
		"arrived by copy. jit records where a project's mounted files are using\n" +
		"absolute paths; renaming, moving or duplicating a folder leaves that\n" +
		"record pointing at the wrong place, and nothing reconciles it on its own.\n\n" +
		"These edit the registry, or the project records they match against, and\n" +
		"nothing else — no secret is read or written, so none needs Touch ID.",
}

var (
	mountRelocateYes bool
	mountRegisterYes bool
	mountRecordYes   bool
)

// `jit mount record` is the backfill. Every mount migrated before project
// records existed is registered and working and has no record, so jit can
// still serve it and still cannot recognise it if the folder moves — the
// repairs above need a record to match against, and nothing writes one for a
// mount that is already healthy.
//
// Deliberately a command rather than something doctor or the service does on
// its own. It writes files into the user's project directories, which are
// git repositories: that is a thing to be asked for once, not a side effect
// of running a health check.
var mountRecordCmd = &cobra.Command{
	Use:   "record",
	Short: "Write the project record for mounts already registered",
	Long: "Writes each registered mount into its own project's record, so jit can\n" +
		"recognise that project if the folder is later renamed, moved or copied.\n\n" +
		"`jit migrate` writes this record for anything it mounts, so this is only\n" +
		"needed once, for mounts migrated before records existed. Mounts that\n" +
		"already have one are left alone, and a mount served from the global\n" +
		"profile store is skipped: \"the project moved\" is not a thing that\n" +
		"happens to your home directory.\n\n" +
		"It writes only inside the projects that already own these mounts, and\n" +
		"changes no registry entry, no manifest and no secret. No Touch ID.",
	Example:      "  jit mount record",
	Args:         requireArgs(0, 0, ""),
	SilenceUsage: true,
	RunE:         runMountRecord,
}

func runMountRecord(cmd *cobra.Command, _ []string) error {
	root, err := vaultRootDir()
	if err != nil {
		return fmt.Errorf("jit mount record: %w", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("jit mount record: %w", err)
	}
	entries, err := mount.LoadRegistry(mount.RegistryPath(root))
	if err != nil {
		return fmt.Errorf("jit mount record: %w", err)
	}
	// Names only, so this never prompts — the same contract completion and
	// listings rely on.
	v, err := openVaultReadOnly()
	if err != nil {
		return fmt.Errorf("jit mount record: %w", err)
	}

	var todo []mount.Entry
	var skipped []string
	for _, e := range entries {
		if _, serr := os.Stat(e.ProfilePath); serr != nil {
			skipped = append(skipped, fmt.Sprintf("%s: its profile is gone", shortPath(e.MountPath)))
			continue
		}
		recordPath := projectrecord.Path(e.ProfilePath)
		project := projectrecord.ProjectRoot(recordPath)
		if canonicalPath(project) == canonicalPath(home) {
			skipped = append(skipped, fmt.Sprintf("%s: served from the global store", shortPath(e.MountPath)))
			continue
		}
		if recorded(recordPath, project, e.MountPath) {
			continue
		}
		todo = append(todo, e)
	}

	out := cmd.OutOrStdout()
	if len(todo) == 0 {
		fmt.Fprintln(out, "Every mount that can have a project record already has one.")
		for _, s := range skipped {
			fmt.Fprintf(out, "  %s %s\n", glyphBullet, s)
		}
		return nil
	}

	fmt.Fprintf(out, "%s write a project record for %s:\n", glyphAction, countWord(len(todo), "mount", "mounts"))
	for _, e := range todo {
		fmt.Fprintf(out, "  %s %s\n", glyphBullet, shortPath(projectrecord.Path(e.ProfilePath)))
	}
	if !mountRecordYes && !confirmPrompt(cmd, "These are files inside your projects, committable like the manifests beside them. Continue? [y/N] ") {
		fmt.Fprintln(out, "Left alone.")
		return nil
	}

	written := 0
	for _, e := range todo {
		if err := projectrecord.Add(e.ProfilePath, e.MountPath, manifestGroupID(v, e.ProfilePath)); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "%s %s: %v\n", glyphWarn, shortPath(e.MountPath), err)
			continue
		}
		written++
	}
	_, _ = cOK.Fprint(out, glyphOK+" ")
	fmt.Fprintf(out, "recorded %s\n", countWord(written, "mount", "mounts"))
	for _, s := range skipped {
		fmt.Fprintf(out, "  %s %s\n", glyphBullet, s)
	}
	return nil
}

// recorded reports whether this mount is already in its project's record.
func recorded(recordPath, project, mountPath string) bool {
	r, ok, err := projectrecord.Read(recordPath)
	if err != nil || !ok {
		return false
	}
	for _, rel := range r.Mounts {
		if abs, rerr := projectrecord.Resolve(project, rel); rerr == nil && canonicalPath(abs) == canonicalPath(mountPath) {
			return true
		}
	}
	return false
}

var mountRelocateCmd = &cobra.Command{
	Use:   "relocate <project dir>",
	Short: "Re-point a mount registration at the project's new location",
	Long: "Updates the registry entries for a project that has been renamed or\n" +
		"moved, so its mounted files are served where they now are.\n\n" +
		"The project must carry a jit record (written by `jit migrate`) naming\n" +
		"the mounts it has. Only entries whose recorded path is GONE are\n" +
		"re-pointed: a registration that still resolves is left alone, so this\n" +
		"can never steal a live mount from another project.\n\n" +
		"No secret is read, so no Touch ID is needed.",
	Example:      "  jit mount relocate ~/work/hibob",
	Args:         requireArgs(1, 1, "the project directory (see `jit doctor`)"),
	SilenceUsage: true,
	RunE:         func(cmd *cobra.Command, args []string) error { return runMountRepair(cmd, args[0], true) },
}

var mountRegisterCmd = &cobra.Command{
	Use:   "register <project dir>",
	Short: "Serve a project's mounts on this Mac",
	Long: "Adds a project's mounted files to this Mac's registry, so the background\n" +
		"service serves them. Use it for a project that arrived by copy or clone:\n" +
		"the file comes with the folder, the registration never does, and until\n" +
		"this runs anything reading that file waits forever for a writer that\n" +
		"does not exist.\n\n" +
		"The project must carry a jit record (written by `jit migrate`) naming\n" +
		"the mounts it has, and each named file must already be there — this\n" +
		"creates nothing.\n\n" +
		"No secret is read, so no Touch ID is needed.",
	Example:      "  jit mount register ~/Security-Ops/custom_scripts/hibob2",
	Args:         requireArgs(1, 1, "the project directory (see `jit doctor`)"),
	SilenceUsage: true,
	RunE:         func(cmd *cobra.Command, args []string) error { return runMountRepair(cmd, args[0], false) },
}

// runMountRepair is both subcommands: they differ only in which registry
// state they accept, which is one condition, not two implementations.
func runMountRepair(cmd *cobra.Command, dir string, relocate bool) error {
	verb := "register"
	if relocate {
		verb = "relocate"
	}
	fail := func(format string, a ...any) error {
		return fmt.Errorf("jit mount "+verb+": "+format, a...)
	}

	projectDir, err := filepath.Abs(dir)
	if err != nil {
		return fail("%v", err)
	}
	root, err := vaultRootDir()
	if err != nil {
		return fail("%v", err)
	}
	registryPath := mount.RegistryPath(root)

	found, records, err := projectMounts(projectDir)
	if err != nil {
		return fail("%v", err)
	}
	if records == 0 {
		return fail("%s carries no jit mount record; `jit migrate` writes one for the files it mounts", shortPath(projectDir))
	}
	if len(found) == 0 {
		// The record is there and every file it names is not. Distinct from
		// having no record at all, and saying "carries no record" here sent
		// the user looking for a file that was never the problem.
		fmt.Fprintf(cmd.OutOrStdout(), "Nothing to %s: %s records %s, and none of them is there.\n",
			verb, shortPath(projectDir), countWord(records, "mount", "mounts"))
		return nil
	}

	entries, err := mount.LoadRegistry(registryPath)
	if err != nil {
		return fail("%v", err)
	}
	registered := map[string]bool{}
	for _, e := range entries {
		registered[canonicalPath(e.MountPath)] = true
	}

	var plan []mount.Entry
	var skipped []string
	for _, f := range found {
		switch {
		case registered[canonicalPath(f.MountPath)]:
			// Already served from here. Never re-pointed and never
			// duplicated — whichever half of this the user asked for.
			skipped = append(skipped, fmt.Sprintf("%s is already served", shortPath(f.MountPath)))
			continue
		case !relocate:
			plan = append(plan, f)
		default:
			// Relocate replaces the entries this project used to own. A dead
			// entry is one whose manifest is gone, which is the only state
			// that can be a relocation — an entry that still resolves belongs
			// to a project that is still there, and stealing it is exactly
			// the accident this guard exists to prevent.
			dead := deadEntryFor(entries, f)
			if dead == "" {
				skipped = append(skipped, fmt.Sprintf("%s has no dead registration to re-point", shortPath(f.MountPath)))
				continue
			}
			plan = append(plan, f)
		}
	}
	if len(plan) == 0 {
		out := cmd.OutOrStdout()
		fmt.Fprintf(out, "Nothing to %s.\n", verb)
		for _, s := range skipped {
			fmt.Fprintf(out, "  %s %s\n", glyphBullet, s)
		}
		return nil
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "%s %s in %s:\n", glyphAction, verb, shortPath(projectDir))
	for _, e := range plan {
		fmt.Fprintf(out, "  %s %s  (profile %s)\n", glyphBullet, shortPath(e.MountPath),
			strings.TrimSuffix(filepath.Base(e.ProfilePath), filepath.Ext(e.ProfilePath)))
	}
	yes := mountRegisterYes
	if relocate {
		yes = mountRelocateYes
	}
	if !yes && !confirmPrompt(cmd, "This changes which files jit serves on this Mac. Continue? [y/N] ") {
		fmt.Fprintln(out, "Left alone.")
		return nil
	}

	for _, e := range plan {
		if relocate {
			if dead := deadEntryFor(entries, e); dead != "" {
				if _, rerr := mount.RemoveMount(registryPath, dead); rerr != nil {
					return fail("clearing %s: %w", shortPath(dead), rerr)
				}
			}
		}
		if err := mount.AddMount(registryPath, e); err != nil {
			return fail("%v", err)
		}
	}

	_, _ = cOK.Fprint(out, glyphOK+" ")
	fmt.Fprintf(out, "%sd %s\n", verb, countWord(len(plan), "mount", "mounts"))
	// The service is told now rather than at the next lock/unlock, the same
	// reason migrate refreshes: until it knows, a read against the file it
	// now owns still hangs.
	if client := agent.NewClient(agent.SocketPath(root)); client.Reachable() {
		if err := client.Refresh(); err != nil {
			fmt.Fprint(cmd.ErrOrStderr(), hlCmds(fmt.Sprintf("%s could not tell the running service: %v; `jit service restart` picks it up\n", glyphWarn, err)))
		} else {
			fmt.Fprintln(out, "  the background service is serving it now")
		}
	}
	return nil
}

// projectMounts is the registry entries a project's own record describes,
// with every path validated and every named file confirmed present.
// The second return is how many mounts the records NAMED, which the caller
// needs to tell "no record here" from "a record whose files are all gone" —
// two states with very different answers.
func projectMounts(projectDir string) ([]mount.Entry, int, error) {
	store := filepath.Join(projectDir, profile.ProfilesDir)
	names, err := os.ReadDir(store)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, nil
		}
		return nil, 0, err
	}
	var out []mount.Entry
	named := 0
	for _, entry := range names {
		if entry.IsDir() || filepath.Ext(entry.Name()) != projectrecord.Suffix {
			continue
		}
		recordPath := filepath.Join(store, entry.Name())
		r, ok, rerr := projectrecord.Read(recordPath)
		if rerr != nil || !ok {
			continue
		}
		manifest := strings.TrimSuffix(recordPath, projectrecord.Suffix) + ".yaml"
		if _, serr := os.Stat(manifest); serr != nil {
			// A record whose manifest is gone describes nothing servable:
			// the mount would have no variable list behind it.
			continue
		}
		for _, rel := range r.Mounts {
			named++
			abs, aerr := projectrecord.Resolve(projectDir, rel)
			if aerr != nil {
				return nil, named, fmt.Errorf("%s: %w", shortPath(recordPath), aerr)
			}
			// Never creates anything: a record naming a file that is not
			// there is a project whose mount was never made on this Mac, and
			// inventing a FIFO for it would serve decoys at a path nothing
			// asked for.
			if _, serr := os.Lstat(abs); serr != nil {
				continue
			}
			out = append(out, mount.Entry{MountPath: abs, ProfilePath: manifest})
		}
	}
	return out, named, nil
}

// deadEntryFor is the registered mount path this project's entry replaces:
// one whose manifest no longer exists and whose file basename and profile
// name both match. Empty when there is nothing to re-point.
func deadEntryFor(entries []mount.Entry, want mount.Entry) string {
	wantName := strings.TrimSuffix(filepath.Base(want.ProfilePath), filepath.Ext(want.ProfilePath))
	for _, e := range entries {
		if _, err := os.Stat(e.ProfilePath); !os.IsNotExist(err) {
			continue
		}
		name := strings.TrimSuffix(filepath.Base(e.ProfilePath), filepath.Ext(e.ProfilePath))
		if name == wantName && filepath.Base(e.MountPath) == filepath.Base(want.MountPath) {
			return e.MountPath
		}
	}
	return ""
}

func init() {
	mountRelocateCmd.Flags().BoolVarP(&mountRelocateYes, "yes", "y", false, "skip the confirmation prompt")
	mountRegisterCmd.Flags().BoolVarP(&mountRegisterYes, "yes", "y", false, "skip the confirmation prompt")
	mountRecordCmd.Flags().BoolVarP(&mountRecordYes, "yes", "y", false, "skip the confirmation prompt")
	mountCmd.AddCommand(mountRelocateCmd, mountRegisterCmd, mountRecordCmd)
	rootCmd.AddCommand(mountCmd)
}
