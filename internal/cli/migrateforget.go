// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/pointerfile"
)

// `jit migrate forget` deletes ONE pointer file jit wrote that nothing uses
// any more, and nothing else.
//
// It exists because jit could write these files and never take one back.
// `jit migrate remove` is the only command that deletes a pointer file, and
// it takes the whole project with it — every mount, every profile, and the
// vault secrets they name — which is not a proportionate answer to one
// leftover companion beside a folder whose group was renamed two machines
// ago. Without this the only route was `rm`, leaving the user to clean up
// jit's own artifact by hand while doctor kept reporting it.
//
// The guards are what make a delete verb defensible here, and every one of
// them refuses rather than asks:
//
//   - the file must carry jit's pointer-file header, so this can only ever
//     delete something jit itself wrote;
//   - no registered mount may serve it, because then the file is live
//     documentation of a mount that is working;
//   - the vault must hold NOTHING under the group it names, because a group
//     that exists means the values are real and the file is current — the
//     same test doctor uses before it calls a companion stale.
//
// Nothing is read from the vault but names, so there is no Touch ID; and
// nothing else on disk is touched, so a mistake is one `git checkout` away
// on the committed file this is designed to find.
var (
	migrateForgetYes    bool
	migrateForgetDryRun bool
)

// forgetExamplePath spells the companion suffix from the package that owns
// it, so the help text cannot drift from the format jit actually writes.
var forgetExamplePath = pointerfile.CompanionPath("~/Security-Ops/custom_scripts/wiz/.env")

var migrateForgetCmd = &cobra.Command{
	Use:   "forget <pointer file>...",
	Short: "Delete a pointer file nothing uses any more",
	Long: "Deletes a jit pointer file (a `.pointers` companion, or a file jit\n" +
		"rewrote in place) that no longer refers to anything: no registered\n" +
		"mount serves it, and the vault holds nothing under the group it\n" +
		"names. These are what a renamed or never-restored vault group leaves\n" +
		"behind, and `jit doctor` reports them as [stale pointers].\n\n" +
		"It refuses any file that fails those tests, so it cannot delete a\n" +
		"live mount's companion or a file jit did not write. Nothing else is\n" +
		"touched: no profile, no mount, no secret. Compare `jit migrate\n" +
		"remove`, which takes a whole project back out of jit.\n\n" +
		"No value is read, so no Touch ID is needed.",
	Example: "  jit migrate forget " + forgetExamplePath + "\n" +
		"  jit migrate forget --dry-run " + forgetExamplePath,
	Args: requireArgs(1, -1, "a pointer file (see `jit doctor`)"),
	ValidArgsFunction: func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return nil, cobra.ShellCompDirectiveDefault
	},
	SilenceUsage: true,
	RunE:         runMigrateForget,
}

func runMigrateForget(cmd *cobra.Command, args []string) error {
	root, err := vaultRootDir()
	if err != nil {
		return fmt.Errorf("jit migrate forget: %w", err)
	}
	v, err := openVaultReadOnly()
	if err != nil {
		return fmt.Errorf("jit migrate forget: %w", err)
	}
	paths, err := v.List()
	if err != nil {
		return fmt.Errorf("jit migrate forget: listing the vault: %w", err)
	}
	secrets, _ := splitBackupPaths(paths)
	groups := map[string]bool{}
	for _, p := range secrets {
		if g, _, ok := strings.Cut(p, "/"); ok {
			groups[g] = true
		}
	}
	mounted := map[string]bool{}
	if entries, mErr := mount.LoadRegistry(mount.RegistryPath(root)); mErr == nil {
		for _, e := range entries {
			mounted[filepath.Clean(e.MountPath)] = true
			mounted[filepath.Clean(pointerfile.CompanionPath(e.MountPath))] = true
		}
	}

	out := cmd.OutOrStdout()
	for _, arg := range args {
		file, err := filepath.Abs(arg)
		if err != nil {
			return fmt.Errorf("jit migrate forget: %s: %w", arg, err)
		}
		if err := migrateForgetOne(cmd, out, file, groups, mounted); err != nil {
			return err
		}
	}
	return nil
}

func migrateForgetOne(cmd *cobra.Command, out io.Writer, file string, groups, mounted map[string]bool) error {
	data, err := os.ReadFile(file) // #nosec G304 -- a path the user named, verified below to be jit's own pointer file
	if err != nil {
		return fmt.Errorf("jit migrate forget: %s: %w", shortPath(file), err)
	}
	if !pointerfile.HasHeader(data) {
		return fmt.Errorf("jit migrate forget: %s is not a jit pointer file", shortPath(file))
	}
	if mounted[filepath.Clean(file)] {
		return fmt.Errorf("jit migrate forget: %s belongs to a registered mount; `jit unmount %s` first",
			shortPath(file), shortPath(strings.TrimSuffix(file, pointerfile.CompanionSuffix)))
	}
	named := migrateForgetGroups(data)
	if len(named) == 0 {
		return fmt.Errorf("jit migrate forget: %s names no vault path", shortPath(file))
	}
	for _, g := range named {
		if groups[g] {
			return fmt.Errorf("jit migrate forget: %s names %s/, which the vault holds; it is current, not stale", shortPath(file), g)
		}
	}

	if migrateForgetDryRun {
		fmt.Fprintln(out, hlCmds(fmt.Sprintf("%s would delete %s (names %s, none in the vault)",
			glyphAction, shortPath(file), strings.Join(migrateForgetDisplay(named), ", "))))
		return nil
	}
	if !migrateForgetYes {
		if !confirmPrompt(cmd, fmt.Sprintf("Delete %s? It names %s, which the vault doesn't hold. [y/N] ",
			shortPath(file), strings.Join(migrateForgetDisplay(named), ", "))) {
			fmt.Fprintln(out, "Left alone.")
			return nil
		}
	}
	if err := os.Remove(file); err != nil {
		return fmt.Errorf("jit migrate forget: %s: %w", shortPath(file), err)
	}
	_, _ = cOK.Fprint(out, glyphOK+" ")
	fmt.Fprintf(out, "deleted %s\n", shortPath(file))
	return nil
}

// migrateForgetDisplay renders group names as the user reads them in a
// vault path: with the trailing slash that makes "wiz" a group and not a key.
func migrateForgetDisplay(groups []string) []string {
	out := make([]string, len(groups))
	for i, g := range groups {
		out[i] = g + "/"
	}
	return out
}

// migrateForgetGroups returns the distinct vault groups a pointer file names,
// in first-seen order.
func migrateForgetGroups(data []byte) []string {
	seen := map[string]bool{}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		p, ok := pointerfile.VaultPath(strings.Trim(strings.TrimSpace(value), `"'`))
		if !ok || p == "" {
			continue
		}
		g, _, ok := strings.Cut(p, "/")
		if !ok || g == "" || seen[g] {
			continue
		}
		seen[g] = true
		out = append(out, g)
	}
	return out
}

func init() {
	migrateForgetCmd.Flags().BoolVarP(&migrateForgetYes, "yes", "y", false, "skip the confirmation prompt")
	migrateForgetCmd.Flags().BoolVar(&migrateForgetDryRun, "dry-run", false, "show what would be deleted; change nothing")
	migrateCmd.AddCommand(migrateForgetCmd)
}
