// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

var migrateRemoveYes bool

// migrateRemoveCmd is `jit migrate undo`'s stronger sibling (GAPS.md #59):
// undo reverses files and deliberately keeps the vault; remove takes jit
// out of the current project COMPLETELY — files back to plaintext (current
// vault values, matching unmount's semantics rather than undo's
// restore-the-backup), then the project's profiles, their vault secrets,
// its encrypted file backups, and the .jit/ directory
// all deleted. Both plaintext-restoring AND destructive, so it takes the
// strictest gate this package has: plan → [y/N] confirm →
// openVaultFreshAuth (always its own Touch ID/passcode challenge, never a
// cached agent session — GAPS.md #50's class).
var migrateRemoveCmd = &cobra.Command{
	Use:   "remove",
	Short: "Remove jit from this project completely (restore plaintext, delete its secrets)",
	Long: "jit migrate remove takes jit back out of the current project: every live\n" +
		"mount and pointer file under this directory tree becomes a plain file\n" +
		"again, and any server in the project's own mcp.json/.mcp.json launching\n" +
		"through jit gets its plaintext env block back (all written from the\n" +
		"CURRENT vault values, so edits made with `jit vault set` since migration\n" +
		"are kept), and then the project's profile manifests, including the ones\n" +
		"created for this project's MCP servers, the vault secrets they\n" +
		"reference, the project's encrypted file backups, and the .jit/ directory\n" +
		"itself are all deleted.\n\n" +
		"Machine-level migrations (shell configs, AWS, kubeconfig, Terraform\n" +
		"Cloud, GCP application-default credentials, the global ~/.npmrc,\n" +
		"Claude Desktop's MCP config) are not touched, they aren't part of any\n" +
		"one project; reverse those with `jit migrate undo`.\n\n" +
		"A vault secret also referenced by a profile OUTSIDE this project is\n" +
		"kept (and reported), never deleted out from under the other profile.\n\n" +
		"This both writes real secret values back to disk in PLAINTEXT and\n" +
		"permanently deletes them from the vault, so it always requires its own\n" +
		"Touch ID/passcode approval, a running service session is deliberately\n" +
		"not enough.",
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE:         runMigrateRemove,
}

// projectRemovalPlan is everything runMigrateRemove decided to do, gathered
// before anything is confirmed, authed, or mutated.
type projectRemovalPlan struct {
	cwd          string
	mounts       []mount.Entry // registered mounts under cwd's tree
	companions   []string      // .pointers companion files (deleted)
	inPlace      []string      // in-place pointer files (restored to plaintext)
	profileInfos []profile.Info
	// ownedGlobal are global-store profiles a .source sidecar records as
	// owned by an MCP config file inside this project (a project mcp.json's
	// profile lives in the global store, since an MCP host's subprocess
	// can't do a project-relative lookup) — part of THIS project, deleted
	// with it, unlike genuinely machine-level global profiles. Also listed
	// in profileInfos for display; kept separately because their manifest
	// (+ sidecar) files need explicit deletion — they don't live under the
	// .jit directory RemoveAll covers.
	ownedGlobal []profile.Info
	// mcpRestores: config file → (profile name → manifest path) for owned
	// profiles whose server entry is still wrapped as `jit run --profile
	// ... --` — those get their plaintext env block back (current vault
	// values) before the profile and its secrets are deleted.
	mcpRestores map[string]map[string]string
	deletePaths []string // vault secret paths to delete
	keptShared  []string // vault paths kept because another profile references them
	backups     []migrate.BackupRecord
	jitDir      string
}

func runMigrateRemove(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("jit migrate remove: %w", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("jit migrate remove: %w", err)
	}
	root, err := vaultRootDir()
	if err != nil {
		return fmt.Errorf("jit migrate remove: %w", err)
	}

	plan, err := buildProjectRemovalPlan(root, cwd)
	if err != nil {
		return fmt.Errorf("jit migrate remove: %w", err)
	}
	if len(plan.mounts) == 0 && len(plan.inPlace) == 0 && len(plan.companions) == 0 &&
		len(plan.profileInfos) == 0 && len(plan.ownedGlobal) == 0 && len(plan.backups) == 0 && plan.jitDir == "" {
		fmt.Fprintln(out, "No jit artifacts found in this project, nothing to remove. (Machine-level migrations are reversed with `jit migrate undo`.)")
		return nil
	}

	printProjectRemovalPlan(out, home, plan)

	// Confirm BEFORE auth — declining must never cost a Touch ID prompt
	// for work that's about to be aborted (the ordering every mutating
	// command here uses, GAPS.md #17).
	if !migrateRemoveYes && !confirmPrompt(cmd, fmt.Sprintf(
		"Restore %d file(s) to PLAINTEXT and permanently delete %d vault secret(s) + %d backup(s)? This can't be undone. [y/N] ",
		len(plan.mounts)+len(plan.inPlace)+len(plan.mcpRestores), len(plan.deletePaths), len(plan.backups))) {
		fmt.Fprintln(out, "Aborted. Nothing was changed.")
		return nil
	}

	// Fresh challenge on purpose, even while an agent session is unlocked —
	// this command both puts plaintext back on disk AND permanently deletes
	// vault secrets; neither may ride a cached session another same-user
	// process could be riding (see openVaultFreshAuth).
	v, err := openVaultFreshAuth()
	if err != nil {
		return fmt.Errorf("jit migrate remove: %w", err)
	}
	// ...and the challenge must fire NOW, explicitly — not lazily on first
	// key use. A run with nothing left to restore (files already back via
	// `jit migrate undo` — the common removal sequence) is deletion-only,
	// and Vault.Remove never touches the KeyWrapper, so without this the
	// promised Touch ID approval silently never happened (GAPS.md #60, a
	// real first-run report). Priming here also means a run that DOES
	// restore files won't prompt a second time. Fail loud if the fresh-auth
	// wrapper ever stops supporting an explicit challenge — silently
	// skipping is exactly the bug this exists to prevent.
	presence, ok := v.KeyWrapper.(interface{ RequireUserPresence(string) error })
	if !ok {
		return fmt.Errorf("jit migrate remove: internal error: fresh-auth vault has no explicit user-presence challenge")
	}
	if err := presence.RequireUserPresence("permanently remove this project's secrets from the vault"); err != nil {
		return fmt.Errorf("jit migrate remove: %w", err)
	}

	registryPath := mount.RegistryPath(root)
	agentClient := agent.NewClient(agent.SocketPath(root))
	agentReachable := agentClient.Reachable()

	// Files first, deletions last: no vault secret is destroyed until every
	// file that needs its value is back on disk in plaintext — the same
	// "never destroy the original before its values are safely elsewhere"
	// ordering migrate itself uses, run in reverse.
	for _, e := range plan.mounts {
		if agentReachable {
			if err := agentClient.StopMount(e.MountPath); err != nil {
				return fmt.Errorf("jit migrate remove: stopping the running service's mount %s: %w", e.MountPath, err)
			}
		}
		names, err := migrate.UnmountFile(v, e.ProfilePath, e.MountPath, e.TemplatePath)
		if err != nil {
			return fmt.Errorf("jit migrate remove: %w", err)
		}
		if _, err := mount.RemoveMount(registryPath, e.MountPath); err != nil {
			return fmt.Errorf("jit migrate remove: %w", err)
		}
		fmt.Fprintf(out, "Restored %s (%d variable(s) written back as plaintext).\n", displayPath(home, e.MountPath), len(names))
	}
	for _, p := range plan.inPlace {
		names, err := migrate.RestorePointerFile(v, p)
		if err != nil {
			return fmt.Errorf("jit migrate remove: %w", err)
		}
		fmt.Fprintf(out, "Restored %s (%d variable(s) written back as plaintext).\n", displayPath(home, p), len(names))
	}
	// A project MCP config still launching servers through jit's wrapper
	// gets its plaintext env blocks back BEFORE its profiles and secrets are
	// deleted — the same files-first ordering as the mounts above.
	mcpConfigs := make([]string, 0, len(plan.mcpRestores))
	for cfg := range plan.mcpRestores {
		mcpConfigs = append(mcpConfigs, cfg)
	}
	sort.Strings(mcpConfigs)
	for _, cfg := range mcpConfigs {
		restores, err := migrate.UnwrapMCPConfig(v, cfg, plan.mcpRestores[cfg])
		if err != nil {
			return fmt.Errorf("jit migrate remove: %w", err)
		}
		for _, r := range restores {
			fmt.Fprintf(out, "Restored server %q in %s (%d variable(s) written back as plaintext).\n", r.ServerName, displayPath(home, cfg), len(r.Variables))
		}
	}

	for _, p := range plan.companions {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("jit migrate remove: removing pointer companion %s: %w", p, err)
		}
	}

	// A secret already gone (a manifest referencing something a `jit vault
	// clean`/`rm` deleted earlier) is the desired end state, not a failure
	// worth stranding the removal halfway over.
	for _, sp := range plan.deletePaths {
		if err := v.Remove(sp); err != nil && !errors.Is(err, vault.ErrNotFound) {
			return fmt.Errorf("jit migrate remove: deleting vault secret %s: %w", sp, err)
		}
	}
	for _, rec := range plan.backups {
		if err := v.Remove(rec.VaultPath); err != nil && !errors.Is(err, vault.ErrNotFound) {
			return fmt.Errorf("jit migrate remove: deleting backup %s: %w", rec.VaultPath, err)
		}
	}
	if err := migrate.DropBackupRecords(root, plan.backups); err != nil {
		return fmt.Errorf("jit migrate remove: %w", err)
	}

	// Owned global-store profiles live outside the .jit directory the
	// RemoveAll below covers — their manifest (+ .source sidecar) files are
	// deleted explicitly.
	for _, info := range plan.ownedGlobal {
		if err := migrate.RemoveOwnedProfile(info.Path); err != nil {
			return fmt.Errorf("jit migrate remove: removing profile %s: %w", info.Path, err)
		}
	}

	if plan.jitDir != "" {
		if err := os.RemoveAll(plan.jitDir); err != nil {
			return fmt.Errorf("jit migrate remove: removing %s: %w", plan.jitDir, err)
		}
	}

	fmt.Fprintf(out, "\nRemoved jit from this project: %d file(s) restored to plaintext, %d vault secret(s) and %d backup(s) deleted, %s removed.\n",
		len(plan.mounts)+len(plan.inPlace), len(plan.deletePaths), len(plan.backups), displayPath(home, plan.jitDir))
	if len(plan.keptShared) > 0 {
		fmt.Fprintf(out, "Kept %d vault secret(s) another profile still references: %s\n", len(plan.keptShared), strings.Join(plan.keptShared, ", "))
	}
	return nil
}

// buildProjectRemovalPlan gathers everything under cwd's tree that jit
// migrate ever created, without touching the vault's KeyWrapper — planning
// must never cost an auth prompt.
func buildProjectRemovalPlan(root, cwd string) (projectRemovalPlan, error) {
	plan := projectRemovalPlan{cwd: cwd}

	entries, err := mount.LoadRegistry(mount.RegistryPath(root))
	if err != nil {
		return plan, fmt.Errorf("reading mount registry: %w", err)
	}
	for _, e := range entries {
		if pathWithinDir(cwd, e.MountPath) {
			plan.mounts = append(plan.mounts, e)
		}
	}

	plan.companions, plan.inPlace, err = migrate.DiscoverPointerArtifacts(cwd)
	if err != nil {
		return plan, err
	}

	// The project's own profiles: everything in the project-local store,
	// plus any global-store profile whose .source sidecar names an MCP
	// config file inside this tree — the one kind of global profile that
	// belongs to a single project (it only lives in the global store because
	// an MCP host's subprocess can't do a project-relative lookup). Every
	// other global profile is a machine-level migration, out of a project
	// removal's scope by definition.
	infos, err := profile.ListAll(cwd)
	if err != nil {
		return plan, err
	}
	deleteSet := map[string]bool{}
	ownedPaths := map[string]bool{}
	plan.mcpRestores = map[string]map[string]string{}
	wrappedByConfig := map[string]map[string]bool{}
	for _, info := range infos {
		if info.Scope != profile.ScopeProject {
			owner := migrate.ProfileOwnerConfig(info.Path)
			if owner == "" || !pathWithinDir(cwd, owner) {
				continue
			}
			plan.ownedGlobal = append(plan.ownedGlobal, info)
			ownedPaths[info.Path] = true
			if _, checked := wrappedByConfig[owner]; !checked {
				wrappedByConfig[owner] = migrate.WrappedMCPProfiles(owner)
			}
			if wrappedByConfig[owner][info.Name] {
				if plan.mcpRestores[owner] == nil {
					plan.mcpRestores[owner] = map[string]string{}
				}
				plan.mcpRestores[owner][info.Name] = info.Path
			}
		}
		plan.profileInfos = append(plan.profileInfos, info)
		p, err := profile.LoadFile(info.Path)
		if err != nil {
			return plan, fmt.Errorf("loading profile %s: %w", info.Path, err)
		}
		for _, vaultPath := range p {
			deleteSet[vaultPath] = true
		}
	}

	// Never delete a vault path some OTHER profile still references — a
	// pre-#55 vault (flat root/ namespace) genuinely has cross-project
	// shared paths, and deleting one project's copy would break the other
	// project silently. "Other profiles" = every global-store profile plus
	// every registered mount's profile outside this tree.
	shared := map[string]bool{}
	for _, e := range entries {
		if pathWithinDir(cwd, e.MountPath) {
			continue
		}
		if p, err := profile.LoadFile(e.ProfilePath); err == nil {
			for _, vaultPath := range p {
				shared[vaultPath] = true
			}
		}
	}
	for _, info := range infos {
		if info.Scope == profile.ScopeProject || ownedPaths[info.Path] {
			continue // owned-by-this-project profiles are being deleted, not "other"
		}
		if p, err := profile.LoadFile(info.Path); err == nil {
			for _, vaultPath := range p {
				shared[vaultPath] = true
			}
		}
	}
	for vaultPath := range deleteSet {
		if shared[vaultPath] {
			plan.keptShared = append(plan.keptShared, vaultPath)
			continue
		}
		plan.deletePaths = append(plan.deletePaths, vaultPath)
	}
	sort.Strings(plan.deletePaths)
	sort.Strings(plan.keptShared)

	recs, err := migrate.LoadBackupRecords(root)
	if err != nil {
		return plan, err
	}
	for _, rec := range recs {
		if pathWithinDir(cwd, rec.OriginalPath) {
			plan.backups = append(plan.backups, rec)
		}
	}

	jitDir := filepath.Join(cwd, ".jit")
	if info, err := os.Stat(jitDir); err == nil && info.IsDir() {
		plan.jitDir = jitDir
	}
	return plan, nil
}

// pathWithinDir reports whether p is dir itself or lives under dir's tree.
func pathWithinDir(dir, p string) bool {
	rel, err := filepath.Rel(dir, p)
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..")
}

// printProjectRemovalPlan renders the plan in the package's report shape:
// title → grouped sections (only non-empty ones) → the confirmation prompt
// right after serves as the closing line.
func printProjectRemovalPlan(out interface{ Write([]byte) (int, error) }, home string, plan projectRemovalPlan) {
	fmt.Fprintf(out, "Removing jit from %s:\n\n", displayPath(home, plan.cwd))
	if n := len(plan.mounts); n > 0 {
		printMigrateResultCategory(out, "Live mounts -> plain files again (current vault values)", n)
		for _, e := range plan.mounts {
			fmt.Fprintf(out, "  • %s\n", displayPath(home, e.MountPath))
		}
		fmt.Fprintln(out)
	}
	if n := len(plan.inPlace); n > 0 {
		printMigrateResultCategory(out, "Pointer files -> plain files again (current vault values)", n)
		for _, p := range plan.inPlace {
			fmt.Fprintf(out, "  • %s\n", displayPath(home, p))
		}
		fmt.Fprintln(out)
	}
	if n := len(plan.mcpRestores); n > 0 {
		printMigrateResultCategory(out, "MCP config server(s) -> plaintext env again (current vault values)", n)
		cfgs := make([]string, 0, n)
		for cfg := range plan.mcpRestores {
			cfgs = append(cfgs, cfg)
		}
		sort.Strings(cfgs)
		for _, cfg := range cfgs {
			names := make([]string, 0, len(plan.mcpRestores[cfg]))
			for name := range plan.mcpRestores[cfg] {
				names = append(names, name)
			}
			sort.Strings(names)
			fmt.Fprintf(out, "  • %s (profile %s)\n", displayPath(home, cfg), strings.Join(names, ", "))
		}
		fmt.Fprintln(out)
	}
	if n := len(plan.profileInfos); n > 0 {
		printMigrateResultCategory(out, "Profiles + their vault secrets deleted", n)
		for _, info := range plan.profileInfos {
			fmt.Fprintf(out, "  • %q (%s)\n", info.Name, displayPath(home, info.Path))
		}
		fmt.Fprintln(out)
	}
	if n := len(plan.keptShared); n > 0 {
		printMigrateResultCategory(out, "Vault secrets KEPT (another profile still references them)", n)
		for _, p := range plan.keptShared {
			fmt.Fprintf(out, "  • %s\n", p)
		}
		fmt.Fprintln(out)
	}
	if n := len(plan.backups); n > 0 {
		printMigrateResultCategory(out, "Encrypted file backups deleted (jit migrate undo loses these)", n)
		for _, rec := range plan.backups {
			fmt.Fprintf(out, "  • %s\n", rec.VaultPath)
		}
		fmt.Fprintln(out)
	}
	if plan.jitDir != "" {
		fmt.Fprintf(out, "The %s directory is removed entirely.\n", displayPath(home, plan.jitDir))
	}
}

func init() {
	migrateRemoveCmd.Flags().BoolVarP(&migrateRemoveYes, "yes", "y", false, "skip the confirmation prompt and remove immediately")
	migrateCmd.AddCommand(migrateRemoveCmd)
}
