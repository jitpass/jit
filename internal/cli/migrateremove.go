// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
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
// out of a project COMPLETELY — files back to plaintext (current vault
// values, matching unmount's semantics rather than undo's
// restore-the-backup), then the project's profiles, their vault secrets,
// its encrypted file backups, and the .jit/ directory all deleted. Both
// plaintext-restoring AND destructive, so it takes the strictest gate this
// package has: plan → [y/N] confirm → openVaultFreshAuth (always its own
// Touch ID/passcode challenge, never a cached agent session — GAPS.md #50's
// class). Like jit migrate itself, you must name the project to act on: a
// folder is that project, a file resolves up to the project that owns it.
var migrateRemoveCmd = &cobra.Command{
	Use:   "remove <file-or-dir>...",
	Short: "Remove jit from a project completely (restore plaintext, delete its secrets)",
	Long: "jit migrate remove takes jit back out of a project you name: every live\n" +
		"mount and pointer file under that project tree becomes a plain file\n" +
		"again, and any server in the project's own mcp.json/.mcp.json launching\n" +
		"through jit gets its plaintext env block back (all written from the\n" +
		"CURRENT vault values, so edits made with `jit vault set` since migration\n" +
		"are kept), and then the project's profile manifests, including the ones\n" +
		"created for this project's MCP servers, the vault secrets they\n" +
		"reference, the project's encrypted file backups, and the .jit/ directory\n" +
		"itself are all deleted.\n\n" +
		"You must name the project to remove; a bare `jit migrate remove` with no\n" +
		"path does nothing. Name a FOLDER to remove that project, or name any\n" +
		"FILE inside a project (e.g. its .env) and jit resolves up to the .jit/\n" +
		"project that owns it and removes the whole thing. Name several to remove\n" +
		"several, each confirmed on its own.\n\n" +
		"Naming a LOOSE secret file that has no project of its own (a bare\n" +
		"token.txt migrated at home level) removes just that one file's footprint:\n" +
		"its plaintext back on disk, then its dedicated profile, vault secret(s),\n" +
		"and backup deleted. It never escalates to the whole home store the file\n" +
		"sits above, and naming your home directory itself is refused for that\n" +
		"same reason.\n\n" +
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
	Example: "  jit migrate remove ~/proj\n" +
		"  jit migrate remove ~/proj/.env   # removes the whole ~/proj project\n" +
		"  jit migrate remove ~/token.txt   # removes just that loose secret",
	Args:         requirePaths("jit migrate remove"),
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
	// orphanSecrets are the subset of deletePaths that NO profile references —
	// swept into the removal purely because their birth-time Origin falls
	// inside this project tree. Tracked apart from the profile-derived paths
	// because they have no profile to be listed under, and they are exactly the
	// entries a path-only `jit migrate undo`/`remove` used to strand in the
	// vault forever.
	orphanSecrets []string
	backups       []migrate.BackupRecord
	// rewritten are files this project's migration REWROTE IN PLACE rather
	// than turning into a mount, a pointer file, or an MCP wrapper launch —
	// today that means terraform.tfvars, whose secret assignments are lifted
	// out and replaced with a comment naming the profile that now holds them.
	//
	// They are restored from their encrypted pre-migration backups, the same
	// way `jit migrate undo` reverses them. Without this they were reversed by
	// NOTHING: removal deleted the vault secrets AND the backups while leaving
	// the stripped file on disk pointing at a profile that no longer existed,
	// so `jit migrate remove` on a project with migrated tfvars destroyed
	// those values outright. The confirm prompt even said "Restore 0 file(s)"
	// while deleting the only two copies that existed.
	//
	// Matched by backup record rather than by file type on purpose: any future
	// rewrite-in-place category is covered the moment it takes a backup, which
	// every migration already does.
	rewritten []migrate.BackupRecord
	// jitDirs are every .jit/ store this removal deletes: the named
	// project's own first, then any NESTED project root under its tree,
	// deepest-last. Nested roots exist because migrate gives each migrated
	// .env its OWN project directory (see migrate.go's envProfilesRoot), so
	// `proj/sub/.env` builds a second store at `proj/sub/.jit` — which a
	// single `filepath.Join(cwd, ".jit")` silently left behind, stranding a
	// profile manifest that pointed at vault secrets this same removal had
	// just deleted. `jit run` in that subdirectory then failed with a bare
	// "secret not found" and nothing to act on.
	jitDirs []string
}

func runMigrateRemove(cmd *cobra.Command, args []string) error {
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

	targets, err := resolveRemovalTargets(cwd, home, args)
	if err != nil {
		return fmt.Errorf("jit migrate remove: %w", err)
	}
	// Each named target is planned, confirmed, and (freshly) authed on its
	// own — one removal is a distinct destructive act, and a combined confirm
	// would let a single [y/N] delete several at once. Deliberately sequential
	// rather than aggregated for that reason. A loose secret file (a bare
	// token.txt migrated at home level, no project of its own) is removed at
	// file granularity; everything else is a whole project.
	for _, t := range targets {
		if t.loose {
			if err := removeOneLooseFile(cmd, root, home, t.path); err != nil {
				return err
			}
			continue
		}
		if err := removeOneProject(cmd, root, home, t.path); err != nil {
			return err
		}
	}
	return nil
}

// removalTarget is one thing `jit migrate remove` will act on: either a
// project root (loose=false, path is the directory holding the .jit/ store) or
// a single loose secret file (loose=true, path is the file itself). The
// distinction exists because a loose secret migrated at home level has no
// project of its own — its only .jit/ ancestor is the home-level GLOBAL
// profile store, which is emphatically not "a project" to tear down.
type removalTarget struct {
	path  string
	loose bool
}

// resolveRemovalTargets classifies each named file/dir into a removalTarget,
// deduped in first-seen order. A directory is a project root as named. A file
// resolves to the nearest ancestor holding a .jit/ store, so naming any file
// in a project (its .env, say) removes that whole project — UNLESS that
// ancestor is the home directory itself: the home-level .jit/ is the GLOBAL
// profile store (shell/AWS/kube/MCP/loose-file migrations all live there), not
// a project, so resolving a home-level file to "the ~ project" would propose
// deleting every global migration at once. A bare token migrated at home is
// exactly that case; it becomes a single-file (loose) removal instead. Naming
// the home directory as a DIRECTORY is refused outright for the same reason. A
// target that doesn't exist or is a symlink is a loud error, never a silent
// no-op.
func resolveRemovalTargets(cwd, home string, targets []string) ([]removalTarget, error) {
	seen := map[string]bool{}
	var out []removalTarget
	add := func(t removalTarget) {
		key := t.path
		if t.loose {
			key = "loose\x00" + key
		}
		if !seen[key] {
			seen[key] = true
			out = append(out, t)
		}
	}
	for _, target := range targets {
		abs := expandTilde(target, home)
		if !filepath.IsAbs(abs) {
			abs = filepath.Join(cwd, abs)
		}
		abs = filepath.Clean(abs)
		info, err := os.Lstat(abs)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, fmt.Errorf("%s does not exist", displayPath(home, abs))
			}
			return nil, fmt.Errorf("%s: %w", displayPath(home, abs), err)
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return nil, fmt.Errorf("%s is a symlink; name its target directly", displayPath(home, abs))
		}
		if info.IsDir() {
			if abs == home {
				return nil, fmt.Errorf("%s is your home directory, not a jit project; its .jit/ is the global profile store — name a specific project folder, or name the migrated file to remove just that", displayPath(home, abs))
			}
			add(removalTarget{path: abs})
			continue
		}
		// A file inside a real project (a .jit/ store in a SUBdirectory) names
		// that whole project, as documented. But a file whose only .jit/
		// ancestor is the home global store (or none at all) is a loose secret
		// with no project of its own — remove just that file's footprint.
		if projectRoot, ok := findProjectRoot(filepath.Dir(abs)); ok && projectRoot != home {
			add(removalTarget{path: projectRoot})
			continue
		}
		add(removalTarget{path: abs, loose: true})
	}
	return out, nil
}

// findProjectRoot walks up from start looking for the directory that holds a
// .jit/ store — the project root jit migrate remove deletes. Stops at the
// filesystem root.
func findProjectRoot(start string) (string, bool) {
	dir := start
	for {
		if info, err := os.Stat(filepath.Join(dir, ".jit")); err == nil && info.IsDir() {
			return dir, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

// removeOneProject plans, confirms, freshly authenticates, and applies the
// removal of a single project rooted at projectRoot.
func removeOneProject(cmd *cobra.Command, root, home, projectRoot string) error {
	out := cmd.OutOrStdout()

	// A read-only vault for planning only: buildProjectRemovalPlan reads secret
	// metadata (Origin) to find orphaned secrets, which is envelope-plaintext
	// and never touches the KeyWrapper, so planning stays auth-free. The
	// destructive pass below opens its OWN fresh-auth vault.
	rv, err := openVaultReadOnly()
	if err != nil {
		return fmt.Errorf("jit migrate remove: %w", err)
	}
	plan, err := buildProjectRemovalPlan(root, home, projectRoot, rv)
	if err != nil {
		return fmt.Errorf("jit migrate remove: %w", err)
	}
	if len(plan.mounts) == 0 && len(plan.inPlace) == 0 && len(plan.companions) == 0 &&
		len(plan.profileInfos) == 0 && len(plan.ownedGlobal) == 0 && len(plan.backups) == 0 &&
		len(plan.deletePaths) == 0 && len(plan.jitDirs) == 0 {
		fmt.Fprint(out, hlCmds(fmt.Sprintf("No jit artifacts found in %s, nothing to remove. (Machine-level migrations are reversed with `jit migrate undo`.)\n", displayPath(home, projectRoot))))
		return nil
	}

	printProjectRemovalPlan(out, home, plan)

	// Confirm BEFORE auth — declining must never cost a Touch ID prompt
	// for work that's about to be aborted (the ordering every mutating
	// command here uses, GAPS.md #17).
	if !migrateRemoveYes && !confirmPrompt(cmd, fmt.Sprintf(
		"Restore %s to PLAINTEXT and permanently delete %s + %s? This can't be undone. [y/N] ",
		countWord(len(plan.mounts)+len(plan.inPlace)+len(plan.mcpRestores)+len(plan.rewritten), "file", "files"),
		countWord(len(plan.deletePaths), "vault secret", "vault secrets"),
		countWord(len(plan.backups), "backup", "backups"))) {
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
	// restore files won't prompt a second time. requireFreshUserPresence
	// also records the fresh auth into this invocation's audit entry.
	if err := requireFreshUserPresence(v, "permanently remove this project's secrets from the vault"); err != nil {
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
		fmt.Fprintf(out, "Restored %s (%s written back as plaintext).\n", displayPath(home, e.MountPath), countWord(len(names), "variable", "variables"))
	}
	for _, p := range plan.inPlace {
		names, err := migrate.RestorePointerFile(v, p)
		if err != nil {
			return fmt.Errorf("jit migrate remove: %w", err)
		}
		fmt.Fprintf(out, "Restored %s (%s written back as plaintext).\n", displayPath(home, p), countWord(len(names), "variable", "variables"))
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
			fmt.Fprintf(out, "Restored server %q in %s (%s written back as plaintext).\n", r.ServerName, displayPath(home, cfg), countWord(len(r.Variables), "variable", "variables"))
		}
	}

	// Files this migration rewrote in place (tfvars today) come back from
	// their encrypted backups — still before any deletion, same files-first
	// ordering. Nothing else reverses these; without it the removal deleted
	// their vault secrets and their backups and left the stripped file
	// behind, which is straightforward data loss.
	for _, rec := range plan.rewritten {
		same, err := backupMatchesDisk(v, rec)
		if err != nil {
			return fmt.Errorf("jit migrate remove: reading backup of %s: %w", displayPath(home, rec.OriginalPath), err)
		}
		if same {
			// Already reversed (`jit migrate undo` first, then remove).
			// Rewriting identical bytes would only add an undo-index entry.
			continue
		}
		if err := migrate.RestoreFromBackup(v, rec); err != nil {
			return fmt.Errorf("jit migrate remove: restoring %s: %w", displayPath(home, rec.OriginalPath), err)
		}
		fmt.Fprintf(out, "Restored %s from its pre-migration backup (secret values written back as plaintext).\n", displayPath(home, rec.OriginalPath))
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
	// plan.backups was captured before anything ran, so it can't include a
	// record this very removal created: RestoreFromBackup snapshots whatever
	// it is about to overwrite, which means every rewritten-in-place file
	// leaves a fresh entry behind. Harmless in content (it's the migrated,
	// secret-free state) but it outlives the project it belongs to, leaving
	// `jit migrate undo` offering a path this command just finished erasing.
	// Re-read and sweep whatever is still indexed under the tree.
	late, err := migrate.LoadBackupRecords(root)
	if err != nil {
		return fmt.Errorf("jit migrate remove: %w", err)
	}
	var stragglers []migrate.BackupRecord
	for _, rec := range late {
		if pathWithinDir(projectRoot, rec.OriginalPath) {
			stragglers = append(stragglers, rec)
		}
	}
	if len(stragglers) > 0 {
		for _, rec := range stragglers {
			if rec.VaultPath == "" {
				continue
			}
			if err := v.Remove(rec.VaultPath); err != nil && !errors.Is(err, vault.ErrNotFound) {
				return fmt.Errorf("jit migrate remove: deleting backup %s: %w", rec.VaultPath, err)
			}
		}
		if err := migrate.DropBackupRecords(root, stragglers); err != nil {
			return fmt.Errorf("jit migrate remove: %w", err)
		}
	}

	// Owned global-store profiles live outside the .jit directory the
	// RemoveAll below covers — their manifest (+ .source sidecar) files are
	// deleted explicitly.
	for _, info := range plan.ownedGlobal {
		if err := migrate.RemoveOwnedProfile(info.Path); err != nil {
			return fmt.Errorf("jit migrate remove: removing profile %s: %w", info.Path, err)
		}
	}

	for _, dir := range plan.jitDirs {
		if err := os.RemoveAll(dir); err != nil {
			return fmt.Errorf("jit migrate remove: removing %s: %w", dir, err)
		}
	}

	fmt.Fprintf(out, "\nRemoved jit from this project: %s restored to plaintext, %s and %s deleted, %s removed.\n",
		countWord(len(plan.mounts)+len(plan.inPlace)+len(plan.mcpRestores)+len(plan.rewritten), "file", "files"),
		countWord(len(plan.deletePaths), "vault secret", "vault secrets"),
		countWord(len(plan.backups), "backup", "backups"), displayJitDirs(home, plan.jitDirs))
	if len(plan.keptShared) > 0 {
		fmt.Fprintf(out, "Kept %s another profile still references: %s\n", countWord(len(plan.keptShared), "vault secret", "vault secrets"), strings.Join(plan.keptShared, ", "))
	}
	return nil
}

// looseFileRemovalPlan is everything removeOneLooseFile decided to do for a
// single loose secret file, gathered before anything is confirmed, authed, or
// mutated. A loose secret has a self-contained footprint — its own dedicated
// profile in the global store, its own vault secrets (class loose_file, origin
// pointing back at this file), its own backups — so removal is scoped to
// exactly that, never the whole home store the file happens to sit above.
type looseFileRemovalPlan struct {
	file       string
	isMount    bool        // a live --mount FIFO: unmount it back to plaintext
	mountEntry mount.Entry // valid when isMount
	isPointer  bool        // a neutralized pointer file: restore its backed-up bytes
	// restoreBackup is the pre-migration backup whose exact bytes go back to
	// disk for the pointer (neutralize) case — a loose file's pointer is in
	// KEY=jit://vault/… form, so reconstructing from vault values would change
	// a bare token.txt into a dotenv file; the backup is the faithful original.
	restoreBackup *migrate.BackupRecord
	profilePaths  []string // this file's dedicated profile manifest(s), deleted
	deletePaths   []string // vault secret paths deleted
	keptShared    []string // vault paths kept because another profile references them
	backups       []migrate.BackupRecord
}

// removeOneLooseFile plans, confirms, freshly authenticates, and applies the
// removal of a single loose secret file: its plaintext back on disk, then its
// dedicated profile, vault secrets, and backups all deleted. The strict gate
// mirrors removeOneProject's — plan → [y/N] → openVaultFreshAuth (its own
// Touch ID/passcode, never a cached agent session) — because this both writes
// plaintext to disk AND permanently deletes vault secrets.
func removeOneLooseFile(cmd *cobra.Command, root, home, file string) error {
	out := cmd.OutOrStdout()

	// Read-only vault for planning: buildLooseFileRemovalPlan reads secret
	// metadata (Origin/Class) only, which is envelope-plaintext and never
	// touches the KeyWrapper, so planning stays auth-free. The destructive
	// pass opens its OWN fresh-auth vault.
	rv, err := openVaultReadOnly()
	if err != nil {
		return fmt.Errorf("jit migrate remove: %w", err)
	}
	plan, err := buildLooseFileRemovalPlan(root, home, file, rv)
	if err != nil {
		return fmt.Errorf("jit migrate remove: %w", err)
	}
	if !plan.isMount && !plan.isPointer && len(plan.profilePaths) == 0 &&
		len(plan.deletePaths) == 0 && len(plan.backups) == 0 {
		fmt.Fprintf(out, "No jit artifacts found for %s, nothing to remove.\n", displayPath(home, file))
		return nil
	}

	printLooseFileRemovalPlan(out, home, plan)

	restoreCount := 0
	if plan.isMount || plan.isPointer {
		restoreCount = 1
	}
	// Confirm BEFORE auth — declining must never cost a Touch ID prompt for
	// work about to be aborted (GAPS.md #17's ordering).
	if !migrateRemoveYes && !confirmPrompt(cmd, fmt.Sprintf(
		"Restore %s to PLAINTEXT and permanently delete %s + %s? This can't be undone. [y/N] ",
		countWord(restoreCount, "file", "files"),
		countWord(len(plan.deletePaths), "vault secret", "vault secrets"),
		countWord(len(plan.backups), "backup", "backups"))) {
		fmt.Fprintln(out, "Aborted. Nothing was changed.")
		return nil
	}

	v, err := openVaultFreshAuth()
	if err != nil {
		return fmt.Errorf("jit migrate remove: %w", err)
	}
	// Force the fresh challenge NOW and audit it: a run whose file is already
	// plaintext (undo already ran) is deletion-only, and Vault.Remove never
	// touches the KeyWrapper, so without this the promised Touch ID approval
	// would silently never happen (the same GAPS.md #60 class removeOneProject
	// guards against). Priming here also means a run that DOES restore prompts
	// exactly once.
	if err := requireFreshUserPresence(v, "permanently remove this migrated file's secrets from the vault"); err != nil {
		return fmt.Errorf("jit migrate remove: %w", err)
	}

	registryPath := mount.RegistryPath(root)
	agentClient := agent.NewClient(agent.SocketPath(root))
	agentReachable := agentClient.Reachable()

	// File first: its plaintext is back before any secret it needs is deleted
	// (migrate's ordering, run in reverse).
	if plan.isMount {
		e := plan.mountEntry
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
		if e.TemplatePath != "" {
			if err := os.Remove(e.TemplatePath); err != nil && !os.IsNotExist(err) {
				fmt.Fprintf(out, "  warning: removing template %s: %v\n", displayPath(home, e.TemplatePath), err)
			}
		}
		fmt.Fprintf(out, "Restored %s (%s written back as plaintext).\n", displayPath(home, e.MountPath), countWord(len(names), "variable", "variables"))
	} else if plan.isPointer {
		if plan.restoreBackup != nil {
			if err := migrate.RestoreFromBackup(v, *plan.restoreBackup); err != nil {
				return fmt.Errorf("jit migrate remove: %w", err)
			}
			fmt.Fprintf(out, "Restored %s from its pre-migration backup.\n", displayPath(home, plan.file))
		} else {
			// No indexed backup (a pre-index migration): fall back to
			// reconstructing from the pointer's vault references. The values
			// land on disk, though as KEY=value lines rather than the original
			// layout — better than deleting the secrets out from under a
			// pointer that would then dangle.
			names, err := migrate.RestorePointerFile(v, plan.file)
			if err != nil {
				return fmt.Errorf("jit migrate remove: %w", err)
			}
			fmt.Fprintf(out, "Restored %s (%s, reconstructed from the vault — no backup was indexed).\n", displayPath(home, plan.file), countWord(len(names), "variable", "variables"))
		}
	}

	// A secret already gone is the desired end state, not a failure worth
	// stranding the removal halfway.
	for _, sp := range plan.deletePaths {
		if err := v.Remove(sp); err != nil && !errors.Is(err, vault.ErrNotFound) {
			return fmt.Errorf("jit migrate remove: deleting vault secret %s: %w", sp, err)
		}
	}

	// Re-load the backup index AFTER the restore: RestoreFromBackup snapshots
	// whatever occupied the path before overwriting it (its "an undo is itself
	// undoable" property), so a fresh record may have appeared since planning.
	// Delete every backup for this file — the planned ones plus any snapshot —
	// so a removed loose file leaves nothing behind.
	recs, err := migrate.LoadBackupRecords(root)
	if err != nil {
		return fmt.Errorf("jit migrate remove: %w", err)
	}
	var toDrop []migrate.BackupRecord
	for _, rec := range recs {
		if rec.OriginalPath == plan.file {
			toDrop = append(toDrop, rec)
			if rec.VaultPath == "" {
				continue
			}
			if err := v.Remove(rec.VaultPath); err != nil && !errors.Is(err, vault.ErrNotFound) {
				return fmt.Errorf("jit migrate remove: deleting backup %s: %w", rec.VaultPath, err)
			}
		}
	}
	if err := migrate.DropBackupRecords(root, toDrop); err != nil {
		return fmt.Errorf("jit migrate remove: %w", err)
	}

	// Profiles last: nothing above needed them once the file's plaintext is
	// back. RemoveOwnedProfile clears the manifest and any .source sidecar,
	// idempotent on an already-missing file.
	for _, pp := range plan.profilePaths {
		if err := migrate.RemoveOwnedProfile(pp); err != nil {
			return fmt.Errorf("jit migrate remove: removing profile %s: %w", pp, err)
		}
	}

	fmt.Fprintf(out, "\nRemoved jit from %s: %s restored to plaintext, %s, %s, and %s deleted.\n",
		displayPath(home, plan.file),
		countWord(restoreCount, "file", "files"),
		countWord(len(plan.deletePaths), "vault secret", "vault secrets"),
		countWord(len(plan.profilePaths), "profile", "profiles"),
		countWord(len(toDrop), "backup", "backups"))
	if len(plan.keptShared) > 0 {
		fmt.Fprintf(out, "Kept %s another profile still references: %s\n", countWord(len(plan.keptShared), "vault secret", "vault secrets"), strings.Join(plan.keptShared, ", "))
	}
	return nil
}

// buildLooseFileRemovalPlan gathers a loose secret file's whole footprint
// without touching the vault's KeyWrapper — planning must never cost an auth
// prompt (rv reads envelope-plaintext metadata only).
func buildLooseFileRemovalPlan(root, home, file string, rv *vault.Vault) (looseFileRemovalPlan, error) {
	plan := looseFileRemovalPlan{file: file}

	entries, err := mount.LoadRegistry(mount.RegistryPath(root))
	if err != nil {
		return plan, fmt.Errorf("reading mount registry: %w", err)
	}
	for _, e := range entries {
		if e.MountPath == file {
			plan.isMount = true
			plan.mountEntry = e
			break
		}
	}
	if !plan.isMount && migrate.IsPointerFile(file) {
		plan.isPointer = true
	}

	// The secrets this file's migration created: every vault entry whose
	// birth-time Origin resolves back to this exact file. A loose secret gets
	// its own dedicated profile, so this Origin link ties the file to its vault
	// entries even after any profile is gone.
	originSecrets := map[string]bool{}
	if rv != nil {
		paths, err := rv.List()
		if err != nil {
			return plan, fmt.Errorf("listing vault for origin match: %w", err)
		}
		for _, p := range paths {
			if vault.IsBackupPath(p) {
				continue
			}
			info, err := rv.Info(p)
			if err != nil {
				return plan, fmt.Errorf("reading secret metadata for %s: %w", p, err)
			}
			if info.Origin != "" && expandTilde(info.Origin, home) == file {
				originSecrets[p] = true
			}
		}
	}

	// The profile(s) dedicated to this file: any profile referencing one of the
	// origin-matched secrets, plus the mount's own profile. Their full
	// reference sets join the delete set — a loose profile belongs to one file.
	infos, err := profile.ListAll(home)
	if err != nil {
		return plan, err
	}
	deleteSet := map[string]bool{}
	for p := range originSecrets {
		deleteSet[p] = true
	}
	ourProfiles := map[string]bool{}
	for _, info := range infos {
		refs, err := profile.LoadFile(info.Path)
		if err != nil {
			return plan, fmt.Errorf("loading profile %s: %w", info.Path, err)
		}
		owns := plan.isMount && info.Path == plan.mountEntry.ProfilePath
		if !owns {
			for _, vp := range refs {
				if originSecrets[vp] {
					owns = true
					break
				}
			}
		}
		if !owns {
			continue
		}
		ourProfiles[info.Path] = true
		plan.profilePaths = append(plan.profilePaths, info.Path)
		for _, vp := range refs {
			deleteSet[vp] = true
		}
	}
	sort.Strings(plan.profilePaths)

	// Never delete a secret another profile or another mount still references
	// (a pre-namespaced vault can genuinely share paths). "Other" = every
	// profile NOT marked as this file's, and every mount but this one.
	shared := map[string]bool{}
	for _, info := range infos {
		if ourProfiles[info.Path] {
			continue
		}
		if refs, err := profile.LoadFile(info.Path); err == nil {
			for _, vp := range refs {
				shared[vp] = true
			}
		}
	}
	for _, e := range entries {
		if e.MountPath == file {
			continue
		}
		if refs, err := profile.LoadFile(e.ProfilePath); err == nil {
			for _, vp := range refs {
				shared[vp] = true
			}
		}
	}
	for vp := range deleteSet {
		if shared[vp] {
			plan.keptShared = append(plan.keptShared, vp)
			continue
		}
		plan.deletePaths = append(plan.deletePaths, vp)
	}
	sort.Strings(plan.deletePaths)
	sort.Strings(plan.keptShared)

	recs, err := migrate.LoadBackupRecords(root)
	if err != nil {
		return plan, err
	}
	for _, rec := range recs {
		if rec.OriginalPath == file {
			plan.backups = append(plan.backups, rec)
		}
	}
	// The faithful bytes to put back for a pointer restore: the newest
	// non-created backup (LatestBackups picks max-timestamp per path — the
	// content captured just before the migration that left today's pointer).
	if plan.isPointer {
		for _, rec := range migrate.LatestBackups(plan.backups) {
			if rec.OriginalPath == file && !rec.RemoveOnRestore {
				r := rec
				plan.restoreBackup = &r
			}
		}
	}
	return plan, nil
}

// printLooseFileRemovalPlan renders a loose file's removal plan in the
// package's report shape: title → grouped non-empty sections → the
// confirmation prompt right after serves as the closing line.
func printLooseFileRemovalPlan(out interface{ Write([]byte) (int, error) }, home string, plan looseFileRemovalPlan) {
	fmt.Fprintf(out, "Removing jit from %s:\n\n", displayPath(home, plan.file))
	switch {
	case plan.isMount:
		printMigrateResultCategory(out, "Live mount -> plain file again (current vault values)", 1)
		fmt.Fprintf(out, "  "+glyphBullet+" %s\n\n", displayPath(home, plan.file))
	case plan.isPointer:
		printMigrateResultCategory(out, "Pointer file -> plain file again (pre-migration backup)", 1)
		fmt.Fprintf(out, "  "+glyphBullet+" %s\n\n", displayPath(home, plan.file))
	}
	if n := len(plan.profilePaths); n > 0 {
		printMigrateResultCategory(out, pluralWord(n, "Profile + its", "Profiles + their")+" vault secrets deleted", n)
		for _, p := range plan.profilePaths {
			fmt.Fprintf(out, "  "+glyphBullet+" %s\n", displayPath(home, p))
		}
		fmt.Fprintln(out)
	}
	if n := len(plan.deletePaths); n > 0 {
		printMigrateResultCategory(out, "Vault secrets deleted", n)
		for _, p := range plan.deletePaths {
			fmt.Fprintf(out, "  "+glyphBullet+" %s\n", p)
		}
		fmt.Fprintln(out)
	}
	if n := len(plan.keptShared); n > 0 {
		printMigrateResultCategory(out, "Vault secrets KEPT (another profile still references them)", n)
		for _, p := range plan.keptShared {
			fmt.Fprintf(out, "  "+glyphBullet+" %s\n", p)
		}
		fmt.Fprintln(out)
	}
	if n := len(plan.backups); n > 0 {
		printMigrateResultCategory(out, "Encrypted file backups deleted", n)
		for _, rec := range plan.backups {
			fmt.Fprintf(out, "  "+glyphBullet+" %s\n", rec.VaultPath)
		}
		fmt.Fprintln(out)
	}
}

// buildProjectRemovalPlan gathers everything under cwd's tree that jit
// migrate ever created, without touching the vault's KeyWrapper — planning
// must never cost an auth prompt.
func buildProjectRemovalPlan(root, home, cwd string, rv *vault.Vault) (projectRemovalPlan, error) {
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
	// ListAll only sees cwd's own store (plus the global one). A nested
	// project root's profiles are just as much part of this project — their
	// secrets already get swept by the Origin pass below, so without this
	// their manifests would survive pointing at deleted vault entries.
	nestedRoots, err := discoverNestedProjectRoots(cwd)
	if err != nil {
		return plan, err
	}
	for _, nested := range nestedRoots {
		names, err := profile.ListNames(nested)
		if err != nil {
			return plan, err
		}
		for _, name := range names {
			path, err := profile.Path(nested, name)
			if err != nil {
				return plan, err
			}
			infos = append(infos, profile.Info{Name: name, Scope: profile.ScopeProject, Path: path})
		}
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

	// Snapshot the profile-derived set before the Origin sweep widens it, so
	// the sweep's additions can be reported as orphans (nothing names them).
	profileDerived := make(map[string]bool, len(deleteSet))
	for p := range deleteSet {
		profileDerived[p] = true
	}

	// A path-only `jit migrate undo`/`remove` reverses a project's files and
	// backups, but the vault secrets a migration created can outlive every
	// profile that ever named them (a project's .jit/ profiles deleted, or a
	// profile that was never persisted for this source). Those secrets are
	// orphaned — invisible to the profile walk above — so a removal trusting
	// profiles alone strands them in the vault forever (a real dogfood run left
	// twelve custom_scripts-descope/* secrets behind after undo+remove). Each
	// secret's birth-time Origin is the surviving link from this project's
	// files back to its vault entries, so sweep by it too: any secret whose
	// normalized Origin resolves inside cwd joins the delete set. Origin is
	// best-effort and allowed to go stale, so this only ever ADDS candidates;
	// the shared[] guard below still spares anything another profile references,
	// and Info reads envelope plaintext only (no key, no auth prompt), so
	// planning stays auth-free.
	if rv != nil {
		paths, err := rv.List()
		if err != nil {
			return plan, fmt.Errorf("listing vault for origin sweep: %w", err)
		}
		for _, p := range paths {
			// _backups/ entries are raw file snapshots handled by their own
			// records below, never project secrets — skip them.
			if deleteSet[p] || vault.IsBackupPath(p) {
				continue
			}
			info, err := rv.Info(p)
			if err != nil {
				return plan, fmt.Errorf("reading secret metadata for %s: %w", p, err)
			}
			if info.Origin == "" {
				continue
			}
			if pathWithinDir(cwd, expandTilde(info.Origin, home)) {
				deleteSet[p] = true
			}
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
		if !profileDerived[vaultPath] {
			plan.orphanSecrets = append(plan.orphanSecrets, vaultPath)
		}
	}
	sort.Strings(plan.deletePaths)
	sort.Strings(plan.keptShared)
	sort.Strings(plan.orphanSecrets)

	recs, err := migrate.LoadBackupRecords(root)
	if err != nil {
		return plan, err
	}
	for _, rec := range recs {
		if pathWithinDir(cwd, rec.OriginalPath) {
			plan.backups = append(plan.backups, rec)
		}
	}
	plan.rewritten = rewrittenInPlace(plan)

	if info, err := os.Stat(filepath.Join(cwd, ".jit")); err == nil && info.IsDir() {
		plan.jitDirs = append(plan.jitDirs, filepath.Join(cwd, ".jit"))
	}
	for _, nested := range nestedRoots {
		plan.jitDirs = append(plan.jitDirs, filepath.Join(nested, ".jit"))
	}
	return plan, nil
}

// backupMatchesDisk reports whether rec's backed-up bytes are already what
// sits at rec.OriginalPath — i.e. the file needs no reversing. A missing file
// is not a match: there is something to put back.
func backupMatchesDisk(v *vault.Vault, rec migrate.BackupRecord) (bool, error) {
	want, err := v.Get(rec.VaultPath)
	if err != nil {
		if errors.Is(err, vault.ErrNotFound) {
			// No bytes to compare against and none to restore; treat as
			// "nothing to do" rather than failing the whole removal.
			return true, nil
		}
		return false, err
	}
	got, err := os.ReadFile(rec.OriginalPath) // #nosec G304 -- path from jit's own undo index, validated by RestoreFromBackup
	if err != nil {
		return false, nil
	}
	return bytes.Equal(got, want), nil
}

// rewrittenInPlace picks the backed-up project files that no other restore
// path in this plan covers — see projectRemovalPlan.rewritten. A file counts
// only when all of these hold:
//
//   - it has a real backup (RemoveOnRestore records describe a file migration
//     CREATED, which removal has no business resurrecting);
//   - it isn't a mount, a pointer file, an MCP config, or a .pointers
//     companion, each of which has its own, better reversal that writes
//     CURRENT vault values rather than pre-migration ones;
//   - it still exists as a regular file, so there is something to replace.
//
// Whether the file still NEEDS reversing can't be decided here: the plan is
// built before the vault is authed, so the backup's bytes aren't readable
// yet. removeOneProject makes that call at restore time, skipping a file
// whose content already matches its backup (the common `jit migrate undo`
// then `jit migrate remove` sequence).
//
// Only the newest backup per path is used, matching `jit migrate undo`.
func rewrittenInPlace(plan projectRemovalPlan) []migrate.BackupRecord {
	covered := map[string]bool{}
	for _, e := range plan.mounts {
		covered[e.MountPath] = true
	}
	for _, p := range plan.inPlace {
		covered[p] = true
	}
	for _, p := range plan.companions {
		covered[p] = true
	}
	for cfg := range plan.mcpRestores {
		covered[cfg] = true
	}

	var out []migrate.BackupRecord
	for _, rec := range migrate.LatestBackups(plan.backups) {
		if rec.RemoveOnRestore || rec.VaultPath == "" || covered[rec.OriginalPath] {
			continue
		}
		if info, err := os.Lstat(rec.OriginalPath); err != nil || !info.Mode().IsRegular() {
			continue
		}
		out = append(out, rec)
	}
	return out
}

// discoverNestedProjectRoots returns every directory strictly BELOW cwd that
// holds its own .jit/ store, shallowest first. `jit migrate <dir>` walks a
// tree and migrates each .env it finds into a project rooted at that file's
// own directory, so one `jit migrate ~/proj` can build several stores —
// ~/proj/.jit and ~/proj/sub/.jit — that `jit migrate remove ~/proj` must
// tear down together to keep its "removes jit from this project completely"
// promise. A .jit directory is never descended into (nothing nests inside a
// store), and an unreadable subtree is skipped rather than failing the whole
// removal: a store we cannot see is one we cannot delete either way.
func discoverNestedProjectRoots(cwd string) ([]string, error) {
	var roots []string
	err := filepath.WalkDir(cwd, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path == cwd {
				return err
			}
			return fs.SkipDir
		}
		if !d.IsDir() || d.Name() != ".jit" {
			return nil
		}
		// cwd's OWN store is the named project's, already accounted for by
		// the caller — skipping the directory (not just the append) is also
		// what stops the walk descending into any store.
		if filepath.Dir(path) == cwd {
			return fs.SkipDir
		}
		roots = append(roots, filepath.Dir(path))
		return fs.SkipDir
	})
	if err != nil {
		return nil, fmt.Errorf("scanning %s for nested jit projects: %w", cwd, err)
	}
	sort.Strings(roots)
	return roots, nil
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
			fmt.Fprintf(out, "  "+glyphBullet+" %s\n", displayPath(home, e.MountPath))
		}
		fmt.Fprintln(out)
	}
	if n := len(plan.inPlace); n > 0 {
		printMigrateResultCategory(out, "Pointer files -> plain files again (current vault values)", n)
		for _, p := range plan.inPlace {
			fmt.Fprintf(out, "  "+glyphBullet+" %s\n", displayPath(home, p))
		}
		fmt.Fprintln(out)
	}
	if n := len(plan.rewritten); n > 0 {
		// "pre-migration backup", not "current vault values", because that is
		// genuinely what these get — the distinction matters to anyone who has
		// run `jit vault set` on one of these since migrating.
		printMigrateResultCategory(out, "Rewritten files -> restored from their pre-migration backup", n)
		for _, rec := range plan.rewritten {
			fmt.Fprintf(out, "  "+glyphBullet+" %s\n", displayPath(home, rec.OriginalPath))
		}
		fmt.Fprintln(out)
	}
	if n := len(plan.mcpRestores); n > 0 {
		printMigrateResultCategory(out, pluralWord(n, "MCP config server", "MCP config servers")+" -> plaintext env again (current vault values)", n)
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
			fmt.Fprintf(out, "  "+glyphBullet+" %s (profile %s)\n", displayPath(home, cfg), strings.Join(names, ", "))
		}
		fmt.Fprintln(out)
	}
	if n := len(plan.profileInfos); n > 0 {
		printMigrateResultCategory(out, "Profiles + their vault secrets deleted", n)
		for _, info := range plan.profileInfos {
			fmt.Fprintf(out, "  "+glyphBullet+" %q (%s)\n", info.Name, displayPath(home, info.Path))
		}
		fmt.Fprintln(out)
	}
	if n := len(plan.orphanSecrets); n > 0 {
		printMigrateResultCategory(out, "Orphaned vault secrets deleted (no profile; matched by origin in this project)", n)
		for _, p := range plan.orphanSecrets {
			fmt.Fprintf(out, "  "+glyphBullet+" %s\n", p)
		}
		fmt.Fprintln(out)
	}
	if n := len(plan.keptShared); n > 0 {
		printMigrateResultCategory(out, "Vault secrets KEPT (another profile still references them)", n)
		for _, p := range plan.keptShared {
			fmt.Fprintf(out, "  "+glyphBullet+" %s\n", p)
		}
		fmt.Fprintln(out)
	}
	if n := len(plan.backups); n > 0 {
		printMigrateResultCategory(out, "Encrypted file backups deleted (jit migrate undo loses these)", n)
		for _, rec := range plan.backups {
			fmt.Fprintf(out, "  "+glyphBullet+" %s\n", rec.VaultPath)
		}
		fmt.Fprintln(out)
	}
	if n := len(plan.jitDirs); n > 0 {
		fmt.Fprintf(out, "The %s %s removed entirely.\n",
			displayJitDirs(home, plan.jitDirs), pluralWord(n, "directory is", "directories are"))
	}
}

// displayJitDirs renders a plan's .jit stores for the confirm prompt and the
// closing summary. Naming each one matters here: a nested store is exactly
// the thing a user does not know exists until `jit migrate remove` says it
// deleted it.
func displayJitDirs(home string, dirs []string) string {
	shown := make([]string, 0, len(dirs))
	for _, d := range dirs {
		shown = append(shown, displayPath(home, d))
	}
	return strings.Join(shown, ", ")
}

func init() {
	migrateRemoveCmd.Flags().BoolVarP(&migrateRemoveYes, "yes", "y", false, "skip the confirmation prompt and remove immediately")
	migrateCmd.AddCommand(migrateRemoveCmd)
}
