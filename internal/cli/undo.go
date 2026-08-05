// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/vault"
)

var migrateUndoCmd = &cobra.Command{
	Use:   "undo <path>...",
	Short: "Restore named migrated files from their encrypted pre-migration backups",
	Long: "jit migrate undo puts back what jit migrate rewrote, using the encrypted\n" +
		"backup every category stores in the vault before touching a file:\n" +
		".env live mounts become plain files again, rewritten shell configs/\n" +
		"MCP configs/AWS files/kubeconfigs/npmrc files get their exact original\n" +
		"bytes back. You must name what to restore: a file path restores just\n" +
		"that file, a DIRECTORY path restores every migrated file recorded under\n" +
		"that tree, so you can undo a single project without disturbing anything\n" +
		"migrated elsewhere. A bare `jit migrate undo` with no path does nothing.\n\n" +
		"A file that can't be restored (its backup was cleaned from the vault, a\n" +
		"symlink reappeared at the path, …) is reported and skipped, the rest\n" +
		"still restore, and the command exits non-zero if any file failed, so a\n" +
		"single missing backup never silently aborts the whole batch partway.\n\n" +
		"What it does per file: if the file is a registered live mount, the\n" +
		"running service stops serving it first (other mounts are undisturbed), the\n" +
		"registry entry and the .pointers companion are removed, then the backed-\n" +
		"up content is written back. The current content is snapshotted into the\n" +
		"vault before being overwritten, so an undo is itself undoable, nothing\n" +
		"is ever simply destroyed.\n\n" +
		"What it deliberately does NOT do: vault secrets and profile manifests\n" +
		"stay (`jit migrate remove` deletes a project's completely, and\n" +
		"`jit migrate remove <file>` deletes a loose secret's completely). When an\n" +
		"undone file was a loose secret, undo ends by pointing you at that command.\n\n" +
		"Like every restore-to-plaintext operation, this writes real secret\n" +
		"values back to disk, it prints the full plan and confirms first\n" +
		"(--yes skips, --dry-run previews only).\n\n" +
		"To see every restorable file first, run `jit migrate undo <dir> --dry-run`\n" +
		"(e.g. your $HOME). Backups made by jit builds before this command existed\n" +
		"aren't in its index, restore those by hand: `jit vault list` (look under\n" +
		"_backups/) + `jit vault get <path>`.",
	Example: "  jit migrate undo ~/proj/.env    # restore one migrated file\n" +
		"  jit migrate undo ~/proj         # restore everything migrated under a project\n" +
		"  jit migrate undo ~/proj --dry-run",
	Args:              requirePaths("jit migrate undo"),
	ValidArgsFunction: completeMigrateUndoPaths,
	RunE:              runMigrateUndo,
}

// completeMigrateUndoPaths makes the `[path...]` argument discoverable at
// the one place people look for what a command accepts: `jit migrate undo
// <TAB>`. Without it the shell offered only flags, so a real user couldn't
// tell a path could scope the restore at all (the whole reason for this
// function). It offers exactly the files a run could restore, plus each
// one's parent directory — a directory arg restores everything migrated
// under it — each labeled so the two kinds are self-explanatory. The
// Default (not NoFileComp) directive keeps normal filesystem completion
// alive too, so a relative `.` from inside a project still completes.
func completeMigrateUndoPaths(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	root, err := vaultRootDir()
	if err != nil {
		return nil, cobra.ShellCompDirectiveDefault
	}
	recs, err := migrate.LoadBackupRecords(root)
	if err != nil {
		return nil, cobra.ShellCompDirectiveDefault
	}
	seen := map[string]bool{}
	var out []string
	add := func(p, desc string) {
		if p == "" || seen[p] || !strings.HasPrefix(p, toComplete) {
			return
		}
		seen[p] = true
		out = append(out, p+"\t"+desc)
	}
	for _, r := range migrate.LatestBackups(recs) {
		add(r.OriginalPath, "restore this migrated file")
		add(filepath.Dir(r.OriginalPath), "restore everything migrated under here")
	}
	return out, cobra.ShellCompDirectiveDefault
}

func runMigrateUndo(cmd *cobra.Command, args []string) error {
	// --only filters by CATEGORY; undo operates on recorded files. Refuse
	// rather than silently ignore — the exact silently-accepted-and-ignored
	// trap GAPS.md #21/#25 fixed elsewhere in this command tree.
	if len(migrateOnly) > 0 {
		return fmt.Errorf("jit migrate undo: --only doesn't apply here, pass a path argument to restore a single file")
	}

	out := cmd.OutOrStdout()
	root, err := vaultRootDir()
	if err != nil {
		return fmt.Errorf("jit migrate undo: %w", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("jit migrate undo: %w", err)
	}
	recs, err := migrate.LoadBackupRecords(root)
	if err != nil {
		return fmt.Errorf("jit migrate undo: %w", err)
	}
	// Report the empty state before matching against the path args: with
	// nothing recorded at all, a bare "no recorded backup for <path>" would
	// read as "that one file" rather than "nothing to restore anywhere."
	all := migrate.LatestBackups(recs)
	if len(all) == 0 {
		fmt.Fprintln(out, hlCmds("No jit-written backups are recorded, nothing to restore. (Backups made by builds before `jit migrate undo` existed aren't indexed; see `jit vault list` under _backups/ for those.)"))
		return nil
	}
	// args is non-empty (the command requires a path) and all is non-empty,
	// so selectBackups either returns at least one record or fails loud on an
	// arg that matched nothing — latest is never empty past here.
	latest, err := selectBackups(all, args)
	if err != nil {
		return fmt.Errorf("jit migrate undo: %w", err)
	}

	if migrateDryRun {
		// Same leading banner discipline as jit migrate (GAPS.md #32): the
		// preview-vs-real signal comes BEFORE the plan, not only after it.
		_, _ = cPathBold.Fprintln(out, "[DRY RUN] Preview, this run changes nothing; the plan below is what a real run would do.")
	}

	registryPath := mount.RegistryPath(root)
	mounted := map[string]mount.Entry{}
	fmt.Fprintf(out, "Restoring %s from encrypted backups:\n", countWord(len(latest), "file", "files"))
	for _, rec := range latest {
		entry, found, err := mount.FindMount(registryPath, rec.OriginalPath)
		if err != nil {
			return fmt.Errorf("jit migrate undo: %w", err)
		}
		note := ""
		if found {
			mounted[rec.OriginalPath] = entry
			note = ", live mount: stops being served, unregistered"
		}
		if rec.RemoveOnRestore {
			fmt.Fprintf(out, "  • %s (created by migration, will be removed)%s\n", displayPath(home, rec.OriginalPath), note)
			continue
		}
		fmt.Fprintf(out, "  • %s (backed up %s ago)%s\n", displayPath(home, rec.OriginalPath), humanAgo(time.Since(time.Unix(rec.UnixTS, 0))), note)
	}
	fmt.Fprintln(out)
	warn := cWarn
	_, _ = warn.Fprintln(out, "Each file is restored EXACTLY as backed up, edits made since are replaced")
	_, _ = warn.Fprintln(out, "(the replaced content is snapshotted into the vault first, so this is itself")
	_, _ = warn.Fprintln(out, "undoable), and real secret values return to disk in PLAINTEXT.")
	fmt.Fprintln(out, "Vault secrets and profile manifests are left in place, this reverses files, never the vault.")

	if migrateDryRun {
		fmt.Fprintln(out)
		_, _ = cPathBold.Fprint(out, "[DRY RUN]")
		fmt.Fprintln(out, " No files were changed.")
		return nil
	}

	// Before openVault(), always: declining must never cost a Touch ID
	// prompt for work about to be aborted (GAPS.md #17's ordering).
	if !migrateYes && !confirmPrompt(cmd, fmt.Sprintf("Restore %s, writing real secrets back to disk in PLAINTEXT? [y/N] ", countWord(len(latest), "file", "files"))) {
		fmt.Fprintln(out, "Aborted. Nothing was changed.")
		return nil
	}

	// Fresh challenge on purpose, even while the agent session is
	// unlocked — see openVaultFreshAuth: restoring plaintext files should
	// never happen silently on a cached session some other same-user
	// process could be riding.
	v, err := openVaultFreshAuth()
	if err != nil {
		return fmt.Errorf("jit migrate undo: %w", err)
	}
	// Force the fresh Touch ID/passcode NOW, explicitly, and record it into
	// this invocation's audit entry — the restore below would trigger a
	// challenge on its first decrypt anyway, but priming it here makes the
	// fingerprint mandatory and audited even if a future restore path ever
	// wrote a file back without decrypting one (and means a multi-file batch
	// prompts exactly once). Mirrors jit migrate remove's gate.
	if err := requireFreshUserPresence(v, "restore migrated files to plaintext"); err != nil {
		return fmt.Errorf("jit migrate undo: %w", err)
	}
	agentClient := agent.NewClient(agent.SocketPath(root))
	agentUp := agentClient.Reachable()

	// Per-file restore, wrapped so runRestores can drive every file
	// uniformly. A mount whose Serve goroutine won't stop must NOT proceed
	// to the write (GAPS.md #36's FIFO race), so a stop/unregister failure
	// returns here before RestoreFromBackup — that one file is recorded as
	// failed and skipped, and the rest of the batch still restores.
	restoreOne := func(rec migrate.BackupRecord) error {
		if _, isMount := mounted[rec.OriginalPath]; isMount {
			// Same ordering discipline as jit unmount: the agent's Serve
			// goroutine must have genuinely stopped (StopMount blocks on
			// it) before anything replaces the FIFO, or an in-flight cycle
			// can clobber the fresh plaintext back into an empty pipe.
			if agentUp {
				if err := agentClient.StopMount(rec.OriginalPath); err != nil {
					return fmt.Errorf("stopping the running service's mount: %w", err)
				}
			}
			if _, err := mount.RemoveMount(registryPath, rec.OriginalPath); err != nil {
				return err
			}
		}

		if err := migrate.RestoreFromBackup(v, rec); err != nil {
			return err
		}

		// The .pointers companion describes a mount that no longer exists —
		// stale the moment the real file is back. Its removal is cosmetic
		// (the restore already succeeded), so a failure here is a warning,
		// never a failed file. Deliberately NOT gated on the path still
		// being a registered mount: a file unmounted before this undo ran
		// isn't in the registry anymore, but an older jit's unmount may have
		// left its companion behind — and for a never-mounted record
		// (.mcp.json, a shell config) both cleanups are exact no-ops anyway.
		if err := os.Remove(migrate.PointerFilePath(rec.OriginalPath)); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(out, "  warning: removing stale pointer file for %s: %v\n", displayPath(home, rec.OriginalPath), err)
		}
		return nil
	}

	restoreErr := runRestores(out, home, latest, restoreOne)
	// A restored loose secret file's dedicated vault secret is still there —
	// undo reverses files, never the vault. Unlike a project secret it is
	// unshared and has no further use once its file is back, so point the user
	// at the one command that clears it too. Best-effort and auth-free (Info
	// reads envelope plaintext); printed even after a partial failure, since
	// the nudge only names files whose secret genuinely still exists.
	nudgeLooseRemainders(out, v, home, latest)
	return restoreErr
}

// nudgeLooseRemainders prints, for each just-restored file that still has a
// dedicated loose_file vault secret pointing back at it, a hint to the
// file-scoped `jit migrate remove` that would delete that secret too. Any read
// error simply skips the nudge — it never affects the undo's own result.
func nudgeLooseRemainders(out io.Writer, v *vault.Vault, home string, recs []migrate.BackupRecord) {
	restored := make(map[string]bool, len(recs))
	for _, rec := range recs {
		restored[rec.OriginalPath] = true
	}
	paths, err := v.List()
	if err != nil {
		return
	}
	remaining := map[string]bool{}
	for _, p := range paths {
		if strings.HasPrefix(p, "_backups/") {
			continue
		}
		info, err := v.Info(p)
		if err != nil || info.Class != vault.ClassLooseFile || info.Origin == "" {
			continue
		}
		if origin := expandTilde(info.Origin, home); restored[origin] {
			remaining[origin] = true
		}
	}
	if len(remaining) == 0 {
		return
	}
	files := make([]string, 0, len(remaining))
	for f := range remaining {
		files = append(files, f)
	}
	sort.Strings(files)
	fmt.Fprintln(out)
	for _, f := range files {
		_, _ = cPath.Fprintf(out,
			"Its vault secret is still stored. `jit migrate remove %s` deletes that too.\n", displayPath(home, f))
	}
}

// undoFailure records one file runRestores could not restore, so the batch
// can finish the others and still report — and exit non-zero — at the end.
type undoFailure struct {
	path string
	err  error
}

// runRestores restores every record via restoreOne, NEVER aborting the whole
// batch on a single file's failure: a missing backup, a symlink that
// reappeared at the destination, or a mount that won't stop takes down only
// that one file. Each success and skip is reported inline; the closing
// summary states how many restored and lists any that didn't, and the call
// returns a non-nil error (non-zero exit) iff at least one failed — so a
// script can still trust the exit code while a human never ends up with a
// silently half-restored machine. The pre-existing behavior was the hazard
// this replaces: the first missing backup aborted mid-loop, leaving earlier
// files restored and later ones untouched, with no summary of which was which.
func runRestores(out io.Writer, home string, recs []migrate.BackupRecord, restoreOne func(migrate.BackupRecord) error) error {
	var restored int
	var failures []undoFailure
	for _, rec := range recs {
		if err := restoreOne(rec); err != nil {
			failures = append(failures, undoFailure{path: rec.OriginalPath, err: err})
			_, _ = cWarn.Fprintf(out, "SKIPPED %s, %v\n", displayPath(home, rec.OriginalPath), err)
			continue
		}
		restored++
		if rec.RemoveOnRestore {
			fmt.Fprintf(out, "Removed %s (created by migration)\n", displayPath(home, rec.OriginalPath))
		} else {
			fmt.Fprintf(out, "Restored %s\n", displayPath(home, rec.OriginalPath))
		}
	}

	fmt.Fprintln(out)
	if restored > 0 {
		fmt.Fprint(out, hlCmds(fmt.Sprintf("Restored %s. Vault secrets and profile manifests are still there, `jit migrate remove` deletes a project's completely.\n", countWord(restored, "file", "files"))))
	}
	if len(failures) > 0 {
		_, _ = cWarn.Fprintf(out, "%s could NOT be restored and %s left exactly as %s:\n",
			countWord(len(failures), "file", "files"),
			pluralWord(len(failures), "was", "were"),
			pluralWord(len(failures), "it was", "they were"))
		for _, f := range failures {
			fmt.Fprintf(out, "  • %s: %v\n", displayPath(home, f.path), f.err)
		}
		total := restored + len(failures)
		return fmt.Errorf("jit migrate undo: %d of %s failed to restore", len(failures), countWord(total, "file", "files"))
	}
	return nil
}

// selectBackups narrows latest to the records the path args name (the caller
// always names at least one — the command requires it). Each arg is resolved
// to an absolute, cleaned path and matches a record whose OriginalPath either
// equals it (a single file) or lies under it (the arg names a directory) —
// so `jit migrate undo ~/project` restores every file jit migrated anywhere
// under that tree, the scoping that makes undoing one project without
// touching another safe. Naming a broad directory ($HOME, say) restores
// everything under it, so a machine-wide restore is still one arg away. An
// arg that matches nothing is a loud error naming it, never a silent no-op
// (the GAPS.md #21/#25 trap). Results are deduped (overlapping args can name
// the same file) and returned in the path-sorted order LatestBackups
// already guarantees.
func selectBackups(latest []migrate.BackupRecord, args []string) ([]migrate.BackupRecord, error) {
	if len(args) == 0 {
		return latest, nil
	}
	seen := map[string]bool{}
	var out []migrate.BackupRecord
	for _, a := range args {
		abs, err := filepath.Abs(a)
		if err != nil {
			return nil, err
		}
		abs = filepath.Clean(abs)
		matched := 0
		for _, r := range latest {
			if r.OriginalPath == abs || strings.HasPrefix(r.OriginalPath, abs+string(os.PathSeparator)) {
				matched++
				if !seen[r.OriginalPath] {
					seen[r.OriginalPath] = true
					out = append(out, r)
				}
			}
		}
		if matched == 0 {
			return nil, fmt.Errorf("no recorded backup for %s, run `jit migrate undo ~ --dry-run` (or name a broader directory) to see every restorable file", abs)
		}
	}
	out = expandRestoreWith(latest, out, seen)
	sort.Slice(out, func(i, j int) bool { return out[i].OriginalPath < out[j].OriginalPath })
	return out, nil
}

// expandRestoreWith pulls in the files a selected record says must come back
// with it (BackupRecord.RestoreWith), so naming one file cannot produce a
// half-restored state.
//
// The case it exists for: `jit migrate undo <.mcp.json>` on a server that had
// been reading `--env-file secrets.env`. Restoring the config re-adds the flag,
// and without this the .env stays a pointer file, so the server comes back
// launching against "KEY=jit://vault/..." literals. The user asked to undo a
// migration and got a config that looks right and a server that cannot work.
//
// Transitive by construction (a pulled-in record's own RestoreWith is walked
// too), and cycle-safe via the shared seen set. A linked path with no record
// left in the index — its backup pruned, say — is skipped silently: undo
// already reports per-file failures for everything it was asked to restore,
// and there is nothing to put back.
func expandRestoreWith(latest, selected []migrate.BackupRecord, seen map[string]bool) []migrate.BackupRecord {
	byPath := make(map[string]migrate.BackupRecord, len(latest))
	for _, r := range latest {
		byPath[r.OriginalPath] = r
	}
	for i := 0; i < len(selected); i++ {
		for _, linked := range selected[i].RestoreWith {
			if seen[linked] {
				continue
			}
			rec, ok := byPath[linked]
			if !ok {
				continue
			}
			seen[linked] = true
			selected = append(selected, rec)
		}
	}
	return selected
}

func init() {
	migrateCmd.AddCommand(migrateUndoCmd)
}
