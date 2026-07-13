// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

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

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/mount"
)

var migrateUndoCmd = &cobra.Command{
	Use:   "undo [path...]",
	Short: "Restore migrated files from their encrypted pre-migration backups",
	Long: "jit migrate undo puts back what jit migrate rewrote, using the encrypted\n" +
		"backup every category stores in the vault before touching a file:\n" +
		".env live mounts become plain files again, rewritten shell configs/\n" +
		"MCP configs/AWS files/kubeconfigs/npmrc files get their exact original\n" +
		"bytes back. With no argument it restores EVERY file with a recorded\n" +
		"backup (each to its most recent one). Pass one or more paths to scope\n" +
		"it: a file path restores just that file, a DIRECTORY path restores every\n" +
		"migrated file recorded under that tree — so you can undo a single project\n" +
		"without disturbing anything migrated elsewhere.\n\n" +
		"A file that can't be restored (its backup was cleaned from the vault, a\n" +
		"symlink reappeared at the path, …) is reported and skipped — the rest\n" +
		"still restore, and the command exits non-zero if any file failed, so a\n" +
		"single missing backup never silently aborts the whole batch partway.\n\n" +
		"What it does per file: if the file is a registered live mount, the\n" +
		"running agent stops serving it first (other mounts are undisturbed), the\n" +
		"registry entry and the .pointers companion are removed, then the backed-\n" +
		"up content is written back. The current content is snapshotted into the\n" +
		"vault before being overwritten, so an undo is itself undoable — nothing\n" +
		"is ever simply destroyed.\n\n" +
		"It also reverses the `jit agent reveal` hook migrate wired into a\n" +
		"mount's .envrc/package.json — surgically, removing only jit's own\n" +
		"marked command for the mount being restored, so a script you edited\n" +
		"yourself is never touched and another mount's hook is left intact. Once\n" +
		"a hook file has no jit command left, its .jit-bak backup is cleaned up.\n\n" +
		"What it deliberately does NOT do: vault secrets and profile manifests\n" +
		"stay (`jit migrate remove` deletes a project's completely).\n\n" +
		"Like every restore-to-plaintext operation, this writes real secret\n" +
		"values back to disk — it prints the full plan and confirms first\n" +
		"(--yes skips, --dry-run previews only).\n\n" +
		"Backups made by jit builds before this command existed aren't in its\n" +
		"index — restore those by hand: `jit vault list` (look under _backups/)\n" +
		"+ `jit vault get <path>`.",
	Args: cobra.ArbitraryArgs,
	RunE: runMigrateUndo,
}

func runMigrateUndo(cmd *cobra.Command, args []string) error {
	// --only filters by CATEGORY; undo operates on recorded files. Refuse
	// rather than silently ignore — the exact silently-accepted-and-ignored
	// trap GAPS.md #21/#25 fixed elsewhere in this command tree.
	if len(migrateOnly) > 0 {
		return fmt.Errorf("jit migrate undo: --only doesn't apply here — pass a path argument to restore a single file")
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
	latest, err := selectBackups(migrate.LatestBackups(recs), args)
	if err != nil {
		return fmt.Errorf("jit migrate undo: %w", err)
	}

	if len(latest) == 0 {
		fmt.Fprintln(out, "No jit-written backups are recorded — nothing to restore. (Backups made by builds before `jit migrate undo` existed aren't indexed; see `jit vault list` under _backups/ for those.)")
		return nil
	}

	if migrateDryRun {
		// Same leading banner discipline as migrate local/home (GAPS.md
		// #32): the preview-vs-real signal comes BEFORE the plan, not only
		// after it.
		_, _ = color.New(color.FgCyan, color.Bold).Fprintln(out, "[DRY RUN] Preview — this run changes nothing; the plan below is what a real run would do.")
	}

	registryPath := mount.RegistryPath(root)
	mounted := map[string]mount.Entry{}
	fmt.Fprintf(out, "Restoring %d file(s) from encrypted backups:\n", len(latest))
	for _, rec := range latest {
		entry, found, err := mount.FindMount(registryPath, rec.OriginalPath)
		if err != nil {
			return fmt.Errorf("jit migrate undo: %w", err)
		}
		note := ""
		if found {
			mounted[rec.OriginalPath] = entry
			note = " — live mount: stops being served, unregistered"
		}
		if rec.RemoveOnRestore {
			fmt.Fprintf(out, "  • %s (created by migration — will be removed)%s\n", displayPath(home, rec.OriginalPath), note)
			continue
		}
		fmt.Fprintf(out, "  • %s (backed up %s ago)%s\n", displayPath(home, rec.OriginalPath), humanAgo(time.Since(time.Unix(rec.UnixTS, 0))), note)
	}
	fmt.Fprintln(out)
	// Path scoping is easy to miss from --help alone — a real user asked
	// for "project-specific undo" while the path argument already did
	// exactly that. Say it at the moment it matters: a no-arg run about to
	// restore more than one file. Same section-scoped-hint pattern as
	// printMigratePlan's --only suggestion (yellow: actionable, not a
	// passive "why" label).
	if len(args) == 0 && len(latest) > 1 {
		_, _ = color.New(color.FgYellow).Fprintln(out, "This restores EVERY file listed above. To undo just one project or file, pass its path: `jit migrate undo <path>` (a directory restores only what's under it).")
		fmt.Fprintln(out)
	}
	warn := color.New(color.FgYellow)
	_, _ = warn.Fprintln(out, "Each file is restored EXACTLY as backed up — edits made since are replaced")
	_, _ = warn.Fprintln(out, "(the replaced content is snapshotted into the vault first, so this is itself")
	_, _ = warn.Fprintln(out, "undoable), and real secret values return to disk in PLAINTEXT.")
	fmt.Fprintln(out, "Vault secrets and profile manifests are left in place — this reverses files, never the vault.")

	if migrateDryRun {
		fmt.Fprintln(out)
		_, _ = color.New(color.FgCyan, color.Bold).Fprint(out, "[DRY RUN]")
		fmt.Fprintln(out, " No files were changed.")
		return nil
	}

	// Before openVault(), always: declining must never cost a Touch ID
	// prompt for work about to be aborted (GAPS.md #17's ordering).
	if !migrateYes && !confirmPrompt(cmd, fmt.Sprintf("Restore %d file(s), writing real secrets back to disk in PLAINTEXT? [y/N] ", len(latest))) {
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
					return fmt.Errorf("stopping the running agent's mount: %w", err)
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
		// Reverse the reveal hook migrate wired into this mount's
		// directory (package.json/.envrc) — surgically, for just this
		// mount, so undoing one mount never disturbs another's hook or a
		// script the user edited. Also cosmetic relative to the restore
		// that already succeeded: a failure warns, never fails the file.
		if err := migrate.UninstallRevealHook(filepath.Dir(rec.OriginalPath), rec.OriginalPath); err != nil {
			fmt.Fprintf(out, "  warning: removing reveal hook for %s: %v\n", displayPath(home, rec.OriginalPath), err)
		}
		return nil
	}

	return runRestores(out, home, latest, restoreOne)
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
			_, _ = color.New(color.FgYellow).Fprintf(out, "SKIPPED %s — %v\n", displayPath(home, rec.OriginalPath), err)
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
		fmt.Fprintf(out, "Restored %d file(s). Vault secrets and profile manifests are still there — `jit migrate remove` deletes a project's completely.\n", restored)
	}
	if len(failures) > 0 {
		_, _ = color.New(color.FgYellow).Fprintf(out, "%d file(s) could NOT be restored and were left exactly as they were:\n", len(failures))
		for _, f := range failures {
			fmt.Fprintf(out, "  • %s: %v\n", displayPath(home, f.path), f.err)
		}
		return fmt.Errorf("jit migrate undo: %d of %d file(s) failed to restore", len(failures), restored+len(failures))
	}
	return nil
}

// selectBackups narrows latest to the records the path args name. No args ->
// the whole set (a machine-wide restore). Otherwise each arg is resolved to
// an absolute, cleaned path and matches a record whose OriginalPath either
// equals it (a single file) or lies under it (the arg names a directory) —
// so `jit migrate undo ~/project` restores every file jit migrated anywhere
// under that tree, the scoping that makes undoing one project without
// touching another safe. An arg that matches nothing is a loud error naming
// it, never a silent no-op (the GAPS.md #21/#25 trap). Results are deduped
// (overlapping args can name the same file) and returned in the path-sorted
// order LatestBackups already guarantees.
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
			return nil, fmt.Errorf("no recorded backup for %s — run `jit migrate undo --dry-run` with no argument to see every restorable file", abs)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].OriginalPath < out[j].OriginalPath })
	return out, nil
}

func init() {
	migrateCmd.AddCommand(migrateUndoCmd)
}
