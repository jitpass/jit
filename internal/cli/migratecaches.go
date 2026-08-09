// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/migrate"
)

// migrateCachesCmd is `jit migrate caches`: sweep every AI agent cache for
// verbatim copies of ANY credential in the vault, and redact them in place.
//
// It exists because the automatic sweep on `jit migrate` can only hunt the
// values THAT run just vaulted, and three real copies fall outside that
// window: a secret migrated before the sweep existed, one whose live-session
// transcript was skipped and is now a pointer nothing can search for, and a
// wrap-captured token vaulted after the file sweep finished. All three are
// "a copy exists, but no per-run sweep will ever look for it again." This
// command is the second chance — re-runnable, stateless, and a strict
// superset of the automatic path.
//
// It decrypts every vault entry, so it takes its own fresh Touch ID: that
// prompt is the consent for reading the whole vault at once, the same bar
// `jit vault export` and rekey hold. Everything else matches the rest of the
// migrate command tree — the full plan prints, a [y/N] gate precedes any
// write (--yes skips, --dry-run previews), every rewrite is backed up
// encrypted first, and `jit migrate undo` restores it.
var migrateCachesCmd = &cobra.Command{
	Use:   "caches",
	Short: "Remove copies of your vaulted secrets that AI agents cached (whole-vault sweep)",
	Long: "jit migrate caches searches every AI coding agent's local cache — Claude\n" +
		"Code's file-history, paste-cache and transcripts, and the equivalents for\n" +
		"Cursor, Cline, OpenCode, Codex and others — for verbatim copies of any\n" +
		"credential currently in your vault, and redacts each copy in place,\n" +
		"replacing it with a <jit:redacted:VAR> marker naming the vault entry.\n\n" +
		"`jit migrate` already does this automatically for the secrets each run\n" +
		"moves. This command is the whole-vault version, and it reaches what that\n" +
		"per-run sweep cannot: a secret you migrated before this feature existed,\n" +
		"a copy left in a Claude session that was live during an earlier migrate\n" +
		"(run this once the session has ended), and tokens captured by jit wrap.\n\n" +
		"It decrypts every secret in the vault, so it asks for Touch ID up front —\n" +
		"that prompt is the consent for reading the whole vault at once. A file an\n" +
		"agent is writing at that moment is left alone and reported; a binary\n" +
		"store (a SQLite session db) is reported, never rewritten, because a\n" +
		"length-changing edit would corrupt it. Every file jit does rewrite is\n" +
		"backed up encrypted first — `jit migrate undo <path>` restores it.",
	Example: "  jit migrate caches            # clean copies of every vaulted secret\n" +
		"  jit migrate caches --dry-run  # show what would be cleaned, change nothing",
	Args: cobra.NoArgs,
	RunE: runMigrateCaches,
}

func init() {
	migrateCmd.AddCommand(migrateCachesCmd)
}

func runMigrateCaches(cmd *cobra.Command, _ []string) error {
	out := cmd.OutOrStdout()
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("jit migrate caches: %w", err)
	}

	// Fresh auth: this reads the entire vault, so it takes its own presence
	// check rather than riding a cached agent session.
	v, err := openVaultFreshAuth()
	if err != nil {
		return fmt.Errorf("jit migrate caches: %w", err)
	}

	secrets, err := migrate.CollectVaultSecrets(v)
	if err != nil {
		return fmt.Errorf("jit migrate caches: reading the vault: %w", err)
	}
	if len(secrets) == 0 {
		fmt.Fprintln(out, "The vault holds no secrets to search agent caches for.")
		return nil
	}

	// Plan first, from the same discovery the real run acts on, so the [y/N]
	// is consent for exactly what will happen (and --dry-run shows the truth).
	plan, err := migrate.PreviewAgentCaches(home, secrets)
	if err != nil {
		return fmt.Errorf("jit migrate caches: scanning agent caches: %w", err)
	}
	if len(plan.Edited) == 0 && len(plan.Skipped) == 0 {
		fmt.Fprintln(out, "No AI agent cache holds a copy of any vaulted secret. Nothing to do.")
		return nil
	}

	renderAgentCleanupPlan(out, home, plan)

	if migrateDryRun {
		fmt.Fprintln(out, "\n[dry-run] Nothing was changed.")
		return nil
	}
	if !migrateYes && !confirmPrompt(cmd, "Redact these copies? [y/N] ") {
		fmt.Fprintln(out, "Aborted. Nothing was changed.")
		return nil
	}

	cleanup, cleanErr := migrate.CleanAgentCaches(v, home, secrets)
	renderAgentCleanupResult(out, home, cleanup)
	// This whole-vault sweep has just shown the complete current picture, so
	// whatever an earlier automatic run deferred is now accounted for. A live
	// skip HERE rewrites the crumb with the fresh count rather than leaving a
	// stale one; no live skip clears it.
	if root, rerr := vaultRootDir(); rerr == nil {
		migrate.WriteCacheBreadcrumb(root, cleanup.LiveSkips(), time.Now().UnixNano())
	}
	if cleanErr != nil {
		// The edits already made are real and undoable; report the stop
		// reason without pretending the whole run failed.
		fmt.Fprintf(out, "jit: stopped early: %v\n", cleanErr)
	}
	return nil
}

// --- shared rendering, used by `jit migrate` and `jit migrate caches` ---

// agentAreaOrder groups a cleanup's files by agent and cache area for a
// stable, human summary line ("Claude Code   4 in edit history, 5 in
// transcripts") instead of a list of hash-named files.
func agentAreaBreakdown(byAgent map[string]map[string]int, agent string) string {
	areas := byAgent[agent]
	names := make([]string, 0, len(areas))
	for a := range areas {
		names = append(names, a)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, a := range names {
		label := a
		if label == "" {
			label = "its cache"
		}
		parts = append(parts, fmt.Sprintf("%d in %s", areas[a], label))
	}
	return joinList(parts)
}

// renderAgentCleanupPlan prints what a sweep WOULD do (the confirm plan and
// --dry-run share it). Occurrences aren't known per file until the read, so
// this counts files and copies, grouped by agent and area.
func renderAgentCleanupPlan(w io.Writer, home string, c migrate.AgentCacheCleanup) {
	if len(c.Edited) > 0 {
		copies := c.Occurrences()
		_, _ = cBold.Fprintf(w, "AI agent caches\n")
		fmt.Fprintf(w, "  %s of your vaulted secrets sit in %s jit will redact:\n",
			countWord(copies, "copy", "copies"), countWord(len(c.Edited), "file", "files"))
		for _, agent := range sortedAgents(c.Edited) {
			fmt.Fprintf(w, "    %-14s %s\n", agent, agentAreaBreakdown(editsByAgentArea(c.Edited), agent))
		}
	}
	renderAgentSkips(w, c)
}

// renderAgentCleanupResult prints what a sweep DID. Green for what was
// cleared, amber for what was deliberately left (a live file, a binary store).
func renderAgentCleanupResult(w io.Writer, home string, c migrate.AgentCacheCleanup) {
	if len(c.Edited) > 0 {
		_, _ = cOK.Fprintf(w, "%s ", glyphDone)
		_, _ = cBold.Fprintf(w, "Cleared %s from AI agent caches\n",
			countWord(c.Occurrences(), "copy", "copies"))
		for _, agent := range sortedAgents(c.Edited) {
			fmt.Fprintf(w, "    %-14s %s\n", agent, agentAreaBreakdown(editsByAgentArea(c.Edited), agent))
		}
		// Naming the files, because undo cannot find them on its own. These
		// are separate paths from the one the user migrated, and
		// `jit migrate undo <that file>` restores only what it is pointed at
		// (selectBackups is deliberately explicit — see GAPS.md #21/#25). The
		// old wording, "`jit migrate undo` restores the file", read as a
		// promise that undoing the migration reversed this too; it does not,
		// and a real run left ten redacted spans in a transcript after an undo
		// the user reasonably believed was complete (measured 2026-08-09).
		fmt.Fprintln(w, hlCmds("    each replaced by a `<jit:redacted:VAR>` marker"))
		fmt.Fprintln(w, "    these are separate files: undoing the migrated file does not restore them")
		fmt.Fprint(w, "    "+cPath.Sprint(glyphAction)+" ")
		fmt.Fprintln(w, cPath.Sprint(agentCleanupUndoCommand(home, c.Edited)))
	}
	renderAgentSkips(w, c)
}

// maxNamedCleanupPaths is how many paths the undo command spells out before
// it collapses to the agent directories holding them. Past a handful the line
// stops being something a reader can check and becomes something they paste
// blind.
const maxNamedCleanupPaths = 3

// agentCleanupUndoCommand is the exact command that restores the files this
// sweep rewrote — the thing the old one-liner assumed the reader could
// derive, and could not: these paths are hash-named files inside an agent's
// private cache, and nothing else in the report names them.
func agentCleanupUndoCommand(home string, edits []migrate.AgentCacheEdit) string {
	seen := map[string]bool{}
	var paths []string
	for _, e := range edits {
		if e.Path == "" || seen[e.Path] {
			continue
		}
		seen[e.Path] = true
		paths = append(paths, displayPath(home, e.Path))
	}
	sort.Strings(paths)
	if len(paths) > maxNamedCleanupPaths {
		paths = agentDirsOf(paths)
	}
	return "jit migrate undo " + strings.Join(paths, " ")
}

// agentDirsOf reduces display paths to the distinct "~/<agent dir>" roots
// holding them, so a long list still names everything without printing
// everything. `jit migrate undo` walks a directory argument, so the shorter
// command restores the same set.
func agentDirsOf(paths []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range paths {
		root := p
		// Only collapse a "~/<agent>/…" display path to "~/<agent>". An
		// ABSOLUTE path (displayPath returns one unchanged when it is not
		// under home — a symlinked or overridden HOME) begins with "/", so
		// SplitN would take its first two components and yield "/Users",
		// turning the printed command into `jit migrate undo /Users` — a
		// paste-ready command aimed at a whole tree. Leave any non-"~/" path
		// whole; a handful of full paths beats one dangerous short one.
		if strings.HasPrefix(p, "~/") {
			if parts := strings.SplitN(p, "/", 3); len(parts) >= 2 {
				root = parts[0] + "/" + parts[1]
			}
		}
		if !seen[root] {
			seen[root] = true
			out = append(out, root)
		}
	}
	sort.Strings(out)
	return out
}

// renderAgentSkips prints the copies jit found but deliberately did not touch,
// each with the reason in the user's terms. Amber, because every one is a copy
// still on disk that the user has to decide about — the honest counterweight
// to the green line above it.
func renderAgentSkips(w io.Writer, c migrate.AgentCacheCleanup) {
	if len(c.Skipped) == 0 {
		return
	}
	_, _ = cWarnBold.Fprintf(w, "%s ", glyphMark)
	_, _ = cBold.Fprintf(w, "%s left in place\n", countWord(len(c.Skipped), "copy", "copies"))
	for _, s := range c.Skipped {
		agent := s.Agent
		if agent == "" {
			agent = "an agent"
		}
		fmt.Fprintf(w, "    %-14s %s\n", agent, s.Reason)
	}
	fmt.Fprintln(w, "    "+glyphAction+" delete those files yourself, or re-run after any live session ends")
}

// editsByAgentArea buckets edits as agent -> area -> count.
func editsByAgentArea(edits []migrate.AgentCacheEdit) map[string]map[string]int {
	m := map[string]map[string]int{}
	for _, e := range edits {
		agent := e.Agent
		if agent == "" {
			agent = "an agent"
		}
		if m[agent] == nil {
			m[agent] = map[string]int{}
		}
		m[agent][e.Area]++
	}
	return m
}

func sortedAgents(edits []migrate.AgentCacheEdit) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range edits {
		agent := e.Agent
		if agent == "" {
			agent = "an agent"
		}
		if !seen[agent] {
			seen[agent] = true
			out = append(out, agent)
		}
	}
	sort.Strings(out)
	return out
}

// joinList renders ["a","b","c"] as "a, b, c".
func joinList(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	return out
}
