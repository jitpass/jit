// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"fmt"
	"io"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/termtext"
)

// This file is real migrate's MUTATION LOG rendering — the per-category
// result headers, the consolidated migrateSummary that collapses repeated
// explanations, and reportAgentStatus's closing pointer. Split out of
// migrate.go (which keeps command wiring and runMigrate's orchestration)
// the same way mountmanager.go was split out of agent.go: one concern per
// file. The plan rendering both --dry-run and the confirmation prompt
// share lives in migrateplan.go.

// printMigrateResultCategory renders the same bold "[Label] <count>" header
// the plan itself uses (printMigratePlanCategoryAnnotated) — the past-tense
// mutation log visually matches the future-tense plan directly above it,
// instead of reading like a different tool's output. Kept in lockstep with
// the plan header on purpose: a bold name, a plain count, no rule.
func printMigrateResultCategory(w io.Writer, label string, n int) {
	fmt.Fprintf(w, "[%s]", label)
	_, _ = fmt.Fprintf(w, " %d\n", n)
}

// opLinkedRow is one linked-instead-of-copied secret for the [1Password]
// mutation-log block: the vault path, and the reference in its
// human-readable name form (the stored one is rename-proof ID form; the
// name form is what the user recognizes from the 1Password app).
type opLinkedRow struct{ path, ref string }

// printOpLinkResult renders the 1Password dedupe outcome after the
// per-category results (design/1password-adapter.md). Three cases: the
// check failed (one amber note — the run continued with copies, fail
// open), nothing matched (silence; an empty block would be noise on every
// run op is merely installed for), or N linked (the block naming each
// path → reference, so the user knows exactly which secrets now follow
// 1Password rotation).
func printOpLinkResult(w io.Writer, linked []opLinkedRow, offered, itemsChecked int, skipNote string) {
	if skipNote != "" {
		_, _ = cWarn.Fprint(w, glyphWarn)
		wrapBody(w, 1, "  ", " 1Password check skipped: "+skipNote+"; values were copied, not linked")
		fmt.Fprintln(w)
		return
	}
	if len(linked) == 0 {
		return
	}
	widest := 0
	for _, r := range linked {
		if len(r.path) > widest {
			widest = len(r.path)
		}
	}
	printMigrateResultCategoryLabel(w, fmt.Sprintf("%d of %d linked, not copied · %s checked", len(linked), offered, countWord(itemsChecked, "item", "items")))
	for _, r := range linked {
		// Truncate the variable tail rather than wrap: one row per secret.
		row := fmt.Sprintf("  %-*s %s %s", widest, r.path, glyphAction, r.ref)
		fmt.Fprintln(w, truncateEnd(row, termtext.Width()))
	}
	fmt.Fprintln(w, "  Rotate these in 1Password; jit follows. The vault holds the")
	fmt.Fprintln(w, "  reference, never a copy.")
	fmt.Fprintln(w)
}

// printMigrateResultCategoryLabel is printMigrateResultCategory for a
// header whose tail is richer than a bare count.
func printMigrateResultCategoryLabel(w io.Writer, tail string) {
	fmt.Fprintf(w, "[1Password] %s\n", tail)
}

// migrateSummary collects everything that used to print inline, once per
// file, during a real migrate run's mutation loop — git-history warnings,
// pointer-file confirmations, and reveal-hook results — so it can be
// reported once, consolidated, instead of repeating the same explanation
// after every single file. A real, reported problem: a six-file run
// repeated an identical 5-line git-history paragraph six times and an
// identical 2-line "no pre-run hook" paragraph four times, more than 40
// lines of boilerplate burying the one line that actually mattered (the
// closing "run `jit service restart`" pointer). Each explanation in
// migrateSummary.print now appears exactly once, with the affected files
// listed under it — the same collapse-identical-explanations convention
// already applied to jit scan's human report.
type migrateSummary struct {
	// home is the user's home directory, used to "~"-shorten the paths
	// this summary displays (the recorded strings below are display-only;
	// nothing re-reads them as paths).
	home            string
	gitHistoryFiles []string
	pointerFiles    int
	backupOnlyFiles int
	// exportNudge is set when the vault holding everything just migrated
	// has never been exported at all — the one moment this is most worth
	// saying, since the plaintext originals are about to be gone and the
	// vault only decrypts on this machine. Deliberately NOT set for a
	// merely stale export: every migrate run writes new secrets, so
	// "stale" here is a tautology and nagging on it every run would teach
	// people to skip the whole summary. `jit status` owns staleness.
	exportNudge bool
	// agentCleanup is what the post-migration sweep removed from AI agent
	// caches, and what it deliberately left alone. Empty on a run that
	// vaulted nothing an agent had copied, which is the common case.
}

// checkGitHistory records path if it has ever been committed (RFC.md
// B7) — migrating a file never scrubs its git history, so silently
// implying "migrated = safe" would be wrong for anything already in a
// repo. Recording, not blocking: moving the value into the vault is
// still the right next step even for an already-committed file.
func (s *migrateSummary) checkGitHistory(path string) {
	if hasHistory, err := migrate.HasGitHistory(path); err == nil && hasHistory {
		s.gitHistoryFiles = append(s.gitHistoryFiles, displayPath(s.home, path))
	}
}

// writePointerFile loads the just-written profile manifest at profilePath
// and writes its git-safe, IDE-peekable .pointers companion alongside
// mountPath (GAPS.md #26) — reads the profile back from disk rather than
// threading its in-memory map through ApplyEnvFile/ApplyNpmrc, since both
// already return everything else the caller needs via their own result
// structs and this is the one extra piece only the CLI layer's feature
// needs.
func (s *migrateSummary) writePointerFile(mountPath, profilePath string) error {
	p, varOrder, err := profile.LoadFileOrdered(profilePath)
	if err != nil {
		return fmt.Errorf("loading profile to write pointer file: %w", err)
	}
	if err := migrate.WritePointerFile(mountPath, p, varOrder); err != nil {
		return err
	}
	s.pointerFiles++
	return nil
}

// print renders every non-empty block collected above, once each,
// between the per-file "Migrated ..." lines above and reportAgentStatus's
// closing pointer below.
// print's caller already ends its own last category block with a blank
// line, so the FIRST block here must not add a second one on top of it
// — separated is only skipped for the very first block actually printed.
func (s *migrateSummary) print(w io.Writer) {
	separated := false
	sep := func() {
		if separated {
			fmt.Fprintln(w)
		}
		separated = true
	}

	if s.backupOnlyFiles > 0 {
		sep()
		fmt.Fprintf(w, "%s (.bak/.old/.orig/.backup) had %s secrets moved to the vault but %s never mounted, nothing reads a backup file live, so each was replaced with a safe pointer file instead of a FIFO.\n",
			countWord(s.backupOnlyFiles, "backup-suffixed file", "backup-suffixed files"),
			pluralWord(s.backupOnlyFiles, "its", "their"),
			pluralWord(s.backupOnlyFiles, "was", "were"))
	}
	if len(s.gitHistoryFiles) > 0 {
		sep()
		// Amber bold on the marker only, plain on the sentence: the "!" is
		// the state (rule 2), and a line of prose painted amber reads as a
		// second warning (rule 5). Same shape as the findings marks in
		// jit scan, which is where a reader has already met it.
		_, _ = cWarnBold.Fprintf(w, "%s ", glyphMark)
		wrapBody(w, 2, "  ", fmt.Sprintf("%s migrated already %s git history, jit migrate does not scrub it:",
			countWord(len(s.gitHistoryFiles), "file", "files"),
			pluralWord(len(s.gitHistoryFiles), "has", "have")))
		for _, f := range s.gitHistoryFiles {
			fmt.Fprintf(w, "  "+glyphBullet+" %s\n", f)
		}
		fmt.Fprintln(w, hlCmds("  Any value ever committed is still recoverable via `git log -p`/`git blame` for the life of"))
		fmt.Fprintln(w, "  the repository, and by anyone who already has a clone or fork. To actually remove it,")
		fmt.Fprintln(w, "  rotate the secret and rewrite history with git-filter-repo (https://github.com/newren/")
		fmt.Fprintln(w, "  git-filter-repo) or BFG Repo-Cleaner.")
	}
	if s.pointerFiles > 0 {
		sep()
		fmt.Fprintf(w, "%s written alongside the %s above, %s vault paths only, safe to open or commit.\n",
			countWord(s.pointerFiles, "git-safe .pointers file", "git-safe .pointers files"),
			pluralWord(s.pointerFiles, "mount", "mounts"),
			pluralWord(s.pointerFiles, "lists", "list"))
	}
	if s.exportNudge {
		sep()
		// The glyph carries the state (rule 2); the sentence after it is
		// advice, and advice in amber reads as a second warning (rule 5).
		_, _ = cWarnBold.Fprintf(w, "%s ", glyphMark)
		wrapBody(w, 2, "  ", hlCmds("These secrets now live only in this Mac's vault, and no passphrase-encrypted "+
			"backup of it has ever been made, run `jit vault export <file>` once (`jit status` will say "+
			"when it needs refreshing)."))
	}
}

// reportAgentStatus prints whether the running service picked up new
// mounts, or nudges toward `jit service restart` if none is running — for
// EVERY category migrate just touched, not only when a mount was
// produced. Every category resolves the vault at some later point
// (eval line, jit run, credential_process, exec block, or the mount
// itself), and every one of those benefits from a shared agent session
// instead of an independent Touch ID challenge — some invoked from
// contexts that can't show a prompt at all (a cron job, kubectl, an
// MCP host launching a subprocess headlessly; see aws-credential-
// process/k8s-exec-credential's own --help text). A version of this that
// only nudged when envFiles/npmrcFiles produced a mount was a real gap:
// kubeconfig/AWS/MCP/shell-config migrations got no hint at all.
// This is deliberately the very last thing runMigrate prints, and its
// action lines are bolded (matching confirmPrompt's own bold treatment)
// for the same reason: it's the single next step every other line in a
// real migrate run's output was leading up to, and it must not read as
// just more body text after a long plan and per-file migration log.
func reportAgentStatus(w io.Writer, root string, producedMount bool) {
	agentClient := agent.NewClient(agent.SocketPath(root))
	bold := func(format string, a ...interface{}) {
		fmt.Fprintln(w)
		_, _ = cBold.Fprintf(w, format, a...)
		fmt.Fprintln(w)
	}
	// refreshMounts tells a reachable agent about the mount(s) this run just
	// registered so they're served now, not only after the next lock/unlock
	// cycle. Shared by the already-running and just-auto-installed paths so
	// their success/warning wording can't drift.
	refreshMounts := func(justInstalled bool) {
		// Its own OnUnlock (if this migrate run's vault writes were the very
		// unlock that just happened) fires BEFORE this point, so a scan at that
		// moment would have found nothing yet. Refreshing now instead of
		// waiting for the next full lock/unlock cycle was a real bug fix: the
		// mount would otherwise sit unserved (any read against it just hangs)
		// until something else happened to unlock again.
		if err := agentClient.Refresh(); err != nil {
			fmt.Fprintln(w)
			_, _ = cWarn.Fprintf(w, "Warning: could not tell the running service about the new mount(s): %v\n", err)
			bold("Run `jit service status`, or `jit lock` then unlock again, to pick it up.")
			return
		}
		if justInstalled {
			fmt.Fprintln(w, "\njit's background service is now set up (starts automatically at login) and serving the new mount(s).")
		} else {
			fmt.Fprintln(w, "\njit's background service is already running and now serving the new mount(s).")
		}
	}
	switch {
	case agentClient.Reachable():
		if producedMount {
			refreshMounts(false)
		}
		// Agent already running, nothing mount-related to refresh: shell-
		// config/MCP/AWS/kubeconfig already resolve transparently through the
		// running agent's shared session — nothing new to say.
	case agentInstalled():
		// Installed but not answering — crashed or mid-restart. Don't reinstall
		// on top of it; point at restart, the same guidance every other surface
		// gives for this state (installedNotRunningAdvice).
		bold("%s", hlCmds(installedNotRunningAdvice("jit's background service")))
	default:
		// Never installed. Set it up silently now — this used to be the single
		// next step every migrate run ended by telling the user to run
		// themselves. Doing it for them is the whole
		// point of the agent being part of the app, not a separate step.
		didInstall, running := ensureAgentInstalled()
		switch {
		case running && producedMount:
			refreshMounts(true)
		case running:
			fmt.Fprintln(w, "\njit's background service is now set up and starts automatically at login, so kubectl/AWS CLI/MCP hosts/new shells share one unlocked session instead of each prompting Touch ID.")
		case didInstall:
			// Plist written but the socket hasn't answered yet (launchd still
			// spawning). It'll be up momentarily; don't send the user off to
			// reinstall something that's already installed.
			fmt.Fprintln(w, hlCmds("\njit's background service is starting up in the background (give `jit service status` a few seconds); it'll serve your mounts and share one unlocked session across tools."))
		case producedMount:
			// Auto-install failed outright — fall back to the original nudge.
			bold("Run `jit service restart` to start serving the new mount(s), and so kubectl/AWS CLI/MCP hosts/new shells don't each need their own Touch ID prompt.")
		default:
			bold("Run `jit service restart` so kubectl/AWS CLI/MCP hosts/new shells don't each need their own Touch ID prompt, some of those run headless and would otherwise hang waiting for one.")
		}
	}
}
