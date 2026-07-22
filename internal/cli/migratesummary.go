// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"fmt"
	"io"

	"github.com/fatih/color"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/profile"
)

// This file is real migrate's MUTATION LOG rendering — the per-category
// result headers, the consolidated migrateSummary that collapses repeated
// explanations, and reportAgentStatus's closing pointer. Split out of
// migrate.go (which keeps command wiring and runMigrate's orchestration)
// the same way mountmanager.go was split out of agent.go: one concern per
// file. The plan rendering both --dry-run and the confirmation prompt
// share lives in migrateplan.go.

// printMigrateResultCategory renders the same "[Label] (N)" header the
// plan itself uses (printMigratePlanCategory) — the past-tense mutation
// log now visually matches the future-tense plan directly above it,
// instead of reading like a different tool's output.
func printMigrateResultCategory(w io.Writer, label string, n int) {
	fmt.Fprintf(w, "[%s] (%d)\n", label, n)
}

// migrateSummary collects everything that used to print inline, once per
// file, during a real migrate run's mutation loop — git-history warnings,
// pointer-file confirmations, and reveal-hook results — so it can be
// reported once, consolidated, instead of repeating the same explanation
// after every single file. A real, reported problem: a six-file run
// repeated an identical 5-line git-history paragraph six times and an
// identical 2-line "no pre-run hook" paragraph four times, more than 40
// lines of boilerplate burying the one line that actually mattered (the
// closing "run `jit agent install`" pointer). Each explanation in
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
		fmt.Fprintf(w, "%d backup-suffixed file(s) (.bak/.old/.orig/.backup) had their secrets moved to the vault but were never mounted, nothing reads a backup file live, so each was replaced with a safe pointer file instead of a FIFO.\n", s.backupOnlyFiles)
	}
	if len(s.gitHistoryFiles) > 0 {
		sep()
		_, _ = color.New(color.FgYellow).Fprintf(w, "⚠ %d file(s) migrated already have git history, jit migrate does not scrub it:\n", len(s.gitHistoryFiles))
		for _, f := range s.gitHistoryFiles {
			fmt.Fprintf(w, "  • %s\n", f)
		}
		fmt.Fprintln(w, "  Any value ever committed is still recoverable via `git log -p`/`git blame` for the life of")
		fmt.Fprintln(w, "  the repository, and by anyone who already has a clone or fork. To actually remove it,")
		fmt.Fprintln(w, "  rotate the secret and rewrite history with git-filter-repo (https://github.com/newren/")
		fmt.Fprintln(w, "  git-filter-repo) or BFG Repo-Cleaner.")
	}
	if s.pointerFiles > 0 {
		sep()
		fmt.Fprintf(w, "%d git-safe .pointers file(s) written alongside the mount(s) above, list vault paths only, safe to open or commit.\n", s.pointerFiles)
	}
	if s.exportNudge {
		sep()
		_, _ = color.New(color.FgYellow).Fprintln(w, "⚠ These secrets now live only in this Mac's vault, and no passphrase-encrypted backup of it has ever been made, run `jit vault export <file>` once (`jit status` will say when it needs refreshing).")
	}
}

// reportAgentStatus prints whether the running agent picked up new
// mounts, or nudges toward `jit agent install` if none is running — for
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
		_, _ = color.New(color.Bold).Fprintf(w, format, a...)
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
			_, _ = color.New(color.FgYellow).Fprintf(w, "Warning: could not tell the running agent about the new mount(s): %v\n", err)
			bold("Run `jit agent status`, or `jit agent lock` then unlock again, to pick it up.")
			return
		}
		if justInstalled {
			fmt.Fprintln(w, "\njit agent is now set up (starts automatically at login) and serving the new mount(s).")
		} else {
			fmt.Fprintln(w, "\njit agent is already running and now serving the new mount(s).")
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
		bold("%s", installedNotRunningAdvice("jit agent is"))
	default:
		// Never installed. Set it up silently now — this used to be the single
		// next step every migrate run ended by telling the user to run
		// themselves (`jit agent install`). Doing it for them is the whole
		// point of the agent being part of the app, not a separate step.
		didInstall, running := ensureAgentInstalled()
		switch {
		case running && producedMount:
			refreshMounts(true)
		case running:
			fmt.Fprintln(w, "\njit agent is now set up and starts automatically at login, so kubectl/AWS CLI/MCP hosts/new shells share one unlocked session instead of each prompting Touch ID.")
		case didInstall:
			// Plist written but the socket hasn't answered yet (launchd still
			// spawning). It'll be up momentarily; don't send the user off to
			// reinstall something that's already installed.
			fmt.Fprintln(w, "\njit agent is starting up in the background (give `jit agent status` a few seconds); it'll serve your mounts and share one unlocked session across tools.")
		case producedMount:
			// Auto-install failed outright — fall back to the original nudge.
			bold("Run `jit agent install` to start serving the new mount(s), and so kubectl/AWS CLI/MCP hosts/new shells don't each need their own Touch ID prompt.")
		default:
			bold("Run `jit agent install` so kubectl/AWS CLI/MCP hosts/new shells don't each need their own Touch ID prompt, some of those run headless and would otherwise hang waiting for one.")
		}
	}
}
