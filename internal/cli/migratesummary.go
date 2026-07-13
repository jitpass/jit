// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

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
// already applied to jit audit's human report.
type migrateSummary struct {
	// home is the user's home directory, used to "~"-shorten the paths
	// this summary displays (the recorded strings below are display-only;
	// nothing re-reads them as paths).
	home            string
	gitHistoryFiles []string
	pointerFiles    int
	hooksWired      []string
	hooksMissing    []string
	hookErrors      []string
	backupOnlyFiles int
	// pendingHookDirs/pendingHookPaths buffer recordRevealHook calls so
	// wireRevealHooks can install each directory's hooks in ONE
	// InstallRevealHook call — a per-mount call re-edited (and re-backed-
	// up) the same package.json once per mount, leaving several
	// near-identical .jit-bak siblings from a single migrate run.
	pendingHookDirs  []string
	pendingHookPaths map[string][]string
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
	p, err := profile.LoadFile(profilePath)
	if err != nil {
		return fmt.Errorf("loading profile to write pointer file: %w", err)
	}
	if err := migrate.WritePointerFile(mountPath, p); err != nil {
		return err
	}
	s.pointerFiles++
	return nil
}

// recordRevealHook queues mountPath for an automatic `jit agent reveal`
// trigger in dir's pre-run hook (GAPS.md #2's ergonomic layer on top of
// the decoy-by-default mount — see migrate.InstallRevealHook for why this
// is best-effort and deliberately narrow). Buffered, not installed
// immediately: wireRevealHooks later installs each directory's queued
// mounts in one InstallRevealHook call, so one migrate run edits (and
// backs up) a given .envrc/package.json exactly once no matter how many
// mounts the directory produced.
func (s *migrateSummary) recordRevealHook(dir, mountPath string) {
	if s.pendingHookPaths == nil {
		s.pendingHookPaths = map[string][]string{}
	}
	if _, seen := s.pendingHookPaths[dir]; !seen {
		s.pendingHookDirs = append(s.pendingHookDirs, dir)
	}
	s.pendingHookPaths[dir] = append(s.pendingHookPaths[dir], mountPath)
}

// wireRevealHooks installs every queued reveal hook, one InstallRevealHook
// call per directory, and records the per-mount outcomes for print. A
// failure here is a warning, not a migrate-ending error: the manual
// `jit agent reveal` command and the automatic post-unlock reveal window both
// still work with no hook installed at all.
func (s *migrateSummary) wireRevealHooks() {
	for _, dir := range s.pendingHookDirs {
		paths := s.pendingHookPaths[dir]
		kind, err := migrate.InstallRevealHook(dir, paths...)
		for _, mountPath := range paths {
			switch {
			case err != nil:
				s.hookErrors = append(s.hookErrors, fmt.Sprintf("%s: %v", displayPath(s.home, mountPath), err))
			case kind != migrate.RevealHookNone:
				s.hooksWired = append(s.hooksWired, fmt.Sprintf("%s (%s)", displayPath(s.home, mountPath), kind))
			default:
				s.hooksMissing = append(s.hooksMissing, displayPath(s.home, mountPath))
			}
		}
	}
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
		fmt.Fprintf(w, "%d backup-suffixed file(s) (.bak/.old/.orig/.backup) had their secrets moved to the vault but were never mounted — nothing reads a backup file live, so each was replaced with a safe pointer file instead of a FIFO.\n", s.backupOnlyFiles)
	}
	if len(s.gitHistoryFiles) > 0 {
		sep()
		_, _ = color.New(color.FgYellow).Fprintf(w, "⚠ %d file(s) migrated already have git history — jit migrate does not scrub it:\n", len(s.gitHistoryFiles))
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
		fmt.Fprintf(w, "%d git-safe .pointers file(s) written alongside the mount(s) above — list vault paths only, safe to open or commit.\n", s.pointerFiles)
	}
	if len(s.hooksWired) > 0 {
		sep()
		fmt.Fprintf(w, "Wired an automatic reveal trigger for %d mount(s) so real values are ready right before they're read:\n", len(s.hooksWired))
		for _, h := range s.hooksWired {
			fmt.Fprintf(w, "  • %s\n", h)
		}
	}
	if len(s.hooksMissing) > 0 {
		sep()
		fmt.Fprintf(w, "%d mount(s) have no project-level pre-run hook (direnv/.envrc or npm dev/start scripts):\n", len(s.hooksMissing))
		for _, p := range s.hooksMissing {
			fmt.Fprintf(w, "  • %s\n", p)
		}
		fmt.Fprintln(w, "  Run `jit agent reveal <path>` before reading one of these, or rely on the short window after unlock.")
	}
	if len(s.hookErrors) > 0 {
		sep()
		fmt.Fprintf(w, "%d mount(s) failed to wire an automatic reveal trigger:\n", len(s.hookErrors))
		for _, e := range s.hookErrors {
			fmt.Fprintf(w, "  • %s\n", e)
		}
		fmt.Fprintln(w, "  Run `jit agent reveal <path>` by hand before reading one of these, or rely on the short window after unlock.")
	}
	if s.exportNudge {
		sep()
		_, _ = color.New(color.FgYellow).Fprintln(w, "⚠ These secrets now live only in this Mac's vault, and no passphrase-encrypted backup of it has ever been made — run `jit vault export <file>` once (`jit status` will say when it needs refreshing).")
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
	switch {
	case !agentClient.Reachable() && producedMount:
		bold("Run `jit agent install` to start serving the new mount(s), and so kubectl/AWS CLI/MCP hosts/new shells don't each need their own Touch ID prompt.")
	case !agentClient.Reachable():
		bold("Run `jit agent install` so kubectl/AWS CLI/MCP hosts/new shells don't each need their own Touch ID prompt — some of those run headless and would otherwise hang waiting for one.")
	case producedMount:
		// Its own OnUnlock (if this migrate run's vault writes were the
		// very unlock that just happened) fires BEFORE this point, so a
		// scan at that moment would have found nothing yet. Waiting for
		// the next full lock/unlock cycle instead of refreshing now was a
		// real bug: the mount would sit unserved (any read against it
		// just hangs) until something else happened to unlock again.
		if err := agentClient.Refresh(); err != nil {
			fmt.Fprintln(w)
			_, _ = color.New(color.FgYellow).Fprintf(w, "Warning: could not tell the running agent about the new mount(s): %v\n", err)
			bold("Run `jit agent status`, or `jit agent lock` then unlock again, to pick it up.")
		} else {
			fmt.Fprintln(w, "\njit agent is already running and now serving the new mount(s).")
		}
	}
	// Agent already running, nothing mount-related to refresh: shell-
	// config/MCP/AWS/kubeconfig already resolve transparently through the
	// running agent's shared session — nothing new to say.
}
