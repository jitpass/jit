// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/fatih/color"

	"github.com/jitpass/jit/internal/migrate"
)

// This file is the migrate PLAN rendering — the single printMigratePlan
// path both --dry-run's preview and the real confirmation prompt share
// (GAPS.md #26's no-drift guarantee), plus its category/scope-split
// helpers. Split out of migrate.go (command wiring + runMigrate) the same
// way mountmanager.go was split out of agent.go; the mutation-log side
// lives in migratesummary.go.

// printMigratePlan prints what a run in this scope is about to do — the
// SAME rendering used for both --dry-run's preview and the real
// confirmation prompt right before mutating, so the two can never drift
// apart (GAPS.md #26; GAPS.md #17 for the confirmation gate itself).
//
// Every category label states the user-visible OUTCOME, never jit's
// internal mechanism. "vault + jit run wrapper" and "vault + exec
// plugin" describe jit's own mechanism, not what changes for the
// developer reading this — a developer who's never read RFC.md doesn't
// need to know what an "exec plugin" is to understand "kubectl keeps
// working, the token just isn't sitting in the file anymore." The
// mechanism name is still in `jit migrate --help`'s Long text for
// whoever wants it.
//
// The plan is split into two groups instead of one flat list of six
// categories. `jit migrate local` never discovers shell config/AWS/
// kubeconfig at all — they have no project-scoped component, so "local"
// (only what's under this directory tree) means they simply don't
// apply — and DiscoverMCPConfigs/DiscoverNpmrcFiles only include their
// fixed Claude Desktop/global-~/.npmrc path when wholeHome is true, for
// the same reason. Only a `home` run can ever populate the
// "machine-wide" group below; `local`'s plan is always just "scoped to
// this run." This replaced an earlier design where every category was
// always discovered regardless of scope and each got its own per-item
// dim scope note explaining why it showed up anyway — a real, reported
// point of confusion ("I asked for local, why am I seeing home paths?")
// that a note alone didn't fix, because the underlying discovery still
// disagreed with what the subcommand name promised. mcpConfigs/
// npmrcFiles are still split item-by-item within a `home` run
// (splitMCPByScope/splitNpmrcByScope) since a single Discover* call
// there still mixes the fixed path in with items found by the
// whole-$HOME walk.
func printMigratePlan(w io.Writer, home string, wholeHome bool, envFiles, shellConfigs, mcpConfigs, awsProfiles, k8sUsers, terraformHosts, gcpADCFiles, npmrcFiles, revealHookFiles []string) {
	scope := "local"
	if wholeHome {
		scope = "home"
	}
	fmt.Fprintf(w, "jit migrate, plan (%s scope)\n", scope)
	fmt.Fprintln(w, "Each modified file is backed up before it's rewritten.")
	fmt.Fprintln(w)

	// scopedTree deliberately reads as "under the current directory
	// tree"/"anywhere under $HOME" (not just the trailing noun phrase) —
	// TestMigrateHomeLabelMentionsHome checks for these exact phrases.
	scopedTree := "under the current directory tree"
	if wholeHome {
		scopedTree = "anywhere under $HOME"
	}

	// Split by scope BEFORE display-shortening — the split compares against
	// full fixed paths (Claude Desktop's config, the global ~/.npmrc), and a
	// "~"-shortened copy would never match them.
	mcpScoped, mcpFixed := splitMCPByScope(home, mcpConfigs)
	npmrcScoped, npmrcFixed := splitNpmrcByScope(home, npmrcFiles)

	shorten := func(items []string) []string {
		out := make([]string, len(items))
		for i, item := range items {
			out[i] = displayPath(home, item)
		}
		return out
	}

	hasScoped := len(envFiles) > 0 || len(mcpScoped) > 0 || len(npmrcScoped) > 0 || len(revealHookFiles) > 0
	hasFixed := len(shellConfigs) > 0 || len(mcpFixed) > 0 || len(awsProfiles) > 0 || len(k8sUsers) > 0 || len(terraformHosts) > 0 || len(gcpADCFiles) > 0 || len(npmrcFixed) > 0

	if hasScoped {
		_, _ = color.New(color.Bold).Fprintf(w, "Scoped to this run, %s\n\n", scopedTree)
		printMigratePlanCategoryAnnotated(w,
			".env file(s) → secrets move to the vault; the file keeps working as a live, auto-updating mount",
			shorten(envFiles),
			func(item string) string {
				if migrate.IsEnvBackupOnlySuffix(filepath.Base(item)) {
					return "backup-suffixed, replaced with a safe pointer file instead, never mounted"
				}
				return ""
			})
		printMigratePlanCategory(w,
			"MCP config(s) → secrets move to the vault; injected automatically when the server launches",
			shorten(mcpScoped))
		printMigratePlanCategory(w,
			"npmrc file(s) → secrets move to the vault; the file keeps working via a live, auto-updating mount",
			shorten(npmrcScoped))
		// The reveal-hook wiring rewrites a file the categories above never
		// name (issue #3: `--dry-run` promised the full plan while
		// package.json changed invisibly) — so it's a planned change like
		// any other, listed and counted.
		printMigratePlanCategory(w,
			"project hook file(s) → a `jit agent reveal` pre-run line is added (npm predev/prestart or .envrc) so the mounts above show real values right before they're read",
			shorten(revealHookFiles))
	}

	if hasFixed {
		_, _ = color.New(color.Faint).Fprintln(w, "Machine-wide config files, only included on a home-scope run")
		fmt.Fprintln(w)
		printMigratePlanCategory(w,
			"shell config(s) → secrets move to the vault; loaded back automatically when your shell starts",
			shorten(shellConfigs))
		printMigratePlanCategory(w,
			"MCP config(s) → secrets move to the vault; injected automatically when the server launches",
			shorten(mcpFixed))
		// AWS/kubeconfig/Terraform items are profile/user/host NAMES, not
		// paths — nothing to shorten.
		printMigratePlanCategory(w,
			"AWS profile(s) in ~/.aws/credentials → secrets move to the vault; fetched automatically when the AWS CLI/SDK needs them",
			awsProfiles)
		printMigratePlanCategory(w,
			"kubeconfig user(s) in ~/.kube/config → secrets move to the vault; fetched automatically whenever kubectl runs",
			k8sUsers)
		printMigratePlanCategory(w,
			"Terraform Cloud host(s) in ~/.terraform.d/credentials.tfrc.json → tokens move to the vault; fetched automatically whenever terraform runs",
			terraformHosts)
		printMigratePlanCategory(w,
			"GCP application-default credentials → secrets move to the vault; the file keeps working via a live, auto-updating mount",
			shorten(gcpADCFiles))
		printMigratePlanCategory(w,
			"npmrc file(s) → secrets move to the vault; the file keeps working via a live, auto-updating mount",
			shorten(npmrcFixed))

		// --only filters by CATEGORY, not by this scoped/machine-wide
		// split — selecting "mcp" or "npmrc" always pulls in their own
		// always-checked fixed file too (Claude Desktop's config, global
		// ~/.npmrc), since that file is inherent to the category, not a
		// separate scope switch. "env" is the one category with no
		// machine-wide sibling at all, so it's the only token that
		// actually guarantees zero items from this section — recommending
		// mcp/npmrc here would promise something --only can't do (a real
		// bug, caught by a user testing `--only mcp` and still seeing
		// Claude Desktop's config in the plan).
		if len(envFiles) > 0 {
			caveat := ""
			if len(mcpScoped) > 0 || len(npmrcScoped) > 0 {
				caveat = " (mcp/npmrc still pull in their own always-checked file above when selected)"
			}
			_, _ = color.New(color.FgYellow).Fprintf(w, "  Use --only env to leave these machine-wide files out of the plan%s.\n\n", caveat)
		}
	}

	categories, total := 0, 0
	for _, items := range [][]string{envFiles, shellConfigs, mcpConfigs, awsProfiles, k8sUsers, terraformHosts, gcpADCFiles, npmrcFiles, revealHookFiles} {
		if len(items) > 0 {
			categories++
		}
		total += len(items)
	}
	fmt.Fprintln(w, strings.Repeat("─", 44))
	fmt.Fprintf(w, "  %d change(s) planned across %d %s\n", total, categories, pluralWord(categories, "category", "categories"))
}

// planRevealHooks predicts which project hook files (.envrc/package.json)
// wireRevealHooks will edit after mutation, so the plan and --dry-run list
// them and count them (issue #3: package.json was rewritten by every npm-
// project migrate yet never appeared in the plan, the change count, or the
// undo list). Mirrors runMigrate's recordRevealHook calls exactly: every
// .env that will become a live mount (backup-suffixed ones become pointer
// files instead) plus every project-local .npmrc, grouped per directory
// the way wireRevealHooks batches them. Best-effort like the wiring
// itself — a directory whose prediction errors is simply left out.
func planRevealHooks(home string, envFiles, npmrcFiles []string) []string {
	var dirs []string
	byDir := map[string][]string{}
	add := func(path string) {
		dir := filepath.Dir(path)
		if _, seen := byDir[dir]; !seen {
			dirs = append(dirs, dir)
		}
		byDir[dir] = append(byDir[dir], path)
	}
	for _, envPath := range envFiles {
		if migrate.IsEnvBackupOnlySuffix(filepath.Base(envPath)) {
			continue // replaced with a pointer file, never mounted, no hook
		}
		add(envPath)
	}
	for _, npmrcPath := range npmrcFiles {
		if npmrcPath == migrate.GlobalNpmrcPath(home) {
			continue // not tied to any one project dir, never hooked
		}
		add(npmrcPath)
	}
	var hookFiles []string
	for _, dir := range dirs {
		hookPath, _, err := migrate.PlanRevealHook(dir, byDir[dir]...)
		if err != nil || hookPath == "" {
			continue
		}
		hookFiles = append(hookFiles, hookPath)
	}
	return hookFiles
}

// splitMCPByScope separates Claude Desktop's always-checked fixed path
// (RFC.md's home-rooted global store) from any project-scoped
// mcp.json/.mcp.json findings in the same DiscoverMCPConfigs result, so
// printMigratePlan can render them in different sections instead of
// implying both are subject to the same local/home scope rule.
func splitMCPByScope(home string, mcpConfigs []string) (scoped, fixed []string) {
	claudePath := migrate.ClaudeDesktopConfigPath(home)
	for _, path := range mcpConfigs {
		if path == claudePath {
			fixed = append(fixed, path)
		} else {
			scoped = append(scoped, path)
		}
	}
	return scoped, fixed
}

// splitNpmrcByScope separates the always-checked global ~/.npmrc from any
// project-scoped .npmrc findings in the same DiscoverNpmrcFiles result —
// same reasoning as splitMCPByScope.
func splitNpmrcByScope(home string, npmrcFiles []string) (scoped, fixed []string) {
	globalPath := migrate.GlobalNpmrcPath(home)
	for _, path := range npmrcFiles {
		if path == globalPath {
			fixed = append(fixed, path)
		} else {
			scoped = append(scoped, path)
		}
	}
	return scoped, fixed
}

// printMigratePlanCategory renders one category's bracketed headline
// (the user-visible outcome, never jit's internal mechanism name) and
// its items as bullets — a no-op if items is empty. Matches jit
// audit's [Category] section convention (internal/audit/report.go) so
// every jit report reads the same way. Which of printMigratePlan's two
// groups a category's items appear under is what now conveys why those
// paths were checked (see printMigratePlan's doc comment), so this no
// longer prints a per-category scope note the way it used to.
func printMigratePlanCategory(w io.Writer, headline string, items []string) {
	printMigratePlanCategoryAnnotated(w, headline, items, nil)
}

// printMigratePlanCategoryAnnotated is printMigratePlanCategory, plus an
// optional per-item note appended to a bullet when annotate returns
// non-empty — used by .env's own category (GAPS.md #34) so a backup-
// suffixed file's different real outcome (replaced with a pointer file,
// never mounted) is visible right on its own bullet, instead of the
// category headline's "the file keeps working as a live mount" promise
// silently not applying to every item it covers.
func printMigratePlanCategoryAnnotated(w io.Writer, headline string, items []string, annotate func(string) string) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(w, "[%s] (%d)\n", headline, len(items))
	for _, item := range items {
		note := ""
		if annotate != nil {
			note = annotate(item)
		}
		if note != "" {
			fmt.Fprintf(w, "  • %s (%s)\n", item, note)
		} else {
			fmt.Fprintf(w, "  • %s\n", item)
		}
	}
	fmt.Fprintln(w)
}
