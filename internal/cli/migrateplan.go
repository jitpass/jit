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
// helpers. Split out of migrate.go (command wiring + discovery) the same
// way mountmanager.go was split out of agent.go; the mutation-log side
// lives in migratesummary.go.

// printMigratePlan prints what a run is about to do — the SAME rendering
// used for both --dry-run's preview and the real confirmation prompt right
// before mutating, so the two can never drift apart (GAPS.md #26; GAPS.md
// #17 for the confirmation gate itself).
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
// The plan is split into two groups instead of one flat list: project
// files the caller named (or found under a named directory) vs. the
// machine-wide fixed-path files they named explicitly. A migrate run only
// ever converts what was named, so both groups appear only because the
// caller asked for their contents. mcpConfigs/npmrcFiles are still split
// item-by-item (splitMCPByScope/splitNpmrcByScope) since Claude Desktop's
// config / the global ~/.npmrc belong in the machine-wide group while a
// project mcp.json/.npmrc belongs with the scoped files.
func printMigratePlan(w io.Writer, home string, envFiles, tfvarsFiles, shellConfigs, mcpConfigs, awsProfiles, k8sUsers, terraformHosts, dockerRegistries, gitHosts, gcpADCFiles, sopsAgeFiles, npmrcFiles, netrcFiles, looseSecretFiles []string) {
	fmt.Fprintln(w, "jit migrate, plan")
	fmt.Fprintln(w, "Each modified file is backed up before it's rewritten.")
	fmt.Fprintln(w)

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

	hasScoped := len(envFiles) > 0 || len(tfvarsFiles) > 0 || len(mcpScoped) > 0 || len(npmrcScoped) > 0 || len(looseSecretFiles) > 0
	hasFixed := len(shellConfigs) > 0 || len(mcpFixed) > 0 || len(awsProfiles) > 0 || len(k8sUsers) > 0 || len(terraformHosts) > 0 || len(dockerRegistries) > 0 || len(gitHosts) > 0 || len(gcpADCFiles) > 0 || len(sopsAgeFiles) > 0 || len(npmrcFixed) > 0 || len(netrcFiles) > 0

	if hasScoped {
		_, _ = color.New(color.Bold).Fprintf(w, "Project files you named\n\n")
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
			"Terraform tfvars file(s) → secret values move to the vault; terraform reads them back as TF_VAR_ environment variables when run through jit",
			shorten(tfvarsFiles))
		printMigratePlanCategory(w,
			"MCP config(s) → secrets move to the vault; injected automatically when the server launches",
			shorten(mcpScoped))
		printMigratePlanCategory(w,
			"npmrc file(s) → secrets move to the vault; the file keeps working via a live, auto-updating mount",
			shorten(npmrcScoped))
		looseHeadline := "loose secret file(s) → the whole file is a bare token; it moves to the vault and the file is replaced with a git-safe pointer (retrieve with `jit vault get`)"
		if migrateMount {
			looseHeadline = "loose secret file(s) → the secret(s) move to the vault; the file stays live at its path as a mount (real value to `jit run` grants, a decoy otherwise), non-secret content preserved"
		}
		printMigratePlanCategory(w, looseHeadline, shorten(looseSecretFiles))
	}

	if hasFixed {
		// These appear only because the caller named a machine-wide file (or
		// its exact path) explicitly — a migrate run never reaches them on its
		// own, so the header states plainly that the caller asked for them.
		_, _ = color.New(color.Faint).Fprintln(w, "Machine-wide config files you named")
		fmt.Fprintln(w)
		printMigratePlanCategory(w,
			"shell config(s) → secrets move to the vault; loaded back automatically when your shell starts",
			shorten(shellConfigs))
		printMigratePlanCategory(w,
			"MCP config(s) → secrets move to the vault; injected automatically when the server launches",
			shorten(mcpFixed))
		// AWS/kubeconfig/Terraform/Docker items are profile/user/host/
		// registry NAMES, not paths — nothing to shorten.
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
			"Docker registry credential(s) in ~/.docker/config.json → credentials move to the vault; fetched automatically whenever docker needs them (docker login/logout keep working)",
			dockerRegistries)
		printMigratePlanCategory(w,
			"git HTTPS host(s) in ~/.git-credentials → credentials move to the vault; fetched automatically whenever git pushes/fetches over HTTPS (credential.helper set to jit)",
			gitHosts)
		printMigratePlanCategory(w,
			"GCP application-default credentials → secrets move to the vault; the file keeps working via a live, auto-updating mount",
			shorten(gcpADCFiles))
		printMigratePlanCategory(w,
			"SOPS age key file(s) → the key moves to the vault; sops/kluctl keep working via a live, auto-updating mount (or sops's own SOPS_AGE_KEY_CMD hook)",
			shorten(sopsAgeFiles))
		printMigratePlanCategory(w,
			"npmrc file(s) → secrets move to the vault; the file keeps working via a live, auto-updating mount",
			shorten(npmrcFixed))
		printMigratePlanCategory(w,
			"~/.netrc password(s) → secrets move to the vault; the file keeps working via a live, auto-updating mount (login/machine lines untouched)",
			shorten(netrcFiles))

		// --only filters by CATEGORY, not by this scoped/machine-wide
		// split — selecting "mcp" or "npmrc" always pulls in their own
		// always-checked fixed file too (Claude Desktop's config, global
		// ~/.npmrc), since that file is inherent to the category, not a
		// separate scope switch. "env" and "tfvars" are the only categories
		// with no machine-wide sibling at all, so they're the only tokens
		// that actually guarantee zero items from this section — recommending
		// mcp/npmrc here would promise something --only can't do (a real
		// bug, caught by a user testing `--only mcp` and still seeing
		// Claude Desktop's config in the plan).
		var onlyTokens []string
		if len(envFiles) > 0 {
			onlyTokens = append(onlyTokens, "env")
		}
		if len(tfvarsFiles) > 0 {
			onlyTokens = append(onlyTokens, "tfvars")
		}
		if len(onlyTokens) > 0 {
			caveat := ""
			if len(mcpScoped) > 0 || len(npmrcScoped) > 0 {
				caveat = " (mcp/npmrc still pull in their own always-checked file above when selected)"
			}
			_, _ = color.New(color.FgYellow).Fprintf(w, "  Use --only %s to leave these machine-wide files out of the plan%s.\n\n", strings.Join(onlyTokens, ","), caveat)
		}
	}

	categories, total := 0, 0
	for _, items := range [][]string{envFiles, tfvarsFiles, shellConfigs, mcpConfigs, awsProfiles, k8sUsers, terraformHosts, dockerRegistries, gitHosts, gcpADCFiles, sopsAgeFiles, npmrcFiles, netrcFiles, looseSecretFiles} {
		if len(items) > 0 {
			categories++
		}
		total += len(items)
	}
	fmt.Fprintln(w, strings.Repeat("─", 44))
	fmt.Fprintf(w, "  %d change(s) planned across %d %s\n", total, categories, pluralWord(categories, "category", "categories"))
}

// splitMCPByScope separates Claude Desktop's always-checked fixed path
// (RFC.md's home-rooted global store) from any project-scoped
// mcp.json/.mcp.json findings in the same DiscoverMCPConfigs result, so
// printMigratePlan can render them in different sections instead of
// implying both belong in the same section of the plan.
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

// planSectionRule is the faint underline beneath each category header,
// the same width jit scan's [Category] sections use
// (internal/audit/report.go) so both reports read as one house style.
var planSectionRule = strings.Repeat("─", 35)

// splitHeadline separates a category headline's short NAME from its longer
// "→ outcome" clause. The two used to render jammed together inside one set
// of brackets — `[loose secret file(s) → the whole file is a bare token; it
// moves to the vault and …] (1)` — which was a wall of text hard to scan.
// Split, the name anchors a bold header and the outcome drops to its own
// line, matching how scan renders a bold [Category] over its detail.
func splitHeadline(headline string) (name, outcome string) {
	if i := strings.Index(headline, " → "); i >= 0 {
		return headline[:i], headline[i+len(" → "):]
	}
	return headline, ""
}

// printMigratePlanCategoryAnnotated is printMigratePlanCategory, plus an
// optional per-item note appended to a bullet when annotate returns
// non-empty — used by .env's own category (GAPS.md #34) so a backup-
// suffixed file's different real outcome (replaced with a pointer file,
// never mounted) is visible right on its own bullet, instead of the
// category headline's "the file keeps working as a live mount" promise
// silently not applying to every item it covers.
//
// The block mirrors jit scan's [Category] layout: a bold `[name] (count)`
// header, a faint rule, then the "→ outcome" description on its own faint
// line above the file bullets — one consistent report shape across the app,
// and far easier on the eyes than the old one-line bracketed headline.
func printMigratePlanCategoryAnnotated(w io.Writer, headline string, items []string, annotate func(string) string) {
	if len(items) == 0 {
		return
	}
	name, outcome := splitHeadline(headline)
	_, _ = color.New(color.Bold).Fprintf(w, "[%s] (%d)\n", name, len(items))
	_, _ = color.New(color.Faint).Fprintf(w, "  %s\n", planSectionRule)
	if outcome != "" {
		_, _ = color.New(color.Faint).Fprintf(w, "  → %s\n", outcome)
	}
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
