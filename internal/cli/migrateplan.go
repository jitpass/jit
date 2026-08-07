// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/jitpass/jit/internal/audit"
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
// printMigratePlan renders the "what jit will rewrite" plan.
//
// It takes *discovered rather than the seventeen positional []string it used
// to, and that is a correctness change, not tidying: every argument had the
// same type, so transposing any two compiled, ran, and mislabelled the plan --
// showing the user one category's files under another category's heading, on
// the screen whose whole job is to obtain informed consent before rewriting
// them. Named fields make the same mistake a compile error.
func printMigratePlan(w io.Writer, home string, d *discovered) {
	fmt.Fprintln(w, "jit migrate, plan")
	fmt.Fprintln(w, "Each modified file is backed up before it's rewritten.")
	fmt.Fprintln(w)

	// Split by scope BEFORE display-shortening — the split compares against
	// full fixed paths (Claude Desktop's config, the global ~/.npmrc), and a
	// "~"-shortened copy would never match them.
	mcpScoped, mcpFixed := splitMCPByScope(home, d.mcpConfigs)
	npmrcScoped, npmrcFixed := splitNpmrcByScope(home, d.npmrcFiles)

	shorten := func(items []string) []string {
		out := make([]string, len(items))
		for i, item := range items {
			out[i] = displayPath(home, item)
		}
		return out
	}

	// shorten() rewrites each path for display, so the annotate callbacks
	// need a way back to the real one — same shape as envOriginal below.
	mcpOriginal := make(map[string]string, len(d.mcpConfigs))
	for _, p := range d.mcpConfigs {
		mcpOriginal[shorten([]string{p})[0]] = p
	}

	hasScoped := len(d.envFiles) > 0 || len(d.tfvarsFiles) > 0 || len(d.k8sManifests) > 0 || len(mcpScoped) > 0 || len(npmrcScoped) > 0 || len(d.looseSecretFiles) > 0
	hasFixed := len(d.shellConfigs) > 0 || len(d.historyFiles) > 0 || len(mcpFixed) > 0 || len(d.awsProfiles) > 0 || len(d.k8sUsers) > 0 || len(d.terraformHosts) > 0 || len(d.dockerRegistries) > 0 || len(d.gitHosts) > 0 || len(d.gcpADCFiles) > 0 || len(d.sopsAgeFiles) > 0 || len(npmrcFixed) > 0 || len(d.netrcFiles) > 0 || len(d.pypircFiles) > 0

	if hasScoped {
		// The annotation callback below is handed the display-shortened path,
		// which can't be opened; keep the mapping back to the real one so each
		// .env can be counted.
		envOriginal := make(map[string]string, len(d.envFiles))
		for _, p := range d.envFiles {
			envOriginal[displayPath(home, p)] = p
		}
		_, _ = cBold.Fprintf(w, "Project files you named\n\n")
		printMigratePlanCategoryAnnotated(w,
			pluralWord(len(d.envFiles), ".env file", ".env files")+" "+glyphAction+" EVERY variable moves to the vault (ordinary config too, so the file still works); the file keeps working as a live, auto-updating mount",
			shorten(d.envFiles),
			func(item string) string {
				if migrate.IsEnvBackupOnlySuffix(filepath.Base(item)) {
					return "backup-suffixed, replaced with a safe pointer file instead, never mounted"
				}
				// Per-file counts, because "3 change(s)" (three FILES) was the
				// only number the plan gave for an operation that moves every
				// variable in each of them into the vault.
				total, shaped, ok := migrate.EnvFilePreview(envOriginal[item])
				if !ok || total == 0 {
					return ""
				}
				if shaped == 0 {
					return countWord(total, "variable", "variables")
				}
				return fmt.Sprintf("%s, %d secret-shaped", countWord(total, "variable", "variables"), shaped)
			})
		printMigratePlanCategory(w,
			pluralWord(len(d.tfvarsFiles), "Terraform tfvars file", "Terraform tfvars files")+" "+glyphAction+" secret values move to the vault; terraform reads them back as TF_VAR_ environment variables when run through jit",
			shorten(d.tfvarsFiles))
		k8sOriginal := make(map[string]string, len(d.k8sManifests))
		for _, p := range d.k8sManifests {
			k8sOriginal[displayPath(home, p)] = p
		}
		printMigratePlanCategoryAnnotated(w,
			pluralWord(len(d.k8sManifests), "Kubernetes Secret manifest", "Kubernetes Secret manifests")+" "+glyphAction+" secret values move to the vault; the manifest stays at its path as a live mount: `jit run -- kubectl apply` gets real values, anything else gets decoys kubectl rejects",
			shorten(d.k8sManifests),
			func(item string) string {
				secrets, converts, ok := migrate.K8sManifestPreview(k8sOriginal[item])
				if !ok {
					return ""
				}
				note := countWord(secrets, "secret", "secrets")
				if converts {
					note += ", stringData: becomes data:, same Secret in the cluster"
				}
				return note
			})
		printMigratePlanCategoryAnnotated(w,
			pluralWord(len(mcpScoped), "MCP config", "MCP configs")+" "+glyphAction+" secrets move to the vault; injected automatically when the server launches",
			shorten(mcpScoped), func(item string) string {
				// The user named a config file; this names the OTHER file on
				// disk the run will rewrite into a pointer. Without it the
				// plan said "1 change" for a run that touches two files.
				targets := migrate.MCPEnvFilePreview(mcpOriginal[item])
				if len(targets) == 0 {
					return ""
				}
				short := make([]string, 0, len(targets))
				for _, t := range targets {
					short = append(short, shortHome(t))
				}
				return "also rewrites " + strings.Join(short, ", ")
			})
		printMigratePlanCategory(w,
			pluralWord(len(npmrcScoped), "npmrc file", "npmrc files")+" "+glyphAction+" secrets move to the vault; the file keeps working via a live, auto-updating mount",
			shorten(npmrcScoped))
		looseName := pluralWord(len(d.looseSecretFiles), "loose secret file", "loose secret files")
		looseHeadline := looseName + " " + glyphAction + " the whole file is a bare token; it moves to the vault and the file is replaced with a git-safe pointer (retrieve with `jit vault get`)"
		if migrateMount {
			looseHeadline = looseName + " " + glyphAction + " the " + pluralWord(len(d.looseSecretFiles), "secret moves", "secrets move") + " to the vault; the file stays live at its path as a mount (real value to `jit run` grants, a decoy otherwise), non-secret content preserved"
		}
		printMigratePlanCategory(w, looseHeadline, shorten(d.looseSecretFiles))
	}

	if hasFixed {
		// These appear only because the caller named a machine-wide file (or
		// its exact path) explicitly — a migrate run never reaches them on its
		// own, so the header states plainly that the caller asked for them.
		_, _ = fmt.Fprintln(w, "Machine-wide config files you named")
		fmt.Fprintln(w)
		printMigratePlanCategory(w,
			pluralWord(len(d.shellConfigs), "shell config", "shell configs")+" "+glyphAction+" secrets move to the vault; loaded back automatically when your shell starts",
			shorten(d.shellConfigs))
		historyOriginal := make(map[string]string, len(d.historyFiles))
		for _, p := range d.historyFiles {
			historyOriginal[displayPath(home, p)] = p
		}
		printMigratePlanCategoryAnnotated(w,
			pluralWord(len(d.historyFiles), "shell history file", "shell history files")+" "+glyphAction+" recorded credentials move to the vault, every occurrence is redacted in place; your commands stay, the secrets don't (rotation still recommended)",
			shorten(d.historyFiles),
			func(item string) string {
				secrets, occ, err := migrate.PreviewShellHistory(historyOriginal[item])
				if err != nil || secrets == 0 {
					return ""
				}
				if occ == secrets {
					return countWord(secrets, "secret", "secrets")
				}
				return fmt.Sprintf("%s across %s", countWord(secrets, "secret", "secrets"), countWord(occ, "occurrence", "occurrences"))
			})
		printMigratePlanCategoryAnnotated(w,
			pluralWord(len(mcpFixed), "MCP config", "MCP configs")+" "+glyphAction+" secrets move to the vault; injected automatically when the server launches",
			shorten(mcpFixed), func(item string) string {
				// The user named a config file; this names the OTHER file on
				// disk the run will rewrite into a pointer. Without it the
				// plan said "1 change" for a run that touches two files.
				targets := migrate.MCPEnvFilePreview(mcpOriginal[item])
				if len(targets) == 0 {
					return ""
				}
				short := make([]string, 0, len(targets))
				for _, t := range targets {
					short = append(short, shortHome(t))
				}
				return "also rewrites " + strings.Join(short, ", ")
			})
		// AWS/kubeconfig/Terraform/Docker items are profile/user/host/
		// registry NAMES, not paths — nothing to shorten.
		printMigratePlanCategory(w,
			pluralWord(len(d.awsProfiles), "AWS profile", "AWS profiles")+" in ~/.aws/credentials "+glyphAction+" secrets move to the vault; fetched automatically when the AWS CLI/SDK needs them",
			d.awsProfiles)
		printMigratePlanCategory(w,
			pluralWord(len(d.k8sUsers), "kubeconfig user", "kubeconfig users")+" in ~/.kube/config "+glyphAction+" secrets move to the vault; fetched automatically whenever kubectl runs",
			d.k8sUsers)
		printMigratePlanCategory(w,
			pluralWord(len(d.terraformHosts), "Terraform Cloud host", "Terraform Cloud hosts")+" in ~/.terraform.d/credentials.tfrc.json "+glyphAction+" tokens move to the vault; fetched automatically whenever terraform runs",
			d.terraformHosts)
		printMigratePlanCategory(w,
			pluralWord(len(d.dockerRegistries), "Docker registry credential", "Docker registry credentials")+" in ~/.docker/config.json "+glyphAction+" credentials move to the vault; fetched automatically whenever docker needs them (docker login/logout keep working)",
			d.dockerRegistries)
		printMigratePlanCategory(w,
			pluralWord(len(d.gitHosts), "git HTTPS host", "git HTTPS hosts")+" in ~/.git-credentials "+glyphAction+" credentials move to the vault; fetched automatically whenever git pushes/fetches over HTTPS (credential.helper set to jit)",
			d.gitHosts)
		printMigratePlanCategory(w,
			"GCP application-default credentials "+glyphAction+" secrets move to the vault; the file keeps working via a live, auto-updating mount",
			shorten(d.gcpADCFiles))
		printMigratePlanCategory(w,
			pluralWord(len(d.sopsAgeFiles), "SOPS age key file", "SOPS age key files")+" "+glyphAction+" the "+pluralWord(len(d.sopsAgeFiles), "key moves", "keys move")+" to the vault; sops/kluctl keep working via a live, auto-updating mount (or sops's own SOPS_AGE_KEY_CMD hook)",
			shorten(d.sopsAgeFiles))
		printMigratePlanCategory(w,
			pluralWord(len(npmrcFixed), "npmrc file", "npmrc files")+" "+glyphAction+" secrets move to the vault; the file keeps working via a live, auto-updating mount",
			shorten(npmrcFixed))
		printMigratePlanCategory(w,
			pluralWord(len(d.netrcFiles), "~/.netrc password", "~/.netrc passwords")+" "+glyphAction+" secrets move to the vault; the file keeps working via a live, auto-updating mount (login/machine lines untouched)",
			shorten(d.netrcFiles))
		printMigratePlanCategory(w,
			pluralWord(len(d.pypircFiles), "~/.pypirc credential", "~/.pypirc credentials")+" "+glyphAction+" secrets move to the vault; the file keeps working via a live, auto-updating mount (repository/username lines untouched)",
			shorten(d.pypircFiles))

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
		if len(d.envFiles) > 0 {
			onlyTokens = append(onlyTokens, "env")
		}
		if len(d.tfvarsFiles) > 0 {
			onlyTokens = append(onlyTokens, "tfvars")
		}
		if len(onlyTokens) > 0 {
			caveat := ""
			if len(mcpScoped) > 0 || len(npmrcScoped) > 0 {
				caveat = " (mcp/npmrc still pull in their own always-checked file above when selected)"
			}
			_, _ = cWarn.Fprintf(w, "  Use --only %s to leave these machine-wide files out of the plan%s.\n\n", strings.Join(onlyTokens, ","), caveat)
		}
	}

	categories, total := 0, 0
	for _, items := range [][]string{d.envFiles, d.tfvarsFiles, d.k8sManifests, d.shellConfigs, d.historyFiles, d.mcpConfigs, d.awsProfiles, d.k8sUsers, d.terraformHosts, d.dockerRegistries, d.gitHosts, d.gcpADCFiles, d.sopsAgeFiles, d.npmrcFiles, d.netrcFiles, d.pypircFiles, d.looseSecretFiles} {
		if len(items) > 0 {
			categories++
		}
		total += len(items)
	}
	fmt.Fprintln(w, strings.Repeat(glyphRule, 44))
	fmt.Fprintf(w, "  %s planned across %s\n", countWord(total, "change", "changes"), countWord(categories, "category", "categories"))
}

// splitMCPByScope separates Claude Desktop's always-checked fixed path
// (RFC.md's home-rooted global store) from any project-scoped
// mcp.json/.mcp.json findings in the same DiscoverMCPConfigs result, so
// printMigratePlan can render them in different sections instead of
// implying both belong in the same section of the plan.
func splitMCPByScope(home string, mcpConfigs []string) (scoped, fixed []string) {
	fixedPaths := map[string]bool{}
	for _, p := range audit.FixedMCPConfigPaths(home) {
		fixedPaths[p] = true
	}
	for _, path := range mcpConfigs {
		if fixedPaths[path] {
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

// splitHeadline separates a category headline's short NAME from its longer
// "→ outcome" clause. The two used to render jammed together inside one set
// of brackets — `[loose secret file(s) → the whole file is a bare token; it
// moves to the vault and …] (1)` — which was a wall of text hard to scan.
// Split, the name anchors the bracketed header and the outcome drops to its
// own line, matching how scan renders a [Category] over its detail.
func splitHeadline(headline string) (name, outcome string) {
	if i := strings.Index(headline, " "+glyphAction+" "); i >= 0 {
		return headline[:i], headline[i+len(" "+glyphAction+" "):]
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
// The block mirrors jit scan's [Category] layout: a `[name]` header in default
// weight with a plain count (rule 1 — not bold, and no parens around the
// count), no rule, then the "→ outcome" description on its own
// line above the file bullets — one consistent report shape across the app,
// and far easier on the eyes than the old one-line bracketed headline.
func printMigratePlanCategoryAnnotated(w io.Writer, headline string, items []string, annotate func(string) string) {
	if len(items) == 0 {
		return
	}
	name, outcome := splitHeadline(headline)
	fmt.Fprintf(w, "[%s]", name)
	_, _ = fmt.Fprintf(w, " %d\n", len(items))
	if outcome != "" {
		_, _ = fmt.Fprintf(w, "  "+glyphAction+" %s\n", outcome)
	}
	for _, item := range items {
		note := ""
		if annotate != nil {
			note = annotate(item)
		}
		if note != "" {
			fmt.Fprintf(w, "  "+glyphBullet+" %s (%s)\n", item, note)
		} else {
			fmt.Fprintf(w, "  "+glyphBullet+" %s\n", item)
		}
	}
	fmt.Fprintln(w)
}
