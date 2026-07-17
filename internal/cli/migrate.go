// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/vault"
)

var (
	migrateDryRun          bool
	migrateYes             bool
	migrateOnly            []string
	migrateIncludeArchived bool
)

// migrateCategories are the --only tokens real (non---dry-run) migrate
// accepts (GAPS.md #21), in the same order printMigratePlan reports them.
// Keyed by the short token a caller passes, not the display label used in
// output — keep the two lists in this exact order so error messages and
// --only's own help text stay in sync with printMigratePlan.
var migrateCategories = []string{"env", "shell", "mcp", "aws", "kube", "terraform", "gcp", "npmrc"}

// noteNamespaceMove explains a claimNamespace bump (GAPS.md #55) directly
// under the item it happened to. Yellow, matching the "heads up, read
// this" advisory convention: a vault namespace that doesn't match the
// project's own directory name reads as a bug when left unexplained, and
// the reader should know the other namespace holds a DIFFERENT secret
// under the same variable name before assuming the two are interchangeable.
func noteNamespaceMove(w io.Writer, movedFrom, profileName string) {
	if movedFrom == "" {
		return
	}
	_, _ = color.New(color.FgYellow).Fprintf(w, "    note: vault namespace %q already holds a different migration's secrets — this file's secrets live under %q instead\n", movedFrom, profileName)
}

// filterMigrateOnly validates only (the raw --only tokens) against
// migrateCategories and returns the set of selected categories. An unknown
// token fails loud rather than being silently ignored — a typo'd category
// name should never look like "nothing found" once the confirmation
// prompt already fired.
func filterMigrateOnly(only []string) (map[string]bool, error) {
	valid := make(map[string]bool, len(migrateCategories))
	for _, c := range migrateCategories {
		valid[c] = true
	}
	selected := make(map[string]bool, len(only))
	for _, token := range only {
		if !valid[token] {
			return nil, fmt.Errorf("unknown --only category %q (valid: %s)", token, strings.Join(migrateCategories, ", "))
		}
		selected[token] = true
	}
	return selected, nil
}

var migrateCmd = &cobra.Command{
	Use:     "migrate",
	GroupID: groupWorkflow,
	Short:   "Guided fix path for findings jit audit reports",
	Long: "jit migrate moves the plaintext secrets jit audit finds into the encrypted\n" +
		"vault and rewrites each file so everything keeps working without the secret\n" +
		"sitting on disk. It's a separate command from jit audit, not a flag on it,\n" +
		"so the read-only scanner can never be turned into a mutating one by a\n" +
		"mistyped flag.\n\n" +
		"Pick a scope:\n\n" +
		"  jit migrate local   only what's under the current directory tree\n" +
		"                       (.env files, project mcp.json, project .npmrc)\n" +
		"  jit migrate home    the whole machine: everything local finds, anywhere\n" +
		"                       under $HOME, plus the machine-wide files that live at\n" +
		"                       fixed home paths (shell configs, ~/.aws/credentials,\n" +
		"                       ~/.kube/config, Terraform Cloud credentials, GCP\n" +
		"                       application-default credentials, Claude Desktop's MCP\n" +
		"                       config, the global ~/.npmrc)\n\n" +
		"Every run prints the full plan and asks for confirmation before touching\n" +
		"anything, and every modified file is backed up (encrypted, into the vault)\n" +
		"first — `jit migrate undo` restores any migrated file from that backup.\n" +
		"See each subcommand's --help for exactly what happens to each kind of file.",
	Example: "  jit migrate local --dry-run    # preview this project's plan, change nothing\n" +
		"  jit migrate local              # fix this project\n" +
		"  jit migrate home --only aws,kube\n" +
		"  jit migrate undo               # restore migrated files from their backups",
}

var migrateLocalCmd = &cobra.Command{
	Use:   "local",
	Short: "Convert findings under the current directory only",
	Long: "Converts findings under the current directory tree ONLY — nothing outside\n" +
		"the project you're standing in is discovered or touched. Machine-wide files\n" +
		"(shell configs, AWS, kubeconfig, Terraform Cloud, GCP application-default\n" +
		"credentials, Claude Desktop's config, the global ~/.npmrc) live at fixed\n" +
		"paths under $HOME, so only `jit migrate home` ever includes them.\n\n" +
		"What happens per category:\n\n" +
		"  .env files   Keys move into a profile and the vault; the file itself keeps\n" +
		"               working as a live mount served by jit agent, showing\n" +
		"               fake-looking values until revealed (`jit agent reveal` — wired\n" +
		"               automatically into an existing .envrc or package.json\n" +
		"               dev/start script when one exists). A git-safe <file>.pointers\n" +
		"               companion is written alongside, listing vault paths only —\n" +
		"               always safe to open or commit.\n" +
		"  MCP configs  Each server's env-block secrets move into the vault, and the\n" +
		"               server's command is rewritten to launch via `jit run`.\n" +
		"  .npmrc       Secret lines move into the vault; the file keeps working as a\n" +
		"               live mount, with non-secret settings preserved verbatim.\n\n" +
		"Migrating never scrubs git history: a value that was ever committed stays\n" +
		"recoverable via `git log -p` regardless — jit warns per file instead of\n" +
		"implying \"migrated = safe\".",
	Example: "  jit migrate local --dry-run\n" +
		"  jit migrate local --only env",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runMigrate(cmd, false)
	},
}

var migrateHomeCmd = &cobra.Command{
	Use:   "home",
	Short: "Convert findings anywhere under $HOME — the whole machine, not just this project",
	Long: "Converts findings anywhere under $HOME — the whole machine, not just this\n" +
		"project. Covers everything `jit migrate local` does (see its --help for the\n" +
		"per-category detail), discovered across every project under $HOME, plus the\n" +
		"machine-wide files that live at fixed home paths:\n\n" +
		"  Shell configs    Secret-shaped `export KEY=value` lines in .zshrc/.bashrc/\n" +
		"                   etc. move into the vault; the file loads them back via\n" +
		"                   `eval \"$(jit export --profile ...)\"` instead.\n" +
		"  AWS              ~/.aws/credentials profiles move into the vault; the AWS\n" +
		"                   CLI/SDK fetches them live via a credential_process line\n" +
		"                   in ~/.aws/config — no keys on disk at all.\n" +
		"  kubeconfig       A user's bearer token or client-certificate pair moves\n" +
		"                   into the vault; kubectl fetches it via an exec block.\n" +
		"  Terraform Cloud  ~/.terraform.d/credentials.tfrc.json tokens move into the\n" +
		"                   vault; terraform fetches them through its own\n" +
		"                   credentials-helper protocol (`terraform login`/`logout`\n" +
		"                   keep working). Fails loud, before touching anything, if a\n" +
		"                   different credentials helper is already configured.\n" +
		"  GCP              ~/.config/gcloud/application_default_credentials.json's\n" +
		"                   refresh token (or a service account key's private key)\n" +
		"                   moves into the vault; the file keeps working as a live\n" +
		"                   mount — Google SDKs read the same path, non-secret fields\n" +
		"                   preserved verbatim. (GCP has no AWS-style\n" +
		"                   credential_process hook for these credential types, so\n" +
		"                   the mount is what keeps SDKs working with no key on disk.)\n" +
		"  Claude Desktop's MCP config and the global ~/.npmrc get the same\n" +
		"  treatment as project MCP configs and .npmrc files.\n\n" +
		"Skips anything under an archived/backup-looking directory (archive,\n" +
		"archived, backup, backups, .trash) unless --include-archived: converting a\n" +
		"forgotten project's .env into a live mount nobody will ever serve again\n" +
		"would make it unreadable, which is worse than plaintext.",
	Example: "  jit migrate home --dry-run\n" +
		"  jit migrate home --only aws,kube\n" +
		"  jit migrate home --include-archived",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runMigrate(cmd, true)
	},
}

// runMigrate implements both jit migrate local (wholeHome=false) and
// jit migrate home (wholeHome=true). wholeHome changes which root the
// .env/MCP/npmrc Discover* calls walk (cwd vs $HOME), AND whether
// shell config/AWS/kubeconfig/Claude Desktop's config/global ~/.npmrc
// are discovered at all — those five have no project-scoped form, so
// `local` (only what's under this directory tree) must skip them
// entirely, not just narrow their walk. Sharing one function for
// discovery, --only filtering, plan printing, confirmation, and apply is
// what guarantees --dry-run's preview and a real run's actual behavior
// can never drift apart the way a single whole-machine-scanning --dry-run
// used to (GAPS.md #26): both paths call the exact same discovery with
// the exact same root before branching on migrateDryRun.
func runMigrate(cmd *cobra.Command, wholeHome bool) error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("jit migrate: %w", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("jit migrate: %w", err)
	}

	projectRoot := cwd
	if wholeHome {
		projectRoot = home
	}

	envFiles, err := migrate.DiscoverEnvFiles(projectRoot)
	if err != nil {
		return fmt.Errorf("jit migrate: %w", err)
	}
	mcpConfigs, err := migrate.DiscoverMCPConfigs(home, projectRoot, wholeHome)
	if err != nil {
		return fmt.Errorf("jit migrate: %w", err)
	}
	npmrcFiles, err := migrate.DiscoverNpmrcFiles(home, projectRoot, wholeHome)
	if err != nil {
		return fmt.Errorf("jit migrate: %w", err)
	}

	// Shell config/AWS/kubeconfig have no project-scoped component at
	// all — they live at exactly one fixed path under $HOME regardless
	// of cwd. `local` means "only what's under this directory tree," so
	// it must never discover them; only `home`'s whole-machine sweep
	// does. This is what makes `local` actually match its name (a real,
	// reported point of confusion when both scopes always included
	// these — see GAPS.md #26).
	var shellConfigs, awsProfiles, k8sUsers, terraformHosts, gcpADCFiles []string
	if wholeHome {
		shellConfigs, err = migrate.DiscoverShellConfigs(home)
		if err != nil {
			return fmt.Errorf("jit migrate: %w", err)
		}
		awsProfiles, err = migrate.DiscoverAWSProfiles(home)
		if err != nil {
			return fmt.Errorf("jit migrate: %w", err)
		}
		k8sUsers, err = migrate.DiscoverKubeconfigUsers(home)
		if err != nil {
			return fmt.Errorf("jit migrate: %w", err)
		}
		terraformHosts, err = migrate.DiscoverTerraformHosts(home)
		if err != nil {
			return fmt.Errorf("jit migrate: %w", err)
		}
		gcpADCFiles, err = migrate.DiscoverGCPADC(home)
		if err != nil {
			return fmt.Errorf("jit migrate: %w", err)
		}
	}

	// Whole-machine sweeps skip anything that looks archived/backed-up by
	// default (GAPS.md #26) — see archived.go's doc comment for why a
	// live-mounted pipe is a worse outcome than plaintext for a project
	// nobody will run `jit agent` from again. `local` never filters:
	// deliberately cd-ing into an old project and running `migrate local`
	// is an explicit action, not an implicit sweep, so there's nothing to
	// protect the caller from.
	var skippedArchived []string
	if wholeHome && !migrateIncludeArchived {
		var skipped []string
		envFiles, skipped = migrate.FilterArchived(envFiles)
		skippedArchived = append(skippedArchived, skipped...)
		mcpConfigs, skipped = migrate.FilterArchived(mcpConfigs)
		skippedArchived = append(skippedArchived, skipped...)
		npmrcFiles, skipped = migrate.FilterArchived(npmrcFiles)
		skippedArchived = append(skippedArchived, skipped...)
	}

	// --only scopes a run to just the named categories (GAPS.md #21) —
	// validated against migrateCategories BEFORE anything else, including
	// the "nothing to migrate" check below, so a typo'd category name
	// fails loud rather than silently reporting nothing found. Discovery
	// above always runs for every category regardless of --only,
	// deliberately: it's cheap, read-only, and keeps this filter a pure
	// post-discovery narrowing rather than a second, diverging discovery
	// path to keep in sync.
	// One token→slice table drives the --only filter and the emptiness
	// check. The guard right below is what actually keeps it in sync with
	// migrateCategories: filterMigrateOnly validates tokens against that
	// list, but the nil-out loop iterates THIS map — an eighth category
	// added there but forgotten here would silently survive --only and be
	// migrated even when the user explicitly excluded it. Fail loud
	// instead, on every run, before anything is filtered or mutated.
	categorySlices := map[string]*[]string{
		"env":       &envFiles,
		"shell":     &shellConfigs,
		"mcp":       &mcpConfigs,
		"aws":       &awsProfiles,
		"kube":      &k8sUsers,
		"terraform": &terraformHosts,
		"gcp":       &gcpADCFiles,
		"npmrc":     &npmrcFiles,
	}
	if len(categorySlices) != len(migrateCategories) {
		return fmt.Errorf("jit migrate: internal error: category table (%d) out of sync with --only categories (%d)", len(categorySlices), len(migrateCategories))
	}
	for _, token := range migrateCategories {
		if _, ok := categorySlices[token]; !ok {
			return fmt.Errorf("jit migrate: internal error: --only category %q has no entry in the category table", token)
		}
	}
	if len(migrateOnly) > 0 {
		selected, err := filterMigrateOnly(migrateOnly)
		if err != nil {
			return fmt.Errorf("jit migrate: %w", err)
		}
		for token, items := range categorySlices {
			if !selected[token] {
				*items = nil
			}
		}
	}

	total := 0
	for _, items := range categorySlices {
		total += len(*items)
	}
	if total == 0 {
		if len(migrateOnly) > 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "Nothing to migrate in the selected --only %s: %s.\n", pluralWord(len(migrateOnly), "category", "categories"), strings.Join(migrateOnly, ", "))
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), "Nothing to migrate: no .env files, no secret-shaped shell-config exports, no MCP")
			fmt.Fprintln(cmd.OutOrStdout(), "server secrets, no AWS/kubeconfig/Terraform Cloud/GCP credentials, and no npmrc secrets found.")
		}
		if len(skippedArchived) > 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "(%d finding(s) skipped under an archived/backup-looking directory — rerun with --include-archived to include them.)\n", len(skippedArchived))
		}
		return nil
	}

	// A real, reported point of confusion: the ONLY "this is a preview"
	// signal used to be the "[DRY RUN]" disclaimer at the very END of the
	// plan — after every category, every file, every scope note. A
	// reader skimming a long plan (or one who stops reading partway
	// through) could easily mistake it for a description of changes
	// already made, especially once the plan's own leading line ("Each
	// modified file is backed up before it's rewritten.") reads like a
	// statement of fact rather than a preview of what a real run would
	// do. Printing the same cyan/bold "[DRY RUN]" banner BEFORE the plan
	// too — not just after — means that risk exists for at most one line,
	// not the whole plan. printMigratePlan itself stays unaware of
	// migrateDryRun (this banner is printed here, at the call site, not
	// inside it) specifically so it keeps rendering the exact same plan
	// for --dry-run and the real confirmation prompt (GAPS.md #26's core
	// guarantee) — see TestMigrateLocalDryRunMatchesRealPlanExactly.
	if migrateDryRun {
		_, _ = color.New(color.FgCyan, color.Bold).Fprintln(cmd.OutOrStdout(), "[DRY RUN] Preview — this run changes nothing; the plan below is what a real run would do.")
		fmt.Fprintln(cmd.OutOrStdout())
	}

	// Confirm before touching anything — vault set/rm both gate a single
	// secret behind [y/N], but migrate can rewrite shell configs, MCP
	// configs, AWS config, kubeconfig, and npmrc in one invocation with
	// no equivalent gate (GAPS.md #17). Deliberately placed BEFORE
	// openVault(): declining must never trigger a Touch ID prompt for
	// work that's about to be aborted anyway. This same plan is what
	// --dry-run prints too (see below) — one rendering path, so the
	// preview you confirm against is exactly the preview --dry-run shows.
	printMigratePlan(cmd.OutOrStdout(), home, wholeHome, envFiles, shellConfigs, mcpConfigs, awsProfiles, k8sUsers, terraformHosts, gcpADCFiles, npmrcFiles, planRevealHooks(home, envFiles, npmrcFiles))
	if len(skippedArchived) > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "\n(Skipped %d finding(s) under an archived/backup-looking directory — rerun with --include-archived to include them.)\n", len(skippedArchived))
	}

	if migrateDryRun {
		out := cmd.OutOrStdout()
		fmt.Fprintln(out)
		_, _ = color.New(color.FgCyan, color.Bold).Fprint(out, "[DRY RUN]")
		fmt.Fprintln(out, " No files were changed. Run without --dry-run to apply this plan.")
		_, _ = color.New(color.FgYellow).Fprintln(out, "This only covers what jit migrate can act on — run `jit audit` for a complete picture, including findings it can never auto-fix, like private keys.")
		return nil
	}

	if !migrateYes && !confirmPrompt(cmd, "Proceed? [y/N] ") {
		fmt.Fprintln(cmd.OutOrStdout(), "Aborted. Nothing was changed.")
		return nil
	}

	v, err := openVault()
	if err != nil {
		return fmt.Errorf("jit migrate: %w", err)
	}
	root, err := vaultRootDir()
	if err != nil {
		return fmt.Errorf("jit migrate: %w", err)
	}
	registryPath := mount.RegistryPath(root)

	out := cmd.OutOrStdout()
	summary := &migrateSummary{home: home}

	// One tracker for the whole run: AWS/kube/terraform each migrate several
	// units (profiles/users/hosts) out of ONE shared file in a per-unit loop
	// below, and without this each unit's Apply would back that file up again
	// after the previous unit already stripped it — undo then restores the
	// last, most-degraded snapshot and silently loses the earlier units'
	// secrets (GAPS.md #65). Threading the same tracker makes the first
	// (pristine) backup of each shared file the only one.
	backups := migrate.NewBackupTracker()

	// Each migrated category gets the same "[Label] (N)" header + bullet
	// shape the plan itself already uses (printMigratePlan/
	// printMigratePlanCategory) — a real, reported problem: this log used
	// to be a flat run of long, unbroken sentences (path, profile name,
	// variable count, mount status, and backup path all crammed into one
	// line each), visually disconnected from the plan's own grouped,
	// bulleted style directly above it. printMigrateResultCategory is the
	// shared header+bullet renderer both use.
	if n := len(envFiles); n > 0 {
		printMigrateResultCategory(out, ".env file(s) migrated", n)
		for _, envPath := range envFiles {
			summary.checkGitHistory(envPath)

			// profilesRoot must be the file's OWN project directory in
			// wholeHome mode, never the invoking cwd: deriveProfileName
			// computes a relative path from profilesRoot to the file's
			// directory, and in home mode a discovered .env can be under
			// a completely unrelated project. Passing cwd there would
			// silently derive a nonsensical profile name/path
			// disconnected from the project the secret actually came
			// from. In local mode every discovered file is genuinely
			// under cwd, so cwd is correct and unchanged — this only
			// branches for wholeHome.
			envProfilesRoot := cwd
			if wholeHome {
				envProfilesRoot = filepath.Dir(envPath)
			}
			result, err := migrate.ApplyEnvFile(v, envProfilesRoot, envPath)
			if err != nil {
				return fmt.Errorf("jit migrate: %w", err)
			}
			// A backup-suffixed file (.bak/.old/.orig/.backup) never
			// became a live mount at all (GAPS.md #34) — ApplyEnvFile
			// replaced it in place with a pointer file instead, so
			// there's no mount to register, no separate .pointers
			// companion to write alongside it (EnvPath already IS the
			// pointer file), and nothing to reveal.
			if !result.Mounted {
				summary.backupOnlyFiles++
				fmt.Fprintf(out, "  • %s -> profile %q (%d var(s)); backup: `jit vault get %s` — replaced with a safe pointer file (never mounted; nothing reads a backup file live)\n",
					displayPath(home, envPath), result.ProfileName, len(result.Variables), result.BackupPath)
				noteNamespaceMove(out, result.NamespaceMovedFrom, result.ProfileName)
				continue
			}
			if err := mount.AddMount(registryPath, mount.Entry{MountPath: result.EnvPath, ProfilePath: result.ProfilePath}); err != nil {
				return fmt.Errorf("jit migrate: registering mount for %s: %w", result.EnvPath, err)
			}
			if err := summary.writePointerFile(result.EnvPath, result.ProfilePath); err != nil {
				return fmt.Errorf("jit migrate: %w", err)
			}
			fmt.Fprintf(out, "  • %s -> profile %q (%d var(s)); backup: `jit vault get %s`\n", displayPath(home, envPath), result.ProfileName, len(result.Variables), result.BackupPath)
			noteNamespaceMove(out, result.NamespaceMovedFrom, result.ProfileName)
			summary.recordRevealHook(filepath.Dir(result.EnvPath), result.EnvPath)
		}
		fmt.Fprintln(out)
	}

	if n := len(shellConfigs); n > 0 {
		printMigrateResultCategory(out, "shell config(s) migrated", n)
		for _, shellPath := range shellConfigs {
			summary.checkGitHistory(shellPath)

			result, err := migrate.ApplyShellConfig(v, shellPath)
			if err != nil {
				return fmt.Errorf("jit migrate: %w", err)
			}
			fmt.Fprintf(out, "  • %s -> profile %q (%d var(s)); backup: `jit vault get %s` — open a new shell (or `source %s`)\n",
				displayPath(home, shellPath), result.ProfileName, len(result.Variables), result.BackupPath, displayPath(home, shellPath))
		}
		fmt.Fprintln(out)
	}

	if n := len(mcpConfigs); n > 0 {
		printMigrateResultCategory(out, "MCP config(s) migrated", n)
		for _, mcpPath := range mcpConfigs {
			summary.checkGitHistory(mcpPath)

			result, err := migrate.ApplyMCPConfig(v, mcpPath)
			if err != nil {
				return fmt.Errorf("jit migrate: %w", err)
			}
			for _, sm := range result.Servers {
				fmt.Fprintf(out, "  • %s server %q -> profile %q (%d var(s)); backup: `jit vault get %s`\n",
					displayPath(home, mcpPath), sm.ServerName, sm.ProfileName, len(sm.Variables), result.BackupPath)
				noteNamespaceMove(out, sm.NamespaceMovedFrom, sm.ProfileName)
			}
		}
		fmt.Fprintln(out, "  Restart the MCP host(s) above to pick up the change.")
		fmt.Fprintln(out)
	}

	if len(awsProfiles) > 0 {
		summary.checkGitHistory(migrate.AWSCredentialsPath(home))
		printMigrateResultCategory(out, "AWS profile(s) migrated", len(awsProfiles))
		for _, awsProfile := range awsProfiles {
			result, err := migrate.ApplyAWSProfile(v, home, awsProfile, backups)
			if err != nil {
				return fmt.Errorf("jit migrate: %w", err)
			}
			backups := fmt.Sprintf("`jit vault get %s`", result.CredentialsBackup)
			if result.ConfigBackup != "" {
				backups += fmt.Sprintf(", `jit vault get %s`", result.ConfigBackup)
			}
			fmt.Fprintf(out, "  • %q -> vault profile %q (%d var(s)); backups: %s\n",
				awsProfile, result.VaultProfileName, len(result.Variables), backups)
		}
		fmt.Fprintln(out)
	}

	if len(k8sUsers) > 0 {
		summary.checkGitHistory(migrate.KubeconfigPath(home))
		printMigrateResultCategory(out, "kubeconfig user(s) migrated", len(k8sUsers))
		for _, k8sUser := range k8sUsers {
			result, err := migrate.ApplyKubeconfigUser(v, home, k8sUser, backups)
			if err != nil {
				return fmt.Errorf("jit migrate: %w", err)
			}
			fmt.Fprintf(out, "  • %q (%s) -> vault profile %q (%d var(s)); backup: `jit vault get %s`\n",
				k8sUser, result.AuthType, result.VaultProfileName, len(result.Variables), result.Backup)
		}
		fmt.Fprintln(out)
	}

	if len(terraformHosts) > 0 {
		summary.checkGitHistory(migrate.TerraformCredentialsPath(home))
		printMigrateResultCategory(out, "Terraform Cloud host(s) migrated", len(terraformHosts))
		for _, tfHost := range terraformHosts {
			result, err := migrate.ApplyTerraformHost(v, home, tfHost, backups)
			if err != nil {
				return fmt.Errorf("jit migrate: %w", err)
			}
			backups := fmt.Sprintf("`jit vault get %s`", result.CredentialsBackup)
			if result.RCBackup != "" {
				backups += fmt.Sprintf(", `jit vault get %s`", result.RCBackup)
			}
			fmt.Fprintf(out, "  • %q -> vault profile %q (%d var(s)); backups: %s\n",
				tfHost, result.VaultProfileName, len(result.Variables), backups)
		}
		fmt.Fprintln(out)
	}

	if n := len(gcpADCFiles); n > 0 {
		printMigrateResultCategory(out, "GCP application-default credentials migrated", n)
		for _, adcPath := range gcpADCFiles {
			summary.checkGitHistory(adcPath)

			result, err := migrate.ApplyGCPADC(v, home, adcPath)
			if err != nil {
				return fmt.Errorf("jit migrate: %w", err)
			}
			if err := mount.AddMount(registryPath, mount.Entry{MountPath: adcPath, ProfilePath: result.ProfilePath, TemplatePath: result.TemplatePath}); err != nil {
				return fmt.Errorf("jit migrate: registering mount for %s: %w", adcPath, err)
			}
			if err := summary.writePointerFile(adcPath, result.ProfilePath); err != nil {
				return fmt.Errorf("jit migrate: %w", err)
			}
			fmt.Fprintf(out, "  • %s (%s) -> profile %q (%d var(s)); backup: `jit vault get %s`\n",
				displayPath(home, adcPath), result.CredType, result.ProfileName, len(result.Variables), result.BackupPath)
			noteNamespaceMove(out, result.NamespaceMovedFrom, result.ProfileName)
			// Like the global ~/.npmrc: not tied to any one project
			// directory, so there's no project-level hook to wire a reveal
			// call into — the post-unlock default reveal window is what
			// makes the next SDK read work.
		}
		fmt.Fprintln(out)
	}

	if n := len(npmrcFiles); n > 0 {
		printMigrateResultCategory(out, "npmrc file(s) migrated", n)
		for _, npmrcPath := range npmrcFiles {
			summary.checkGitHistory(npmrcPath)

			globalNpmrc := npmrcPath == migrate.GlobalNpmrcPath(home)
			npmrcRoot := home
			if !globalNpmrc {
				npmrcRoot = cwd
				if wholeHome {
					npmrcRoot = filepath.Dir(npmrcPath)
				}
			}
			result, err := migrate.ApplyNpmrc(v, npmrcRoot, npmrcPath, globalNpmrc)
			if err != nil {
				return fmt.Errorf("jit migrate: %w", err)
			}
			if err := mount.AddMount(registryPath, mount.Entry{MountPath: npmrcPath, ProfilePath: result.ProfilePath, TemplatePath: result.TemplatePath}); err != nil {
				return fmt.Errorf("jit migrate: registering mount for %s: %w", npmrcPath, err)
			}
			if err := summary.writePointerFile(npmrcPath, result.ProfilePath); err != nil {
				return fmt.Errorf("jit migrate: %w", err)
			}
			fmt.Fprintf(out, "  • %s -> profile %q (%d var(s)); backup: `jit vault get %s`\n",
				displayPath(home, npmrcPath), result.ProfileName, len(result.Variables), result.BackupPath)
			noteNamespaceMove(out, result.NamespaceMovedFrom, result.ProfileName)
			if npmrcPath != migrate.GlobalNpmrcPath(home) {
				// The global ~/.npmrc isn't tied to any one project
				// directory, so there's no single project-level hook
				// (.envrc/package.json) to wire a reveal call into — only a
				// project-local .npmrc has a natural "dir" for this.
				summary.recordRevealHook(filepath.Dir(npmrcPath), npmrcPath)
			}
		}
		fmt.Fprintln(out)
	}

	// Best-effort: an unreadable marker means no nudge, never a failed
	// migrate — everything above already succeeded.
	if _, recorded, err := vault.LastExport(root); err == nil && !recorded {
		summary.exportNudge = true
	}

	summary.wireRevealHooks()
	summary.print(out)
	reportAgentStatus(out, root, len(envFiles) > 0 || len(npmrcFiles) > 0 || len(gcpADCFiles) > 0)
	return nil
}

func init() {
	migrateCmd.PersistentFlags().BoolVar(&migrateDryRun, "dry-run", false, "preview the plan for this scope without changing anything")
	migrateCmd.PersistentFlags().BoolVarP(&migrateYes, "yes", "y", false, "skip the confirmation prompt and migrate immediately")
	migrateCmd.PersistentFlags().StringSliceVar(&migrateOnly, "only", nil, "scope a run to just these comma-separated categories: "+strings.Join(migrateCategories, ",")+" (default: all)")
	migrateHomeCmd.Flags().BoolVar(&migrateIncludeArchived, "include-archived", false, "also convert findings under an archived/backup-looking directory (archive, archived, backup, backups, .trash)")

	migrateCmd.AddCommand(migrateLocalCmd, migrateHomeCmd)
	rootCmd.AddCommand(migrateCmd)
}
