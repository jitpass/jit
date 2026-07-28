// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/vault"
	"github.com/jitpass/jit/internal/wrap"
)

var (
	migrateDryRun bool
	migrateYes    bool
	migrateOnly   []string
	migrateMount  bool
)

// migrateCategories are the --only tokens real (non---dry-run) migrate
// accepts (GAPS.md #21), in the same order printMigratePlan reports them.
// Keyed by the short token a caller passes, not the display label used in
// output — keep the two lists in this exact order so error messages and
// --only's own help text stay in sync with printMigratePlan.
var migrateCategories = []string{"env", "tfvars", "shell", "mcp", "aws", "kube", "terraform", "docker", "git", "gcp", "sops", "npmrc", "netrc", "pypirc", "loose"}

// discovered holds one run's findings per category. runMigratePath resolves
// each named target into one of these and hands it to applyMigrate — the
// single plan/confirm/apply path — so every migrate run gets identical
// backups, dry-run parity, pointer files, and the confirmation gate no
// matter which file(s) were named.
type discovered struct {
	envFiles          []string
	tfvarsFiles       []string
	tfvarsComplexOnly []string
	shellConfigs      []string
	mcpConfigs        []string
	awsProfiles       []string
	k8sUsers          []string
	terraformHosts    []string
	dockerRegistries  []string
	gitHosts          []string
	gcpADCFiles       []string
	sopsAgeFiles      []string
	npmrcFiles        []string
	netrcFiles        []string
	pypircFiles       []string
	looseSecretFiles  []string
	// looseEmbeddedSkipped is note-only (like tfvarsComplexOnly): files that
	// mix a secret with other content, which neutralize can't move whole.
	// Populated only without --mount; with --mount they migrate as templates
	// and land in looseSecretFiles instead.
	looseEmbeddedSkipped []string
}

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
	_, _ = color.New(color.FgYellow).Fprintf(w, "    note: vault namespace %q already holds a different migration's secrets, this file's secrets live under %q instead\n", movedFrom, profileName)
}

// noteFolderRename warns, when a project's folder has been renamed since its
// .env was migrated, that the vault still labels this project's secrets under
// the OLD folder name. Purely informational: the secrets keep working (the
// pointer files and manifests carry the frozen vault paths untouched), the
// name is just cosmetic. Shared by jit migrate (local mode) and jit status;
// stays silent unless migrate.DetectRenamedRootProject is confident.
func noteFolderRename(w io.Writer, root string) {
	oldName, newName, ok := migrate.DetectRenamedRootProject(root)
	if !ok {
		return
	}
	_, _ = color.New(color.FgYellow).Fprintf(w, "note: this project's folder was renamed after migration (migrated as %q, now %q). Nothing is broken: your secrets still work and jit keeps serving them under the original %q label, which is only cosmetic. No action is needed. Run `jit status --secrets` to see where they live, or `jit doctor` to verify the vault is healthy.\n", oldName, newName, oldName)
}

// printSkippedFindings renders one whole-machine-sweep skip note: a
// yellow headline with the count and reason, then the skipped paths
// themselves, then an optional hint line. Listing the paths is the point
// (a real, reported gap): a bare "(Skipped N finding(s)...)" count gave
// the reader no way to map a finding `jit scan` just showed them onto
// "migrate deliberately left this one alone", which reads as the tool
// losing findings rather than protecting them.
func printSkippedFindings(w io.Writer, home string, count int, reason string, paths []string, hint string) {
	if count == 0 {
		return
	}
	_, _ = color.New(color.FgYellow).Fprintf(w, "\nSkipped %d finding(s) %s:\n", count, reason)
	for _, p := range paths {
		fmt.Fprintf(w, "  - %s\n", displayPath(home, p))
	}
	if hint != "" {
		fmt.Fprintf(w, "  %s\n", hint)
	}
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
	Use:     "migrate <file-or-dir>...",
	GroupID: groupWorkflow,
	Short:   "Guided fix path for findings jit scan reports (name the file(s) to convert)",
	Long: "jit migrate moves the plaintext secrets jit scan finds into the encrypted\n" +
		"vault and rewrites each file so everything keeps working without the secret\n" +
		"sitting on disk. It's a separate command from jit scan, not a flag on it,\n" +
		"so the read-only scanner can never be turned into a mutating one by a\n" +
		"mistyped flag.\n\n" +
		"You must name the file(s) and/or folder(s) to convert — jit migrate never\n" +
		"sweeps your whole machine on its own. Nothing is discovered or touched\n" +
		"except the targets you name, so a bare `jit migrate` with no path does\n" +
		"nothing. Each target is resolved on its own:\n\n" +
		"  A file       is routed to the right category by what it is. A project file\n" +
		"               (.env, *.tfvars, mcp.json/.mcp.json, .npmrc) has its secrets\n" +
		"               moved into a profile and the vault, the file keeps working as a\n" +
		"               live mount (a git-safe <file>.pointers companion is written\n" +
		"               alongside). A machine-wide file at a known path (a shell config\n" +
		"               like ~/.zshrc, ~/.aws/credentials, ~/.kube/config, Terraform\n" +
		"               Cloud creds, ~/.docker/config.json, ~/.git-credentials, GCP\n" +
		"               application-default credentials, a SOPS age key, ~/.netrc,\n" +
		"               ~/.pypirc, Claude Desktop's MCP config, the global ~/.npmrc)\n" +
		"               is routed to that credential type's handling\n" +
		"               (credential_process, exec plugin, credential helper, or\n" +
		"               live mount, as appropriate).\n" +
		"  A directory  is walked for its .env/tfvars/mcp/npmrc findings only, never\n" +
		"               the machine-wide fixed-path files (those aren't \"under\" any\n" +
		"               project directory) — name them explicitly to convert them.\n\n" +
		"Targets are explicit, so nothing is skipped for looking archived/backup-like:\n" +
		"naming a file is itself the decision to convert it. Every run prints the full\n" +
		"plan and asks for confirmation before touching anything, and every modified\n" +
		"file is backed up (encrypted, into the vault) first, `jit migrate undo <path>`\n" +
		"restores a migrated file from that backup.",
	Example: "  jit migrate ~/proj/.env         # migrate just one file\n" +
		"  jit migrate ~/proj              # walk one project for .env/tfvars/mcp/npmrc\n" +
		"  jit migrate ~/.zshrc ~/proj/.env\n" +
		"  jit migrate ~/proj/.env --dry-run   # preview the plan, change nothing\n" +
		"  jit migrate ~/.aws/credentials --only aws\n" +
		"  jit migrate undo ~/proj/.env    # restore a migrated file from its backup",
	Args: requirePaths("jit migrate"),
	// migrateCmd carries subcommands (path/undo/remove), and cobra defaults
	// argument completion on any command that has subcommands to NoFileComp —
	// which silently suppresses the shell's file completion for the bare
	// `jit migrate <file>` form (whereas `jit scan <file>`, a leaf command,
	// gets file completion for free). Return Default here to opt file
	// completion back in, so `jit migrate tok<Tab>` offers token.txt just like
	// scan does. Cobra still lists the subcommand names alongside these.
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return nil, cobra.ShellCompDirectiveDefault
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		return runMigratePath(cmd, args)
	},
}

// migratePathCmd keeps `jit migrate path <file>...` working as an explicit
// alias of the bare `jit migrate <file>...` form — same code path, same
// behavior — so existing scripts and muscle memory don't break now that the
// path is named directly on the parent command.
var migratePathCmd = &cobra.Command{
	Use:   "path <file-or-dir>...",
	Short: "Alias for `jit migrate <file-or-dir>...`",
	Long:  "Alias for `jit migrate <file-or-dir>...` — see `jit migrate --help`.",
	Args:  requirePaths("jit migrate path"),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runMigratePath(cmd, args)
	},
}

// applyMigrate is the single plan/confirm/apply path runMigratePath funnels
// its findings through once they're gathered into d. Keeping one mutation
// path is what guarantees every migrate run gets the same encrypted backups,
// --dry-run/real-plan parity (GAPS.md #26), pointer files, mount
// registration, git-history warnings, and confirmation gate (GAPS.md #17).
// A .env/tfvars/npmrc profile name always derives from the file's OWN
// directory: an explicitly named target can sit under any project, so
// deriving from the invoking cwd would produce a nonsensical profile name
// disconnected from the secret's real home.
func applyMigrate(cmd *cobra.Command, home string, d *discovered) error {
	// Locals aliased to d's fields so the --only filter, plan, and apply
	// loops below read exactly as they did before this function was split
	// out. categorySlices points at these locals, and the --only nil-out
	// clears them, leaving d untouched (it's already served its purpose as
	// the discovery hand-off).
	envFiles := d.envFiles
	tfvarsFiles := d.tfvarsFiles
	tfvarsComplexOnly := d.tfvarsComplexOnly
	shellConfigs := d.shellConfigs
	mcpConfigs := d.mcpConfigs
	awsProfiles := d.awsProfiles
	k8sUsers := d.k8sUsers
	terraformHosts := d.terraformHosts
	dockerRegistries := d.dockerRegistries
	gitHosts := d.gitHosts
	gcpADCFiles := d.gcpADCFiles
	sopsAgeFiles := d.sopsAgeFiles
	npmrcFiles := d.npmrcFiles
	netrcFiles := d.netrcFiles
	pypircFiles := d.pypircFiles
	looseSecretFiles := d.looseSecretFiles
	looseEmbeddedSkipped := d.looseEmbeddedSkipped

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
		"tfvars":    &tfvarsFiles,
		"shell":     &shellConfigs,
		"mcp":       &mcpConfigs,
		"aws":       &awsProfiles,
		"kube":      &k8sUsers,
		"terraform": &terraformHosts,
		"docker":    &dockerRegistries,
		"git":       &gitHosts,
		"gcp":       &gcpADCFiles,
		"sops":      &sopsAgeFiles,
		"npmrc":     &npmrcFiles,
		"netrc":     &netrcFiles,
		"pypirc":    &pypircFiles,
		"loose":     &looseSecretFiles,
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
		if !selected["tfvars"] {
			tfvarsComplexOnly = nil // note-only companion of the tfvars category, scoped with it
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
			// The caller named specific target(s), so say plainly that the
			// paths they named held nothing migratable (a missing path already
			// failed loud in runMigratePath before ever reaching here).
			fmt.Fprintln(cmd.OutOrStdout(), "Nothing to migrate: none of the path(s) you named contain plaintext secrets jit can move.")
		}
		printSkippedFindings(cmd.OutOrStdout(), home, len(tfvarsComplexOnly), "in Terraform variable file(s) whose secret-shaped values aren't simple one-line strings", tfvarsComplexOnly,
			"Nothing migrate can move safely; they stay in place, and `jit scan` keeps reporting them.")
		printSkippedFindings(cmd.OutOrStdout(), home, len(looseEmbeddedSkipped), "file(s) that mix a secret with other content", looseEmbeddedSkipped,
			"Re-run with --mount to protect them in place as a live mount (the non-secret content is preserved); otherwise they stay put and `jit scan` keeps reporting them.")
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
		_, _ = color.New(color.FgCyan, color.Bold).Fprintln(cmd.OutOrStdout(), "[DRY RUN] Preview, this run changes nothing; the plan below is what a real run would do.")
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
	printMigratePlan(cmd.OutOrStdout(), home, envFiles, tfvarsFiles, shellConfigs, mcpConfigs, awsProfiles, k8sUsers, terraformHosts, dockerRegistries, gitHosts, gcpADCFiles, sopsAgeFiles, npmrcFiles, netrcFiles, pypircFiles, looseSecretFiles)
	printSkippedFindings(cmd.OutOrStdout(), home, len(tfvarsComplexOnly), "in Terraform variable file(s) whose secret-shaped values aren't simple one-line strings", tfvarsComplexOnly,
		"Nothing migrate can move safely; they stay in place, and `jit scan` keeps reporting them.")
	printSkippedFindings(cmd.OutOrStdout(), home, len(looseEmbeddedSkipped), "file(s) that mix a secret with other content", looseEmbeddedSkipped,
		"Re-run with --mount to protect them in place as a live mount (the non-secret content is preserved); otherwise they stay put and `jit scan` keeps reporting them.")

	if migrateDryRun {
		out := cmd.OutOrStdout()
		fmt.Fprintln(out)
		_, _ = color.New(color.FgCyan, color.Bold).Fprint(out, "[DRY RUN]")
		fmt.Fprintln(out, " No files were changed. Run without --dry-run to apply this plan.")
		_, _ = color.New(color.FgYellow).Fprintln(out, "This only covers what jit migrate can act on, run `jit scan` for a complete picture, including findings it can never auto-fix, like private keys.")
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

			// profilesRoot is the file's OWN project directory:
			// deriveProfileName computes a relative path from profilesRoot to
			// the file's directory, and an explicitly named .env can sit under
			// any project, so deriving from the invoking cwd would silently
			// produce a nonsensical profile name/path disconnected from the
			// project the secret actually came from.
			envProfilesRoot := filepath.Dir(envPath)
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
				fmt.Fprintf(out, "  • %s -> profile %q (%d var(s)); backup: `jit vault get %s`, replaced with a safe pointer file (never mounted; nothing reads a backup file live)\n",
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
		}
		fmt.Fprintln(out)
	}

	if n := len(looseSecretFiles); n > 0 {
		printMigrateResultCategory(out, "loose secret file(s) migrated", n)
		for _, path := range looseSecretFiles {
			summary.checkGitHistory(path)
			// profilesRoot is the file's OWN directory, same rule as .env: an
			// explicitly named loose file can sit anywhere, so its profile lives
			// alongside it, not under the invoking cwd.
			if migrateMount {
				// --mount: the file becomes a live FIFO serving a template.
				result, err := migrate.ApplyLooseSecretFileMount(v, filepath.Dir(path), path)
				if err != nil {
					return fmt.Errorf("jit migrate: %w", err)
				}
				if err := mount.AddMount(registryPath, mount.Entry{MountPath: path, ProfilePath: result.ProfilePath, TemplatePath: result.TemplatePath}); err != nil {
					return fmt.Errorf("jit migrate: registering mount for %s: %w", path, err)
				}
				if err := summary.writePointerFile(path, result.ProfilePath); err != nil {
					return fmt.Errorf("jit migrate: %w", err)
				}
				fmt.Fprintf(out, "  • %s -> profile %q (%d secret(s)); backup: `jit vault get %s`, live mount (real value to `jit run` grants, a decoy otherwise)\n",
					displayPath(home, path), result.ProfileName, len(result.Variables), result.BackupPath)
				noteNamespaceMove(out, result.NamespaceMovedFrom, result.ProfileName)
				continue
			}
			// Default: vault-and-neutralize. ApplyLooseSecretFile replaced the
			// file in place with a git-safe pointer, so there's no mount to
			// register and nothing to reveal — retrieval is `jit vault get`.
			result, err := migrate.ApplyLooseSecretFile(v, filepath.Dir(path), path)
			if err != nil {
				return fmt.Errorf("jit migrate: %w", err)
			}
			summary.backupOnlyFiles++
			fmt.Fprintf(out, "  • %s -> profile %q (%d secret(s)); backup: `jit vault get %s`, replaced with a safe pointer file (retrieve with `jit vault get %s/%s`)\n",
				displayPath(home, path), result.ProfileName, len(result.Variables), result.BackupPath, result.ProfileName, result.Variables[0])
			noteNamespaceMove(out, result.NamespaceMovedFrom, result.ProfileName)
		}
		fmt.Fprintln(out)
	}

	if n := len(tfvarsFiles); n > 0 {
		printMigrateResultCategory(out, "Terraform variable file(s) migrated", n)
		// One profile per directory: every tfvars file in a directory feeds
		// the same terraform root, so they migrate as a unit (see
		// migrate.ApplyTfvarsDir's doc comment on precedence).
		tfvarsDirs, tfvarsByDir := migrate.GroupTfvarsByDir(tfvarsFiles)
		for _, dir := range tfvarsDirs {
			for _, path := range tfvarsByDir[dir] {
				summary.checkGitHistory(path)
			}
			// Same profilesRoot rule as .env above: the directory's own path.
			result, err := migrate.ApplyTfvarsDir(v, dir, dir, tfvarsByDir[dir])
			if err != nil {
				return fmt.Errorf("jit migrate: %w", err)
			}
			backups := make([]string, len(result.Backups))
			for i, b := range result.Backups {
				backups[i] = fmt.Sprintf("`jit vault get %s`", b)
			}
			fmt.Fprintf(out, "  • %s (%d file(s)) -> profile %q (%d var(s)); backup(s): %s\n",
				displayPath(home, dir), len(result.Files), result.ProfileName, len(result.Variables), strings.Join(backups, ", "))
			noteNamespaceMove(out, result.NamespaceMovedFrom, result.ProfileName)
			if len(result.SkippedComplex) > 0 {
				_, _ = color.New(color.FgYellow).Fprintf(out, "    note: %d secret-shaped value(s) left in place, not simple one-line strings: %s\n",
					len(result.SkippedComplex), strings.Join(result.SkippedComplex, ", "))
			}
			fmt.Fprintf(out, "    run terraform through jit from that directory: jit run --profile %s -- terraform apply\n", result.ProfileName)
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
			fmt.Fprintf(out, "  • %s -> profile %q (%d var(s)); backup: `jit vault get %s`, open a new shell (or `source %s`)\n",
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

	if len(dockerRegistries) > 0 {
		summary.checkGitHistory(migrate.DockerConfigPath(home))
		printMigrateResultCategory(out, "Docker registry credential(s) migrated", len(dockerRegistries))
		claimedDefaultStore := false
		for _, dockerRegistry := range dockerRegistries {
			result, err := migrate.ApplyDockerRegistry(v, home, dockerRegistry, backups)
			if err != nil {
				return fmt.Errorf("jit migrate: %w", err)
			}
			claimedDefaultStore = claimedDefaultStore || result.ClaimedDefaultStore
			fmt.Fprintf(out, "  • %q -> vault profile %q (%d var(s)); backup: `jit vault get %s`\n",
				dockerRegistry, result.VaultProfileName, len(result.Variables), result.ConfigBackup)
		}
		if claimedDefaultStore {
			fmt.Fprintln(out, "  ~/.docker/config.json had no credential store, so jit is now its default:")
			fmt.Fprintln(out, "  a future `docker login` to ANY registry lands in the vault, not in base64.")
		}
		// Docker discovers docker-credential-jit strictly by $PATH lookup,
		// and the helper lives in jit's shim directory — reuse wrap's own
		// rc-file PATH line so the next shell (and everything it spawns,
		// docker included) resolves it. Idempotent; a machine that already
		// wrapped a tool has the line and prints nothing new here.
		rc := wrap.RcFile(home, os.Getenv("SHELL"))
		rcChanged, err := wrap.EnsurePathLine(rc)
		if err != nil {
			return fmt.Errorf("jit migrate: %w", err)
		}
		if rcChanged {
			fmt.Fprintf(out, "  Added to %s: %s\n", displayPath(home, rc), wrap.PathLine())
			fmt.Fprintln(out, "  (docker finds the credential helper via PATH, open a new shell before the next pull/push)")
		}
		fmt.Fprintln(out)
	}

	if len(gitHosts) > 0 {
		summary.checkGitHistory(migrate.GitCredentialsPath(home))
		printMigrateResultCategory(out, "git HTTPS credential(s) migrated", len(gitHosts))
		replacedStore := false
		for _, gitHost := range gitHosts {
			result, err := migrate.ApplyGitCredential(v, home, gitHost, backups)
			if err != nil {
				return fmt.Errorf("jit migrate: %w", err)
			}
			replacedStore = replacedStore || result.ReplacedStoreHelper
			backupNote := fmt.Sprintf("`jit vault get %s`", result.CredentialsBackup)
			if result.ConfigBackup != "" {
				backupNote += fmt.Sprintf(", `jit vault get %s`", result.ConfigBackup)
			}
			fmt.Fprintf(out, "  • %q -> vault profile %q (%d var(s)); backups: %s\n",
				gitHost, result.VaultProfileName, len(result.Variables), backupNote)
		}
		if replacedStore {
			fmt.Fprintln(out, "  Replaced git's plaintext `store` credential helper with jit.")
		}
		// git discovers git-credential-jit strictly by $PATH lookup, and the
		// helper lives in jit's shim directory — reuse wrap's own rc-file PATH
		// line so the next shell (and everything it spawns, git included)
		// resolves it. Idempotent; a machine that already wrapped a tool or
		// migrated docker has the line and prints nothing new here.
		rc := wrap.RcFile(home, os.Getenv("SHELL"))
		rcChanged, err := wrap.EnsurePathLine(rc)
		if err != nil {
			return fmt.Errorf("jit migrate: %w", err)
		}
		if rcChanged {
			fmt.Fprintf(out, "  Added to %s: %s\n", displayPath(home, rc), wrap.PathLine())
			fmt.Fprintln(out, "  (git finds the credential helper via PATH, open a new shell before the next push/fetch)")
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
			// A machine-global mount: usage is explicit `jit run --with` intent
			// (plan §12a), so name the tools and the command right here.
			if g, ok := globalMountGuidanceForPath(home, adcPath); ok {
				fmt.Fprintf(out, "    tools that read it (%s): jit run --with %s <command>\n", g.tools, g.name)
				fmt.Fprintf(out, "    or, to keep typing gcloud directly: jit wrap add gcloud --grant %s\n", g.name)
			}
		}
		fmt.Fprintln(out)
	}

	if n := len(sopsAgeFiles); n > 0 {
		printMigrateResultCategory(out, "SOPS age key file(s) migrated", n)
		for _, keyPath := range sopsAgeFiles {
			summary.checkGitHistory(keyPath)

			result, err := migrate.ApplySOPSAge(v, home, keyPath)
			if err != nil {
				return fmt.Errorf("jit migrate: %w", err)
			}
			if err := mount.AddMount(registryPath, mount.Entry{MountPath: keyPath, ProfilePath: result.ProfilePath, TemplatePath: result.TemplatePath}); err != nil {
				return fmt.Errorf("jit migrate: registering mount for %s: %w", keyPath, err)
			}
			if err := summary.writePointerFile(keyPath, result.ProfilePath); err != nil {
				return fmt.Errorf("jit migrate: %w", err)
			}
			fmt.Fprintf(out, "  • %s -> profile %q; backup: `jit vault get %s`\n",
				displayPath(home, keyPath), result.ProfileName, result.BackupPath)
			noteNamespaceMove(out, result.NamespaceMovedFrom, result.ProfileName)
			// Two consumption paths, user's pick: the live mount serves the
			// key file itself (any sops version, kluctl's embedded sops,
			// anything else that reads keys.txt), while sops v3.10+ can skip
			// the file entirely via its native command hook. keys.txt is a
			// machine-global mount: usage is explicit `jit run --with sops`
			// intent — print the one-liner instead.
			fmt.Fprintf(out, "    sops v3.10+ can fetch it directly: export SOPS_AGE_KEY_CMD=\"jit sops-age-key\"\n")
			fmt.Fprintf(out, "    older sops/kluctl read the mounted file: jit run --with sops -- kluctl deploy\n")
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
				npmrcRoot = filepath.Dir(npmrcPath)
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
			if npmrcPath == migrate.GlobalNpmrcPath(home) {
				if g, ok := globalMountGuidanceForPath(home, npmrcPath); ok {
					// The global ~/.npmrc is a machine-wide mount: usage is
					// explicit `jit run --with npm` intent (plan §12a).
					fmt.Fprintf(out, "    %s read it with: jit run --with %s <command>\n", g.tools, g.name)
				}
			}
		}
		fmt.Fprintln(out)
	}

	if n := len(netrcFiles); n > 0 {
		printMigrateResultCategory(out, ".netrc password(s) migrated", n)
		for _, netrcPath := range netrcFiles {
			summary.checkGitHistory(netrcPath)

			result, err := migrate.ApplyNetrc(v, home, netrcPath)
			if err != nil {
				return fmt.Errorf("jit migrate: %w", err)
			}
			if err := mount.AddMount(registryPath, mount.Entry{MountPath: netrcPath, ProfilePath: result.ProfilePath, TemplatePath: result.TemplatePath}); err != nil {
				return fmt.Errorf("jit migrate: registering mount for %s: %w", netrcPath, err)
			}
			if err := summary.writePointerFile(netrcPath, result.ProfilePath); err != nil {
				return fmt.Errorf("jit migrate: %w", err)
			}
			fmt.Fprintf(out, "  • %s -> profile %q (%d var(s)); backup: `jit vault get %s`\n",
				displayPath(home, netrcPath), result.ProfileName, len(result.Variables), result.BackupPath)
			noteNamespaceMove(out, result.NamespaceMovedFrom, result.ProfileName)
			// ~/.netrc is a machine-wide mount, same as the global ~/.npmrc:
			// usage is explicit `jit run --with netrc` intent (plan §12a).
			if g, ok := globalMountGuidanceForPath(home, netrcPath); ok {
				fmt.Fprintf(out, "    %s read it with: jit run --with %s <command>\n", g.tools, g.name)
			}
		}
		fmt.Fprintln(out)
	}

	if n := len(pypircFiles); n > 0 {
		printMigrateResultCategory(out, "~/.pypirc credential(s) migrated", n)
		for _, pypircPath := range pypircFiles {
			summary.checkGitHistory(pypircPath)

			result, err := migrate.ApplyPypirc(v, home, pypircPath)
			if err != nil {
				return fmt.Errorf("jit migrate: %w", err)
			}
			if err := mount.AddMount(registryPath, mount.Entry{MountPath: pypircPath, ProfilePath: result.ProfilePath, TemplatePath: result.TemplatePath}); err != nil {
				return fmt.Errorf("jit migrate: registering mount for %s: %w", pypircPath, err)
			}
			if err := summary.writePointerFile(pypircPath, result.ProfilePath); err != nil {
				return fmt.Errorf("jit migrate: %w", err)
			}
			fmt.Fprintf(out, "  • %s -> profile %q (%d var(s)); backup: `jit vault get %s`\n",
				displayPath(home, pypircPath), result.ProfileName, len(result.Variables), result.BackupPath)
			noteNamespaceMove(out, result.NamespaceMovedFrom, result.ProfileName)
			// ~/.pypirc is a machine-wide mount, same as ~/.netrc and the
			// global ~/.npmrc: usage is explicit `jit run --with pypi` intent
			// (plan §12a), or the per-process consent prompt by default.
			if g, ok := globalMountGuidanceForPath(home, pypircPath); ok {
				fmt.Fprintf(out, "    %s read it with: jit run --with %s <command>\n", g.tools, g.name)
			}
		}
		fmt.Fprintln(out)
	}

	// Best-effort: an unreadable marker means no nudge, never a failed
	// migrate — everything above already succeeded.
	if _, recorded, err := vault.LastExport(root); err == nil && !recorded {
		summary.exportNudge = true
	}

	summary.print(out)
	reportAgentStatus(out, root, len(envFiles) > 0 || len(npmrcFiles) > 0 || len(gcpADCFiles) > 0 || len(sopsAgeFiles) > 0 || len(netrcFiles) > 0 || len(pypircFiles) > 0)
	// The folder-rename advisory is left to `jit status`: an explicitly named
	// migrate target can sit under any project, so there's no single "this
	// project" here whose rename to flag (see noteFolderRename, still used by
	// status).
	return nil
}

// runMigratePath implements `jit migrate <file-or-dir>...` (and its `path`
// alias): convert only the file(s) and folder(s) named on the command line,
// with no directory walk beyond a named folder itself. The caller always
// names exactly what they want moved (one project's .env, a single ~/.zshrc,
// a directory of tfvars files). Each target is resolved and classified on
// its own, its findings merged into one discovered set, then handed to the
// shared applyMigrate path for the plan/confirm gate, encrypted backups, and
// undo support.
func runMigratePath(cmd *cobra.Command, targets []string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("jit migrate path: %w", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("jit migrate path: %w", err)
	}

	// Discovery walks each named directory looking for migratable secrets and
	// is otherwise silent — the plan only prints once every target has been
	// examined. A status trail on stderr keeps a large-tree scan from looking
	// hung. It's stopped before applyMigrate, which streams its own per-item
	// output to stdout (and prompts for confirmation), so the spinner never
	// overlaps a prompt. defer covers the early error returns below; the
	// explicit Stop handles the happy path before the plan is printed.
	progress := newProgress(cmd, false)
	defer progress.Stop()

	d := &discovered{}
	for _, target := range targets {
		abs := expandTilde(target, home)
		if !filepath.IsAbs(abs) {
			abs = filepath.Join(cwd, abs)
		}
		abs = filepath.Clean(abs)
		progress.Step("Scanning "+displayPath(home, abs)+" for secrets…", "Scanned "+displayPath(home, abs))

		info, err := os.Lstat(abs)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("jit migrate path: %s does not exist", displayPath(home, abs))
			}
			return fmt.Errorf("jit migrate path: %s: %w", displayPath(home, abs), err)
		}
		// A symlink is refused rather than silently followed: the walk-based
		// scopes skip symlinks precisely so migrate never rewrites through a
		// link into a target that may sit outside the tree being converted
		// (DiscoverEnvFiles' own regular-files-only guard). Naming a symlink
		// here would quietly reintroduce exactly that, so ask for the real
		// path instead of guessing which end the caller meant.
		if info.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("jit migrate path: %s is a symlink; name its target file directly", displayPath(home, abs))
		}
		if info.IsDir() {
			if err := discoverDirTarget(d, home, abs); err != nil {
				return fmt.Errorf("jit migrate path: %s: %w", displayPath(home, abs), err)
			}
			continue
		}
		if err := discoverFileTarget(d, home, abs); err != nil {
			return fmt.Errorf("jit migrate path: %s: %w", displayPath(home, abs), err)
		}
	}
	// Overlapping targets (the same file named twice, or a folder plus a
	// file inside it) would otherwise migrate a finding more than once, so
	// collapse duplicates before applyMigrate, which assumes a unique set.
	d.dedupe()

	progress.Stop() // settle the discovery trail before the plan/prompt prints
	return applyMigrate(cmd, home, d)
}

// expandTilde turns a leading ~ or ~/ into home. A login shell expands this
// before the argument ever reaches jit, but a quoted or programmatically
// supplied "~/.zshrc" would otherwise be treated as a literal relative path
// under cwd and fail the does-not-exist check.
func expandTilde(p, home string) string {
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(home, p[2:])
	}
	return p
}

// discoverDirTarget walks a named directory for project files only
// (.env/tfvars/mcp/npmrc), never the fixed machine-wide paths. Those live
// under $HOME at large rather than "inside" any project directory, so a
// folder target that happens to be $HOME must not sweep them in — a migrate
// run is deliberately narrow, converting only what was named.
func discoverDirTarget(d *discovered, home, dir string) error {
	envs, err := migrate.DiscoverEnvFiles(dir)
	if err != nil {
		return err
	}
	d.envFiles = append(d.envFiles, envs...)
	tf, tfc, err := migrate.DiscoverTfvarsFiles(dir)
	if err != nil {
		return err
	}
	d.tfvarsFiles = append(d.tfvarsFiles, tf...)
	d.tfvarsComplexOnly = append(d.tfvarsComplexOnly, tfc...)
	mcps, err := migrate.DiscoverMCPConfigs(home, dir, false)
	if err != nil {
		return err
	}
	d.mcpConfigs = append(d.mcpConfigs, mcps...)
	npms, err := migrate.DiscoverNpmrcFiles(home, dir, false)
	if err != nil {
		return err
	}
	d.npmrcFiles = append(d.npmrcFiles, npms...)
	return nil
}

// discoverFileTarget classifies one explicitly named file and routes it to
// the right category. A fixed machine-wide path (a shell config, ~/.aws/
// credentials, ~/.kube/config, ...) is matched by exact path and handed to
// that category's own machine-wide discovery, narrowed back to just this file
// for the path-keyed categories. Anything else is treated as a project file
// and run through the same single-file project discovery discoverDirTarget
// uses (WalkDir over one regular file yields just that file), so all the
// .env/tfvars/mcp/npmrc naming and secret-content rules stay in one place —
// including the global ~/.npmrc, whose global profile rooting applyMigrate
// re-derives from the path itself.
func discoverFileTarget(d *discovered, home, path string) error {
	// Shell configs: five fixed names under $HOME, each keyed by path.
	for _, p := range migrate.ShellConfigPaths(home) {
		if path == p {
			cfgs, err := migrate.DiscoverShellConfigs(home)
			if err != nil {
				return err
			}
			d.shellConfigs = append(d.shellConfigs, filterToTarget(cfgs, path)...)
			return nil
		}
	}
	// SOPS age keys: up to two fixed locations, keyed by path.
	for _, p := range migrate.SOPSAgeKeyPaths(home) {
		if path == p {
			files, err := migrate.DiscoverSOPSAge(home)
			if err != nil {
				return err
			}
			d.sopsAgeFiles = append(d.sopsAgeFiles, filterToTarget(files, path)...)
			return nil
		}
	}
	// The remaining fixed files each live at exactly one path. The name-keyed
	// categories (aws/kube/terraform/docker/git) migrate every profile/user/
	// host/registry the one file holds, so there's nothing to narrow; the
	// path-keyed ones (gcp/netrc/Claude Desktop MCP) get filterToTarget.
	switch path {
	case migrate.AWSCredentialsPath(home):
		profiles, err := migrate.DiscoverAWSProfiles(home)
		if err != nil {
			return err
		}
		d.awsProfiles = append(d.awsProfiles, profiles...)
		return nil
	case migrate.KubeconfigPath(home):
		users, err := migrate.DiscoverKubeconfigUsers(home)
		if err != nil {
			return err
		}
		d.k8sUsers = append(d.k8sUsers, users...)
		return nil
	case migrate.TerraformCredentialsPath(home):
		hosts, err := migrate.DiscoverTerraformHosts(home)
		if err != nil {
			return err
		}
		d.terraformHosts = append(d.terraformHosts, hosts...)
		return nil
	case migrate.DockerConfigPath(home):
		regs, err := migrate.DiscoverDockerRegistries(home)
		if err != nil {
			return err
		}
		d.dockerRegistries = append(d.dockerRegistries, regs...)
		return nil
	case migrate.GitCredentialsPath(home):
		creds, err := migrate.DiscoverGitCredentials(home)
		if err != nil {
			return err
		}
		for _, c := range creds {
			d.gitHosts = append(d.gitHosts, c.Host)
		}
		return nil
	case migrate.GCPADCPath(home):
		files, err := migrate.DiscoverGCPADC(home)
		if err != nil {
			return err
		}
		d.gcpADCFiles = append(d.gcpADCFiles, filterToTarget(files, path)...)
		return nil
	case migrate.NetrcPath(home):
		files, err := migrate.DiscoverNetrc(home)
		if err != nil {
			return err
		}
		d.netrcFiles = append(d.netrcFiles, filterToTarget(files, path)...)
		return nil
	case migrate.PypircPath(home):
		files, err := migrate.DiscoverPypirc(home)
		if err != nil {
			return err
		}
		d.pypircFiles = append(d.pypircFiles, filterToTarget(files, path)...)
		return nil
	case migrate.ClaudeDesktopConfigPath(home):
		// Passing path (the config file itself) as the walk root adds nothing
		// via the walk — its name isn't one of the project mcp.json names —
		// while includeClaudeDesktop=true is what actually pulls it in; the
		// filter then keeps only it.
		cfgs, err := migrate.DiscoverMCPConfigs(home, path, true)
		if err != nil {
			return err
		}
		d.mcpConfigs = append(d.mcpConfigs, filterToTarget(cfgs, path)...)
		return nil
	}
	// Not a fixed machine-wide path — treat it as a project file (.env/tfvars/
	// mcp/npmrc by name).
	before := d.total()
	if err := discoverDirTarget(d, home, path); err != nil {
		return err
	}
	// If no structured category claimed this explicitly-named file, fall back
	// to loose-secret detection: a file whose whole content is bare token(s)
	// (a JWT in token.txt) matches none of the named formats but is exactly
	// what `jit scan <file>` flags as an exposed_secret. Only "pure" secret
	// files are migratable this way — one that mixes a token with other content
	// would lose that content if replaced wholesale, so it's left alone (jit
	// scan keeps reporting it). Never runs on a directory walk, only on a file
	// the user named directly, matching the intent gate scan uses.
	if d.total() == before {
		if tokens, pure, err := migrate.ClassifyLooseSecretFile(path); err == nil && len(tokens) > 0 {
			switch {
			case pure || migrateMount:
				// A pure file neutralizes by default (or mounts with --mount);
				// an embedded file can only be protected as a template mount,
				// so it needs --mount to be migrated at all. applyMigrate reads
				// migrateMount to pick neutralize vs mount for each.
				d.looseSecretFiles = append(d.looseSecretFiles, path)
			default:
				// Embedded, no --mount: neutralizing would destroy the file's
				// non-secret content, so note it instead of moving it.
				d.looseEmbeddedSkipped = append(d.looseEmbeddedSkipped, path)
			}
		}
	}
	return nil
}

// filterToTarget keeps only the entries equal to target, narrowing a
// category's whole-$HOME discovery down to the single file the caller named
// (the path-keyed fixed categories whose Discover* returns every candidate
// under $HOME, not just the one asked for).
func filterToTarget(items []string, target string) []string {
	var out []string
	for _, it := range items {
		if it == target {
			out = append(out, it)
		}
	}
	return out
}

// dedupe removes duplicate findings from every category, preserving
// first-seen order — two overlapping targets (a folder plus a file inside it,
// or the same path named twice) can otherwise surface the same file more than
// once, and applyMigrate assumes a unique set.
func (d *discovered) dedupe() {
	for _, s := range []*[]string{
		&d.envFiles, &d.tfvarsFiles, &d.tfvarsComplexOnly, &d.shellConfigs,
		&d.mcpConfigs, &d.awsProfiles, &d.k8sUsers, &d.terraformHosts,
		&d.dockerRegistries, &d.gitHosts, &d.gcpADCFiles, &d.sopsAgeFiles,
		&d.npmrcFiles, &d.netrcFiles, &d.pypircFiles, &d.looseSecretFiles, &d.looseEmbeddedSkipped,
	} {
		dedupeStrings(s)
	}
}

// total counts everything discovered across every category, so
// discoverFileTarget can tell whether the structured scanners already claimed
// a named file before falling back to loose-secret detection. tfvarsComplexOnly
// is note-only (nothing migrate acts on), so it's excluded deliberately.
func (d *discovered) total() int {
	n := 0
	for _, s := range [][]string{
		d.envFiles, d.tfvarsFiles, d.shellConfigs, d.mcpConfigs, d.awsProfiles,
		d.k8sUsers, d.terraformHosts, d.dockerRegistries, d.gitHosts,
		d.gcpADCFiles, d.sopsAgeFiles, d.npmrcFiles, d.netrcFiles, d.pypircFiles,
		d.looseSecretFiles,
	} {
		n += len(s)
	}
	return n
}

// dedupeStrings drops repeated entries in place, keeping first-seen order.
func dedupeStrings(s *[]string) {
	if len(*s) < 2 {
		return
	}
	seen := make(map[string]bool, len(*s))
	out := (*s)[:0]
	for _, v := range *s {
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	*s = out
}

// completeMigrateCategories completes the comma-separated `--only` flag one
// category at a time: it splits on the last comma so `--only env,tf<TAB>`
// completes to `env,tfvars`, carries the already-chosen prefix through, and
// omits categories already listed so the menu only ever shows what's left
// to add. Sourced from migrateCategories, the same list the flag validates.
func completeMigrateCategories(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	base, seg := "", toComplete
	if i := strings.LastIndex(toComplete, ","); i >= 0 {
		base, seg = toComplete[:i+1], toComplete[i+1:]
	}
	chosen := map[string]bool{}
	for _, c := range strings.Split(base, ",") {
		chosen[c] = true
	}
	var out []string
	for _, cat := range migrateCategories {
		if chosen[cat] || !strings.HasPrefix(cat, seg) {
			continue
		}
		out = append(out, base+cat)
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}

func init() {
	// Persistent so the flags work on both `jit migrate <path>` and its
	// `path` alias subcommand (and undo/remove, which read the same vars).
	migrateCmd.PersistentFlags().BoolVar(&migrateDryRun, "dry-run", false, "preview the plan without changing anything")
	migrateCmd.PersistentFlags().BoolVarP(&migrateYes, "yes", "y", false, "skip the confirmation prompt and migrate immediately")
	migrateCmd.PersistentFlags().StringSliceVar(&migrateOnly, "only", nil, "scope a run to just these comma-separated categories: "+strings.Join(migrateCategories, ",")+" (default: all)")
	_ = migrateCmd.RegisterFlagCompletionFunc("only", completeMigrateCategories)
	migrateCmd.PersistentFlags().BoolVar(&migrateMount, "mount", false, "for a loose secret file, keep it live at its path as a mount (real value to `jit run` grants, a decoy otherwise) instead of replacing it with a pointer; also required to protect a file that mixes a secret with other content")

	migrateCmd.AddCommand(migratePathCmd)
	rootCmd.AddCommand(migrateCmd)
}
