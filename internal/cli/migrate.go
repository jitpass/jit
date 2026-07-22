// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

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
var migrateCategories = []string{"env", "tfvars", "shell", "mcp", "aws", "kube", "terraform", "docker", "git", "gcp", "sops", "npmrc", "netrc"}

// migrateScope is which set of files a run discovers. It replaced a plain
// wholeHome bool once a third scope (path) existed that is neither "walk
// cwd" nor "walk $HOME": scopePath discovers nothing by walking at all, it
// converts exactly the file(s)/folder(s) named on the command line. The
// three differ only in DISCOVERY (which files become findings) and a few
// cosmetic labels — every scope funnels the same discovered set through the
// one applyMigrate path, so backups, dry-run parity, pointer files, and the
// confirmation gate are identical no matter how the findings were gathered.
type migrateScope int

const (
	scopeLocal migrateScope = iota // only what's under the current directory tree
	scopeHome                      // everything under $HOME plus the fixed machine-wide files
	scopePath                      // only the explicit file/folder target(s) named on the command line
)

// discovered holds one run's findings per category, plus the skip list a
// home sweep produces (archived). Both the walk-based
// discovery (runMigrate) and the target dispatch (runMigratePath) populate
// one of these and hand it to applyMigrate — the single plan/confirm/apply
// path — so a `jit migrate path` run is byte-for-byte as safe as a home
// sweep, just over a narrower, explicitly named set of files.
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
	skippedArchived   []string
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
	_, _ = color.New(color.FgYellow).Fprintf(w, "note: this project's folder was renamed after migration (migrated as %q, now %q). Nothing is broken: your secrets still work and jit keeps serving them under the original %q label, which is only cosmetic. No action is needed. Run `jit profile show %s` to see where they live, or `jit doctor` to verify the vault is healthy.\n", oldName, newName, oldName, oldName)
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
	Use:     "migrate",
	GroupID: groupWorkflow,
	Short:   "Guided fix path for findings jit scan reports",
	Long: "jit migrate moves the plaintext secrets jit scan finds into the encrypted\n" +
		"vault and rewrites each file so everything keeps working without the secret\n" +
		"sitting on disk. It's a separate command from jit scan, not a flag on it,\n" +
		"so the read-only scanner can never be turned into a mutating one by a\n" +
		"mistyped flag.\n\n" +
		"By default it covers the same ground jit scan scans, the whole machine:\n" +
		"`jit migrate` is `jit migrate home`. Narrow the scope with a subcommand:\n\n" +
		"  jit migrate local   only what's under the current directory tree\n" +
		"                       (.env files, tfvars files, project mcp.json, project .npmrc)\n" +
		"  jit migrate home    the default: everything local finds, anywhere\n" +
		"                       under $HOME, plus the machine-wide files that live at\n" +
		"                       fixed home paths (shell configs, ~/.aws/credentials,\n" +
		"                       ~/.kube/config, Terraform Cloud credentials,\n" +
		"                       ~/.docker/config.json registry logins,\n" +
		"                       ~/.git-credentials HTTPS logins, GCP\n" +
		"                       application-default credentials, Claude Desktop's MCP\n" +
		"                       config, the global ~/.npmrc)\n" +
		"  jit migrate path    only the specific file(s)/folder(s) you name, with no\n" +
		"                       directory walk (e.g. one project's .env, a single\n" +
		"                       ~/.zshrc). The fast choice when a home sweep would\n" +
		"                       take too long and you already know what to move\n\n" +
		"Every run prints the full plan and asks for confirmation before touching\n" +
		"anything, and every modified file is backed up (encrypted, into the vault)\n" +
		"first, `jit migrate undo` restores any migrated file from that backup.\n" +
		"See each subcommand's --help for exactly what happens to each kind of file.",
	Example: "  jit migrate --dry-run          # preview the whole-machine plan, change nothing\n" +
		"  jit migrate                    # fix everything the plan shows\n" +
		"  jit migrate local --dry-run    # preview just this project's plan\n" +
		"  jit migrate home --only aws,kube\n" +
		"  jit migrate path ~/proj/.env   # migrate just one file, no walk\n" +
		"  jit migrate undo               # restore migrated files from their backups",
	// Bare `jit migrate` runs the home scope: jit scan scans the whole
	// machine with no scope choice, so the natural next step after reading
	// its report must not fork into a local/home decision the reader has
	// no basis to make (picking `local` from an arbitrary cwd silently
	// leaves most of the audit's findings unfixed). The plan+confirm gate,
	// encrypted backups, and `jit migrate undo` are what make a
	// whole-machine default safe; scope was never the real safety net.
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runMigrate(cmd, scopeHome)
	},
}

var migrateLocalCmd = &cobra.Command{
	Use:   "local",
	Short: "Convert findings under the current directory only",
	Long: "Converts findings under the current directory tree ONLY, nothing outside\n" +
		"the project you're standing in is discovered or touched. Machine-wide files\n" +
		"(shell configs, AWS, kubeconfig, Terraform Cloud, Docker registry logins,\n" +
		"git HTTPS logins, GCP application-default credentials, Claude Desktop's\n" +
		"config, the global ~/.npmrc) live at fixed paths under $HOME, so only\n" +
		"`jit migrate home` ever includes them.\n\n" +
		"What happens per category:\n\n" +
		"  .env files   Keys move into a profile and the vault; the file itself keeps\n" +
		"               working as a live mount served by jit's background service, showing\n" +
		"               fake-looking values by default. Real values reach a tool\n" +
		"               through `jit run` (env injection, or `jit run --live` for a\n" +
		"               tool that reads the file itself). A git-safe <file>.pointers\n" +
		"               companion is written alongside, listing vault paths only,\n" +
		"               always safe to open or commit.\n" +
		"  tfvars       Secret-shaped `name = \"value\"` assignments in terraform.tfvars\n" +
		"               and *.auto.tfvars move into the vault, one profile per directory.\n" +
		"               Terraform reads them back as TF_VAR_ environment variables when\n" +
		"               you run it through jit: `jit run --profile <p> -- terraform apply`.\n" +
		"  MCP configs  Each server's env-block secrets move into the vault, and the\n" +
		"               server's command is rewritten to launch via `jit run`.\n" +
		"  .npmrc       Secret lines move into the vault; the file keeps working as a\n" +
		"               live mount, with non-secret settings preserved verbatim.\n\n" +
		"Migrating never scrubs git history: a value that was ever committed stays\n" +
		"recoverable via `git log -p` regardless, jit warns per file instead of\n" +
		"implying \"migrated = safe\".",
	Example: "  jit migrate local --dry-run\n" +
		"  jit migrate local --only env",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runMigrate(cmd, scopeLocal)
	},
}

var migratePathCmd = &cobra.Command{
	Use:   "path <file-or-dir>...",
	Short: "Convert only the specific file(s)/folder(s) you name, no directory walk",
	Long: "Converts only the exact file(s) and/or folder(s) you name, nothing else is\n" +
		"discovered or touched. Use this when a `jit migrate home` sweep of a large\n" +
		"$HOME would take too long and you already know which secret you want moved:\n" +
		"a single project's .env, one ~/.zshrc, a directory of tfvars files.\n\n" +
		"Each target is resolved on its own:\n\n" +
		"  A file       is routed to the right category by what it is. A project file\n" +
		"               (.env, *.tfvars, mcp.json/.mcp.json, .npmrc) migrates exactly as\n" +
		"               `jit migrate local` would migrate it. A machine-wide file at a\n" +
		"               known path (a shell config like ~/.zshrc, ~/.aws/credentials,\n" +
		"               ~/.kube/config, Terraform Cloud creds, ~/.docker/config.json,\n" +
		"               ~/.git-credentials, GCP application-default credentials, a SOPS\n" +
		"               age key, ~/.netrc, Claude Desktop's MCP config, the global\n" +
		"               ~/.npmrc) is routed to that category's `home` handling.\n" +
		"  A directory  is walked like `jit migrate local` rooted at that directory:\n" +
		"               its .env/tfvars/mcp/npmrc findings only, never the machine-wide\n" +
		"               fixed-path files (those aren't \"under\" any project directory).\n\n" +
		"Unlike `jit migrate home`, path targets are explicit, so nothing is skipped\n" +
		"for looking archived/backup-like. Naming a file is itself the decision to\n" +
		"convert it. The per-category outcome (live mount, exec plugin, credential\n" +
		"helper, ...) is identical to the other scopes; see `jit migrate local --help` and\n" +
		"`jit migrate home --help` for the detail. Every run still prints the full\n" +
		"plan and asks for confirmation, backs each file up into the vault first, and\n" +
		"is reversible with `jit migrate undo`.",
	Example: "  jit migrate path ~/proj/.env\n" +
		"  jit migrate path ~/.zshrc ~/proj/.env\n" +
		"  jit migrate path ~/proj/config --dry-run\n" +
		"  jit migrate path ~/.aws/credentials --only aws",
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runMigratePath(cmd, args)
	},
}

var migrateHomeCmd = &cobra.Command{
	Use:   "home",
	Short: "Convert findings anywhere under $HOME, the whole machine, not just this project",
	Long: "Converts findings anywhere under $HOME, the whole machine, not just this\n" +
		"project. Covers everything `jit migrate local` does (see its --help for the\n" +
		"per-category detail), discovered across every project under $HOME, plus the\n" +
		"machine-wide files that live at fixed home paths:\n\n" +
		"  Shell configs    Secret-shaped `export KEY=value` lines in .zshrc/.bashrc/\n" +
		"                   etc. move into the vault; the file loads them back via\n" +
		"                   `eval \"$(jit export --profile ...)\"` instead.\n" +
		"  AWS              ~/.aws/credentials profiles move into the vault; the AWS\n" +
		"                   CLI/SDK fetches them live via a credential_process line\n" +
		"                   in ~/.aws/config, no keys on disk at all.\n" +
		"  kubeconfig       A user's bearer token or client-certificate pair moves\n" +
		"                   into the vault; kubectl fetches it via an exec block.\n" +
		"  Terraform Cloud  ~/.terraform.d/credentials.tfrc.json tokens move into the\n" +
		"                   vault; terraform fetches them through its own\n" +
		"                   credentials-helper protocol (`terraform login`/`logout`\n" +
		"                   keep working). Fails loud, before touching anything, if a\n" +
		"                   different credentials helper is already configured.\n" +
		"  Docker           plaintext registry logins in ~/.docker/config.json (base64\n" +
		"                   is encoding, not encryption) move into the vault; docker\n" +
		"                   fetches them through its own credential-helper protocol\n" +
		"                   (`docker login`/`logout` keep working, compose and buildx\n" +
		"                   pulls too). Never replaces an existing credential store\n" +
		"                   like Docker Desktop's; jit becomes the default store only\n" +
		"                   when the config had none at all.\n" +
		"  git              plaintext HTTPS logins in ~/.git-credentials move into the\n" +
		"                   vault; git fetches them through its own credential-helper\n" +
		"                   protocol (credential.helper set to jit, the plaintext\n" +
		"                   `store` helper replaced), so `git push`/`fetch` over HTTPS\n" +
		"                   keep working. A secure helper like osxkeychain is left in\n" +
		"                   place.\n" +
		"  GCP              ~/.config/gcloud/application_default_credentials.json's\n" +
		"                   refresh token (or a service account key's private key)\n" +
		"                   moves into the vault; the file keeps working as a live\n" +
		"                   mount, Google SDKs read the same path, non-secret fields\n" +
		"                   preserved verbatim. (GCP has no AWS-style\n" +
		"                   credential_process hook for these credential types, so\n" +
		"                   the mount is what keeps SDKs working with no key on disk.)\n" +
		"  SOPS age key     keys.txt (~/.config/sops/age/ or its Application Support\n" +
		"                   sibling) moves into the vault; the file keeps working as\n" +
		"                   a live mount for sops/kluctl/Flux/helm-secrets, and sops\n" +
		"                   v3.10+ can fetch the key directly via\n" +
		"                   SOPS_AGE_KEY_CMD=\"jit sops-age-key\", no file read at all.\n" +
		"  .netrc           Every `password` value in ~/.netrc moves into the vault;\n" +
		"                   the file keeps working as a live mount, curl/git/ftp\n" +
		"                   read it exactly as before, `machine`/`login` lines and\n" +
		"                   any macdef scripts survive verbatim.\n" +
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
		return runMigrate(cmd, scopeHome)
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
func runMigrate(cmd *cobra.Command, scope migrateScope) error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("jit migrate: %w", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("jit migrate: %w", err)
	}

	wholeHome := scope == scopeHome
	projectRoot := cwd
	if wholeHome {
		projectRoot = home
	}

	d := &discovered{}
	d.envFiles, err = migrate.DiscoverEnvFiles(projectRoot)
	if err != nil {
		return fmt.Errorf("jit migrate: %w", err)
	}
	d.tfvarsFiles, d.tfvarsComplexOnly, err = migrate.DiscoverTfvarsFiles(projectRoot)
	if err != nil {
		return fmt.Errorf("jit migrate: %w", err)
	}
	d.mcpConfigs, err = migrate.DiscoverMCPConfigs(home, projectRoot, wholeHome)
	if err != nil {
		return fmt.Errorf("jit migrate: %w", err)
	}
	d.npmrcFiles, err = migrate.DiscoverNpmrcFiles(home, projectRoot, wholeHome)
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
	if wholeHome {
		d.shellConfigs, err = migrate.DiscoverShellConfigs(home)
		if err != nil {
			return fmt.Errorf("jit migrate: %w", err)
		}
		d.awsProfiles, err = migrate.DiscoverAWSProfiles(home)
		if err != nil {
			return fmt.Errorf("jit migrate: %w", err)
		}
		d.k8sUsers, err = migrate.DiscoverKubeconfigUsers(home)
		if err != nil {
			return fmt.Errorf("jit migrate: %w", err)
		}
		d.terraformHosts, err = migrate.DiscoverTerraformHosts(home)
		if err != nil {
			return fmt.Errorf("jit migrate: %w", err)
		}
		d.dockerRegistries, err = migrate.DiscoverDockerRegistries(home)
		if err != nil {
			return fmt.Errorf("jit migrate: %w", err)
		}
		gitCreds, err := migrate.DiscoverGitCredentials(home)
		if err != nil {
			return fmt.Errorf("jit migrate: %w", err)
		}
		for _, c := range gitCreds {
			d.gitHosts = append(d.gitHosts, c.Host)
		}
		d.gcpADCFiles, err = migrate.DiscoverGCPADC(home)
		if err != nil {
			return fmt.Errorf("jit migrate: %w", err)
		}
		d.sopsAgeFiles, err = migrate.DiscoverSOPSAge(home)
		if err != nil {
			return fmt.Errorf("jit migrate: %w", err)
		}
		d.netrcFiles, err = migrate.DiscoverNetrc(home)
		if err != nil {
			return fmt.Errorf("jit migrate: %w", err)
		}
	}

	// Whole-machine sweeps skip anything that looks archived/backed-up by
	// default (GAPS.md #26) — see archived.go's doc comment for why a
	// live-mounted pipe is a worse outcome than plaintext for a project
	// nobody will run `jit service` from again. `local` never filters:
	// deliberately cd-ing into an old project and running `migrate local`
	// is an explicit action, not an implicit sweep, so there's nothing to
	// protect the caller from.
	if wholeHome && !migrateIncludeArchived {
		var skipped []string
		d.envFiles, skipped = migrate.FilterArchived(d.envFiles)
		d.skippedArchived = append(d.skippedArchived, skipped...)
		d.tfvarsFiles, skipped = migrate.FilterArchived(d.tfvarsFiles)
		d.skippedArchived = append(d.skippedArchived, skipped...)
		d.mcpConfigs, skipped = migrate.FilterArchived(d.mcpConfigs)
		d.skippedArchived = append(d.skippedArchived, skipped...)
		d.npmrcFiles, skipped = migrate.FilterArchived(d.npmrcFiles)
		d.skippedArchived = append(d.skippedArchived, skipped...)
		// Note-only paths (nothing migratable in them), so an archived one
		// is dropped silently rather than added to skippedArchived — the
		// archived note's "rerun with --include-archived" would falsely
		// promise a rerun could convert it.
		d.tfvarsComplexOnly, _ = migrate.FilterArchived(d.tfvarsComplexOnly)
	}

	return applyMigrate(cmd, scope, cwd, home, d)
}

// applyMigrate is the single plan/confirm/apply path every scope funnels
// through once its findings are gathered into d — runMigrate (local/home
// walk) and runMigratePath (explicit targets) both end here. Keeping one
// mutation path is what guarantees a `jit migrate path` run gets the exact
// same encrypted backups, --dry-run/real-plan parity (GAPS.md #26), pointer
// files, mount registration, git-history warnings, and confirmation gate
// (GAPS.md #17) as a whole-machine sweep. scope survives into here only to
// drive the plan's cosmetic labels and three behavior forks: which root a
// profile name derives from (cwd for local, the file's own directory
// otherwise), and whether the local-only folder-rename note fires.
func applyMigrate(cmd *cobra.Command, scope migrateScope, cwd, home string, d *discovered) error {
	// Locals aliased to d's fields so the --only filter, plan, and apply
	// loops below read exactly as they did before this function was split
	// out of runMigrate. categorySlices points at these locals, and the
	// --only nil-out clears them, leaving d untouched (it's already served
	// its purpose as the discovery hand-off).
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
	skippedArchived := d.skippedArchived

	// perFileRoot is false only for local scope. It controls where a .env/
	// tfvars/npmrc profile name derives from: cwd when every finding is
	// genuinely under cwd (local), the file's OWN directory otherwise (home
	// sweep and explicit path targets can both surface a file under a
	// completely unrelated project, so deriving from cwd would produce a
	// nonsensical profile name disconnected from the secret's real home).
	perFileRoot := scope != scopeLocal

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
		} else if scope == scopePath {
			// The caller named specific target(s), so the generic
			// whole-catalog "no .env, no tfvars, ..." list below would read as
			// a machine-wide report they didn't ask for. Say plainly that the
			// paths they named held nothing migratable (a missing path already
			// failed loud in runMigratePath before ever reaching here).
			fmt.Fprintln(cmd.OutOrStdout(), "Nothing to migrate: none of the path(s) you named contain plaintext secrets jit can move.")
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), "Nothing to migrate: no .env files, no tfvars secrets, no secret-shaped shell-config")
			fmt.Fprintln(cmd.OutOrStdout(), "exports, no MCP server secrets, no AWS/kubeconfig/Terraform Cloud/Docker registry/")
			fmt.Fprintln(cmd.OutOrStdout(), "git HTTPS credentials, no GCP credentials, no SOPS age key, no npmrc secrets, and no")
			fmt.Fprintln(cmd.OutOrStdout(), ".netrc passwords found.")
		}
		printSkippedFindings(cmd.OutOrStdout(), home, len(skippedArchived), "under an archived/backup-looking directory", skippedArchived,
			"Rerun with --include-archived to include them.")
		printSkippedFindings(cmd.OutOrStdout(), home, len(tfvarsComplexOnly), "in Terraform variable file(s) whose secret-shaped values aren't simple one-line strings", tfvarsComplexOnly,
			"Nothing migrate can move safely; they stay in place, and `jit scan` keeps reporting them.")
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
	printMigratePlan(cmd.OutOrStdout(), home, scope, envFiles, tfvarsFiles, shellConfigs, mcpConfigs, awsProfiles, k8sUsers, terraformHosts, dockerRegistries, gitHosts, gcpADCFiles, sopsAgeFiles, npmrcFiles, netrcFiles)
	printSkippedFindings(cmd.OutOrStdout(), home, len(skippedArchived), "under an archived/backup-looking directory", skippedArchived,
		"Rerun with --include-archived to include them.")
	printSkippedFindings(cmd.OutOrStdout(), home, len(tfvarsComplexOnly), "in Terraform variable file(s) whose secret-shaped values aren't simple one-line strings", tfvarsComplexOnly,
		"Nothing migrate can move safely; they stay in place, and `jit scan` keeps reporting them.")

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

			// profilesRoot must be the file's OWN project directory in
			// wholeHome mode, never the invoking cwd: deriveProfileName
			// computes a relative path from profilesRoot to the file's
			// directory, and in home mode a discovered .env can be under
			// a completely unrelated project. Passing cwd there would
			// silently derive a nonsensical profile name/path
			// disconnected from the project the secret actually came
			// from. In local mode every discovered file is genuinely
			// under cwd, so cwd is correct and unchanged — this only
			// branches for the non-local scopes (home sweep and explicit
			// path targets, both of which can surface a file anywhere).
			envProfilesRoot := cwd
			if perFileRoot {
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
			// Same profilesRoot rule as .env above: the directory's own
			// path for a home sweep or explicit path target, cwd in local mode.
			tfvarsProfilesRoot := cwd
			if perFileRoot {
				tfvarsProfilesRoot = dir
			}
			result, err := migrate.ApplyTfvarsDir(v, tfvarsProfilesRoot, dir, tfvarsByDir[dir])
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
				npmrcRoot = cwd
				if perFileRoot {
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

	// Best-effort: an unreadable marker means no nudge, never a failed
	// migrate — everything above already succeeded.
	if _, recorded, err := vault.LastExport(root); err == nil && !recorded {
		summary.exportNudge = true
	}

	summary.print(out)
	reportAgentStatus(out, root, len(envFiles) > 0 || len(npmrcFiles) > 0 || len(gcpADCFiles) > 0 || len(sopsAgeFiles) > 0 || len(netrcFiles) > 0)
	// Local mode only: the check reads pointer companions under the project
	// root, which is cwd here but an unrelated per-file directory in home
	// mode (deriveProfileName's profilesRoot comment) — neither a home sweep
	// nor an explicit path target has a single "this project" under cwd
	// whose rename to flag.
	if scope == scopeLocal {
		noteFolderRename(out, cwd)
	}
	return nil
}

// runMigratePath implements jit migrate path: convert only the file(s) and
// folder(s) named on the command line, with no directory walk beyond a
// named folder itself. This is the answer to a home sweep being too slow on
// a large $HOME when the caller already knows which secret they want moved
// (one project's .env, a single ~/.zshrc). Each target is resolved and
// classified on its own, its findings merged into one discovered set, then
// handed to the shared applyMigrate path — so a targeted run gets the exact
// same backups, plan/confirm gate, and undo support as any other scope.
func runMigratePath(cmd *cobra.Command, targets []string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("jit migrate path: %w", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("jit migrate path: %w", err)
	}

	d := &discovered{}
	for _, target := range targets {
		abs := expandTilde(target, home)
		if !filepath.IsAbs(abs) {
			abs = filepath.Join(cwd, abs)
		}
		abs = filepath.Clean(abs)

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
	// file inside it) would otherwise migrate a finding more than once; the
	// walk-based scopes can't produce a duplicate, so applyMigrate is
	// entitled to assume none.
	d.dedupe()

	return applyMigrate(cmd, scopePath, cwd, home, d)
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

// discoverDirTarget walks a named directory the way jit migrate local walks
// cwd: project files only (.env/tfvars/mcp/npmrc), never the fixed
// machine-wide paths. Those live under $HOME at large rather than "inside"
// any project directory, so a folder target that happens to be $HOME must
// not sweep them in — a path run is deliberately narrow.
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
// that category's own home-scoped discovery, narrowed back to just this file
// for the path-keyed categories. Anything else is treated as a project file
// and run through the same single-file discovery jit migrate local applies
// (WalkDir over one regular file yields just that file), so all the
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
	// Not a fixed machine-wide path — treat it as a project file.
	return discoverDirTarget(d, home, path)
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
// first-seen order. Only jit migrate path can produce a duplicate (two
// overlapping targets surfacing the same file); the walk-based scopes each
// discover a sorted, unique set, so applyMigrate assumes uniqueness.
func (d *discovered) dedupe() {
	for _, s := range []*[]string{
		&d.envFiles, &d.tfvarsFiles, &d.tfvarsComplexOnly, &d.shellConfigs,
		&d.mcpConfigs, &d.awsProfiles, &d.k8sUsers, &d.terraformHosts,
		&d.dockerRegistries, &d.gitHosts, &d.gcpADCFiles, &d.sopsAgeFiles,
		&d.npmrcFiles, &d.netrcFiles,
	} {
		dedupeStrings(s)
	}
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
	migrateCmd.PersistentFlags().BoolVar(&migrateDryRun, "dry-run", false, "preview the plan for this scope without changing anything")
	migrateCmd.PersistentFlags().BoolVarP(&migrateYes, "yes", "y", false, "skip the confirmation prompt and migrate immediately")
	migrateCmd.PersistentFlags().StringSliceVar(&migrateOnly, "only", nil, "scope a run to just these comma-separated categories: "+strings.Join(migrateCategories, ",")+" (default: all)")
	_ = migrateCmd.RegisterFlagCompletionFunc("only", completeMigrateCategories)
	// Registered on the bare command AND the home subcommand (same bound
	// var), not as a persistent flag: bare `jit migrate` runs the home
	// sweep so it needs the flag, but `jit migrate local` never filters
	// archived paths and must reject it rather than silently accept a
	// no-op.
	migrateCmd.Flags().BoolVar(&migrateIncludeArchived, "include-archived", false, "also convert findings under an archived/backup-looking directory (archive, archived, backup, backups, .trash)")
	migrateHomeCmd.Flags().BoolVar(&migrateIncludeArchived, "include-archived", false, "also convert findings under an archived/backup-looking directory (archive, archived, backup, backups, .trash)")

	migrateCmd.AddCommand(migrateLocalCmd, migrateHomeCmd, migratePathCmd)
	rootCmd.AddCommand(migrateCmd)
}
