// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/audit"
	"github.com/jitpass/jit/internal/guard"
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/termtext"
	"github.com/jitpass/jit/internal/ui"
	"github.com/jitpass/jit/internal/vault"
	"github.com/jitpass/jit/internal/wrap"
)

var (
	migrateDryRun bool
	migrateYes    bool
	migrateOnly   []string
	migrateMount  bool
	// migrateNo1Password opts OUT of the 1Password link dedupe
	// (design/1password-adapter.md): when op is installed, migrate stores
	// values that already live in 1Password as references by default, and
	// this flag restores plain copies. Opt-out, not opt-in — installing
	// and signing in to `op` was the opt-in.
	migrateNo1Password bool
)

// migrateCategories are the --only tokens real (non---dry-run) migrate
// accepts (GAPS.md #21), in the same order printMigratePlan reports them.
// Keyed by the short token a caller passes, not the display label used in
// output — keep the two lists in this exact order so error messages and
// --only's own help text stay in sync with printMigratePlan.
// "cache" is the one category with no file list of its own: it scopes the
// post-migrate agent-cache sweep, which rewrites files under $HOME that the
// run's other categories never name. Before it existed, --only env still ran
// the sweep and NO token could scope it out (issue #79).
var migrateCategories = []string{"env", "tfvars", "k8s-secret", "shell", "history", "mcp", "aws", "kube", "terraform", "docker", "git", "gcp", "sops", "npmrc", "netrc", "pypirc", "cargo", "streamlit", "loose", "cache"}

// discovered holds one run's findings per category. runMigratePath resolves
// each named target into one of these and hands it to applyMigrate — the
// single plan/confirm/apply path — so every migrate run gets identical
// backups, dry-run parity, pointer files, and the confirmation gate no
// matter which file(s) were named.
type discovered struct {
	envFiles          []string
	tfvarsFiles       []string
	tfvarsComplexOnly []string
	k8sManifests      []string
	// k8sManifestsComplexOnly is note-only (like tfvarsComplexOnly):
	// recognized Secret manifests migrate must refuse to rewrite (block
	// scalars, data: mixed with stringData:), surfaced so the plan can say
	// "seen, nothing movable" instead of staying silent.
	k8sManifestsComplexOnly []string
	shellConfigs            []string
	historyFiles            []string
	mcpConfigs              []string
	awsProfiles             []string
	k8sUsers                []string
	terraformHosts          []string
	dockerRegistries        []string
	gitHosts                []string
	gcpADCFiles             []string
	sopsAgeFiles            []string
	npmrcFiles              []string
	netrcFiles              []string
	pypircFiles             []string
	cargoRegistries         []string
	streamlitFiles          []string
	looseSecretFiles        []string
	// looseEmbeddedSkipped is note-only (like tfvarsComplexOnly): files that
	// mix a secret with other content, which neutralize can't move whole.
	// Populated only without --mount; with --mount they migrate as templates
	// and land in looseSecretFiles instead.
	looseEmbeddedSkipped []string
	// historyKeyOnlyFiles is note-only, like looseEmbeddedSkipped: history
	// files whose only finding is private-key material, which migrate reports
	// and refuses to redact (see migrate.HasOnlyPrivateKeyMaterial).
	historyKeyOnly []string
	// wrapOwnedSkipped is note-only: explicitly named files that belong to
	// a wrappable CLI (a catalog tool's token Source, or clisso's config).
	// Their fix is `jit wrap <tool>`, not loose-secret surgery — routing
	// them into the "mixes a secret with other content" note sent the user
	// at --mount for a file the wrap flow protects whole
	// (design/dry-run-refactor.md D7). The owning tool is re-derived at
	// print time (wrapOwnerForPath) rather than stored beside the path, so
	// dedupe() can treat this like every other []string.
	wrapOwnedSkipped []string
	// jitPaths are artifacts migrate wrote whose recorded jit path is stale
	// (gone, or a version-numbered Homebrew copy the next upgrade deletes),
	// each to be rewritten to jitPathTarget — the durable path resolved
	// once, at plan time, so the plan and the write agree by construction
	// (design/jit-path-refresh.md D2–D5). Counted like any category; scoped
	// by --only through each artifact's own owning category.
	jitPaths      []migrate.RecordedJitPath
	jitPathTarget string
	// jitPathRefused is note-only: the same stale artifacts when this jit
	// has no durable path to record (jitPathRefusal says why). Rendered as
	// a skip hint, never counted, never applied — the refusal is decided
	// here rather than after the user confirmed.
	jitPathRefused []string
	jitPathRefusal string
}

// durableJitPath is the plan-time resolver, a seam for the cli tests: the
// test binary lives under a volatile directory, so the real one correctly
// refuses there, and both outcomes need exercising from this package.
var durableJitPath = migrate.ResolveDurableJitPath

// discoverJitPathRefresh adds every stale recorded jit path that `keep`
// admits (nil keeps all) — as a refresh row when this jit has a durable
// path, as a refusal note when it does not. Read-only and prompt-free:
// the enumeration reads five fixed files, and the resolver never touches
// the vault.
func discoverJitPathRefresh(d *discovered, home string, keep func(migrate.RecordedJitPath) bool) {
	for _, r := range migrate.DiscoverRecordedJitPaths(home) {
		if r.Stale() == "" || (keep != nil && !keep(r)) {
			continue
		}
		to, err := durableJitPath()
		if err != nil {
			d.jitPathRefused = append(d.jitPathRefused, r.Path)
			d.jitPathRefusal = err.Error()
			continue
		}
		d.jitPathTarget = to
		d.jitPaths = append(d.jitPaths, r)
	}
}

// printJitPathRefused renders the refusal note (design/jit-path-refresh.md
// D4) in the shape every other skip hint uses.
func printJitPathRefused(w io.Writer, home string, d *discovered) {
	if len(d.jitPathRefused) == 0 {
		return
	}
	// The frame reads "Skipped N finding(s) <reason>:", so the reason
	// starts mid-sentence, as every other skip note's does.
	printSkippedFindings(w, home, len(d.jitPathRefused),
		"in "+countWord(len(d.jitPathRefused), "config", "configs")+" that "+pluralWord(len(d.jitPathRefused), "runs", "run")+" a jit that is gone or version-pinned, which this jit can't refresh right now",
		d.jitPathRefused, d.jitPathRefusal)
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
	_, _ = cWarn.Fprintf(w, "    note: vault namespace %q already holds a different migration's secrets, this file's secrets live under %q instead\n", movedFrom, profileName)
}

// noteRewrap says a server entry was already launching through jit, so this
// migration REPLACED that wrapper instead of adding one — and, when the entry
// had been wrapped more than once, that the nesting an older jit produced is
// now gone.
//
// Plain prose rather than amber, on noteFolderRename's reasoning: nothing is
// broken and there is nothing to do, and painting that yellow makes it read
// as the warning it explicitly is not. It is still worth a line, because the
// alternative is a migration that silently rewrites a launch command the user
// already had working.
func noteRewrap(w io.Writer, rewrappedFrom []string) {
	switch len(rewrappedFrom) {
	case 0:
	case 1:
		fmt.Fprintln(w, "    note: replaced the wrapper an earlier migration left here")
	default:
		fmt.Fprintf(w, "    note: collapsed %d nested wrappers into one\n", len(rewrappedFrom))
	}
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
	// Plain prose, not an amber wall: this says "nothing is broken, no
	// action needed", and painting a whole reassurance yellow makes it read
	// as the warning it is explicitly not (design/output-style.md rule 5 —
	// amber reports state, on a glyph, never a sentence of advice).
	wrapBody(w, 0, "", hlCmds(fmt.Sprintf("note: this project's folder was renamed after migration (migrated as %q, now %q). "+
		"Nothing is broken: your secrets still work and jit keeps serving them under the original %q label, "+
		"which is only cosmetic. No action is needed. Run `jit status --secrets` to see where they live, "+
		"or `jit doctor` to verify the vault is healthy.", oldName, newName, oldName)))
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
	_, _ = cWarn.Fprintf(w, "\nSkipped %s %s:\n", countWord(count, "finding", "findings"), reason)
	for _, p := range paths {
		// Middle-truncated like scan's own path lists: truncate variable
		// content rather than let a 140-char repo path wrap and shear the
		// list's alignment (design/output-style.md).
		fmt.Fprintf(w, "  - %s\n", termtext.TruncMid(displayPath(home, p), outputWidth()-4))
	}
	if hint != "" {
		fmt.Fprint(w, "  ")
		wrapBody(w, 2, "  ", hlCmds(hint))
	}
}

// printDryRunBanner is the head of the dry-run frame: the FIRST line a
// dry run prints, before any plan or disclosure (GAPS.md #32 — the
// preview-vs-real signal used to live only at the very end, and a reader
// skimming a long plan mistook it for changes already made). Every
// dry-run surface prints exactly two [DRY RUN] markers: this banner and
// printDryRunTrailer's closing line. Nothing else carries the marker —
// design/dry-run-refactor.md D1/D2, and TestDryRunFrameExactlyTwoMarkers
// fails the build on a third.
func printDryRunBanner(w io.Writer) {
	_, _ = cPathBold.Fprintln(w, "[DRY RUN] Preview, this run changes nothing; the plan below is what a real run would do.")
	fmt.Fprintln(w)
}

// printDryRunTrailer is the tail of the dry-run frame: the LAST line(s) a
// dry run prints. It no longer restates the banner's "changes nothing";
// it carries only what the banner cannot — the copy-pasteable apply
// command (the caller's own invocation minus --dry-run) and, for migrate
// itself, the pointer back to `jit scan` for findings migrate can never
// act on.
func printDryRunTrailer(w io.Writer, applyCmd string, scanHint bool) {
	fmt.Fprintln(w)
	_, _ = cPathBold.Fprint(w, "[DRY RUN]")
	fmt.Fprintln(w, hlCmds(fmt.Sprintf(" Apply this plan: `%s`", applyCmd)))
	if scanHint {
		wrapBody(w, 0, "", hlCmds("This only covers what jit migrate can act on; run `jit scan` for the complete picture, including findings it can never auto-fix, like private keys."))
	}
}

// migrateApplyCommand reconstructs the invocation the trailer tells the
// user to run: base + the targets they named + the scope flags that
// shaped this plan (--only, --mount). --yes is deliberately dropped even
// when set: the suggested command should re-show the plan and ask [y/N],
// never propagate a consent skip out of a preview.
func migrateApplyCommand(base string, args []string) string {
	parts := []string{base}
	for _, a := range args {
		parts = append(parts, shellQuoteArg(a))
	}
	if len(migrateOnly) > 0 {
		parts = append(parts, "--only="+strings.Join(migrateOnly, ","))
	}
	if migrateMount {
		parts = append(parts, "--mount")
	}
	if migrateClean {
		parts = append(parts, "--clean")
	}
	return strings.Join(parts, " ")
}

// shellQuoteArg single-quotes an argument that would not survive a paste
// into a shell as-is. Everyday paths pass through untouched so the
// trailer stays readable — including a leading ~/, which jit expands
// itself (expandTilde) whether or not the shell got to it first.
func shellQuoteArg(a string) string {
	if a != "" && !strings.ContainsAny(a, " \t'\"\\$`(){}[]*?;&|<>#") {
		return a
	}
	return "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
}

// wrapOwnerForPath names the catalog tool whose credential file an
// explicitly named path is: a KindShim entry's token Source, or clisso's
// config (KindCapture, so it has no Sources entry for its long-lived
// client-secret).
func wrapOwnerForPath(home, path string) (string, bool) {
	if tool, ok := wrap.WrappableToolForPath(home, path); ok {
		return tool, true
	}
	if path == migrate.ClissoConfigPath(home) {
		return "clisso", true
	}
	return "", false
}

// printSkippedWrapOwned renders the skip note for files a wrappable CLI
// owns, naming the per-tool command that actually protects each one —
// the whole point of the note is the redirect, so the command carries it.
func printSkippedWrapOwned(w io.Writer, home string, paths []string) {
	if len(paths) == 0 {
		return
	}
	_, _ = cWarn.Fprintf(w, "\nSkipped %s in %s a wrappable CLI owns:\n", countWord(len(paths), "finding", "findings"), pluralWord(len(paths), "a file", "files"))
	var cmds []string
	seen := map[string]bool{}
	for _, p := range paths {
		fmt.Fprintf(w, "  - %s\n", termtext.TruncMid(displayPath(home, p), outputWidth()-4))
		if tool, ok := wrapOwnerForPath(home, p); ok && !seen[tool] {
			seen[tool] = true
			cmds = append(cmds, "`jit wrap "+tool+"`")
		}
	}
	fmt.Fprint(w, "  ")
	wrapBody(w, 2, "  ", hlCmds("Protect "+pluralWord(len(paths), "it", "them")+" with "+strings.Join(cmds, ", ")+" instead: the token moves to the vault and the tool keeps working through a shim."))
}

// wrapPlanDetail states what wrapping this catalog tool actually DOES,
// per kind, for the plan's └ evidence line — "would wrap clisso" hides
// four materially different behaviors, and informed consent needs the
// right one. Everything here is read-only and prompt-free: the catalog
// is compiled in, and the two probes (clisso's config, the shell rc)
// are plain file reads.
func wrapPlanDetail(home, tool string) string {
	entry, ok := wrap.Lookup(tool)
	if !ok {
		return ""
	}
	var detail string
	switch entry.Kind {
	case wrap.KindShim:
		detail = entry.Doc + " moves to the vault; its plaintext source is scrubbed (backed up encrypted first)"
	case wrap.KindCapture:
		detail = entry.Doc + ": each mint goes to the vault instead of a plaintext credentials file"
		if tool == "clisso" {
			// The capture flow also moves clisso's own long-lived
			// client-secret out of ~/.clisso.yaml (see runCatalogWrap);
			// disclose it only when the probe says it will happen.
			if found, err := migrate.DiscoverClissoSecrets(home); err == nil && len(found) > 0 {
				detail += "; the client-secret in ~/.clisso.yaml moves to the vault too"
			}
		}
	case wrap.KindNative:
		detail = entry.Doc + ": no shim; delegates to jit's native credential flow for this tool"
	case wrap.KindRunGrant:
		detail = entry.Doc + ": shim only; every run happens inside a jit run grant"
	}
	// A first shim also puts ~/.jit/shims on PATH by appending to the
	// shell rc — a file edit the plan must disclose (ensureShimOnPath).
	if entry.Kind != wrap.KindNative {
		rc := wrap.RcFile(home, os.Getenv("SHELL"))
		data, err := os.ReadFile(rc) // #nosec G304 G703 -- rc is derived from the user's own home dir and $SHELL (same read wrap.EnsurePathLine makes), never external input; read-only probe for the plan's disclosure
		if err != nil || !wrap.RcMentionsShimDir(string(data)) {
			detail += "; adds the shim PATH line to " + displayPath(home, rc)
		}
	}
	return detail
}

// filterMigrateOnly validates only (the raw --only tokens) against
// migrateCategories and returns the set of selected categories. An unknown
// token fails loud rather than being silently ignored — a typo'd category
// name should never look like "nothing found" once the confirmation
// prompt already fired.
// filterJitPathsByCategory keeps the refresh rows whose owning category
// --only selected.
func filterJitPathsByCategory(rows []migrate.RecordedJitPath, selected map[string]bool) []migrate.RecordedJitPath {
	var kept []migrate.RecordedJitPath
	for _, r := range rows {
		if selected[r.Category] {
			kept = append(kept, r)
		}
	}
	return kept
}

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
		"Bare `jit migrate` (no arguments) protects everything the machine-wide\n" +
		"scan judged protectable: it runs the same scan `jit scan` runs, shows the\n" +
		"full plan — every file it will rewrite and every CLI it will wrap — and\n" +
		"asks for confirmation before touching anything. It is exactly the command\n" +
		"the scan report's \"jit will protect these\" section points at.\n\n" +
		"With arguments, discovery is scoped to the targets you name (plus the\n" +
		"agent-cache sweep described below). Each target is resolved on its own:\n\n" +
		"  A file       is routed to the right category by what it is. A project file\n" +
		"               (.env, *.tfvars, mcp.json/.mcp.json, .npmrc,\n" +
		"               .streamlit/secrets.toml) has its secrets\n" +
		"               moved into a profile and the vault, the file keeps working as a\n" +
		"               live mount (a git-safe <file>.pointers companion is written\n" +
		"               alongside). A machine-wide file at a known path (a shell config\n" +
		"               like ~/.zshrc, a shell history file like ~/.zsh_history,\n" +
		"               ~/.aws/credentials, ~/.kube/config, Terraform Cloud creds,\n" +
		"               ~/.docker/config.json, ~/.git-credentials, ~/.cargo/credentials.toml, GCP\n" +
		"               application-default credentials, a SOPS age key, ~/.netrc,\n" +
		"               ~/.pypirc, Claude Desktop's MCP config, Claude Code's\n" +
		"               ~/.claude.json, the global ~/.npmrc, the global\n" +
		"               ~/.streamlit/secrets.toml)\n" +
		"               is routed to that credential type's handling\n" +
		"               (credential_process, exec plugin, credential helper, live\n" +
		"               mount, or in-place redaction for a history file, where each\n" +
		"               recorded credential moves to the vault and the line keeps\n" +
		"               its shape, minus the secret).\n" +
		"  A directory  is walked for its .env/tfvars/mcp/npmrc/streamlit findings only, never\n" +
		"               the machine-wide fixed-path files (those aren't \"under\" any\n" +
		"               project directory) — name them explicitly to convert them.\n\n" +
		"Targets are explicit, so nothing is skipped for looking archived/backup-like:\n" +
		"naming a file is itself the decision to convert it. Every run prints the full\n" +
		"plan and asks for confirmation before touching anything, and every modified\n" +
		"file is backed up (encrypted, into the vault) first, `jit migrate undo <path>`\n" +
		"restores a migrated file from that backup.\n\n" +
		"A machine-wide file jit already migrated is still worth naming: the line it\n" +
		"carries to call back into jit records an absolute path, and if that path has\n" +
		"gone stale (a version-numbered Homebrew copy the last upgrade deleted) the run\n" +
		"refreshes it to the durable one — the fix `jit doctor` prescribes for a\n" +
		"[jit path] finding. Bare `jit migrate` checks every such file it ever wrote.\n\n" +
		"After vaulting, the run also clears verbatim copies of the newly vaulted\n" +
		"credentials from AI agent caches under your home directory — files beyond\n" +
		"the targets you named, each listed in the plan and backed up before it is\n" +
		"touched. Only values the scanner counts as secrets are hunted; ordinary\n" +
		"config a .env migration vaults alongside them is not. `--only` without the\n" +
		"`cache` category skips the sweep entirely.\n\n" +
		"With the 1Password CLI installed and signed in, a value that already lives\n" +
		"in 1Password is vaulted as an op:// reference instead of a copy (one\n" +
		"authenticated check per run, after you confirm), and a value that already IS\n" +
		"an op:// reference stays one; rotate in 1Password and jit follows.\n" +
		"--no-1password stores plain copies instead.",
	Example: "  jit migrate                     # protect everything the scan found\n" +
		"  jit migrate ~/proj/.env         # migrate just one file\n" +
		"  jit migrate ~/proj              # walk one project for .env/tfvars/mcp/npmrc\n" +
		"  jit migrate ~/.zshrc ~/proj/.env\n" +
		"  jit migrate ~/proj/.env --dry-run   # preview the plan, change nothing\n" +
		"  jit migrate ~/.aws/credentials --only aws\n" +
		"  jit migrate undo ~/proj/.env    # restore a migrated file from its backup",
	Args: cobra.ArbitraryArgs,
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
		if len(args) == 0 {
			return runMigrateAll(cmd)
		}
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
// extras carries the plan's non-file categories (wraps and the guard
// offer, from runMigrateAll's scan; nil on targeted runs). applyMigrate
// adds the agent-cache sweep preview itself, AFTER the --only filter,
// because the preview's needles are the values of exactly the files
// this run will vault (design/dry-run-refactor.md D4).
//
// dryRunApplyCmd carries the frame contract (design/dry-run-refactor.md
// D1): non-empty means applyMigrate owns the dry-run frame and prints the
// banner/trailer itself, with this as the trailer's apply command
// (runMigratePath). Empty means the caller owns the frame — runMigrateAll
// prints the banner BEFORE calling here and the trailer after its own
// tail, so the frame still brackets everything the run discloses.
//
// cleanInputs, when non-nil, is filled on a successful apply with what the
// --clean phase needs and only this function has: the values this run
// vaulted (Vault.OnSet) and the cache files its sweep rewrote. The clean
// phase itself runs in the CALLER's tail, after the wraps, so a
// wrap-vaulted token also counts toward an archived copy's redundancy
// proof (design/migrate-clean.md D1).
func applyMigrate(cmd *cobra.Command, home string, d *discovered, extras *planExtras, dryRunApplyCmd string, cleanInputs *cleanPhaseInputs) (bool, error) {
	// Locals aliased to d's fields so the --only filter, plan, and apply
	// loops below read exactly as they did before this function was split
	// out. categorySlices points at these locals, and the --only nil-out
	// clears them, leaving d untouched (it's already served its purpose as
	// the discovery hand-off).
	envFiles := d.envFiles
	tfvarsFiles := d.tfvarsFiles
	tfvarsComplexOnly := d.tfvarsComplexOnly
	k8sManifests := d.k8sManifests
	k8sManifestsComplexOnly := d.k8sManifestsComplexOnly
	shellConfigs := d.shellConfigs
	historyFiles := d.historyFiles
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
	cargoRegistries := d.cargoRegistries
	streamlitFiles := d.streamlitFiles
	looseSecretFiles := d.looseSecretFiles
	looseEmbeddedSkipped := d.looseEmbeddedSkipped
	historyKeyOnly := d.historyKeyOnly
	wrapOwnedSkipped := d.wrapOwnedSkipped
	jitPaths := d.jitPaths
	jitPathRefused := d.jitPathRefused

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
		"env":        &envFiles,
		"tfvars":     &tfvarsFiles,
		"k8s-secret": &k8sManifests,
		"shell":      &shellConfigs,
		"history":    &historyFiles,
		"mcp":        &mcpConfigs,
		"aws":        &awsProfiles,
		"kube":       &k8sUsers,
		"terraform":  &terraformHosts,
		"docker":     &dockerRegistries,
		"git":        &gitHosts,
		"gcp":        &gcpADCFiles,
		"sops":       &sopsAgeFiles,
		"npmrc":      &npmrcFiles,
		"netrc":      &netrcFiles,
		"pypirc":     &pypircFiles,
		"cargo":      &cargoRegistries,
		"streamlit":  &streamlitFiles,
		"loose":      &looseSecretFiles,
	}
	// len-1: "cache" is file-less (the sweep, not a file list) and lives
	// outside the table; cacheSelected below is its whole --only handling.
	if len(categorySlices) != len(migrateCategories)-1 {
		return false, fmt.Errorf("jit migrate: internal error: category table (%d) out of sync with --only categories (%d)", len(categorySlices), len(migrateCategories))
	}
	for _, token := range migrateCategories {
		if token == "cache" {
			continue
		}
		if _, ok := categorySlices[token]; !ok {
			return false, fmt.Errorf("jit migrate: internal error: --only category %q has no entry in the category table", token)
		}
	}
	cacheSelected := true
	if len(migrateOnly) > 0 {
		selected, err := filterMigrateOnly(migrateOnly)
		if err != nil {
			return false, fmt.Errorf("jit migrate: %w", err)
		}
		cacheSelected = selected["cache"]
		for token, items := range categorySlices {
			if !selected[token] {
				*items = nil
			}
		}
		if !selected["tfvars"] {
			tfvarsComplexOnly = nil // note-only companion of the tfvars category, scoped with it
		}
		if !selected["k8s-secret"] {
			k8sManifestsComplexOnly = nil // note-only companion, scoped with its category
		}
		// A recorded-path refresh is scoped by the category whose migration
		// wrote the artifact: `--only aws` refreshes ~/.aws/config exactly
		// as it migrates ~/.aws/credentials. Not a token of its own.
		jitPaths = filterJitPathsByCategory(jitPaths, selected)
		if len(jitPathRefused) > 0 {
			var kept []string
			for _, r := range migrate.DiscoverRecordedJitPaths(home) {
				for _, p := range jitPathRefused {
					if r.Path == p && selected[r.Category] {
						kept = append(kept, p)
					}
				}
			}
			jitPathRefused = kept
		}
	}

	total := len(jitPaths)
	for _, items := range categorySlices {
		total += len(*items)
	}
	// After --only: what this run stores, as opposed to merely rewrites.
	vaultsValues := total-len(jitPaths) > 0
	if total == 0 {
		if len(migrateOnly) > 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "Nothing to migrate in the selected --only %s: %s.\n", pluralWord(len(migrateOnly), "category", "categories"), strings.Join(migrateOnly, ", "))
		} else {
			// The caller named specific target(s), so say plainly that the
			// paths they named held nothing migratable (a missing path already
			// failed loud in runMigratePath before ever reaching here).
			fmt.Fprintln(cmd.OutOrStdout(), "Nothing to migrate: none of the path(s) you named contain plaintext secrets jit can move.")
		}
		printSkippedFindings(cmd.OutOrStdout(), home, len(tfvarsComplexOnly), "in Terraform "+pluralWord(len(tfvarsComplexOnly), "variable file", "variable files")+" whose secret-shaped values aren't simple one-line strings", tfvarsComplexOnly,
			"Nothing migrate can move safely; they stay in place, and `jit scan` keeps reporting them.")
		printSkippedFindings(cmd.OutOrStdout(), home, len(k8sManifestsComplexOnly), "in "+pluralWord(len(k8sManifestsComplexOnly), "Kubernetes Secret manifest", "Kubernetes Secret manifests")+" migrate can't rewrite provably right", k8sManifestsComplexOnly,
			"They stay in place and `jit scan` keeps reporting them. Common causes: a templated manifest (Helm `{{ }}`) that isn't valid YAML, multi-line block-scalar values, or data: mixed with stringData: in one document.")
		printSkippedFindings(cmd.OutOrStdout(), home, len(looseEmbeddedSkipped), pluralWord(len(looseEmbeddedSkipped), "file that mixes", "files that mix")+" a secret with other content", looseEmbeddedSkipped,
			"Re-run with --mount to protect them in place as a live mount (the non-secret content is preserved); otherwise they stay put and `jit scan` keeps reporting them.")
		printSkippedFindings(cmd.OutOrStdout(), home, len(historyKeyOnly), "in "+pluralWord(len(historyKeyOnly), "a history file", "history files")+" holding private key material", historyKeyOnly,
			"jit only matched the -----BEGIN line; the key body is on the lines around it, so redacting would leave the key behind and make the file look clean. Regenerate the key, then delete those lines by hand.")
		printSkippedWrapOwned(cmd.OutOrStdout(), home, wrapOwnedSkipped)
		printJitPathRefused(cmd.OutOrStdout(), home, &discovered{jitPathRefused: jitPathRefused, jitPathRefusal: d.jitPathRefusal})
		return false, nil
	}

	// The banner prints here only when this function owns the frame (a
	// targeted `jit migrate <path>` run); see printDryRunBanner for the
	// GAPS.md #32 rationale. printMigratePlan itself stays unaware of
	// migrateDryRun (the banner is printed at the call site, not inside
	// it) specifically so it keeps rendering the exact same plan for
	// --dry-run and the real confirmation prompt (GAPS.md #26's core
	// guarantee) — see TestMigrateDryRunMatchesRealPlanExactly.
	if migrateDryRun && dryRunApplyCmd != "" {
		printDryRunBanner(cmd.OutOrStdout())
	}

	// Confirm before touching anything — vault set/rm both gate a single
	// secret behind [y/N], but migrate can rewrite shell configs, MCP
	// configs, AWS config, kubeconfig, and npmrc in one invocation with
	// no equivalent gate (GAPS.md #17). Deliberately placed BEFORE
	// openVault(): declining must never trigger a Touch ID prompt for
	// work that's about to be aborted anyway. This same plan is what
	// --dry-run prints too (see below) — one rendering path, so the
	// preview you confirm against is exactly the preview --dry-run shows.
	// Rebuilt from the locals rather than passed as d: the --only nil-out above
	// clears the LOCALS, so d still holds every category and would print a plan
	// wider than the run about to happen. Named fields, so the transposition the
	// old seventeen-argument call invited is now a compile error.
	planned := discovered{
		envFiles:         envFiles,
		tfvarsFiles:      tfvarsFiles,
		k8sManifests:     k8sManifests,
		shellConfigs:     shellConfigs,
		historyFiles:     historyFiles,
		mcpConfigs:       mcpConfigs,
		awsProfiles:      awsProfiles,
		k8sUsers:         k8sUsers,
		terraformHosts:   terraformHosts,
		dockerRegistries: dockerRegistries,
		gitHosts:         gitHosts,
		gcpADCFiles:      gcpADCFiles,
		sopsAgeFiles:     sopsAgeFiles,
		npmrcFiles:       npmrcFiles,
		netrcFiles:       netrcFiles,
		pypircFiles:      pypircFiles,
		cargoRegistries:  cargoRegistries,
		streamlitFiles:   streamlitFiles,
		looseSecretFiles: looseSecretFiles,
		jitPaths:         jitPaths,
		jitPathTarget:    d.jitPathTarget,
	}
	// The cache-sweep preview joins the plan HERE, after the --only
	// filter: its needles are the plaintext values of exactly the files
	// this run will vault, so a scoped-out category must not feed it.
	// Best-effort by design — a failed preview becomes a note, never a
	// failed (or prompting) plan; the apply-time sweep is unaffected
	// either way, its needles come from Vault.OnSet.
	if extras == nil {
		extras = &planExtras{}
	}
	if cacheSelected {
		if needles := migrate.PlanNeedles(envFiles, looseSecretFiles); len(needles) > 0 {
			if preview, err := migrate.PreviewAgentCaches(home, needles); err != nil {
				extras.cacheNote = err.Error()
			} else {
				extras.cacheEdits = preview.Edited
			}
		}
	}
	printMigratePlan(cmd.OutOrStdout(), home, &planned, extras)
	printSkippedFindings(cmd.OutOrStdout(), home, len(tfvarsComplexOnly), "in Terraform "+pluralWord(len(tfvarsComplexOnly), "variable file", "variable files")+" whose secret-shaped values aren't simple one-line strings", tfvarsComplexOnly,
		"Nothing migrate can move safely; they stay in place, and `jit scan` keeps reporting them.")
	printSkippedFindings(cmd.OutOrStdout(), home, len(k8sManifestsComplexOnly), "in "+pluralWord(len(k8sManifestsComplexOnly), "Kubernetes Secret manifest", "Kubernetes Secret manifests")+" migrate can't rewrite provably right", k8sManifestsComplexOnly,
		"They stay in place and `jit scan` keeps reporting them. Common causes: a templated manifest (Helm `{{ }}`) that isn't valid YAML, multi-line block-scalar values, or data: mixed with stringData: in one document.")
	printSkippedFindings(cmd.OutOrStdout(), home, len(looseEmbeddedSkipped), pluralWord(len(looseEmbeddedSkipped), "file that mixes", "files that mix")+" a secret with other content", looseEmbeddedSkipped,
		"Re-run with --mount to protect them in place as a live mount (the non-secret content is preserved); otherwise they stay put and `jit scan` keeps reporting them.")
	printSkippedFindings(cmd.OutOrStdout(), home, len(historyKeyOnly), "in "+pluralWord(len(historyKeyOnly), "a history file", "history files")+" holding private key material", historyKeyOnly,
		"jit only matched the -----BEGIN line; the key body is on the lines around it, so redacting would leave the key behind and make the file look clean. Regenerate the key, then delete those lines by hand.")
	printSkippedWrapOwned(cmd.OutOrStdout(), home, wrapOwnedSkipped)
	printJitPathRefused(cmd.OutOrStdout(), home, &discovered{jitPathRefused: jitPathRefused, jitPathRefusal: d.jitPathRefusal})

	// The 1Password announcement is part of the plan the user confirms
	// against (and --dry-run's, same rendering), but the plan never
	// contacts op: the PATH probe is the whole test here, because the plan
	// must stay free of prompts — 1Password's authorization dialog no less
	// than Touch ID. The real check runs after [y/N].
	if vaultsValues && migrateOpInstalled() && !migrateNo1Password {
		w := cmd.OutOrStdout()
		fmt.Fprintln(w)
		wrapBody(w, 0, "", "1Password CLI detected: values already stored there are linked, not copied (--no-1password to copy).")
	}

	if migrateDryRun {
		if dryRunApplyCmd != "" {
			printDryRunTrailer(cmd.OutOrStdout(), dryRunApplyCmd, true)
		}
		return false, nil
	}

	fmt.Fprintln(cmd.OutOrStdout())
	if !migrateYes && !confirmPrompt(cmd, "Proceed? [y/N] ") {
		fmt.Fprintln(cmd.OutOrStdout(), "Aborted. Nothing was changed.")
		return false, nil
	}

	v, err := openVault()
	if err != nil {
		return false, fmt.Errorf("jit migrate: %w", err)
	}
	// Record every credential this run vaults, so the agent-cache sweep below
	// knows exactly what to hunt copies of. Observing the vault is what keeps
	// this out of the nineteen Apply* signatures, none of which returns a
	// plaintext value and none of which should start (see vault.Vault.OnSet).
	//
	// Scope is deliberately this run's values and nothing else: the
	// authentication the user just gave authorised moving THESE secrets.
	var vaultedSecrets []migrate.AgentCacheSecret
	seenVaulted := map[string]bool{}
	v.OnSet = func(secretPath string, value []byte) {
		// The vault's own encrypted backups are written through Set too
		// (storeSecretBackup), and the sweep below backs up every file it
		// rewrites — so without this guard the collector would ingest whole
		// plaintext cache files as new needles, mid-sweep. A _backups/ entry
		// is never a credential the user typed; it is jit's copy of a whole
		// file, and its last path segment is a timestamp, not a variable name.
		if vault.IsBackupPath(secretPath) {
			return
		}
		val := string(value)
		if seenVaulted[val] {
			return // a rotation re-sets the same value; one needle is enough
		}
		seenVaulted[val] = true
		name := secretPath
		if i := strings.LastIndex(name, "/"); i >= 0 {
			name = name[i+1:]
		}
		vaultedSecrets = append(vaultedSecrets, migrate.AgentCacheSecret{Value: val, Var: name})
	}
	// Captured NOW, not at sweep time: the sweep runs last, after each .env
	// has been rewritten into a pointer file that no longer parses as its
	// old values. These are the values the env migration vaults as ordinary
	// config, which the sweep must not hunt (issue #79).
	envOrdinary := migrate.EnvOrdinaryValues(envFiles)
	root, err := vaultRootDir()
	if err != nil {
		return false, fmt.Errorf("jit migrate: %w", err)
	}
	registryPath := mount.RegistryPath(root)

	// 1Password dedupe (design/1password-adapter.md, migrate1password.go):
	// every value about to be vaulted is offered to the vault's LinkOnSet
	// hook — a byte-exact match against 1Password's concealed fields, or a
	// value that already IS an op:// reference (a .env kept for `op run`),
	// stores the reference instead of a copy. The enumeration behind the
	// match runs lazily on the first value that could link, after [y/N]
	// and Touch ID, never at plan time — the plan's announcement line
	// above is a PATH probe only. Fails open on purpose: a signed-out CLI
	// or a locked app degrades to today's literal copies, reported once in
	// the mutation log.
	var opLinks *opDedupe
	if vaultsValues && migrateOpInstalled() && !migrateNo1Password {
		opLinks = newOpDedupe(func() *ui.Tracker { return newProgress(cmd, false) })
		v.LinkOnSet = opLinks.hook
	}

	// producedMount records whether this run registered ANY live mount, so the
	// closing reportAgentStatus knows to send the running service the Refresh
	// that makes it serve them NOW rather than only after the next lock/unlock
	// cycle (until then a read against an unserved FIFO just hangs). It is set
	// at this one addMount choke point instead of recomputed downstream from a
	// per-category length list: that list silently omitted the loose-secret
	// --mount path, so a `jit migrate <bare-token> --mount` mount sat unserved
	// until a manual `jit service restart`. A choke-point flag can't drift as
	// new mount categories are added.
	producedMount := false
	addMount := func(e mount.Entry) error {
		if err := mount.AddMount(registryPath, e); err != nil {
			return err
		}
		producedMount = true
		return nil
	}

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

	// Lazy, once-per-run index of every value already stored, for the
	// duplicate-disclosure notes below (see migrateduplicates.go). Lazy so
	// a run that migrates none of the disclosing categories never pays the
	// full-vault read.
	dupIdx := &dupIndexOnce{v: v}

	// Recorded jit paths first: a category migration later in this run
	// (a kubeconfig user, an AWS profile) rewrites the same artifact with
	// the same durable path, and the tracker's first backup of the file is
	// the pristine one either way.
	if len(jitPaths) > 0 {
		printMigrateResultCategory(out, pluralWord(len(jitPaths), "recorded jit path refreshed", "recorded jit paths refreshed"), len(jitPaths))
		for _, r := range jitPaths {
			res, err := migrate.RefreshRecordedJitPath(v, r, d.jitPathTarget, backups)
			if err != nil {
				return false, fmt.Errorf("jit migrate: %w", err)
			}
			fmt.Fprint(out, hlCmds(fmt.Sprintf("  "+glyphBullet+" %s -> %s; backup: `jit vault get %s`\n",
				displayPath(home, res.Path), res.To, res.Backup)))
		}
		fmt.Fprintln(out)
	}

	// Each migrated category gets the same "[Label] (N)" header + bullet
	// shape the plan itself already uses (printMigratePlan/
	// printMigratePlanCategory) — a real, reported problem: this log used
	// to be a flat run of long, unbroken sentences (path, profile name,
	// variable count, mount status, and backup path all crammed into one
	// line each), visually disconnected from the plan's own grouped,
	// bulleted style directly above it. printMigrateResultCategory is the
	// shared header+bullet renderer both use.
	if n := len(envFiles); n > 0 {
		printMigrateResultCategory(out, pluralWord(n, ".env file", ".env files")+" migrated", n)
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
				return false, fmt.Errorf("jit migrate: %w", err)
			}
			// A backup-suffixed file (.bak/.old/.orig/.backup) never
			// became a live mount at all (GAPS.md #34) — ApplyEnvFile
			// replaced it in place with a pointer file instead, so
			// there's no mount to register, no separate .pointers
			// companion to write alongside it (EnvPath already IS the
			// pointer file), and nothing to reveal.
			if !result.Mounted {
				summary.backupOnlyFiles++
				fmt.Fprint(out, hlCmds(fmt.Sprintf("  "+glyphBullet+" %s -> profile %q (%s); backup: `jit vault get %s`, replaced with a safe pointer file (never mounted; nothing reads a backup file live)\n",
					displayPath(home, envPath), result.ProfileName, countWord(len(result.Variables), "var", "vars"), result.BackupPath)))
				noteNamespaceMove(out, result.NamespaceMovedFrom, result.ProfileName)
				noteDuplicateValues(out, v, dupIdx.get(), result.ProfileName, result.Variables)
				continue
			}
			if err := addMount(mount.Entry{MountPath: result.EnvPath, ProfilePath: result.ProfilePath}); err != nil {
				return false, fmt.Errorf("jit migrate: registering mount for %s: %w", result.EnvPath, err)
			}
			if err := summary.writePointerFile(result.EnvPath, result.ProfilePath); err != nil {
				return false, fmt.Errorf("jit migrate: %w", err)
			}
			fmt.Fprint(out, hlCmds(fmt.Sprintf("  "+glyphBullet+" %s -> profile %q (%s); backup: `jit vault get %s`\n", displayPath(home, envPath), result.ProfileName, countWord(len(result.Variables), "var", "vars"), result.BackupPath)))
			noteNamespaceMove(out, result.NamespaceMovedFrom, result.ProfileName)
			noteDuplicateValues(out, v, dupIdx.get(), result.ProfileName, result.Variables)
		}
		fmt.Fprintln(out)
	}

	if n := len(looseSecretFiles); n > 0 {
		printMigrateResultCategory(out, pluralWord(n, "loose secret file", "loose secret files")+" migrated", n)
		for _, path := range looseSecretFiles {
			summary.checkGitHistory(path)
			// profilesRoot is the file's OWN directory, same rule as .env: an
			// explicitly named loose file can sit anywhere, so its profile lives
			// alongside it, not under the invoking cwd.
			if migrateMount {
				// --mount: the file becomes a live FIFO serving a template.
				result, err := migrate.ApplyLooseSecretFileMount(v, filepath.Dir(path), path)
				if err != nil {
					return false, fmt.Errorf("jit migrate: %w", err)
				}
				if err := addMount(mount.Entry{MountPath: path, ProfilePath: result.ProfilePath, TemplatePath: result.TemplatePath}); err != nil {
					return false, fmt.Errorf("jit migrate: registering mount for %s: %w", path, err)
				}
				if err := summary.writePointerFile(path, result.ProfilePath); err != nil {
					return false, fmt.Errorf("jit migrate: %w", err)
				}
				fmt.Fprint(out, hlCmds(fmt.Sprintf("  "+glyphBullet+" %s -> profile %q (%s); backup: `jit vault get %s`, live mount (real value to `jit run` grants, a decoy otherwise)\n",
					displayPath(home, path), result.ProfileName, countWord(len(result.Variables), "secret", "secrets"), result.BackupPath)))
				noteNamespaceMove(out, result.NamespaceMovedFrom, result.ProfileName)
				continue
			}
			// Default: vault-and-neutralize. ApplyLooseSecretFile replaced the
			// file in place with a git-safe pointer, so there's no mount to
			// register and nothing to reveal — retrieval is `jit vault get`.
			result, err := migrate.ApplyLooseSecretFile(v, filepath.Dir(path), path)
			if err != nil {
				return false, fmt.Errorf("jit migrate: %w", err)
			}
			summary.backupOnlyFiles++
			fmt.Fprint(out, hlCmds(fmt.Sprintf("  "+glyphBullet+" %s -> profile %q (%s); backup: `jit vault get %s`, replaced with a safe pointer file (retrieve with `jit vault get %s/%s`)\n",
				displayPath(home, path), result.ProfileName, countWord(len(result.Variables), "secret", "secrets"), result.BackupPath, result.ProfileName, result.Variables[0])))
			noteNamespaceMove(out, result.NamespaceMovedFrom, result.ProfileName)
		}
		fmt.Fprintln(out)
	}

	if n := len(tfvarsFiles); n > 0 {
		printMigrateResultCategory(out, pluralWord(n, "Terraform variable file", "Terraform variable files")+" migrated", n)
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
				return false, fmt.Errorf("jit migrate: %w", err)
			}
			backups := make([]string, len(result.Backups))
			for i, b := range result.Backups {
				backups[i] = fmt.Sprintf("`jit vault get %s`", b)
			}
			fmt.Fprintf(out, "  "+glyphBullet+" %s (%s) -> profile %q (%s); %s: %s\n",
				displayPath(home, dir), countWord(len(result.Files), "file", "files"), result.ProfileName,
				countWord(len(result.Variables), "var", "vars"), pluralWord(len(result.Backups), "backup", "backups"), strings.Join(backups, ", "))
			noteNamespaceMove(out, result.NamespaceMovedFrom, result.ProfileName)
			if len(result.SkippedComplex) > 0 {
				_, _ = cWarn.Fprintf(out, "    note: %s left in place, %s: %s\n",
					countWord(len(result.SkippedComplex), "secret-shaped value", "secret-shaped values"),
					pluralWord(len(result.SkippedComplex), "not a simple one-line string", "not simple one-line strings"),
					strings.Join(result.SkippedComplex, ", "))
			}
			fmt.Fprintf(out, "    run terraform through jit from that directory: jit run --profile %s -- terraform apply\n", result.ProfileName)
		}
		fmt.Fprintln(out)
	}

	if n := len(k8sManifests); n > 0 {
		printMigrateResultCategory(out, pluralWord(n, "Kubernetes Secret manifest", "Kubernetes Secret manifests")+" migrated", n)
		for _, path := range k8sManifests {
			summary.checkGitHistory(path)
			// profilesRoot is the manifest's OWN directory, the same rule as
			// .env and loose files: an explicitly named manifest can sit under
			// any project, so its profile lives alongside it.
			result, err := migrate.ApplyK8sSecretManifest(v, filepath.Dir(path), path)
			if err != nil {
				return false, fmt.Errorf("jit migrate: %w", err)
			}
			if err := addMount(mount.Entry{MountPath: path, ProfilePath: result.ProfilePath, TemplatePath: result.TemplatePath}); err != nil {
				return false, fmt.Errorf("jit migrate: registering mount for %s: %w", path, err)
			}
			if err := summary.writePointerFile(path, result.ProfilePath); err != nil {
				return false, fmt.Errorf("jit migrate: %w", err)
			}
			fmt.Fprint(out, hlCmds(fmt.Sprintf("  "+glyphBullet+" %s -> profile %q (%s); backup: `jit vault get %s`, live mount (real manifest to `jit run` grants, rejectable decoys otherwise)\n",
				displayPath(home, path), result.ProfileName, countWord(len(result.Variables), "secret", "secrets"), result.BackupPath)))
			noteNamespaceMove(out, result.NamespaceMovedFrom, result.ProfileName)
			if result.ConvertedStringData {
				_, _ = cWarn.Fprintf(out, "    note: stringData: rewritten as data:; the applied Secret is identical, and decoys are never valid base64\n")
			}
			fmt.Fprintf(out, "    apply through jit: jit run -- kubectl apply -f %s\n", displayPath(home, path))
		}
		fmt.Fprintln(out)
	}

	if n := len(shellConfigs); n > 0 {
		printMigrateResultCategory(out, pluralWord(n, "shell config", "shell configs")+" migrated", n)
		for _, shellPath := range shellConfigs {
			summary.checkGitHistory(shellPath)

			result, err := migrate.ApplyShellConfig(v, shellPath)
			if err != nil {
				return false, fmt.Errorf("jit migrate: %w", err)
			}
			fmt.Fprint(out, hlCmds(fmt.Sprintf("  "+glyphBullet+" %s -> profile %q (%s); backup: `jit vault get %s`, open a new shell (or `source %s`)\n",
				displayPath(home, shellPath), result.ProfileName, countWord(len(result.Variables), "var", "vars"), result.BackupPath, displayPath(home, shellPath))))
		}
		fmt.Fprintln(out)
	}

	if n := len(historyFiles); n > 0 {
		printMigrateResultCategory(out, pluralWord(n, "shell history file", "shell history files")+" redacted", n)
		for _, path := range historyFiles {
			summary.checkGitHistory(path)

			result, err := migrate.ApplyShellHistory(v, path)
			if err != nil {
				return false, fmt.Errorf("jit migrate: %w", err)
			}
			fmt.Fprint(out, hlCmds(fmt.Sprintf("  "+glyphBullet+" %s -> profile %q (%s, %s redacted in place); backup: `jit vault get %s`\n",
				displayPath(home, path), result.ProfileName, countWord(len(result.Variables), "secret", "secrets"),
				countWord(result.Occurrences, "occurrence", "occurrences"), result.BackupPath)))
			// A file can hold both. Never let a successful token redaction
			// imply the file is now clean when key material was deliberately
			// left in it.
			if migrate.HasPrivateKeyMaterial(path) {
				_, _ = cWarn.Fprintf(out, "    note: private key material is STILL in this file — jit matched only the -----BEGIN line, so redacting it would leave the key body behind. Regenerate the key and delete those lines by hand.\n")
			}
		}
		// Two truths the redaction itself cannot deliver, said at the moment
		// of action. Rotation: clearing the recorded copy does not un-expose
		// a value that already sat in plaintext (and history files reach Time
		// Machine and dotfile repos as a matter of routine). Resurrection:
		// zsh's default setup holds history in memory and rewrites the file
		// on exit, so a shell that was open during this run can bring the
		// redacted lines back — re-running migrate re-redacts them into the
		// same vault entries, but reloading or closing those shells is what
		// makes it stick.
		wrapBody(out, 0, "    ", cWarn.Sprint("    rotate these at their provider: redaction clears the recorded copy, it does not un-expose it"))
		wrapBody(out, 0, "    ", hlCmds("    Shells open right now rewrite history when they exit, which can bring a "+
			"redacted line back. Run `fc -R` in each open zsh (bash: `history -r`) or close them, then re-run `jit scan` to confirm."))
		wrapBody(out, 0, "    ", hlCmds("    To stop future secrets reaching the file at all: `jit guard history` (zsh)."))
		fmt.Fprintln(out)
	}

	if n := len(mcpConfigs); n > 0 {
		printMigrateResultCategory(out, pluralWord(n, "MCP config", "MCP configs")+" migrated", n)
		for _, mcpPath := range mcpConfigs {
			summary.checkGitHistory(mcpPath)

			result, err := migrate.ApplyMCPConfig(v, mcpPath)
			if err != nil {
				return false, fmt.Errorf("jit migrate: %w", err)
			}
			for _, sm := range result.Servers {
				fmt.Fprint(out, hlCmds(fmt.Sprintf("  "+glyphBullet+" %s server %q -> profile %q (%s); backup: `jit vault get %s`\n",
					displayPath(home, mcpPath), sm.ServerName, sm.ProfileName, countWord(len(sm.Variables), "var", "vars"), result.BackupPath)))
				noteNamespaceMove(out, sm.NamespaceMovedFrom, sm.ProfileName)
				noteRewrap(out, sm.RewrappedFrom)
				noteDuplicateValues(out, v, dupIdx.get(), sm.ProfileName, sm.Variables)
			}
			// A project block that could not be parsed still holds whatever
			// `jit scan` flagged. Saying nothing here would report success
			// over a file that is still partly exposed — the exact
			// zero-errors dead end the projects support exists to close.
			for _, dir := range result.SkippedProjects {
				fmt.Fprintf(out, "  %s project block %s couldn't be parsed, left unchanged\n", glyphWarn, dir)
				wrapBody(out, 4, "    ", "its servers are NOT migrated; fix the JSON and re-run")
			}
		}
		fmt.Fprintf(out, "  Restart the %s above to pick up the change.\n", pluralWord(n, "MCP host", "MCP hosts"))
		fmt.Fprintln(out)
	}

	if len(awsProfiles) > 0 {
		summary.checkGitHistory(migrate.AWSCredentialsPath(home))
		printMigrateResultCategory(out, pluralWord(len(awsProfiles), "AWS profile", "AWS profiles")+" migrated", len(awsProfiles))
		for _, awsProfile := range awsProfiles {
			result, err := migrate.ApplyAWSProfile(v, home, awsProfile, backups)
			if err != nil {
				return false, fmt.Errorf("jit migrate: %w", err)
			}
			backups := fmt.Sprintf("`jit vault get %s`", result.CredentialsBackup)
			if result.ConfigBackup != "" {
				backups += fmt.Sprintf(", `jit vault get %s`", result.ConfigBackup)
			}
			fmt.Fprintf(out, "  "+glyphBullet+" %q -> vault profile %q (%s); backups: %s\n",
				awsProfile, result.VaultProfileName, countWord(len(result.Variables), "var", "vars"), backups)
		}
		fmt.Fprintln(out)
	}

	if len(k8sUsers) > 0 {
		summary.checkGitHistory(migrate.KubeconfigPath(home))
		printMigrateResultCategory(out, pluralWord(len(k8sUsers), "kubeconfig user", "kubeconfig users")+" migrated", len(k8sUsers))
		for _, k8sUser := range k8sUsers {
			result, err := migrate.ApplyKubeconfigUser(v, home, k8sUser, backups)
			if err != nil {
				return false, fmt.Errorf("jit migrate: %w", err)
			}
			fmt.Fprint(out, hlCmds(fmt.Sprintf("  "+glyphBullet+" %q (%s) -> vault profile %q (%s); backup: `jit vault get %s`\n",
				k8sUser, result.AuthType, result.VaultProfileName, countWord(len(result.Variables), "var", "vars"), result.Backup)))
		}
		fmt.Fprintln(out)
	}

	if len(terraformHosts) > 0 {
		summary.checkGitHistory(migrate.TerraformCredentialsPath(home))
		printMigrateResultCategory(out, pluralWord(len(terraformHosts), "Terraform Cloud host", "Terraform Cloud hosts")+" migrated", len(terraformHosts))
		for _, tfHost := range terraformHosts {
			result, err := migrate.ApplyTerraformHost(v, home, tfHost, backups)
			if err != nil {
				return false, fmt.Errorf("jit migrate: %w", err)
			}
			backups := fmt.Sprintf("`jit vault get %s`", result.CredentialsBackup)
			if result.RCBackup != "" {
				backups += fmt.Sprintf(", `jit vault get %s`", result.RCBackup)
			}
			fmt.Fprintf(out, "  "+glyphBullet+" %q -> vault profile %q (%s); backups: %s\n",
				tfHost, result.VaultProfileName, countWord(len(result.Variables), "var", "vars"), backups)
		}
		fmt.Fprintln(out)
	}

	if len(dockerRegistries) > 0 {
		summary.checkGitHistory(migrate.DockerConfigPath(home))
		printMigrateResultCategory(out, pluralWord(len(dockerRegistries), "Docker registry credential", "Docker registry credentials")+" migrated", len(dockerRegistries))
		claimedDefaultStore := false
		for _, dockerRegistry := range dockerRegistries {
			result, err := migrate.ApplyDockerRegistry(v, home, dockerRegistry, backups)
			if err != nil {
				return false, fmt.Errorf("jit migrate: %w", err)
			}
			claimedDefaultStore = claimedDefaultStore || result.ClaimedDefaultStore
			fmt.Fprint(out, hlCmds(fmt.Sprintf("  "+glyphBullet+" %q -> vault profile %q (%s); backup: `jit vault get %s`\n",
				dockerRegistry, result.VaultProfileName, countWord(len(result.Variables), "var", "vars"), result.ConfigBackup)))
		}
		if claimedDefaultStore {
			fmt.Fprintln(out, "  ~/.docker/config.json had no credential store, so jit is now its default:")
			fmt.Fprintln(out, hlCmds("  a future `docker login` to ANY registry lands in the vault, not in base64."))
		}
		// Docker discovers docker-credential-jit strictly by $PATH lookup,
		// and the helper lives in jit's shim directory — reuse wrap's own
		// rc-file PATH line so the next shell (and everything it spawns,
		// docker included) resolves it. Idempotent; a machine that already
		// wrapped a tool has the line and prints nothing new here.
		rc := wrap.RcFile(home, os.Getenv("SHELL"))
		rcChanged, err := wrap.EnsurePathLine(rc)
		if err != nil {
			return false, fmt.Errorf("jit migrate: %w", err)
		}
		if rcChanged {
			fmt.Fprintf(out, "  Added to %s: %s\n", displayPath(home, rc), wrap.PathLine())
			fmt.Fprintln(out, "  (docker finds the credential helper via PATH, open a new shell before the next pull/push)")
		}
		fmt.Fprintln(out)
	}

	if len(gitHosts) > 0 {
		summary.checkGitHistory(migrate.GitCredentialsPath(home))
		printMigrateResultCategory(out, pluralWord(len(gitHosts), "git HTTPS credential", "git HTTPS credentials")+" migrated", len(gitHosts))
		replacedStore := false
		for _, gitHost := range gitHosts {
			result, err := migrate.ApplyGitCredential(v, home, gitHost, backups)
			// A host jit's host-level model can't represent is SKIPPED, not
			// fatal: aborting here would take the whole migrate run down (every
			// other category included) over one host, and migrating it anyway
			// would delete the account that wasn't vaulted. Said out loud —
			// a credential silently left behind is how a user ends up believing
			// they are protected when they are not.
			if errors.Is(err, migrate.ErrGitMultipleAccounts) {
				fmt.Fprintf(out, "  "+glyphBullet+" %q SKIPPED — %v\n", gitHost, err)
				fmt.Fprintln(out, "    Its credentials are untouched and still work. Vault them by hand with"+
					" `jit vault set` if you want them protected before multi-account support lands.")
				continue
			}
			if err != nil {
				return false, fmt.Errorf("jit migrate: %w", err)
			}
			replacedStore = replacedStore || result.ReplacedStoreHelper
			backupNote := fmt.Sprintf("`jit vault get %s`", result.CredentialsBackup)
			if result.ConfigBackup != "" {
				backupNote += fmt.Sprintf(", `jit vault get %s`", result.ConfigBackup)
			}
			fmt.Fprintf(out, "  "+glyphBullet+" %q -> vault profile %q (%s); backups: %s\n",
				gitHost, result.VaultProfileName, countWord(len(result.Variables), "var", "vars"), backupNote)
		}
		if replacedStore {
			fmt.Fprintln(out, hlCmds("  Replaced git's plaintext `store` credential helper with jit."))
		}
		// git discovers git-credential-jit strictly by $PATH lookup, and the
		// helper lives in jit's shim directory — reuse wrap's own rc-file PATH
		// line so the next shell (and everything it spawns, git included)
		// resolves it. Idempotent; a machine that already wrapped a tool or
		// migrated docker has the line and prints nothing new here.
		rc := wrap.RcFile(home, os.Getenv("SHELL"))
		rcChanged, err := wrap.EnsurePathLine(rc)
		if err != nil {
			return false, fmt.Errorf("jit migrate: %w", err)
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
				return false, fmt.Errorf("jit migrate: %w", err)
			}
			if err := addMount(mount.Entry{MountPath: adcPath, ProfilePath: result.ProfilePath, TemplatePath: result.TemplatePath}); err != nil {
				return false, fmt.Errorf("jit migrate: registering mount for %s: %w", adcPath, err)
			}
			if err := summary.writePointerFile(adcPath, result.ProfilePath); err != nil {
				return false, fmt.Errorf("jit migrate: %w", err)
			}
			fmt.Fprint(out, hlCmds(fmt.Sprintf("  "+glyphBullet+" %s (%s) -> profile %q (%s); backup: `jit vault get %s`\n",
				displayPath(home, adcPath), result.CredType, result.ProfileName, countWord(len(result.Variables), "var", "vars"), result.BackupPath)))
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
		printMigrateResultCategory(out, pluralWord(n, "SOPS age key file", "SOPS age key files")+" migrated", n)
		for _, keyPath := range sopsAgeFiles {
			summary.checkGitHistory(keyPath)

			result, err := migrate.ApplySOPSAge(v, home, keyPath)
			if err != nil {
				return false, fmt.Errorf("jit migrate: %w", err)
			}
			if err := addMount(mount.Entry{MountPath: keyPath, ProfilePath: result.ProfilePath, TemplatePath: result.TemplatePath}); err != nil {
				return false, fmt.Errorf("jit migrate: registering mount for %s: %w", keyPath, err)
			}
			if err := summary.writePointerFile(keyPath, result.ProfilePath); err != nil {
				return false, fmt.Errorf("jit migrate: %w", err)
			}
			fmt.Fprint(out, hlCmds(fmt.Sprintf("  "+glyphBullet+" %s -> profile %q; backup: `jit vault get %s`\n",
				displayPath(home, keyPath), result.ProfileName, result.BackupPath)))
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
		printMigrateResultCategory(out, pluralWord(n, "npmrc file", "npmrc files")+" migrated", n)
		for _, npmrcPath := range npmrcFiles {
			summary.checkGitHistory(npmrcPath)

			globalNpmrc := npmrcPath == migrate.GlobalNpmrcPath(home)
			npmrcRoot := home
			if !globalNpmrc {
				npmrcRoot = filepath.Dir(npmrcPath)
			}
			result, err := migrate.ApplyNpmrc(v, npmrcRoot, npmrcPath, globalNpmrc)
			if err != nil {
				return false, fmt.Errorf("jit migrate: %w", err)
			}
			if err := addMount(mount.Entry{MountPath: npmrcPath, ProfilePath: result.ProfilePath, TemplatePath: result.TemplatePath}); err != nil {
				return false, fmt.Errorf("jit migrate: registering mount for %s: %w", npmrcPath, err)
			}
			if err := summary.writePointerFile(npmrcPath, result.ProfilePath); err != nil {
				return false, fmt.Errorf("jit migrate: %w", err)
			}
			fmt.Fprint(out, hlCmds(fmt.Sprintf("  "+glyphBullet+" %s -> profile %q (%s); backup: `jit vault get %s`\n",
				displayPath(home, npmrcPath), result.ProfileName, countWord(len(result.Variables), "var", "vars"), result.BackupPath)))
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
		printMigrateResultCategory(out, pluralWord(n, ".netrc password", ".netrc passwords")+" migrated", n)
		for _, netrcPath := range netrcFiles {
			summary.checkGitHistory(netrcPath)

			result, err := migrate.ApplyNetrc(v, home, netrcPath)
			if err != nil {
				return false, fmt.Errorf("jit migrate: %w", err)
			}
			if err := addMount(mount.Entry{MountPath: netrcPath, ProfilePath: result.ProfilePath, TemplatePath: result.TemplatePath}); err != nil {
				return false, fmt.Errorf("jit migrate: registering mount for %s: %w", netrcPath, err)
			}
			if err := summary.writePointerFile(netrcPath, result.ProfilePath); err != nil {
				return false, fmt.Errorf("jit migrate: %w", err)
			}
			fmt.Fprint(out, hlCmds(fmt.Sprintf("  "+glyphBullet+" %s -> profile %q (%s); backup: `jit vault get %s`\n",
				displayPath(home, netrcPath), result.ProfileName, countWord(len(result.Variables), "var", "vars"), result.BackupPath)))
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
		printMigrateResultCategory(out, pluralWord(n, "~/.pypirc credential", "~/.pypirc credentials")+" migrated", n)
		for _, pypircPath := range pypircFiles {
			summary.checkGitHistory(pypircPath)

			result, err := migrate.ApplyPypirc(v, home, pypircPath)
			if err != nil {
				return false, fmt.Errorf("jit migrate: %w", err)
			}
			if err := addMount(mount.Entry{MountPath: pypircPath, ProfilePath: result.ProfilePath, TemplatePath: result.TemplatePath}); err != nil {
				return false, fmt.Errorf("jit migrate: registering mount for %s: %w", pypircPath, err)
			}
			if err := summary.writePointerFile(pypircPath, result.ProfilePath); err != nil {
				return false, fmt.Errorf("jit migrate: %w", err)
			}
			fmt.Fprint(out, hlCmds(fmt.Sprintf("  "+glyphBullet+" %s -> profile %q (%s); backup: `jit vault get %s`\n",
				displayPath(home, pypircPath), result.ProfileName, countWord(len(result.Variables), "var", "vars"), result.BackupPath)))
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

	if n := len(cargoRegistries); n > 0 {
		summary.checkGitHistory(migrate.CargoCredentialPaths(home)[0])
		printMigrateResultCategory(out, pluralWord(n, "cargo registry token", "cargo registry tokens")+" migrated", n)
		for _, cargoRegistry := range cargoRegistries {
			result, err := migrate.ApplyCargoRegistry(v, home, cargoRegistry, backups)
			if err != nil {
				return false, fmt.Errorf("jit migrate: %w", err)
			}
			backupNotes := fmt.Sprintf("`jit vault get %s`", result.CredentialsBackup)
			if result.ConfigBackup != "" {
				backupNotes += fmt.Sprintf(", `jit vault get %s`", result.ConfigBackup)
			}
			fmt.Fprint(out, hlCmds(fmt.Sprintf("  "+glyphBullet+" %q -> vault profile %q (%s); backups: %s\n",
				cargoRegistry, result.VaultProfileName, countWord(len(result.Variables), "var", "vars"), backupNotes)))
		}
		fmt.Fprintln(out, hlCmds("  `cargo login`/`logout` keep working — a re-login lands in the vault, not a file."))
		fmt.Fprintln(out)
	}

	if n := len(streamlitFiles); n > 0 {
		printMigrateResultCategory(out, pluralWord(n, "Streamlit secrets file", "Streamlit secrets files")+" migrated", n)
		for _, slPath := range streamlitFiles {
			summary.checkGitHistory(slPath)

			// The project root is the parent of .streamlit — the file's
			// location inside a project is fixed by Streamlit, so the root
			// derives from the path itself, never from the invoking cwd
			// (the deriveProfileName lesson recorded in migrate/doc.go).
			// When that parent IS $HOME, this is the global file.
			globalStreamlit := slPath == migrate.StreamlitGlobalPath(home)
			slRoot := filepath.Dir(filepath.Dir(slPath))
			result, err := migrate.ApplyStreamlitSecrets(v, slRoot, slPath, globalStreamlit)
			if err != nil {
				return false, fmt.Errorf("jit migrate: %w", err)
			}
			if err := addMount(mount.Entry{MountPath: slPath, ProfilePath: result.ProfilePath, TemplatePath: result.TemplatePath}); err != nil {
				return false, fmt.Errorf("jit migrate: registering mount for %s: %w", slPath, err)
			}
			if err := summary.writePointerFile(slPath, result.ProfilePath); err != nil {
				return false, fmt.Errorf("jit migrate: %w", err)
			}
			fmt.Fprint(out, hlCmds(fmt.Sprintf("  "+glyphBullet+" %s -> profile %q (%s); backup: `jit vault get %s`\n",
				displayPath(home, slPath), result.ProfileName, countWord(len(result.Variables), "var", "vars"), result.BackupPath)))
			noteNamespaceMove(out, result.NamespaceMovedFrom, result.ProfileName)
			if globalStreamlit {
				// The global ~/.streamlit/secrets.toml is a machine-wide
				// mount, same as ~/.pypirc: usage is explicit `jit run
				// --with streamlit` intent (plan §12a). A project's own
				// file needs no reminder — `jit run` grants it from the
				// project directory like any project template mount.
				if g, ok := globalMountGuidanceForPath(home, slPath); ok {
					fmt.Fprintf(out, "    %s read it with: jit run --with %s <command>\n", g.tools, g.name)
				}
			}
		}
		fmt.Fprintln(out)
	}

	opLinks.print(out)

	// Best-effort: an unreadable marker means no nudge, never a failed
	// migrate — everything above already succeeded. Only when this run
	// stored a secret: "these secrets now live only in this vault" is
	// false of a run that refreshed a path and vaulted a file backup.
	if _, recorded, err := vault.LastExport(root); err == nil && !recorded && vaultsValues {
		summary.exportNudge = true
	}

	// The credential is not gone from the machine until the agent's copies of
	// it are gone too. Runs last, after every file migration: its needles are
	// the values those migrations just vaulted, and a copy removed before the
	// original was safely stored would be the wrong order to fail in.
	// Detach the collector before the sweep: CleanAgentCaches backs up every
	// file it rewrites through this same vault, and those writes must not feed
	// back into the needle set (nor matter after collection is done).
	v.OnSet = nil
	v.LinkOnSet = nil // the sweep's own backups must never be offered for linking
	// DropOrdinaryValues: needle discipline over the OnSet capture — an env
	// migration vaults ordinary config too, and the sweep must hunt only
	// what scan's cache hunt would (issue #79). --only without "cache"
	// scopes the whole sweep out, matching the plan the user confirmed.
	var cleanup migrate.AgentCacheCleanup
	var cleanErr error
	if cacheSelected {
		cleanup, cleanErr = migrate.CleanAgentCaches(v, home, migrate.DropOrdinaryValues(vaultedSecrets, envOrdinary))
	}

	summary.print(out)
	// Rendered after the file summary, through the same helper `jit migrate
	// caches` uses, so the two commands describe an identical outcome. Printed
	// (not stored on the summary) because it writes files the plan named and a
	// [y/N] approved — the result must always be visible, and the partial
	// result on error most of all: the edits already made are real and
	// undoable, so hiding them would strand the user. Never fatal.
	if len(cleanup.Edited) > 0 || len(cleanup.Skipped) > 0 {
		fmt.Fprintln(out)
		renderAgentCleanupResult(out, home, cleanup)
	}
	if cleanErr != nil {
		fmt.Fprintf(out, "jit: could not finish clearing AI agent caches: %v\n", cleanErr)
	}
	// Remember any copy left ONLY because a session was live: that is the one
	// case a later `jit migrate caches` can still reach (the origin is now a
	// pointer, so scan and a future migrate cannot). Binary/hard-link skips
	// are standing conditions re-running won't fix, so they don't set a
	// reminder — the one-time output already named them. A run with no live
	// skips clears any stale crumb. A run that never swept (--only without
	// "cache") learned nothing and must not clear one either.
	if cacheSelected {
		migrate.WriteCacheBreadcrumb(root, cleanup.LiveSkips(), time.Now().UnixNano())
	}
	reportAgentStatus(out, root, producedMount)
	if cleanInputs != nil {
		cleanInputs.vaulted = vaultedSecrets
		cleanInputs.swept = map[string]bool{}
		for _, e := range cleanup.Edited {
			cleanInputs.swept[e.Path] = true
		}
	}
	// The folder-rename advisory is left to `jit status`: an explicitly named
	// migrate target can sit under any project, so there's no single "this
	// project" here whose rename to flag (see noteFolderRename, still used by
	// status).
	return true, nil
}

// cleanPhaseInputs is applyMigrate's hand-off to runCleanPhase — see
// applyMigrate's doc comment. Zero-valued when the apply never ran (a
// declined plan, a dry run), which the clean phase never reaches anyway.
type cleanPhaseInputs struct {
	vaulted []migrate.AgentCacheSecret
	swept   map[string]bool
}

// runMigratePath implements `jit migrate <file-or-dir>...` (and its `path`
// alias): convert only the file(s) and folder(s) named on the command line,
// with no directory walk beyond a named folder itself. The caller always
// names exactly what they want moved (one project's .env, a single ~/.zshrc,
// a directory of tfvars files). Each target is resolved and classified on
// its own, its findings merged into one discovered set, then handed to the
// shared applyMigrate path for the plan/confirm gate, encrypted backups, and
// undo support.
// runMigrateAll is the bare `jit migrate`: execute the protect plan the
// machine-wide scan computes — the exact manifest `jit scan`'s "jit will
// protect these" section renders, from the same Remedy annotations, so the
// report and the command can never disagree about what will happen.
//
// The consent story is unchanged from targeted migrate: the full plan
// prints and a [y/N] gate precedes any change (applyMigrate's own gate).
// Wraps run after the file migrations, automatically — the design decision
// of 2026-07-28: the plan line is the consent, and each wrap prints its
// undo command right after it happens. Archived findings are skipped, the
// same as every non-explicit migrate path; Low/Info sightings are not part
// of the plan at all (CountedAsSecret).
func runMigrateAll(cmd *cobra.Command) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("jit migrate: %w", err)
	}
	cfg, err := newAuditConfig()
	if err != nil {
		return fmt.Errorf("jit migrate: %w", err)
	}
	if root, rootErr := vaultRootDir(); rootErr == nil {
		cfg.MountRegistryPath = mount.RegistryPath(root)
	}

	progress := newProgress(cmd, false)
	step, settleTrail := collapsedCategoryTrail(progress)
	cfg.Progress = step
	findings, summary, err := audit.Scan(cfg)
	settleTrail()
	if err != nil {
		return fmt.Errorf("jit migrate: %w", err)
	}

	var files []string
	seenFile := map[string]bool{}
	var tools []string
	seenTool := map[string]bool{}
	for _, f := range findings {
		if !audit.CountedAsSecret(f) || f.Archived {
			continue
		}
		switch f.Remedy {
		case audit.RemedyWrap:
			tool := strings.TrimPrefix(f.FixCommand, "jit wrap ")
			if tool != "" && !seenTool[tool] {
				seenTool[tool] = true
				tools = append(tools, tool)
			}
		case audit.RemedyMigrate:
			if f.FilePath != "" && !seenFile[f.FilePath] {
				seenFile[f.FilePath] = true
				files = append(files, f.FilePath)
			}
		}
	}
	// --only scopes the FILE half of the plan (applyMigrate applies it);
	// wraps aren't an --only category, so running them anyway would do work
	// the user explicitly scoped out — skip them, and say so.
	if len(migrateOnly) > 0 && len(tools) > 0 {
		fmt.Fprintf(cmd.ErrOrStderr(), "note: --only is set, skipping %s %s: %s\n", pluralWord(len(tools), "CLI", "CLIs"), pluralWord(len(tools), "wrap", "wraps"), strings.Join(tools, ", "))
		tools = nil
	}
	// The guard is offered only when this scan found a credential in history:
	// bare `jit migrate` is "do what the scan found", and installing a shell
	// hook for a problem the user does not have would be work nobody asked
	// for. Skipped when --only is set, for the same reason wraps are — the
	// user scoped this run. Skipped when it is already installed, and when
	// the login shell is not zsh, since the hook is zsh syntax and would sit
	// in a file that shell never reads.
	offerGuard := false
	for _, f := range findings {
		if f.FindingType == audit.FindingTypeShellHistorySecret && audit.CountedAsSecret(f) && !f.Archived {
			offerGuard = true
			break
		}
	}
	if offerGuard && (len(migrateOnly) > 0 || guard.Installed(home) || filepath.Base(os.Getenv("SHELL")) != "zsh") {
		offerGuard = false
	}

	// --clean plans the delete pass from the same scan (design/
	// migrate-clean.md D1). No exclude set on a bare run: the migrate half
	// above filters out f.Archived and RemedyManual findings, so a migrate
	// target can never also be a deletion candidate here.
	var cleanPlan *migrate.CleanPlan
	if migrateClean {
		cp := migrate.PlanClean(home, findings, nil)
		cleanPlan = &cp
	}

	// The artifacts migrate itself wrote are checked on every bare run —
	// independent of the scan, which is about secrets — so a recorded jit
	// path heals before the upgrade that would break it, under a plan the
	// user previews (design/jit-path-refresh.md D3).
	d := &discovered{}
	discoverJitPathRefresh(d, home, nil)

	if len(files) == 0 && len(tools) == 0 && !offerGuard && d.total() == 0 && len(d.jitPathRefused) == 0 && !cleanHasWork(cleanPlan) {
		fmt.Fprintln(cmd.OutOrStdout(), hlCmds("Nothing to protect — the scan found no secrets jit can act on. Run `jit scan` for the full picture."))
		return nil
	}
	sort.Strings(files)

	for _, path := range files {
		if err := discoverFileTarget(d, home, path); err != nil {
			// One unreadable file must not sink the whole protect run; say
			// so and keep going — the scan will keep reporting it.
			fmt.Fprintf(cmd.ErrOrStderr(), "skipping %s: %v\n", displayPath(home, path), err)
		}
	}
	d.dedupe()

	out := cmd.OutOrStdout()
	if d.total() == 0 && len(tools) == 0 && !offerGuard && !cleanHasWork(cleanPlan) {
		// Discovery routed every candidate to a skip (mixed-content files,
		// or files that changed since the scan). No plan, no prompt, and
		// definitely no coverage promise.
		//
		// The guard keeps this branch open when it is still on offer, because
		// that combination is exactly when it matters most: the scan found a
		// credential in history and discovery could not clean the file (it is
		// hard-linked, or changed under us), so preventing the NEXT one is the
		// only protection left to give. Returning here would have offered it
		// in the plan and then silently not installed it.
		if len(d.jitPathRefused) > 0 {
			printJitPathRefused(out, home, d)
			return nil
		}
		fmt.Fprintln(out, hlCmds("Nothing bare `jit migrate` can protect right now: the flagged file(s) mix secrets with other content or need to be named explicitly. `jit scan` has the details."))
		return nil
	}

	// The frame opens before the plan (design/dry-run-refactor.md D1).
	if migrateDryRun {
		printDryRunBanner(out)
	}

	// The wraps and the guard enter the plan as counted categories rather
	// than prose above it (design/dry-run-refactor.md D3): the plan row is
	// the consent line the single [y/N] below commits to, and it states
	// the OUTCOME per catalog kind — a reader who has never seen `jit wrap`
	// or `jit guard history` cannot evaluate a bare command name, and a
	// line they cannot evaluate is one they should not be agreeing to.
	extras := &planExtras{scanDriven: true}
	for _, tool := range tools {
		extras.wraps = append(extras.wraps, wrapPlanRow{tool: tool, detail: wrapPlanDetail(home, tool)})
	}
	if offerGuard {
		extras.guardItems = []string{displayPath(home, guard.HookPath(home)) + " (sourced from " + displayPath(home, guard.RcPath(home)) + ")"}
	}
	extras.clean = cleanPlan

	applied := true
	var cleanIn cleanPhaseInputs
	if d.total() > 0 {
		applied, err = applyMigrate(cmd, home, d, extras, "", &cleanIn) // "" — this function owns the dry-run frame
		if err != nil {
			return err
		}
	} else {
		// Wraps/guard/deletions only: applyMigrate never runs, so render the
		// same plan shape it would (extras as its only categories) and gate
		// on the same [y/N] — this run installs shims and shell hooks, which
		// is exactly what the plan-then-consent discipline exists for. A
		// deletions-only plan skips this gate: runCleanPhase's own [y/N],
		// which names every path, is that plan's consent, and two prompts
		// for one category teaches people to stop reading them.
		printMigratePlan(out, home, d, extras)
		if len(tools) > 0 || offerGuard {
			if !migrateDryRun && !migrateYes && !confirmPrompt(cmd, "Proceed? [y/N] ") {
				fmt.Fprintln(out, "Aborted. Nothing was changed.")
				return nil
			}
		}
	}
	if !applied && !migrateDryRun {
		return nil // declined at the plan — wraps and the guard must not run either
	}

	// In a dry run the guard and the wraps were already disclosed above the
	// plan, inside the frame — the old post-trailer "[dry-run] would ..."
	// echoes printed a third marker after the line that claimed to be last.
	if offerGuard && !migrateDryRun {
		if _, guardErr := guard.Install(home); guardErr != nil {
			// One failed hook must not fail a migrate that already moved
			// real secrets into the vault.
			fmt.Fprintf(cmd.ErrOrStderr(), "installing the history guard failed: %v\n", guardErr)
		} else {
			// The hook runs on every command the user types from now on,
			// and they agreed to it as one line in a plan. The trail has
			// to say where it came from.
			recordSideEffect("jit guard history", []string{"guard", "history"}, "jit migrate")
			fmt.Fprintln(out)
			_, _ = cOK.Fprintf(out, "%s ", glyphDone)
			wrapBody(out, 2, "  ", hlCmds(fmt.Sprintf("history guard installed (%s, sourced from %s). New shells pick it up; "+
				"run `source ~/.jit/guard.zsh` in ones already open. Reverse with `jit guard history --remove`.",
				displayPath(home, guard.HookPath(home)), displayPath(home, guard.RcPath(home)))))
		}
	}

	wrapped := 0
	for _, tool := range tools {
		if migrateDryRun {
			break // disclosed above the plan, inside the frame
		}
		fmt.Fprintln(out)
		if wrapErr := runCatalogWrap(cmd, tool); wrapErr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "wrapping %s failed: %v\n", tool, wrapErr)
			continue
		}
		fmt.Fprintf(out, "(reversible: jit wrap undo %s)\n", tool)
		wrapped++
	}
	// The per-run cache sweep above hunted the values the FILE migrations
	// vaulted; a wrap vaults its token afterwards, through its own vault
	// handle, so those tokens are not in that sweep. Rather than thread the
	// collector through the wrap path, point the user at the whole-vault
	// command that reads every secret (these included) back from the vault
	// and cleans their copies. Not a silent gap: the nudge is the disclosure.
	if wrapped > 0 && !migrateDryRun {
		fmt.Fprintln(out, hlCmds("\nWrapped tokens may also sit in AI agent caches, run `jit migrate caches` to clear those copies too."))
	}

	// The clean phase runs LAST, after the wraps, so everything this run
	// vaulted — wrap-captured tokens included — counts toward a copy's
	// redundancy proof. Its own [y/N] and fresh Touch ID live inside
	// (design/migrate-clean.md D4/D5); a dry run already disclosed it as
	// the [deletions] category inside the frame.
	if applied && !migrateDryRun && cleanPlan != nil && len(cleanPlan.Candidates) > 0 {
		if err := runCleanPhase(cmd, home, cleanPlan, cleanIn.vaulted, cleanIn.swept); err != nil {
			return err
		}
	}

	// Close the loop with the number the scan report opened with — only
	// after something actually applied; a declined or empty run must not
	// print a coverage gain it didn't produce.
	//
	// d.total() is part of that test, not just `applied`: a run whose files
	// were all skipped by discovery never calls applyMigrate at all, so
	// `applied` stays at its initial true and the projection would promise a
	// jump ("0% → up to 100%") for work that provably did not happen. That
	// path is reachable now that the guard can be the only thing a run does.
	if applied && !migrateDryRun && d.vaultsValues() > 0 && summary.SecretsTotal > 0 {
		before := summary.SecretsProtected * 100 / summary.SecretsTotal
		after := (summary.SecretsProtected + summary.SecretsMigratable) * 100 / summary.SecretsTotal
		fmt.Fprint(out, hlCmds(fmt.Sprintf("\ncoverage: %d%% "+glyphAction+" up to %d%% — run `jit scan` to see the new number\n", before, after)))
	}
	// The frame closes after everything the run disclosed — including the
	// wraps-only case, which never enters applyMigrate at all and used to
	// print no frame whatsoever.
	if migrateDryRun {
		printDryRunTrailer(out, migrateApplyCommand("jit migrate", nil), true)
	}
	return nil
}

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
	var resolved []string
	for _, target := range targets {
		abs := expandTilde(target, home)
		if !filepath.IsAbs(abs) {
			abs = filepath.Join(cwd, abs)
		}
		abs = filepath.Clean(abs)
		resolved = append(resolved, abs)
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

	// --clean on a targeted run: classify the named paths with the scanner
	// (discovery above only routes files to migrations) and route every
	// delete-class file to the delete pass INSTEAD of migration — naming a
	// Trash file with --clean means finish its deletion, and vaulting it
	// would preserve what deletion is about to fix (the scan report's own
	// stance; design/migrate-clean.md D9).
	var cleanPlan *migrate.CleanPlan
	var extras *planExtras
	if migrateClean {
		cfg, cfgErr := newAuditConfig()
		if cfgErr != nil {
			return fmt.Errorf("jit migrate path: %w", cfgErr)
		}
		findings, _, scanErr := audit.TargetedScan(cfg, resolved)
		if scanErr != nil {
			return fmt.Errorf("jit migrate path: %w", scanErr)
		}
		cp := migrate.PlanClean(home, findings, nil)
		cleanPlan = &cp
		dropCleanCandidates(d, cleanPlan)
		extras = &planExtras{clean: cleanPlan}
	}

	applied := true
	var cleanIn cleanPhaseInputs
	if d.total() > 0 || !cleanHasWork(cleanPlan) {
		applied, err = applyMigrate(cmd, home, d, extras, migrateApplyCommand("jit migrate", targets), &cleanIn)
		if err != nil {
			return err
		}
	} else {
		// Deletions-only run: applyMigrate would report "nothing to
		// migrate", so render the same plan shape with the delete pass as
		// its only category, inside the frame this branch now owns. No
		// separate Proceed gate — runCleanPhase's own [y/N], which names
		// every path, IS this plan's consent, and two prompts for one
		// category teaches people to stop reading them.
		out := cmd.OutOrStdout()
		if migrateDryRun {
			printDryRunBanner(out)
		}
		printMigratePlan(out, home, d, extras)
		if migrateDryRun {
			printDryRunTrailer(out, migrateApplyCommand("jit migrate", targets), true)
			return nil
		}
	}
	if applied && !migrateDryRun && cleanPlan != nil && len(cleanPlan.Candidates) > 0 {
		if err := runCleanPhase(cmd, home, cleanPlan, cleanIn.vaulted, cleanIn.swept); err != nil {
			return err
		}
	}
	return nil
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
	k8s, k8sc, err := migrate.DiscoverK8sSecretManifests(dir)
	if err != nil {
		return err
	}
	d.k8sManifests = append(d.k8sManifests, k8s...)
	d.k8sManifestsComplexOnly = append(d.k8sManifestsComplexOnly, k8sc...)
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
	// One walk finds both a project's .streamlit/secrets.toml and — when
	// dir IS $HOME — the global ~/.streamlit/secrets.toml, which is just
	// the copy that happens to sit there (audit's scanner takes the same
	// one-walk stance; see migrate.DiscoverStreamlitSecrets).
	sls, err := migrate.DiscoverStreamlitSecrets(dir)
	if err != nil {
		return err
	}
	d.streamlitFiles = append(d.streamlitFiles, sls...)
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
	// Shell history: routed by NAME (the fixed defaults plus a custom
	// $HISTFILE), and NEVER allowed to fall through to the generic
	// categories — loose-secret classification reads a zsh extended_history
	// line as "embedded" content and would offer --mount, turning the
	// shell's own record into a FIFO no shell can append to. Routing is
	// unconditional; whether the file holds anything is the preview's call
	// (an explicitly named clean history lands in the ordinary "nothing to
	// migrate" report).
	if isHistoryTarget(home, path) {
		secrets, _, err := migrate.PreviewShellHistory(path)
		if err != nil {
			// Fail loud with the reason rather than reporting "nothing to
			// migrate". A history file jit will not touch — hard-linked,
			// unreadable, past the size bound — is a file the user explicitly
			// named, and silently doing nothing reads as "there was nothing
			// there" when the truth is "jit refused, and here is why".
			return err
		}
		switch {
		case secrets > 0:
			d.historyFiles = append(d.historyFiles, path)
		case migrate.HasOnlyPrivateKeyMaterial(path):
			// Flagged by `jit scan`, deliberately not redactable — say so
			// rather than reporting "nothing to migrate" at a file the report
			// just called CRITICAL.
			d.historyKeyOnly = append(d.historyKeyOnly, path)
		}
		return nil
	}
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
	// An artifact migrate itself wrote (~/.kube/config, ~/.aws/config, a
	// credential helper) is also checked for the jit path it records —
	// before the switch, which returns early for the kubeconfig, and in
	// addition to it: a kubeconfig with a plaintext token AND a stale exec
	// line gets both rows (design/jit-path-refresh.md D3). This is what
	// makes doctor's `jit migrate ~/.kube/config` do what it says on a
	// file that has already been migrated.
	discoverJitPathRefresh(d, home, func(r migrate.RecordedJitPath) bool { return r.Path == path })
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
	case migrate.CargoCredentialPaths(home)[0], migrate.CargoCredentialPaths(home)[1]:
		// Name-keyed like aws/kube/terraform: naming either credentials
		// file migrates every registry it holds (and strips the stale
		// copy in the sibling file too — cargo reads only the first).
		regs, err := migrate.DiscoverCargoRegistries(home)
		if err != nil {
			return err
		}
		d.cargoRegistries = append(d.cargoRegistries, regs...)
		return nil
	case migrate.PypircPath(home):
		files, err := migrate.DiscoverPypirc(home)
		if err != nil {
			return err
		}
		d.pypircFiles = append(d.pypircFiles, filterToTarget(files, path)...)
		return nil
	}
	// The fixed MCP configs are a LIST (Claude Desktop's file plus
	// ~/.claude.json), so they're matched against audit's list rather than
	// being one more case above — a fixed path audit scans but this switch
	// doesn't know about is a finding `jit migrate <path>` answers "nothing
	// to do" on, with zero errors anywhere. That was ~/.claude.json.
	for _, fixed := range audit.FixedMCPConfigPaths(home) {
		if path != fixed {
			continue
		}
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
	beforeK8sComplex := len(d.k8sManifestsComplexOnly)
	if err := discoverDirTarget(d, home, path); err != nil {
		return err
	}
	// A Secret manifest the k8s migrator RECOGNIZED but refused (block
	// scalars, mixed data:/stringData:) must not fall through to loose-secret
	// detection: the loose --mount template would turn a stringData: value
	// into a plaintext decoy that `kubectl apply` silently ships to a real
	// cluster — the exact failure the k8s category's rejectable-decoy rule
	// exists to prevent. The refusal note is the outcome.
	if len(d.k8sManifestsComplexOnly) > beforeK8sComplex {
		return nil
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
		// A file a wrappable CLI owns (a catalog tool's token Source, or
		// clisso's config) has a better fix than loose-secret surgery:
		// `jit wrap <tool>` vaults the token and keeps the tool working
		// through a shim. Routing it into the "mixes a secret with other
		// content" note sent the user at --mount instead — the wrong tool
		// for a file the wrap flow protects whole (D7).
		if _, owned := wrapOwnerForPath(home, path); owned {
			d.wrapOwnedSkipped = append(d.wrapOwnedSkipped, path)
			return nil
		}
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

// isHistoryTarget reports whether an explicitly named path is a shell history
// file `jit migrate` routes to redaction: one of the fixed names audit's
// scanner owns (audit.IsShellHistoryPath), the exact file $HISTFILE points at,
// or any name that reads as a history file.
//
// That last rule is looser than anything audit's machine-wide sweep allows,
// and deliberately so — the two commands are answering different questions
// under different risks:
//
//   - $HISTFILE alone is not enough, because neither zsh nor bash EXPORTS it.
//     It is an ordinary shell parameter, so a child process sees it only if
//     the user went out of their way to export it. For the very user this
//     rule exists for, the one who moved their history to ~/.cache/zsh/history,
//     os.Getenv returns "" and the fixed-name list matches nothing.
//   - Falling through is not a harmless miss here. Discovery would hand the
//     file to loose-secret classification, which reads a history file as
//     "a secret embedded in other content" and offers --mount: that turns the
//     shell's own append-only record into a FIFO, which no shell can append
//     to. Guessing wrong in the other direction merely redacts a credential
//     out of a file the user named and asked jit to fix, with a vault backup
//     and `jit migrate undo` behind it.
//
// audit's sweep rejects name-guessing because it visits every file on the
// machine unbidden. Here the user has typed the path.
func isHistoryTarget(home, path string) bool {
	if audit.IsShellHistoryPath(path) {
		return true
	}
	if hf := os.Getenv("HISTFILE"); hf != "" {
		hf = expandTilde(hf, home)
		if abs, err := filepath.Abs(hf); err == nil {
			hf = abs
		}
		if path == hf {
			return true
		}
	}
	return strings.Contains(strings.ToLower(filepath.Base(path)), "history")
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
		&d.envFiles, &d.tfvarsFiles, &d.tfvarsComplexOnly,
		&d.k8sManifests, &d.k8sManifestsComplexOnly, &d.shellConfigs,
		&d.historyFiles, &d.mcpConfigs, &d.awsProfiles, &d.k8sUsers, &d.terraformHosts,
		&d.dockerRegistries, &d.gitHosts, &d.gcpADCFiles, &d.sopsAgeFiles,
		&d.npmrcFiles, &d.netrcFiles, &d.pypircFiles, &d.cargoRegistries, &d.streamlitFiles, &d.looseSecretFiles, &d.looseEmbeddedSkipped,
		&d.historyKeyOnly, &d.wrapOwnedSkipped, &d.jitPathRefused,
	} {
		dedupeStrings(s)
	}
	seen := map[string]bool{}
	kept := d.jitPaths[:0]
	for _, r := range d.jitPaths {
		if k := r.Path + "\x00" + r.Recorded; !seen[k] {
			seen[k] = true
			kept = append(kept, r)
		}
	}
	d.jitPaths = kept
}

// total counts everything discovered across every category, so
// discoverFileTarget can tell whether the structured scanners already claimed
// a named file before falling back to loose-secret detection. tfvarsComplexOnly
// is note-only (nothing migrate acts on), so it's excluded deliberately.
func (d *discovered) total() int {
	n := 0
	for _, s := range [][]string{
		d.envFiles, d.tfvarsFiles, d.k8sManifests, d.shellConfigs, d.historyFiles, d.mcpConfigs, d.awsProfiles,
		d.k8sUsers, d.terraformHosts, d.dockerRegistries, d.gitHosts,
		d.gcpADCFiles, d.sopsAgeFiles, d.npmrcFiles, d.netrcFiles, d.pypircFiles,
		d.cargoRegistries, d.streamlitFiles, d.looseSecretFiles,
	} {
		n += len(s)
	}
	return n + len(d.jitPaths)
}

// vaultsValues counts what the run will actually STORE: every category
// except the recorded-path refresh, which rewrites one line in a file and
// vaults nothing. Everything that exists to serve stored values — the
// 1Password inventory, the export nudge, the coverage projection — gates
// on this, not on total(): a refresh-only run used to spend minutes
// enumerating a 1Password account for values it was never going to write.
func (d *discovered) vaultsValues() int {
	return d.total() - len(d.jitPaths)
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
	// Wording stays verb-neutral: this persistent flag is also what
	// `jit migrate undo` inherits, where "migrate immediately" was simply
	// the wrong verb for a restore.
	migrateCmd.PersistentFlags().BoolVarP(&migrateYes, "yes", "y", false, "skip the confirmation prompt and proceed immediately")
	migrateCmd.PersistentFlags().StringSliceVar(&migrateOnly, "only", nil, "scope a run to just these comma-separated categories: "+strings.Join(migrateCategories, ",")+" (default: all)")
	_ = migrateCmd.RegisterFlagCompletionFunc("only", completeMigrateCategories)
	// --mount is local rather than persistent: only the migrate/path form
	// reads it, so inheriting it advertised a no-op flag on undo and remove.
	// No backquotes in the usage string either: cobra reads a backquoted span
	// as the flag's value placeholder, which made this bool render as
	// "--mount jit run".
	const mountUsage = "for a loose secret file, keep it live at its path as a mount (real value to jit run grants, a decoy otherwise) instead of replacing it with a pointer; also required to protect a file that mixes a secret with other content"
	migrateCmd.Flags().BoolVar(&migrateMount, "mount", false, mountUsage)
	migratePathCmd.Flags().BoolVar(&migrateMount, "mount", false, mountUsage)
	// Local like --mount: undo/remove never vault a new value, so there is
	// nothing for them to link.
	const no1pUsage = "store plain copies even when a value already lives in 1Password (default: matching values are vaulted as op:// references)"
	migrateCmd.Flags().BoolVar(&migrateNo1Password, "no-1password", false, no1pUsage)
	migratePathCmd.Flags().BoolVar(&migrateNo1Password, "no-1password", false, no1pUsage)
	// Local like --mount: undo/remove/caches never delete scan findings.
	// Wording promises the safety net up front — the flag's whole risk is
	// deletion, so the one fact that changes the decision (encrypted
	// backups + jit migrate undo) belongs in the usage string.
	const cleanUsage = "also delete files whose stated fix is deletion (Trash copies, archived copies whose secrets are all vaulted, AI agent cache leftovers); each is backed up encrypted first and jit migrate undo restores it; gated by its own y/N plus Touch ID"
	migrateCmd.Flags().BoolVar(&migrateClean, "clean", false, cleanUsage)
	migratePathCmd.Flags().BoolVar(&migrateClean, "clean", false, cleanUsage)

	migrateCmd.AddCommand(migratePathCmd)
	rootCmd.AddCommand(migrateCmd)
}
