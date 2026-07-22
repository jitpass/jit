// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/audit"
)

// TestMigrateSummaryPrintCollapsesRepeatedExplanations locks in the fix
// for a real, reported problem: migrating several files used to repeat
// the same multi-line git-history/no-pre-run-hook explanation once PER
// FILE, burying the actually-important closing "run `jit agent
// install`" pointer under dozens of near-identical lines. migrateSummary
// (unlike the vault-touching Apply* calls in runMigrate) needs no
// openVault()/Touch ID, so this — the actual collapsing behavior — is
// fully automatable, even though the mutation path around it isn't.
func TestMigrateSummaryPrintCollapsesRepeatedExplanations(t *testing.T) {
	s := &migrateSummary{
		gitHistoryFiles: []string{"/proj/.env", "/proj/.env.bak", "/proj/.env.local"},
		pointerFiles:    3,
	}
	var buf bytes.Buffer
	s.print(&buf)
	out := buf.String()

	if n := strings.Count(out, "jit migrate does not scrub it"); n != 1 {
		t.Errorf("git-history explanation printed %d time(s), want exactly 1 regardless of file count:\n%s", n, out)
	}
	for _, f := range []string{"/proj/.env", "/proj/.env.bak", "/proj/.env.local"} {
		if !strings.Contains(out, f) {
			t.Errorf("expected %s listed in the collapsed git-history block, got:\n%s", f, out)
		}
	}
	if !strings.Contains(out, "3 git-safe .pointers file(s)") {
		t.Errorf("expected the pointer-file count line, got:\n%s", out)
	}
}

// TestMigrateSummaryExportNudge: a run that lands secrets in a
// never-exported vault says so once, in the summary — and a vault with
// an export on record (even a stale one — every migrate run makes an
// export stale by definition, so nagging on staleness here would teach
// people to skip the whole summary; `jit status` owns staleness) says
// nothing.
func TestMigrateSummaryExportNudge(t *testing.T) {
	var buf bytes.Buffer
	(&migrateSummary{exportNudge: true}).print(&buf)
	if !strings.Contains(buf.String(), "jit vault export") {
		t.Errorf("expected the never-exported nudge naming the command, got:\n%s", buf.String())
	}

	buf.Reset()
	(&migrateSummary{}).print(&buf)
	if strings.Contains(buf.String(), "jit vault export") {
		t.Errorf("expected no export nudge without the flag, got:\n%s", buf.String())
	}
}

// execMigrate drives `jit migrate <scope> <args...>` through rootCmd
// (mirrors execAudit's discipline — see audit_test.go), resetting every
// migrate package-level flag var first so tests never inherit state from
// each other. scope is "local", "home", or "" for the bare command
// (which runs the home scope by default).
func execMigrate(t *testing.T, scope string, args ...string) (stdout string, err error) {
	t.Helper()
	migrateDryRun = false
	migrateYes = false
	migrateOnly = nil
	migrateIncludeArchived = false
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)                 // confirmation prompts go to stderr, capture both streams in order
	rootCmd.SetIn(strings.NewReader("")) // default: EOF, i.e. an empty/declined answer if a confirm prompt is hit unexpectedly
	cmdArgs := []string{"migrate"}
	if scope != "" {
		cmdArgs = append(cmdArgs, scope)
	}
	rootCmd.SetArgs(append(cmdArgs, args...))
	err = rootCmd.Execute()
	return buf.String(), err
}

// TestMigrateCommandRejectsUnexpectedPositionalArg is a real bug's
// regression test: migrate had no Args validator at all (unlike every
// other subcommand in this package), so a stray positional argument —
// e.g. `jit migrate local help`, typed expecting help text — was
// silently accepted and ignored, running a real migration attempt
// instead of erroring. cobra.NoArgs makes this fail loud like every
// other zero-argument command already does. Isolates $HOME/cwd anyway,
// in case this regresses to actually reaching real mode's discovery.
func TestMigrateCommandRejectsUnexpectedPositionalArg(t *testing.T) {
	withFixtureHome(t)
	withFixtureCwd(t)
	for _, scope := range []string{"local", "home"} {
		_, err := execMigrate(t, scope, "help")
		if err == nil {
			t.Errorf("jit migrate %s help: expected an error for an unexpected positional argument, got nil", scope)
		}
	}
}

// TestMigrateLocalNoFindings confirms real mode never reaches openVault()
// — and so never needs Touch ID — when there's nothing to migrate. Real
// mutation touching the vault for an actual .env file is verified
// manually against real hardware, same constraint as jit vault set/get
// and jit run/export.
//
// Isolates BOTH cwd and $HOME: shell-config/MCP discovery is deliberately
// home-scoped (DiscoverShellConfigs/DiscoverMCPConfigs), not cwd-scoped
// like .env, so cwd isolation alone doesn't stop this test from touching
// the real machine's real shell configs/MCP configs. A version of this
// test that only isolated cwd did exactly that once — it found and
// migrated the real Claude Desktop config on the machine running `go
// test`, because os.UserHomeDir() still resolved to the real $HOME.
func TestMigrateLocalNoFindings(t *testing.T) {
	withFixtureHome(t) // guaranteed empty, no shell-config/MCP secrets anywhere under it
	withFixtureCwd(t)  // guaranteed empty, no .env files anywhere under it
	out, err := execMigrate(t, "local")
	if err != nil {
		t.Fatalf("jit migrate local on a directory with no .env files: %v", err)
	}
	if !strings.Contains(out, "Nothing to migrate") {
		t.Errorf("expected a nothing-to-migrate message, got:\n%s", out)
	}
}

// TestMigrateLocalDeclinedConfirmationAborts confirms GAPS.md #17's
// confirmation gate: with a real finding present but no --yes and a
// declined (empty-stdin) prompt, migrate must print the plan, abort, and
// — critically — never reach openVault(), so this stays fully
// automatable (no Touch ID) even though it exercises real mode.
//
// Uses `home` scope: shell configs have no project-scoped form at all
// (see the design change in migrate.go's runMigrate doc comment), so
// `local` never discovers them — only `home` can exercise the gate over
// a shell-config finding specifically.
func TestMigrateLocalDeclinedConfirmationAborts(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	shellConfigPath := filepath.Join(home, ".zshrc")
	original := []byte("export STRIPE_API_KEY=sk_test_fixture_value\n")
	if err := os.WriteFile(shellConfigPath, original, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out, err := execMigrate(t, "home")
	if err != nil {
		t.Fatalf("jit migrate home declined confirmation: %v", err)
	}
	if !strings.Contains(out, "Proceed? [y/N]") {
		t.Errorf("expected the confirmation prompt, got:\n%s", out)
	}
	if !strings.Contains(out, "Aborted. Nothing was changed.") {
		t.Errorf("expected the abort message, got:\n%s", out)
	}
	// The plan "~"-shortens paths under $HOME for display (displayPath).
	if !strings.Contains(out, displayPath(home, shellConfigPath)) {
		t.Errorf("expected the discovered shell config path to be named in the printed plan, got:\n%s", out)
	}
	if strings.Contains(out, "sk_test_fixture_value") {
		t.Fatal("CLI output must never contain the raw secret value")
	}

	after, err := os.ReadFile(shellConfigPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(after) != string(original) {
		t.Fatalf("declining the prompt must leave the file untouched, got:\n%s", after)
	}
}

// TestMigrateOnlyScopesToNamedCategories confirms GAPS.md #21: with both an
// .env finding and a shell-config finding present, --only=env must limit
// the printed plan (and, had confirmation been accepted, the actual
// mutation) to just the .env category — the shell-config secret must be
// named nowhere in the output and the shell config file must stay
// untouched, even though it would normally also be migrated in the same
// invocation.
func TestMigrateOnlyScopesToNamedCategories(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)

	envPath := filepath.Join(cwd, ".env")
	if err := os.WriteFile(envPath, []byte("STRIPE_KEY=sk_test_fixture\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	shellConfigPath := filepath.Join(home, ".zshrc")
	shellOriginal := []byte("export AWS_SECRET=sk_test_fixture_value\n")
	if err := os.WriteFile(shellConfigPath, shellOriginal, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out, err := execMigrate(t, "local", "--only=env")
	if err != nil {
		t.Fatalf("jit migrate local --only=env: %v", err)
	}
	if !strings.Contains(out, envPath) {
		t.Errorf("expected the .env finding to be named in the scoped plan, got:\n%s", out)
	}
	if strings.Contains(out, shellConfigPath) {
		t.Errorf("expected the shell-config finding to be excluded by --only=env, got:\n%s", out)
	}
	if !strings.Contains(out, "Aborted. Nothing was changed.") {
		t.Errorf("expected the declined-confirmation abort message, got:\n%s", out)
	}

	after, err := os.ReadFile(shellConfigPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(after) != string(shellOriginal) {
		t.Fatalf("--only=env must never touch a category it excluded, got:\n%s", after)
	}
}

// TestMigrateOnlyNoMatchingFindings confirms an --only category with no
// findings reports a precise, category-aware "nothing to migrate" message
// rather than either the generic six-category message or silently
// pretending nothing at all was found on the machine.
func TestMigrateOnlyNoMatchingFindings(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	if err := os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export AWS_SECRET=sk_test_fixture_value\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out, err := execMigrate(t, "local", "--only=env")
	if err != nil {
		t.Fatalf("jit migrate local --only=env with no .env findings: %v", err)
	}
	if !strings.Contains(out, "Nothing to migrate in the selected --only category: env.") {
		t.Errorf("expected a category-aware nothing-to-migrate message, got:\n%s", out)
	}
}

// TestMigrateOnlyUnknownCategoryErrors confirms a typo'd --only token fails
// loud, before the confirmation prompt or the plan even print — otherwise a
// typo would look identical to "nothing found in that category."
func TestMigrateOnlyUnknownCategoryErrors(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	if err := os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export AWS_SECRET=sk_test_fixture_value\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out, err := execMigrate(t, "local", "--only=bogus")
	if err == nil {
		t.Fatal("expected an error for an unknown --only category, got nil")
	}
	if !strings.Contains(err.Error(), `unknown --only category "bogus"`) {
		t.Errorf("expected the error to name the bad token, got: %v", err)
	}
	if strings.Contains(out, "Proceed?") {
		t.Errorf("expected the confirmation prompt to never fire on an invalid --only, got:\n%s", out)
	}
}

// TestMigrateOnlyWorksWithDryRun confirms --only and --dry-run can now be
// combined (a behavior change from the old single-flag design, GAPS.md
// #26): since --dry-run's preview and a real run now share the exact
// same discovery+filter pipeline, --only scoping the preview to one
// category is just as meaningful as scoping a real run — there's no
// separate, unscoped whole-machine renderer left to disagree with it.
func TestMigrateOnlyWorksWithDryRun(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)
	envPath := filepath.Join(cwd, ".env")
	if err := os.WriteFile(envPath, []byte("STRIPE_KEY=sk_test_fixture\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export AWS_SECRET=sk_test_fixture_value\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out, err := execMigrate(t, "local", "--dry-run", "--only=env")
	if err != nil {
		t.Fatalf("jit migrate local --dry-run --only=env: %v", err)
	}
	if !strings.Contains(out, envPath) {
		t.Errorf("expected the .env finding in the scoped dry-run preview, got:\n%s", out)
	}
	if strings.Contains(out, "shell config") {
		t.Errorf("expected --only=env to exclude the shell-config category from the preview too, got:\n%s", out)
	}
	if !strings.Contains(out, "[DRY RUN] No files were changed.") {
		t.Errorf("expected the dry-run disclaimer, got:\n%s", out)
	}
}

// TestMigrateLocalDryRunMatchesRealPlanExactly locks in GAPS.md #26's
// core guarantee: --dry-run's preview and the plan printed right before
// a real run's confirmation prompt must be byte-identical for the same
// scope and inputs, because both call the exact same discovery+render
// path. This is what makes --dry-run trustworthy again.
func TestMigrateLocalDryRunMatchesRealPlanExactly(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)
	if err := os.WriteFile(filepath.Join(cwd, ".env"), []byte("STRIPE_KEY=sk_test_fixture\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export AWS_SECRET=sk_test_fixture_value\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	dryRunOut, err := execMigrate(t, "local", "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate local --dry-run: %v", err)
	}
	realOut, err := execMigrate(t, "local") // declines via empty stdin, never mutates
	if err != nil {
		t.Fatalf("jit migrate local: %v", err)
	}

	// Strip --dry-run's own LEADING banner (printed before printMigratePlan
	// is even called, at the runMigrate call site — not part of the plan
	// rendering itself) by starting the comparison at the plan's own
	// title line, then strip each mode's trailing disclaimer/prompt lines
	// the same way as before — everything in between (the plan itself)
	// must match exactly. TrimRight because each split point consumes a
	// different number of the newlines immediately preceding it
	// (Fprintln's leading "\n[DRY RUN]" vs a bare "Proceed?" prompt with
	// no leading newline of its own) — a cosmetic artifact of where each
	// mode's own trailing text starts, not a real difference in the plan
	// content itself.
	const planTitle = "jit migrate, plan ("
	dryRunOut = dryRunOut[strings.Index(dryRunOut, planTitle):]
	realOut = realOut[strings.Index(realOut, planTitle):]
	dryPlan := strings.TrimRight(strings.Split(dryRunOut, "\n[DRY RUN]")[0], "\n")
	realPlan := strings.TrimRight(strings.Split(realOut, "\nProceed?")[0], "\n")
	if dryPlan != realPlan {
		t.Errorf("dry-run plan and real-run plan differ:\n--dry-run:\n%s\n--real:\n%s", dryPlan, realPlan)
	}
}

func TestMigrateLocalDryRunCleanFixture(t *testing.T) {
	withFixtureHome(t) // empty fixture, nothing planted
	withFixtureCwd(t)
	out, err := execMigrate(t, "local", "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate local --dry-run: %v", err)
	}
	if !strings.Contains(out, "Nothing to migrate:") {
		t.Errorf("expected a nothing-to-migrate message on a clean fixture, got:\n%s", out)
	}
}

// TestMigrateHomeDiscoversAcrossWholeHome confirms jit migrate home finds
// an .env file anywhere under $HOME, not just under cwd — the actual new
// capability (GAPS.md #26) — while jit migrate local from the same cwd
// does not.
// TestMigrateBareDefaultsToHomeScope: `jit audit` scans the whole machine
// with no scope choice, so its report's "run `jit migrate --dry-run`"
// trailer must work verbatim and cover the same ground — bare `jit
// migrate` used to print help instead, forcing a local/home fork on the
// reader at their highest-intent moment (and `local` from an arbitrary
// cwd silently leaves most audit findings unfixed).
func TestMigrateBareDefaultsToHomeScope(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t) // an unrelated, empty cwd: only a home-scope run can find the .env below

	envPath := filepath.Join(home, "code", "otherproject", ".env")
	if err := os.MkdirAll(filepath.Dir(envPath), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(envPath, []byte("STRIPE_KEY=sk_test_fixture\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out, err := execMigrate(t, "", "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate --dry-run: %v", err)
	}
	if !strings.Contains(out, "plan (home scope)") {
		t.Errorf("expected bare `jit migrate` to run the home scope, got:\n%s", out)
	}
	if !strings.Contains(out, displayPath(home, envPath)) {
		t.Errorf("expected bare `jit migrate --dry-run` to find a .env anywhere under $HOME, got:\n%s", out)
	}

	// The bare command runs the home sweep, so it must accept
	// --include-archived like `jit migrate home` does.
	if _, err := execMigrate(t, "", "--dry-run", "--include-archived"); err != nil {
		t.Errorf("jit migrate --dry-run --include-archived: %v", err)
	}
}

func TestMigrateHomeDiscoversAcrossWholeHome(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t) // cwd is an unrelated, empty fixture dir, NOT under the .env's directory

	otherProjectDir := filepath.Join(home, "code", "otherproject")
	if err := os.MkdirAll(otherProjectDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	envPath := filepath.Join(otherProjectDir, ".env")
	if err := os.WriteFile(envPath, []byte("STRIPE_KEY=sk_test_fixture\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	localOut, err := execMigrate(t, "local", "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate local --dry-run: %v", err)
	}
	if strings.Contains(localOut, envPath) {
		t.Errorf("expected jit migrate local (from an unrelated cwd) to NOT find a .env under a different project, got:\n%s", localOut)
	}

	homeOut, err := execMigrate(t, "home", "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate home --dry-run: %v", err)
	}
	if !strings.Contains(homeOut, displayPath(home, envPath)) {
		t.Errorf("expected jit migrate home --dry-run to find a .env anywhere under $HOME, got:\n%s", homeOut)
	}
}

// TestMigrateTerraformHomeOnlyAndOnlyFlag: Terraform Cloud credentials
// live at exactly one fixed path under $HOME (like AWS/kubeconfig), so
// `local` never discovers them, `home` does, and `--only terraform`
// scopes a home run to just that category (GAPS.md #16).
func TestMigrateTerraformHomeOnlyAndOnlyFlag(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)

	if err := os.MkdirAll(filepath.Join(home, ".terraform.d"), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	credPath := filepath.Join(home, ".terraform.d", "credentials.tfrc.json")
	if err := os.WriteFile(credPath, []byte(`{"credentials":{"app.terraform.io":{"token":"atlasv1.fixture"}}}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// An unrelated .env so --only has something to exclude.
	envPath := filepath.Join(home, "code", "proj", ".env")
	if err := os.MkdirAll(filepath.Dir(envPath), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(envPath, []byte("STRIPE_KEY=sk_test_fixture\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	localOut, err := execMigrate(t, "local", "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate local --dry-run: %v", err)
	}
	if strings.Contains(localOut, "app.terraform.io") {
		t.Errorf("expected local to never discover Terraform credentials (fixed home path), got:\n%s", localOut)
	}

	homeOut, err := execMigrate(t, "home", "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate home --dry-run: %v", err)
	}
	if !strings.Contains(homeOut, "app.terraform.io") || !strings.Contains(homeOut, "Terraform Cloud host(s)") {
		t.Errorf("expected home's plan to include the Terraform category with its host, got:\n%s", homeOut)
	}

	onlyOut, err := execMigrate(t, "home", "--dry-run", "--only", "terraform")
	if err != nil {
		t.Fatalf("jit migrate home --dry-run --only terraform: %v", err)
	}
	if !strings.Contains(onlyOut, "app.terraform.io") {
		t.Errorf("expected --only terraform to keep the Terraform finding, got:\n%s", onlyOut)
	}
	if strings.Contains(onlyOut, envPath) {
		t.Errorf("expected --only terraform to exclude the .env finding, got:\n%s", onlyOut)
	}
}

// TestMigrateGCPADCHomeOnlyAndOnlyFlag: GCP application-default
// credentials live at exactly one fixed path under $HOME (like
// AWS/kubeconfig/Terraform), so `local` never discovers them, `home`
// does, and `--only gcp` scopes a home run to just that category (the
// GCP half of GAPS.md #16).
func TestMigrateGCPADCHomeOnlyAndOnlyFlag(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)

	adcPath := filepath.Join(home, ".config", "gcloud", "application_default_credentials.json")
	if err := os.MkdirAll(filepath.Dir(adcPath), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(adcPath, []byte(`{"client_id":"x.apps.googleusercontent.com","client_secret":"public","refresh_token":"1//0gfixture","type":"authorized_user"}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// An unrelated .env so --only has something to exclude.
	envPath := filepath.Join(home, "code", "proj", ".env")
	if err := os.MkdirAll(filepath.Dir(envPath), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(envPath, []byte("STRIPE_KEY=sk_test_fixture\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	localOut, err := execMigrate(t, "local", "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate local --dry-run: %v", err)
	}
	if strings.Contains(localOut, "application_default_credentials") {
		t.Errorf("expected local to never discover GCP ADC (fixed home path), got:\n%s", localOut)
	}

	homeOut, err := execMigrate(t, "home", "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate home --dry-run: %v", err)
	}
	if !strings.Contains(homeOut, displayPath(home, adcPath)) || !strings.Contains(homeOut, "GCP application-default credentials") {
		t.Errorf("expected home's plan to include the GCP ADC category with its file, got:\n%s", homeOut)
	}

	onlyOut, err := execMigrate(t, "home", "--dry-run", "--only", "gcp")
	if err != nil {
		t.Fatalf("jit migrate home --dry-run --only gcp: %v", err)
	}
	if !strings.Contains(onlyOut, displayPath(home, adcPath)) {
		t.Errorf("expected --only gcp to keep the ADC finding, got:\n%s", onlyOut)
	}
	if strings.Contains(onlyOut, envPath) {
		t.Errorf("expected --only gcp to exclude the .env finding, got:\n%s", onlyOut)
	}
}

// TestMigrateHomeSkipsArchivedByDefault confirms GAPS.md #26's safety net:
// a whole-machine sweep must not convert a finding under an
// archived/backup-looking directory into a live-mounted pipe by default
// — see archived.go's doc comment for why that's a worse outcome than
// leaving it plaintext.
func TestMigrateHomeSkipsArchivedByDefault(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)

	archivedDir := filepath.Join(home, "Documents", "archive", "oldproject")
	if err := os.MkdirAll(archivedDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	envPath := filepath.Join(archivedDir, ".env")
	if err := os.WriteFile(envPath, []byte("STRIPE_KEY=sk_test_fixture\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out, err := execMigrate(t, "home", "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate home --dry-run: %v", err)
	}
	if strings.Contains(out, "• "+displayPath(home, envPath)) {
		t.Errorf("expected the archived finding to never be a planned change, got:\n%s", out)
	}
	if !strings.Contains(out, "Skipped 1 finding(s) under an archived/backup-looking directory") {
		t.Errorf("expected an explicit skipped-archived note (fail safe and loud), got:\n%s", out)
	}
	if !strings.Contains(out, displayPath(home, envPath)) {
		t.Errorf("expected the skip note to list the skipped path itself, not a bare count, got:\n%s", out)
	}
	if !strings.Contains(out, "--include-archived") {
		t.Errorf("expected a pointer to --include-archived, got:\n%s", out)
	}
}

// TestMigrateHomeSkipsPlaygroundLoudly: a jitpass-playground checkout's
// planted bait is excluded from `jit audit`'s score, so a whole-machine
// sweep must skip it too (vaulting fake secrets and live-mounting the tour
// repo's .env files would wreck the checkout) — and must say so with the
// paths, not a bare count, so the skip never reads as a lost finding.
func TestMigrateHomeSkipsPlaygroundLoudly(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)

	playground := filepath.Join(home, "jitpass-playground")
	if err := os.MkdirAll(filepath.Join(playground, "api"), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(playground, audit.PlaygroundMarkerFile), nil, 0o600); err != nil {
		t.Fatalf("WriteFile marker: %v", err)
	}
	pgEnv := filepath.Join(playground, "api", ".env")
	if err := os.WriteFile(pgEnv, []byte("STRIPE_KEY=sk_test_bait\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	realEnv := filepath.Join(home, "code", "realproj", ".env")
	if err := os.MkdirAll(filepath.Dir(realEnv), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(realEnv, []byte("STRIPE_KEY=sk_test_fixture\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out, err := execMigrate(t, "home", "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate home --dry-run: %v", err)
	}
	if strings.Contains(out, "• "+displayPath(home, pgEnv)) {
		t.Errorf("expected the playground .env to never be a planned change, got:\n%s", out)
	}
	if !strings.Contains(out, "Skipped 1 finding(s) inside a jitpass-playground checkout") {
		t.Errorf("expected a loud playground-skip note, got:\n%s", out)
	}
	if !strings.Contains(out, displayPath(home, pgEnv)) {
		t.Errorf("expected the skip note to list the skipped path itself, got:\n%s", out)
	}
	if !strings.Contains(out, "• "+displayPath(home, realEnv)) {
		t.Errorf("expected the real project's .env to still be planned, got:\n%s", out)
	}
}

// TestMigrateLocalInsidePlaygroundStillWorks: the first-run tour has users
// practice a migration from inside the checkout, so `jit migrate local`
// run there must keep discovering the planted files (mirrors audit's own
// home-in-playground escape hatch).
func TestMigrateLocalInsidePlaygroundStillWorks(t *testing.T) {
	home := withFixtureHome(t)

	playground := filepath.Join(home, "jitpass-playground")
	if err := os.MkdirAll(playground, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(playground, audit.PlaygroundMarkerFile), nil, 0o600); err != nil {
		t.Fatalf("WriteFile marker: %v", err)
	}
	pgEnv := filepath.Join(playground, ".env")
	if err := os.WriteFile(pgEnv, []byte("STRIPE_KEY=sk_test_bait\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	original, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	if err := os.Chdir(playground); err != nil {
		t.Fatalf("os.Chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(original) })
	// Discovery roots at os.Getwd(), which resolves macOS's /var ->
	// /private/var symlink while $HOME keeps the unresolved spelling, so
	// build the expected plan bullet from the resolved cwd, not from home.
	resolvedCwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}

	out, err := execMigrate(t, "local", "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate local --dry-run: %v", err)
	}
	if !strings.Contains(out, "• "+displayPath(home, filepath.Join(resolvedCwd, ".env"))) {
		t.Errorf("expected local from inside the playground to plan its .env, got:\n%s", out)
	}
	if strings.Contains(out, "jitpass-playground checkout") && strings.Contains(out, "Skipped") {
		t.Errorf("expected no playground-skip note on a local run, got:\n%s", out)
	}
}

// TestMigrateHomeIncludeArchivedFlag confirms --include-archived overrides
// the default skip.
func TestMigrateHomeIncludeArchivedFlag(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)

	archivedDir := filepath.Join(home, "Documents", "archive", "oldproject")
	if err := os.MkdirAll(archivedDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	envPath := filepath.Join(archivedDir, ".env")
	if err := os.WriteFile(envPath, []byte("STRIPE_KEY=sk_test_fixture\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out, err := execMigrate(t, "home", "--dry-run", "--include-archived")
	if err != nil {
		t.Fatalf("jit migrate home --dry-run --include-archived: %v", err)
	}
	if !strings.Contains(out, displayPath(home, envPath)) {
		t.Errorf("expected --include-archived to include the archived finding, got:\n%s", out)
	}
}

// TestMigrateLocalNeverFiltersArchived confirms `local` never applies the
// archived-directory filter, even when cwd itself is literally inside a
// directory named "archive" — deliberately cd-ing somewhere and running
// `migrate local` is an explicit action, not an implicit sweep, so
// there's nothing to protect the caller from (unlike `home`'s implicit,
// whole-machine walk).
func TestMigrateLocalNeverFiltersArchived(t *testing.T) {
	home := withFixtureHome(t)
	archivedDir := filepath.Join(home, "Documents", "archive", "oldproject")
	if err := os.MkdirAll(archivedDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	original, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(archivedDir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(original) })

	envPath := filepath.Join(archivedDir, ".env")
	if err := os.WriteFile(envPath, []byte("STRIPE_KEY=sk_test_fixture\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out, err := execMigrate(t, "local", "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate local --dry-run: %v", err)
	}
	if !strings.Contains(out, envPath) {
		t.Errorf("expected jit migrate local to never filter archived-looking paths, got:\n%s", out)
	}
}

// TestMigrateHomeLabelMentionsHome confirms the .env category label in
// the printed plan reflects the actual scope, so a home-mode preview
// never implies "just this directory" the way local's label does.
func TestMigrateHomeLabelMentionsHome(t *testing.T) {
	home := withFixtureHome(t)
	if err := os.WriteFile(filepath.Join(home, ".env"), []byte("STRIPE_KEY=sk_test_fixture\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out, err := execMigrate(t, "home", "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate home --dry-run: %v", err)
	}
	if !strings.Contains(out, "anywhere under $HOME") {
		t.Errorf("expected the home-scoped .env label, got:\n%s", out)
	}

	// local is cwd-scoped — plant a separate .env directly under cwd this
	// time, since home's own .env (found above) isn't under whatever
	// unrelated temp directory withFixtureCwd points cwd at.
	cwd := withFixtureCwd(t)
	if err := os.WriteFile(filepath.Join(cwd, ".env"), []byte("STRIPE_KEY=sk_test_fixture\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	localOut, err := execMigrate(t, "local", "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate local --dry-run: %v", err)
	}
	if !strings.Contains(localOut, "under the current directory") {
		t.Errorf("expected the local-scoped .env label, got:\n%s", localOut)
	}
}

// TestMigrateDockerHomeOnlyAndOnlyFlag: Docker registry credentials live
// at exactly one fixed path under $HOME (~/.docker/config.json, like
// AWS/kubeconfig/Terraform), so `local` never discovers them, `home`
// does, and `--only docker` scopes a home run to just that category.
func TestMigrateDockerHomeOnlyAndOnlyFlag(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)

	configPath := filepath.Join(home, ".docker", "config.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(configPath, []byte(`{"auths":{"registry.example.com":{"auth":"YWxpY2U6czNjcmV0LXBhc3M="}}}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// An unrelated .env so --only has something to exclude.
	envPath := filepath.Join(home, "code", "proj", ".env")
	if err := os.MkdirAll(filepath.Dir(envPath), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(envPath, []byte("STRIPE_KEY=sk_test_fixture\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	localOut, err := execMigrate(t, "local", "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate local --dry-run: %v", err)
	}
	if strings.Contains(localOut, "registry.example.com") {
		t.Errorf("expected local to never discover Docker registry credentials (fixed home path), got:\n%s", localOut)
	}

	homeOut, err := execMigrate(t, "home", "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate home --dry-run: %v", err)
	}
	if !strings.Contains(homeOut, "registry.example.com") || !strings.Contains(homeOut, "Docker registry credential(s)") {
		t.Errorf("expected home's plan to include the Docker category with its registry, got:\n%s", homeOut)
	}

	onlyOut, err := execMigrate(t, "home", "--dry-run", "--only", "docker")
	if err != nil {
		t.Fatalf("jit migrate home --dry-run --only docker: %v", err)
	}
	if !strings.Contains(onlyOut, "registry.example.com") {
		t.Errorf("expected --only docker to keep the Docker finding, got:\n%s", onlyOut)
	}
	if strings.Contains(onlyOut, envPath) {
		t.Errorf("expected --only docker to exclude the .env finding, got:\n%s", onlyOut)
	}
}

// TestCompleteMigrateCategories locks in the comma-aware completion of the
// StringSlice `--only` flag: it must carry the already-typed prefix so
// `env,tf` completes to `env,tfvars`, and omit categories already listed
// so the menu only ever offers what's left to add.
func TestCompleteMigrateCategories(t *testing.T) {
	// Bare segment: every category, prefix-filtered.
	got, _ := completeMigrateCategories(nil, nil, "sh")
	if len(got) != 1 || got[0] != "shell" {
		t.Errorf(`"sh" should complete to just [shell], got %v`, got)
	}

	// Mid-list segment carries the base prefix through verbatim.
	got, _ = completeMigrateCategories(nil, nil, "env,tf")
	if len(got) != 1 || got[0] != "env,tfvars" {
		t.Errorf(`"env,tf" should complete to [env,tfvars], got %v`, got)
	}

	// Already-chosen categories are never re-offered for the next segment.
	got, _ = completeMigrateCategories(nil, nil, "env,shell,")
	for _, c := range got {
		if strings.HasSuffix(c, ",env") || strings.HasSuffix(c, ",shell") {
			t.Errorf("already-listed category re-offered: %q in %v", c, got)
		}
	}
	if len(got) != len(migrateCategories)-2 {
		t.Errorf("expected %d remaining categories after choosing 2, got %d: %v", len(migrateCategories)-2, len(got), got)
	}
}

// TestMigratePathEnvFileScopedToJustThatFile confirms the whole point of
// `jit migrate path`: naming one .env file plans only that file, never a
// walk of everything else under $HOME. A second unrelated .env is planted
// far from the target and must appear nowhere in the plan.
func TestMigratePathEnvFileScopedToJustThatFile(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	target := filepath.Join(home, "proj", ".env")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(target, []byte("STRIPE_KEY=sk_test_fixture\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	other := filepath.Join(home, "other", ".env")
	if err := os.MkdirAll(filepath.Dir(other), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(other, []byte("OTHER_KEY=sk_test_other\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out, err := execMigrate(t, "path", target, "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate path <file> --dry-run: %v", err)
	}
	if !strings.Contains(out, "plan (path scope)") {
		t.Errorf("expected the path-scope plan header, got:\n%s", out)
	}
	if !strings.Contains(out, displayPath(home, target)) {
		t.Errorf("expected the named .env in the plan, got:\n%s", out)
	}
	if strings.Contains(out, displayPath(home, other)) {
		t.Errorf("path scope must not discover the unrelated .env, got:\n%s", out)
	}
	if strings.Contains(out, "sk_test_fixture") {
		t.Fatal("CLI output must never contain the raw secret value")
	}
}

// TestMigratePathRoutesShellConfigToShellCategory confirms an explicitly
// named machine-wide file (~/.zshrc) is routed to shell-config handling —
// its name matches none of the project recognizers, so without the fixed-
// path dispatch it would silently fall through to "nothing to migrate."
func TestMigratePathRoutesShellConfigToShellCategory(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	zshrc := filepath.Join(home, ".zshrc")
	if err := os.WriteFile(zshrc, []byte("export AWS_SECRET=sk_test_fixture_value\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out, err := execMigrate(t, "path", zshrc, "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate path ~/.zshrc --dry-run: %v", err)
	}
	if !strings.Contains(out, "shell config(s)") {
		t.Errorf("expected the shell-config category in the plan, got:\n%s", out)
	}
	if !strings.Contains(out, "Machine-wide config files you named") {
		t.Errorf("expected the path-scope machine-wide header, got:\n%s", out)
	}
	if strings.Contains(out, "only included on a home-scope run") {
		t.Errorf("path scope must not claim these are home-only, got:\n%s", out)
	}
}

// TestMigratePathDirectoryWalkExcludesMachineWide confirms a directory
// target is walked like `migrate local` rooted there — project files only,
// never the fixed machine-wide files (a ~/.zshrc under the same home).
func TestMigratePathDirectoryWalkExcludesMachineWide(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	dir := filepath.Join(home, "proj")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("STRIPE_KEY=sk_test_fixture\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// A shell config under the same $HOME must NOT be pulled in by a folder
	// target — it isn't "inside" the named directory.
	if err := os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export AWS_SECRET=sk_test_fixture_value\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out, err := execMigrate(t, "path", dir, "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate path <dir> --dry-run: %v", err)
	}
	if !strings.Contains(out, ".env file(s)") {
		t.Errorf("expected the .env category from the walked directory, got:\n%s", out)
	}
	if strings.Contains(out, "shell config(s)") {
		t.Errorf("a directory target must not discover machine-wide shell configs, got:\n%s", out)
	}
}

// TestMigratePathMissingTargetFailsLoud confirms a nonexistent target is an
// error, not a silent "nothing to migrate" — naming a path is a specific
// request, and a typo should say so rather than look like a clean machine.
func TestMigratePathMissingTargetFailsLoud(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	_, err := execMigrate(t, "path", filepath.Join(home, "does-not-exist.env"), "--dry-run")
	if err == nil {
		t.Fatal("expected an error for a nonexistent target, got nil")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("expected a does-not-exist error, got: %v", err)
	}
}

// TestMigratePathSymlinkRefused confirms a symlink target is refused rather
// than followed — the walk-based scopes skip symlinks so migrate never
// rewrites through a link, and the path scope must not reintroduce that.
func TestMigratePathSymlinkRefused(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	real := filepath.Join(home, "real.env")
	if err := os.WriteFile(real, []byte("STRIPE_KEY=sk_test_fixture\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	link := filepath.Join(home, "link.env")
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	_, err := execMigrate(t, "path", link, "--dry-run")
	if err == nil {
		t.Fatal("expected an error for a symlink target, got nil")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected a symlink error, got: %v", err)
	}
}

// TestMigratePathUnrecognizedFileNothingToMigrate confirms a real file that
// isn't a recognized secret-bearing file reports a path-scoped
// nothing-to-migrate message, not the generic whole-catalog list.
func TestMigratePathUnrecognizedFileNothingToMigrate(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	notes := filepath.Join(home, "notes.txt")
	if err := os.WriteFile(notes, []byte("just some notes, no secrets\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	out, err := execMigrate(t, "path", notes)
	if err != nil {
		t.Fatalf("jit migrate path <plain file>: %v", err)
	}
	if !strings.Contains(out, "none of the path(s) you named") {
		t.Errorf("expected the path-scoped nothing-to-migrate message, got:\n%s", out)
	}
}

// TestMigratePathDedupesOverlappingTargets confirms naming a folder AND a
// file inside it plans the shared finding once, not twice.
func TestMigratePathDedupesOverlappingTargets(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	dir := filepath.Join(home, "proj")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	env := filepath.Join(dir, ".env")
	if err := os.WriteFile(env, []byte("STRIPE_KEY=sk_test_fixture\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	out, err := execMigrate(t, "path", dir, env, "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate path <dir> <file> --dry-run: %v", err)
	}
	if got := strings.Count(out, displayPath(home, env)); got != 1 {
		t.Errorf("expected the overlapping .env to appear exactly once, saw %d times:\n%s", got, out)
	}
	if !strings.Contains(out, "1 change(s) planned") {
		t.Errorf("expected exactly 1 planned change after dedupe, got:\n%s", out)
	}
}
