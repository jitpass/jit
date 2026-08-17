// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMigrateSummaryPrintCollapsesRepeatedExplanations locks in the fix
// for a real, reported problem: migrating several files used to repeat
// the same multi-line git-history/no-pre-run-hook explanation once PER
// FILE, burying the actually-important closing "run `jit agent
// install`" pointer under dozens of near-identical lines. migrateSummary
// (unlike the vault-touching Apply* calls in the mutation path) needs no
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
	if !strings.Contains(out, "3 git-safe .pointers files") {
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

// execMigrate drives `jit migrate <args...>` through rootCmd (mirrors
// execAudit's discipline — see audit_test.go), resetting every migrate
// package-level flag var first so tests never inherit state from each other.
// jit migrate takes the file/dir target(s) to convert directly on the
// command line — there is no whole-machine sweep, so a test always names
// exactly what it wants converted.
func execMigrate(t *testing.T, args ...string) (stdout string, err error) {
	t.Helper()
	migrateDryRun = false
	migrateYes = false
	migrateOnly = nil
	migrateMount = false // omitted once, and --mount leaking out of one test made the next one plan a mount it never asked for
	migrateNo1Password = false
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)                 // confirmation prompts go to stderr, capture both streams in order
	rootCmd.SetIn(strings.NewReader("")) // default: EOF, i.e. an empty/declined answer if a confirm prompt is hit
	rootCmd.SetArgs(append([]string{"migrate"}, args...))
	err = rootCmd.Execute()
	return buf.String(), err
}

// TestMigrateBareRunsProtectPlan: bare `jit migrate` executes the scan's
// protect plan (2026-07-28 redesign — it is the command the scan report's
// green section points at). Consent is preserved: the plan prints and the
// [y/N] gate precedes any change; with EOF on stdin (execMigrate's default)
// the run aborts having changed nothing.
func TestMigrateBareRunsProtectPlan(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)

	t.Run("clean home has nothing to protect", func(t *testing.T) {
		out, err := execMigrate(t)
		if err != nil {
			t.Fatalf("bare jit migrate on a clean home: %v", err)
		}
		if !strings.Contains(out, "Nothing to protect") {
			t.Errorf("expected the nothing-to-protect line, got:\n%s", out)
		}
	})

	t.Run("planted secret shows plan and aborts on decline", func(t *testing.T) {
		path := filepath.Join(home, ".zshrc")
		if err := os.WriteFile(path, []byte("export STRIPE_API_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc\n"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		out, err := execMigrate(t)
		if err != nil {
			t.Fatalf("bare jit migrate: %v", err)
		}
		if !strings.Contains(out, ".zshrc") {
			t.Errorf("plan should name the discovered file, got:\n%s", out)
		}
		if !strings.Contains(out, "Aborted. Nothing was changed.") {
			t.Errorf("EOF on the confirm prompt must abort, got:\n%s", out)
		}
		if data, readErr := os.ReadFile(path); readErr != nil || !strings.Contains(string(data), "sk_live_4eC39HqLyjWDarjtT1zdp7dc") {
			t.Errorf("declined run must leave the file untouched (err=%v):\n%s", readErr, data)
		}
	})
}

// TestMigratePathAliasStillWorks confirms `jit migrate path <file>` keeps
// working as an explicit alias of the bare `jit migrate <file>` form, so
// existing scripts and muscle memory don't break.
func TestMigratePathAliasStillWorks(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	target := filepath.Join(home, "proj", ".env")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(target, []byte("STRIPE_KEY=sk_test_fixture\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out, err := execMigrate(t, "path", target, "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate path <file> --dry-run: %v", err)
	}
	if !strings.Contains(out, displayPath(home, target)) {
		t.Errorf("expected the named .env in the alias plan, got:\n%s", out)
	}
}

// TestMigrateLooseSecretFileDryRun: a file that matches no structured category
// but whose whole content is a bare token is discovered as a loose secret file
// and shown in the plan. This is the migrate half of the scan token.txt bug —
// scan flags it as an exposed_secret, and now migrate can act on it.
func TestMigrateLooseSecretFileDryRun(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20iLCJpZCI6MX0." +
		"i-Bx9F2fjO5nvvo_hlUFY6bvnAOeTs68BiTBa-1zfoE"
	target := filepath.Join(home, "token.txt")
	if err := os.WriteFile(target, []byte(jwt+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out, err := execMigrate(t, target, "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate token.txt --dry-run: %v", err)
	}
	if !strings.Contains(out, "loose secret file") {
		t.Errorf("expected a loose secret file plan section, got:\n%s", out)
	}
	if !strings.Contains(out, "1 change planned") {
		t.Errorf("expected the change counter to include the loose file, got:\n%s", out)
	}
	if strings.Contains(out, jwt) {
		t.Fatal("dry-run plan must never print the raw token")
	}
}

// TestMigrateEmbeddedSecretNotLoose: a file that mixes a token with other
// content is NOT a pure loose secret file (migrating it whole would lose the
// other content), so migrate reports nothing to move — but points the user at
// --mount, which can protect it in place.
func TestMigrateEmbeddedSecretNotLoose(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MX0.i-Bx9F2fjO5nvvo_hlUFY6bvnAOeTs68BiTBa-1zfoE"
	target := filepath.Join(home, "notes.txt")
	if err := os.WriteFile(target, []byte("my token is "+jwt+" keep it safe\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out, err := execMigrate(t, target, "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate notes.txt --dry-run: %v", err)
	}
	if !strings.Contains(out, "Nothing to migrate") {
		t.Errorf("expected nothing-to-migrate for an embedded secret, got:\n%s", out)
	}
	if !strings.Contains(out, "--mount") {
		t.Errorf("expected the skip note to point at --mount, got:\n%s", out)
	}
}

// TestMigrateLooseMountDryRun: with --mount, a pure loose file is planned as a
// live mount (not a neutralized pointer), and an embedded file becomes
// migratable instead of being skipped.
func TestMigrateLooseMountDryRun(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MX0.i-Bx9F2fjO5nvvo_hlUFY6bvnAOeTs68BiTBa-1zfoE"

	pure := filepath.Join(home, "token.txt")
	if err := os.WriteFile(pure, []byte(jwt+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	embedded := filepath.Join(home, "config.txt")
	if err := os.WriteFile(embedded, []byte("key="+jwt+"\nport=8080\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out, err := execMigrate(t, pure, embedded, "--mount", "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate --mount --dry-run: %v", err)
	}
	if !strings.Contains(out, "stays live at its path as a mount") {
		t.Errorf("expected mount wording under --mount, got:\n%s", out)
	}
	if !strings.Contains(out, "2 changes planned") {
		t.Errorf("expected both files planned under --mount, got:\n%s", out)
	}
}

// TestMigrateNoFindings confirms a run over a target with nothing migratable
// never reaches openVault() — and so never needs Touch ID. Real mutation
// touching the vault for an actual .env file is verified manually against
// real hardware, same constraint as jit vault set/get and jit run/export.
func TestMigrateNoFindings(t *testing.T) {
	home := withFixtureHome(t) // guaranteed empty, no secrets anywhere under it
	withFixtureCwd(t)
	out, err := execMigrate(t, home) // walk an empty home dir: nothing to find
	if err != nil {
		t.Fatalf("jit migrate on a directory with no findings: %v", err)
	}
	if !strings.Contains(out, "Nothing to migrate") {
		t.Errorf("expected a nothing-to-migrate message, got:\n%s", out)
	}
}

// TestMigrateDeclinedConfirmationAborts confirms GAPS.md #17's confirmation
// gate: with a real finding present but no --yes and a declined (empty-stdin)
// prompt, migrate must print the plan, abort, and — critically — never reach
// openVault(), so this stays fully automatable (no Touch ID) even though it
// exercises real mode. Uses a named shell config, a machine-wide file routed
// by exact path.
func TestMigrateDeclinedConfirmationAborts(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	shellConfigPath := filepath.Join(home, ".zshrc")
	original := []byte("export STRIPE_API_KEY=sk_test_fixture_value\n")
	if err := os.WriteFile(shellConfigPath, original, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out, err := execMigrate(t, shellConfigPath)
	if err != nil {
		t.Fatalf("jit migrate <shell config> declined confirmation: %v", err)
	}
	if !strings.Contains(out, "Proceed? [y/N]") {
		t.Errorf("expected the confirmation prompt, got:\n%s", out)
	}
	if !strings.Contains(out, "Aborted. Nothing was changed.") {
		t.Errorf("expected the abort message, got:\n%s", out)
	}
	if !strings.Contains(out, displayPath(home, shellConfigPath)) {
		t.Errorf("expected the named shell config in the printed plan, got:\n%s", out)
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
// .env finding and a shell-config finding named, --only=env must limit the
// printed plan (and, had confirmation been accepted, the actual mutation) to
// just the .env category — the shell-config secret must be named nowhere in
// the output and the shell config file must stay untouched.
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

	out, err := execMigrate(t, envPath, shellConfigPath, "--only=env")
	if err != nil {
		t.Fatalf("jit migrate <env> <shell> --only=env: %v", err)
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
// findings among the named targets reports a precise, category-aware
// "nothing to migrate" message rather than silently pretending nothing was
// found.
func TestMigrateOnlyNoMatchingFindings(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	shellConfigPath := filepath.Join(home, ".zshrc")
	if err := os.WriteFile(shellConfigPath, []byte("export AWS_SECRET=sk_test_fixture_value\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out, err := execMigrate(t, shellConfigPath, "--only=env")
	if err != nil {
		t.Fatalf("jit migrate <shell> --only=env with no .env findings: %v", err)
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
	shellConfigPath := filepath.Join(home, ".zshrc")
	if err := os.WriteFile(shellConfigPath, []byte("export AWS_SECRET=sk_test_fixture_value\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out, err := execMigrate(t, shellConfigPath, "--only=bogus")
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

// TestMigrateOnlyWorksWithDryRun confirms --only and --dry-run combine:
// since --dry-run's preview and a real run share the exact same
// discovery+filter pipeline, --only scoping the preview to one category is
// just as meaningful as scoping a real run (GAPS.md #26).
func TestMigrateOnlyWorksWithDryRun(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)
	envPath := filepath.Join(cwd, ".env")
	if err := os.WriteFile(envPath, []byte("STRIPE_KEY=sk_test_fixture\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	shellConfigPath := filepath.Join(home, ".zshrc")
	if err := os.WriteFile(shellConfigPath, []byte("export AWS_SECRET=sk_test_fixture_value\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out, err := execMigrate(t, envPath, shellConfigPath, "--dry-run", "--only=env")
	if err != nil {
		t.Fatalf("jit migrate <env> <shell> --dry-run --only=env: %v", err)
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

// TestMigrateDryRunMatchesRealPlanExactly locks in GAPS.md #26's core
// guarantee: --dry-run's preview and the plan printed right before a real
// run's confirmation prompt must be byte-identical for the same inputs,
// because both call the exact same discovery+render path.
func TestMigrateDryRunMatchesRealPlanExactly(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)
	envPath := filepath.Join(cwd, ".env")
	if err := os.WriteFile(envPath, []byte("STRIPE_KEY=sk_test_fixture\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	shellConfigPath := filepath.Join(home, ".zshrc")
	if err := os.WriteFile(shellConfigPath, []byte("export AWS_SECRET=sk_test_fixture_value\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	dryRunOut, err := execMigrate(t, envPath, shellConfigPath, "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate <targets> --dry-run: %v", err)
	}
	realOut, err := execMigrate(t, envPath, shellConfigPath) // declines via empty stdin, never mutates
	if err != nil {
		t.Fatalf("jit migrate <targets>: %v", err)
	}

	// Strip --dry-run's own LEADING banner (printed before printMigratePlan
	// is even called, at the applyMigrate call site — not part of the plan
	// rendering itself) by starting the comparison at the plan's own title
	// line, then strip each mode's trailing disclaimer/prompt lines the same
	// way — everything in between (the plan itself) must match exactly.
	const planTitle = "jit migrate, plan"
	dryRunOut = dryRunOut[strings.Index(dryRunOut, planTitle):]
	realOut = realOut[strings.Index(realOut, planTitle):]
	dryPlan := strings.TrimRight(strings.Split(dryRunOut, "\n[DRY RUN]")[0], "\n")
	realPlan := strings.TrimRight(strings.Split(realOut, "\nProceed?")[0], "\n")
	if dryPlan != realPlan {
		t.Errorf("dry-run plan and real-run plan differ:\n--dry-run:\n%s\n--real:\n%s", dryPlan, realPlan)
	}
}

func TestMigrateDryRunCleanTarget(t *testing.T) {
	home := withFixtureHome(t) // empty fixture, nothing planted
	withFixtureCwd(t)
	out, err := execMigrate(t, home, "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate <empty home> --dry-run: %v", err)
	}
	if !strings.Contains(out, "Nothing to migrate:") {
		t.Errorf("expected a nothing-to-migrate message on a clean target, got:\n%s", out)
	}
}

// TestMigratePathEnvFileScopedToJustThatFile confirms the whole point of the
// path-only design: naming one .env file plans only that file, never a walk
// of everything else under $HOME. A second unrelated .env is planted far
// from the target and must appear nowhere in the plan.
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

	out, err := execMigrate(t, target, "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate <file> --dry-run: %v", err)
	}
	if !strings.Contains(out, "jit migrate, plan") {
		t.Errorf("expected the migrate plan header, got:\n%s", out)
	}
	if !strings.Contains(out, "Project files you named") {
		t.Errorf("expected the project-files header, got:\n%s", out)
	}
	if !strings.Contains(out, displayPath(home, target)) {
		t.Errorf("expected the named .env in the plan, got:\n%s", out)
	}
	if strings.Contains(out, displayPath(home, other)) {
		t.Errorf("naming one file must not discover the unrelated .env, got:\n%s", out)
	}
	if strings.Contains(out, "sk_test_fixture") {
		t.Fatal("CLI output must never contain the raw secret value")
	}
}

// TestMigrateConvertsArchivedFileWhenNamed confirms the path-only design
// never applies the archived-directory filter: naming a file under an
// "archive" directory is itself the explicit decision to convert it, so it
// must appear as a planned change with no skip note (unlike the old
// whole-machine sweep, which skipped archived paths by default).
func TestMigrateConvertsArchivedFileWhenNamed(t *testing.T) {
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

	out, err := execMigrate(t, envPath, "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate <archived file> --dry-run: %v", err)
	}
	if !strings.Contains(out, displayPath(home, envPath)) {
		t.Errorf("expected an explicitly named archived file to be planned, got:\n%s", out)
	}
	if strings.Contains(out, "archived/backup-looking") {
		t.Errorf("naming a file explicitly must never skip it for looking archived, got:\n%s", out)
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

	out, err := execMigrate(t, zshrc, "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate ~/.zshrc --dry-run: %v", err)
	}
	if !strings.Contains(out, "[shell config]") {
		t.Errorf("expected the shell-config category in the plan, got:\n%s", out)
	}
	if !strings.Contains(out, "Machine-wide config files you named") {
		t.Errorf("expected the machine-wide header, got:\n%s", out)
	}
}

// TestMigratePathDirectoryWalkExcludesMachineWide confirms a directory target
// is walked for project files only, never the fixed machine-wide files (a
// ~/.zshrc under the same home).
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

	out, err := execMigrate(t, dir, "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate <dir> --dry-run: %v", err)
	}
	if !strings.Contains(out, "[.env file]") {
		t.Errorf("expected the .env category from the walked directory, got:\n%s", out)
	}
	if strings.Contains(out, "[shell config]") {
		t.Errorf("a directory target must not discover machine-wide shell configs, got:\n%s", out)
	}
}

// TestMigratePathMissingTargetFailsLoud confirms a nonexistent target is an
// error, not a silent "nothing to migrate" — naming a path is a specific
// request, and a typo should say so rather than look like a clean machine.
func TestMigratePathMissingTargetFailsLoud(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	_, err := execMigrate(t, filepath.Join(home, "does-not-exist.env"), "--dry-run")
	if err == nil {
		t.Fatal("expected an error for a nonexistent target, got nil")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("expected a does-not-exist error, got: %v", err)
	}
}

// TestMigratePathSymlinkRefused confirms a symlink target is refused rather
// than followed — migrate never rewrites through a link into a target that
// may sit outside the tree being converted.
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
	_, err := execMigrate(t, link, "--dry-run")
	if err == nil {
		t.Fatal("expected an error for a symlink target, got nil")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected a symlink error, got: %v", err)
	}
}

// TestMigratePathUnrecognizedFileNothingToMigrate confirms a real file that
// isn't a recognized secret-bearing file reports the path-scoped
// nothing-to-migrate message.
func TestMigratePathUnrecognizedFileNothingToMigrate(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	notes := filepath.Join(home, "notes.txt")
	if err := os.WriteFile(notes, []byte("just some notes, no secrets\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	out, err := execMigrate(t, notes)
	if err != nil {
		t.Fatalf("jit migrate <plain file>: %v", err)
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
	out, err := execMigrate(t, dir, env, "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate <dir> <file> --dry-run: %v", err)
	}
	if got := strings.Count(out, displayPath(home, env)); got != 1 {
		t.Errorf("expected the overlapping .env to appear exactly once, saw %d times:\n%s", got, out)
	}
	if !strings.Contains(out, "1 change planned") {
		t.Errorf("expected exactly 1 planned change after dedupe, got:\n%s", out)
	}
}

// TestMigrateTerraformCredentialsDiscoveryAndOnlyFlag: Terraform Cloud
// credentials live at exactly one fixed path under $HOME. Naming that file
// routes it to the Terraform category, and `--only terraform` scopes a run
// that also named an .env to just that category (GAPS.md #16).
func TestMigrateTerraformCredentialsDiscoveryAndOnlyFlag(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)

	if err := os.MkdirAll(filepath.Join(home, ".terraform.d"), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	credPath := filepath.Join(home, ".terraform.d", "credentials.tfrc.json")
	if err := os.WriteFile(credPath, []byte(`{"credentials":{"app.terraform.io":{"token":"atlasv1.fixture"}}}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	envPath := filepath.Join(home, "code", "proj", ".env")
	if err := os.MkdirAll(filepath.Dir(envPath), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(envPath, []byte("STRIPE_KEY=sk_test_fixture\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out, err := execMigrate(t, credPath, envPath, "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate <tfrc> <env> --dry-run: %v", err)
	}
	if !strings.Contains(out, "app.terraform.io") || !strings.Contains(out, "Terraform Cloud host") {
		t.Errorf("expected the plan to include the Terraform category with its host, got:\n%s", out)
	}

	onlyOut, err := execMigrate(t, credPath, envPath, "--dry-run", "--only", "terraform")
	if err != nil {
		t.Fatalf("jit migrate <tfrc> <env> --dry-run --only terraform: %v", err)
	}
	if !strings.Contains(onlyOut, "app.terraform.io") {
		t.Errorf("expected --only terraform to keep the Terraform finding, got:\n%s", onlyOut)
	}
	if strings.Contains(onlyOut, envPath) {
		t.Errorf("expected --only terraform to exclude the .env finding, got:\n%s", onlyOut)
	}
}

// TestMigrateGCPADCDiscoveryAndOnlyFlag: GCP application-default credentials
// live at exactly one fixed path under $HOME. Naming that file routes it to
// the GCP category, and `--only gcp` scopes a run that also named an .env to
// just that category.
func TestMigrateGCPADCDiscoveryAndOnlyFlag(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)

	adcPath := filepath.Join(home, ".config", "gcloud", "application_default_credentials.json")
	if err := os.MkdirAll(filepath.Dir(adcPath), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(adcPath, []byte(`{"client_id":"x.apps.googleusercontent.com","client_secret":"public","refresh_token":"1//0gfixture","type":"authorized_user"}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	envPath := filepath.Join(home, "code", "proj", ".env")
	if err := os.MkdirAll(filepath.Dir(envPath), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(envPath, []byte("STRIPE_KEY=sk_test_fixture\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out, err := execMigrate(t, adcPath, envPath, "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate <adc> <env> --dry-run: %v", err)
	}
	if !strings.Contains(out, displayPath(home, adcPath)) || !strings.Contains(out, "GCP application-default credentials") {
		t.Errorf("expected the plan to include the GCP ADC category with its file, got:\n%s", out)
	}

	onlyOut, err := execMigrate(t, adcPath, envPath, "--dry-run", "--only", "gcp")
	if err != nil {
		t.Fatalf("jit migrate <adc> <env> --dry-run --only gcp: %v", err)
	}
	if !strings.Contains(onlyOut, displayPath(home, adcPath)) {
		t.Errorf("expected --only gcp to keep the ADC finding, got:\n%s", onlyOut)
	}
	if strings.Contains(onlyOut, envPath) {
		t.Errorf("expected --only gcp to exclude the .env finding, got:\n%s", onlyOut)
	}
}

// TestMigrateDockerDiscoveryAndOnlyFlag: Docker registry credentials live at
// exactly one fixed path under $HOME (~/.docker/config.json). Naming that
// file routes it to the Docker category, and `--only docker` scopes a run
// that also named an .env to just that category.
func TestMigrateDockerDiscoveryAndOnlyFlag(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)

	configPath := filepath.Join(home, ".docker", "config.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(configPath, []byte(`{"auths":{"registry.example.com":{"auth":"YWxpY2U6czNjcmV0LXBhc3M="}}}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	envPath := filepath.Join(home, "code", "proj", ".env")
	if err := os.MkdirAll(filepath.Dir(envPath), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(envPath, []byte("STRIPE_KEY=sk_test_fixture\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out, err := execMigrate(t, configPath, envPath, "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate <docker config> <env> --dry-run: %v", err)
	}
	if !strings.Contains(out, "registry.example.com") || !strings.Contains(out, "Docker registry credential") {
		t.Errorf("expected the plan to include the Docker category with its registry, got:\n%s", out)
	}

	onlyOut, err := execMigrate(t, configPath, envPath, "--dry-run", "--only", "docker")
	if err != nil {
		t.Fatalf("jit migrate <docker config> <env> --dry-run --only docker: %v", err)
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
