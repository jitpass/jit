// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/migrate"
)

// execMigrateUndo drives `jit migrate undo <args...>` through rootCmd,
// resetting migrate's shared package-level flag vars first (same
// discipline as execMigrate — undo inherits migrateCmd's persistent
// --dry-run/--yes/--only).
func execMigrateUndo(t *testing.T, args ...string) (stdout string, err error) {
	t.Helper()
	migrateDryRun = false
	migrateYes = false
	migrateOnly = nil
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)                 // confirmation prompts go to stderr — capture both streams in order
	rootCmd.SetIn(strings.NewReader("")) // EOF = declined if a confirm prompt is hit
	rootCmd.SetArgs(append([]string{"migrate", "undo"}, args...))
	err = rootCmd.Execute()
	return buf.String(), err
}

// plantBackupRecord writes a backups.yaml under the fixture home's vault
// root recording each originalPath — enough for undo's pre-confirmation
// phase (plan + prompt), which never needs the vault itself.
func plantBackupRecord(t *testing.T, originalPaths ...string) {
	t.Helper()
	root, err := vaultRootDir()
	if err != nil {
		t.Fatalf("vaultRootDir: %v", err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("mkdir vault root: %v", err)
	}
	content := "backups:\n"
	for i, originalPath := range originalPaths {
		content += "    - original_path: " + originalPath + "\n" +
			fmt.Sprintf("      vault_path: _backups/fixture.jit-bak-%d\n", i+1) +
			"      unix_ts: " + timestampFixture() + "\n"
	}
	if err := os.WriteFile(migrate.BackupIndexPath(root), []byte(content), 0o600); err != nil {
		t.Fatalf("writing fixture backups.yaml: %v", err)
	}
}

func timestampFixture() string {
	return "1751000000" // fixed past instant; only the "ago" rendering depends on it
}

func TestMigrateUndoNoBackupsRecorded(t *testing.T) {
	withFixtureHome(t)
	withFixtureCwd(t)

	out, err := execMigrateUndo(t)
	if err != nil {
		t.Fatalf("migrate undo on an empty fixture: %v", err)
	}
	if !strings.Contains(out, "No jit-written backups are recorded") {
		t.Errorf("empty state should say what's true and what to do about it, got:\n%s", out)
	}
}

// TestMigrateUndoDeclinedConfirmationChangesNothing mirrors GAPS.md #17's
// discipline: the prompt comes before openVault(), and declining leaves
// every file byte-identical and never triggers a vault (Touch ID) path.
func TestMigrateUndoDeclinedConfirmationChangesNothing(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)

	target := filepath.Join(home, "project", ".env")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	current := "CURRENT=state\n"
	if err := os.WriteFile(target, []byte(current), 0o600); err != nil {
		t.Fatalf("writing target: %v", err)
	}
	plantBackupRecord(t, target)

	out, err := execMigrateUndo(t) // stdin is EOF -> declined
	if err != nil {
		t.Fatalf("migrate undo (declined): %v", err)
	}
	if !strings.Contains(out, "Aborted") {
		t.Errorf("expected an explicit Aborted line, got:\n%s", out)
	}
	// The plan "~"-shortens paths under $HOME for display (displayPath).
	if !strings.Contains(out, displayPath(home, target)) {
		t.Errorf("the plan should have named the file before the prompt, got:\n%s", out)
	}
	data, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatalf("re-reading target: %v", readErr)
	}
	if string(data) != current {
		t.Error("declining the confirmation still changed the file")
	}
}

func TestMigrateUndoDryRunChangesNothing(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)

	target := filepath.Join(home, ".zshrc")
	current := "eval \"$(jit export --profile zshrc)\"\n"
	if err := os.WriteFile(target, []byte(current), 0o600); err != nil {
		t.Fatalf("writing target: %v", err)
	}
	plantBackupRecord(t, target)

	out, err := execMigrateUndo(t, "--dry-run")
	if err != nil {
		t.Fatalf("migrate undo --dry-run: %v", err)
	}
	if !strings.Contains(out, "[DRY RUN]") {
		t.Errorf("expected the [DRY RUN] banner, got:\n%s", out)
	}
	if !strings.Contains(out, displayPath(home, target)) {
		t.Errorf("dry run should list the restorable file, got:\n%s", out)
	}
	data, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatalf("re-reading target: %v", readErr)
	}
	if string(data) != current {
		t.Error("--dry-run changed the file")
	}
}

func TestMigrateUndoUnknownPathFailsLoud(t *testing.T) {
	withFixtureHome(t)
	withFixtureCwd(t)

	_, err := execMigrateUndo(t, "/nonexistent/never-migrated/.env")
	if err == nil {
		t.Fatal("expected an error for a path with no recorded backup")
	}
	if !strings.Contains(err.Error(), "no recorded backup") {
		t.Errorf("error should say no backup is recorded for the path, got: %v", err)
	}
}

func TestMigrateUndoRejectsOnlyFlag(t *testing.T) {
	withFixtureHome(t)
	withFixtureCwd(t)

	_, err := execMigrateUndo(t, "--only", "env")
	if err == nil {
		t.Fatal("expected an error: --only filters categories, undo restores files — accepting and ignoring it is the GAPS.md #21/#25 trap")
	}
}

func recPaths(recs []migrate.BackupRecord) []string {
	out := make([]string, len(recs))
	for i, r := range recs {
		out[i] = r.OriginalPath
	}
	return out
}

// TestSelectBackupsDirectoryAndMultiPathScope locks in the scoping that makes
// "undo just this project" safe: a directory arg restores every file recorded
// under that tree (and nothing outside it), an exact file arg restores just
// that file, and multiple args union-and-dedupe.
func TestSelectBackupsDirectoryAndMultiPathScope(t *testing.T) {
	recs := []migrate.BackupRecord{
		{OriginalPath: "/home/u/proj-a/.env"},
		{OriginalPath: "/home/u/proj-a/sub/.env"},
		{OriginalPath: "/home/u/proj-b/.env"},
		{OriginalPath: "/home/u/.zshrc"},
	}

	// A directory arg -> everything under that tree, nothing else.
	got, err := selectBackups(recs, []string{"/home/u/proj-a"})
	if err != nil {
		t.Fatalf("selectBackups(dir): %v", err)
	}
	if want := []string{"/home/u/proj-a/.env", "/home/u/proj-a/sub/.env"}; strings.Join(recPaths(got), ",") != strings.Join(want, ",") {
		t.Fatalf("directory scope should match only files under proj-a, got %v", recPaths(got))
	}

	// An exact file arg -> just that file (a prefix-hungry match would also
	// grab proj-a/sub, so this guards the boundary).
	got, err = selectBackups(recs, []string{"/home/u/proj-b/.env"})
	if err != nil || len(got) != 1 || got[0].OriginalPath != "/home/u/proj-b/.env" {
		t.Fatalf("exact file scope: err=%v got=%v", err, recPaths(got))
	}

	// Multiple args union and dedupe (the dir overlaps the explicit file under it).
	got, err = selectBackups(recs, []string{"/home/u/proj-a", "/home/u/proj-a/.env", "/home/u/proj-b/.env"})
	if err != nil {
		t.Fatalf("multi-arg: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 deduped records (proj-a x2 + proj-b), got %d: %v", len(got), recPaths(got))
	}
}

func TestSelectBackupsNoArgsReturnsAll(t *testing.T) {
	recs := []migrate.BackupRecord{{OriginalPath: "/a"}, {OriginalPath: "/b"}}
	got, err := selectBackups(recs, nil)
	if err != nil || len(got) != 2 {
		t.Fatalf("no args should restore everything: err=%v n=%d", err, len(got))
	}
}

func TestSelectBackupsUnknownArgFailsLoud(t *testing.T) {
	recs := []migrate.BackupRecord{{OriginalPath: "/home/u/proj-a/.env"}}
	if _, err := selectBackups(recs, []string{"/home/u/proj-z"}); err == nil || !strings.Contains(err.Error(), "no recorded backup") {
		t.Fatalf("an arg matching nothing must fail loud, got: %v", err)
	}
}

// TestRunRestoresContinuesPastFailure is the regression for the real defect
// this session found: a single unrestorable file used to abort the whole
// batch mid-loop, leaving earlier files restored and later ones untouched.
// The batch must now finish every file, report the failure, and exit non-zero.
func TestRunRestoresContinuesPastFailureAndExitsNonZero(t *testing.T) {
	recs := []migrate.BackupRecord{
		{OriginalPath: "/home/u/a/.env"},
		{OriginalPath: "/home/u/b/.env"}, // fails
		{OriginalPath: "/home/u/c/.env"},
	}
	var restored []string
	restoreOne := func(rec migrate.BackupRecord) error {
		if rec.OriginalPath == "/home/u/b/.env" {
			return fmt.Errorf("secret not found")
		}
		restored = append(restored, rec.OriginalPath)
		return nil
	}

	var buf bytes.Buffer
	err := runRestores(&buf, "/home/u", recs, restoreOne)
	if err == nil {
		t.Fatal("a batch with a failed file must return a non-nil error (non-zero exit)")
	}
	if len(restored) != 2 {
		t.Fatalf("the failure must not abort the batch — expected the other 2 restored, got %d (%v)", len(restored), restored)
	}
	out := buf.String()
	if !strings.Contains(out, "Restored 2 file(s)") {
		t.Errorf("summary should report 2 restored, got:\n%s", out)
	}
	if !strings.Contains(out, "could NOT be restored") || !strings.Contains(out, "secret not found") {
		t.Errorf("the failed file and its reason should be listed, got:\n%s", out)
	}
}

func TestRunRestoresAllSucceedReturnsNil(t *testing.T) {
	recs := []migrate.BackupRecord{{OriginalPath: "/home/u/a"}, {OriginalPath: "/home/u/b"}}
	var buf bytes.Buffer
	if err := runRestores(&buf, "/home/u", recs, func(migrate.BackupRecord) error { return nil }); err != nil {
		t.Fatalf("all-success batch must return nil, got %v", err)
	}
	if !strings.Contains(buf.String(), "Restored 2 file(s)") {
		t.Errorf("expected success summary, got:\n%s", buf.String())
	}
}

func TestHumanAgo(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{30 * time.Second, "30s"},
		{5 * time.Minute, "5m"},
		{3 * time.Hour, "3h"},
		{72 * time.Hour, "3d"},
	}
	for _, c := range cases {
		if got := humanAgo(c.d); got != c.want {
			t.Errorf("humanAgo(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}

// A no-arg undo about to restore more than one file must surface the path
// scoping it already supports — a real user asked for "project-specific
// undo" without discovering the path argument from --help. A scoped run (or
// a single-file one) must NOT show the hint: it's answering a question that
// run already answered.
func TestMigrateUndoNoArgHintsPathScoping(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)

	pathA := filepath.Join(home, "proj-a", ".env")
	pathB := filepath.Join(home, "proj-b", ".env")
	for _, p := range []string{pathA, pathB} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(p, []byte("KEY=value\n"), 0o600); err != nil {
			t.Fatalf("writing %s: %v", p, err)
		}
	}
	plantBackupRecord(t, pathA, pathB)

	const hint = "jit migrate undo <path>"

	out, err := execMigrateUndo(t, "--dry-run")
	if err != nil {
		t.Fatalf("migrate undo --dry-run: %v", err)
	}
	if !strings.Contains(out, hint) {
		t.Errorf("no-arg multi-file plan should hint at path scoping, got:\n%s", out)
	}

	scoped, err := execMigrateUndo(t, "--dry-run", filepath.Join(home, "proj-a"))
	if err != nil {
		t.Fatalf("migrate undo --dry-run proj-a: %v", err)
	}
	if strings.Contains(scoped, hint) {
		t.Errorf("a path-scoped run should not repeat the scoping hint, got:\n%s", scoped)
	}
	if !strings.Contains(scoped, displayPath(home, pathA)) || strings.Contains(scoped, displayPath(home, pathB)) {
		t.Errorf("scoping to proj-a should list only proj-a's file, got:\n%s", scoped)
	}
}
