// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Same fake-but-vendor-shaped value convention as internal/migrate's clean
// tests: detected by the scanners, meaningless to push protection.
const cleanCLISecret = "sk-proj-Ab3xKq9ZmPq2LrTvWn5cUd8eFg1hJk0uf4"

func writeCleanTrashEnv(t *testing.T, home string) string {
	t.Helper()
	trashEnv := filepath.Join(home, ".Trash", "old", ".env")
	if err := os.MkdirAll(filepath.Dir(trashEnv), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trashEnv, []byte("OPENAI_API_KEY="+cleanCLISecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return trashEnv
}

// TestMigrateCleanDryRunPlansDeletion: --clean routes a named delete-class
// file to the [deletions] category INSTEAD of migration, inside the intact
// two-marker dry-run frame, and the trailer's apply command carries --clean
// so the preview reproduces the run it previewed (design/migrate-clean.md
// D7/D9).
func TestMigrateCleanDryRunPlansDeletion(t *testing.T) {
	home := withFixtureHome(t)
	trashEnv := writeCleanTrashEnv(t, home)

	out, err := execMigrate(t, trashEnv, "--dry-run", "--clean")
	if err != nil {
		t.Fatalf("jit migrate <trash env> --dry-run --clean: %v\n%s", err, out)
	}
	if !strings.Contains(out, "[deletions] 1") {
		t.Errorf("expected the [deletions] plan category, got:\n%s", out)
	}
	if !strings.Contains(out, "in the Trash") {
		t.Errorf("expected the trash evidence line, got:\n%s", out)
	}
	plan := dryRunPlanOnly(out)
	if strings.Contains(plan, ".env file") {
		t.Errorf("a --clean-claimed trash file must not also be planned for migration, got:\n%s", plan)
	}
	if got := strings.Count(out, "[DRY RUN]"); got != 2 {
		t.Errorf("expected exactly 2 [DRY RUN] markers with --clean, got %d:\n%s", got, out)
	}
	if !strings.Contains(out, "--clean") || !strings.Contains(out, "Apply this plan:") {
		t.Errorf("expected the trailer's apply command to carry --clean, got:\n%s", out)
	}
	if _, statErr := os.Stat(trashEnv); statErr != nil {
		t.Error("a dry run must not touch the file")
	}
}

// TestMigrateCleanOffByDefault: without --clean the same trash file keeps
// today's behavior — a targeted run migrates it, and no [deletions]
// category appears anywhere.
func TestMigrateCleanOffByDefault(t *testing.T) {
	home := withFixtureHome(t)
	trashEnv := writeCleanTrashEnv(t, home)

	out, err := execMigrate(t, trashEnv, "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate <trash env> --dry-run: %v\n%s", err, out)
	}
	if strings.Contains(out, "[deletions]") {
		t.Errorf("[deletions] must not appear without --clean, got:\n%s", out)
	}
	if !strings.Contains(dryRunPlanOnly(out), ".env file") {
		t.Errorf("expected the named trash file to still plan as a migration without --clean, got:\n%s", out)
	}
}

// TestMigrateCleanDeclineDeletesNothing: the deletions get their own [y/N]
// naming every path, an EOF/decline prints the standing-work line, the file
// survives, and no vault (hence no Touch ID) was ever opened — the consent
// order is plan → [y/N] → fresh auth (GAPS.md #17).
func TestMigrateCleanDeclineDeletesNothing(t *testing.T) {
	home := withFixtureHome(t)
	trashEnv := writeCleanTrashEnv(t, home)

	out, err := execMigrate(t, trashEnv, "--clean")
	if err != nil {
		t.Fatalf("jit migrate <trash env> --clean (declined): %v\n%s", err, out)
	}
	if !strings.Contains(out, "Delete this file from disk?") {
		t.Errorf("expected the dedicated deletion prompt, got:\n%s", out)
	}
	if !strings.Contains(out, displayPath(home, trashEnv)) {
		t.Errorf("the deletion prompt must name every path it covers, got:\n%s", out)
	}
	if !strings.Contains(out, "Deletions skipped. Nothing was deleted.") {
		t.Errorf("expected the decline line, got:\n%s", out)
	}
	if _, statErr := os.Stat(trashEnv); statErr != nil {
		t.Error("declining the prompt must leave the file in place")
	}
}
