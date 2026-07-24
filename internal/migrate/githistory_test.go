// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...) // #nosec G204 -- test-only, fixed args from callers below, dir is t.TempDir()
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func initGitRepo(t *testing.T, dir string) {
	t.Helper()
	runGit(t, dir, "init", "-q")
	runGit(t, dir, "config", "user.email", "test@example.com")
	runGit(t, dir, "config", "user.name", "Test")
	runGit(t, dir, "config", "commit.gpgsign", "false")
}

func TestHasGitHistoryTrueForCommittedFile(t *testing.T) {
	dir := t.TempDir()
	initGitRepo(t, dir)
	path := filepath.Join(dir, ".env")
	writeFile(t, path, "A=1\n")
	runGit(t, dir, "add", ".env")
	runGit(t, dir, "commit", "-q", "-m", "add .env")

	has, err := HasGitHistory(path)
	if err != nil {
		t.Fatalf("HasGitHistory: %v", err)
	}
	if !has {
		t.Error("expected true for a committed file, got false")
	}
}

func TestHasGitHistoryFalseForNeverCommittedFile(t *testing.T) {
	dir := t.TempDir()
	initGitRepo(t, dir)
	path := filepath.Join(dir, ".env")
	writeFile(t, path, "A=1\n")
	// Deliberately never added/committed.

	has, err := HasGitHistory(path)
	if err != nil {
		t.Fatalf("HasGitHistory: %v", err)
	}
	if has {
		t.Error("expected false for a never-committed file, got true")
	}
}

func TestHasGitHistoryFalseAfterFileDeletedButHistoryRemains(t *testing.T) {
	dir := t.TempDir()
	initGitRepo(t, dir)
	path := filepath.Join(dir, ".env")
	writeFile(t, path, "SECRET=oops\n")
	runGit(t, dir, "add", ".env")
	runGit(t, dir, "commit", "-q", "-m", "add .env")
	runGit(t, dir, "rm", "-q", ".env")
	runGit(t, dir, "commit", "-q", "-m", "remove .env")
	// Recreate the file at the same path (e.g. a fresh, never-committed
	// .env written after someone tried to "fix" the leak by deleting it) --
	// git log on the path still finds the old commits.
	writeFile(t, path, "SECRET=new\n")

	has, err := HasGitHistory(path)
	if err != nil {
		t.Fatalf("HasGitHistory: %v", err)
	}
	if !has {
		t.Error("expected true, the file has prior history even though it isn't currently tracked, got false")
	}
}

func TestHasGitHistoryFalseOutsideGitRepo(t *testing.T) {
	dir := t.TempDir() // deliberately no git init
	path := filepath.Join(dir, ".env")
	writeFile(t, path, "A=1\n")

	has, err := HasGitHistory(path)
	if err != nil {
		t.Fatalf("HasGitHistory: %v", err)
	}
	if has {
		t.Error("expected false outside a git repository, got true")
	}
}
