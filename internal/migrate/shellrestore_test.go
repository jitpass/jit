// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The reason this exists: everything added to the file after migration,
// jit's own later lines included, has to survive the reversal. A whole-file
// restore from the backup loses all of it.
func TestRestoreShellConfigKeepsEverythingAddedSince(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, ".zshrc")
	writeFile(t, path, "export PATH=/usr/bin\nexport STRIPE_API_KEY=sk_test_123\nexport EDITOR=vim\n")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	v := newTestVault(t)
	if _, err := ApplyShellConfig(v, path); err != nil {
		t.Fatal(err)
	}

	migrated, _ := os.ReadFile(path) // #nosec G304 -- test-controlled path
	since := "alias gs='git status'\n[ -f \"$HOME/.jit/guard.zsh\" ] && source \"$HOME/.jit/guard.zsh\"\n"
	writeFile(t, path, string(migrated)+since)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	// Rotated since: the file must get today's value, not migration day's.
	if err := v.Set("zshrc/STRIPE_API_KEY", []byte("sk_live_it's")); err != nil {
		t.Fatal(err)
	}

	names, err := RestoreShellConfig(v, path)
	if err != nil {
		t.Fatalf("RestoreShellConfig: %v", err)
	}
	if len(names) != 1 || names[0] != "STRIPE_API_KEY" {
		t.Errorf("names = %v, want [STRIPE_API_KEY]", names)
	}
	got, _ := os.ReadFile(path) // #nosec G304 -- test-controlled path
	want := "export PATH=/usr/bin\nexport STRIPE_API_KEY='sk_live_it'\\''s'\nexport EDITOR=vim\n" + since
	if string(got) != want {
		t.Errorf("file after restore:\n%s\nwant:\n%s", got, want)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o644 {
		t.Errorf("mode = %v, want the file's own 0644 kept", info.Mode().Perm())
	}
}

func TestRestoreShellConfigLeavesAFileTheUserUnwired(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, ".zshrc")
	original := "export EDITOR=vim\n"
	writeFile(t, path, original)

	_, err := RestoreShellConfig(newTestVault(t), path)
	if !errors.Is(err, ErrShellConfigNotWired) {
		t.Fatalf("err = %v, want ErrShellConfigNotWired", err)
	}
	got, _ := os.ReadFile(path) // #nosec G304 -- test-controlled path
	if string(got) != original {
		t.Errorf("an unwired file was rewritten: %q", got)
	}
}

// ~/.zshrc as a link into a dotfiles repo: the link stays a link.
func TestRestoreShellConfigWritesThroughADotfilesLink(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	repo := filepath.Join(home, "dotfiles")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(repo, "zshrc")
	link := filepath.Join(home, ".zshrc")
	v := newTestVault(t)
	writeFile(t, link, "export STRIPE_API_KEY=sk_test_123\n")
	if _, err := ApplyShellConfig(v, link); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(link, real); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	if _, err := RestoreShellConfig(v, link); err != nil {
		t.Fatalf("RestoreShellConfig: %v", err)
	}
	if info, _ := os.Lstat(link); info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the dotfiles link was replaced by a regular file")
	}
	got, _ := os.ReadFile(real) // #nosec G304 -- test-controlled path
	if string(got) != "export STRIPE_API_KEY='sk_test_123'\n" {
		t.Errorf("repo file = %q", got)
	}
}
