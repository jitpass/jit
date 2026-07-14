// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package migrate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/profile"
)

func TestDiscoverShellConfigsFindsSecretExports(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".zshrc"), "export PATH=/usr/bin\nexport STRIPE_API_KEY=sk_test_123\n")
	writeFile(t, filepath.Join(home, ".bashrc"), "export EDITOR=vim\n")

	found, err := DiscoverShellConfigs(home)
	if err != nil {
		t.Fatalf("DiscoverShellConfigs: %v", err)
	}
	want := []string{filepath.Join(home, ".zshrc")}
	if len(found) != len(want) || found[0] != want[0] {
		t.Errorf("found = %v, want %v (only .zshrc has a secret-shaped export)", found, want)
	}
}

func TestDiscoverShellConfigsNoneMissing(t *testing.T) {
	home := t.TempDir()
	found, err := DiscoverShellConfigs(home)
	if err != nil {
		t.Fatalf("DiscoverShellConfigs on an empty home: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("found = %v, want empty", found)
	}
}

func TestApplyShellConfigMovesSecretsAndRewritesFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, ".zshrc")
	writeFile(t, path, "export PATH=/usr/bin\nexport STRIPE_API_KEY=sk_test_123\nexport EDITOR=vim\n")

	v := newTestVault(t)
	result, err := ApplyShellConfig(v, path)
	if err != nil {
		t.Fatalf("ApplyShellConfig: %v", err)
	}
	if result.ProfileName != "zshrc" {
		t.Errorf("ProfileName = %q, want %q", result.ProfileName, "zshrc")
	}
	if len(result.Variables) != 1 || result.Variables[0] != "STRIPE_API_KEY" {
		t.Errorf("Variables = %v, want [STRIPE_API_KEY]", result.Variables)
	}

	got, err := v.Get("zshrc/STRIPE_API_KEY")
	if err != nil || string(got) != "sk_test_123" {
		t.Errorf("vault secret = (%q, %v), want (sk_test_123, nil)", got, err)
	}

	rewritten, err := os.ReadFile(path) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading rewritten file: %v", err)
	}
	content := string(rewritten)
	if strings.Contains(content, "sk_test_123") {
		t.Error("rewritten file must not contain the raw secret value")
	}
	if !strings.Contains(content, "export PATH=/usr/bin") || !strings.Contains(content, "export EDITOR=vim") {
		t.Errorf("rewritten file lost a non-secret export line, got:\n%s", content)
	}
	if !strings.Contains(content, `eval "$(jit export --profile zshrc)"`) {
		t.Errorf("rewritten file missing the jit export eval line, got:\n%s", content)
	}

	// The profile lives in the home-rooted global store, resolvable via
	// jit export regardless of what directory a new shell starts in.
	p, err := profile.Load(t.TempDir(), "zshrc")
	if err != nil {
		t.Fatalf("loading migrated profile via the global fallback: %v", err)
	}
	if p["STRIPE_API_KEY"] != "zshrc/STRIPE_API_KEY" {
		t.Errorf("profile entry = %q, want %q", p["STRIPE_API_KEY"], "zshrc/STRIPE_API_KEY")
	}
}

func TestApplyShellConfigWritesBackup(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, ".zshrc")
	original := "export STRIPE_API_KEY=sk_test_123\n"
	writeFile(t, path, original)

	v := newTestVault(t)
	result, err := ApplyShellConfig(v, path)
	if err != nil {
		t.Fatalf("ApplyShellConfig: %v", err)
	}
	if result.BackupPath == "" {
		t.Fatal("expected a non-empty BackupPath")
	}
	backup, err := v.Get(result.BackupPath)
	if err != nil {
		t.Fatalf("reading backup from vault: %v", err)
	}
	if string(backup) != original {
		t.Errorf("backup content = %q, want the original file content %q", backup, original)
	}
}

func TestApplyShellConfigNoSecretsErrors(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, ".zshrc")
	writeFile(t, path, "export PATH=/usr/bin\n")

	v := newTestVault(t)
	if _, err := ApplyShellConfig(v, path); err == nil {
		t.Fatal("expected an error migrating a file with no secret-shaped exports")
	}
}

func TestApplyShellConfigIsIdempotentAndMergesOnSecondRun(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, ".zshrc")
	writeFile(t, path, "export STRIPE_API_KEY=sk_test_123\n")

	v := newTestVault(t)
	if _, err := ApplyShellConfig(v, path); err != nil {
		t.Fatalf("first ApplyShellConfig: %v", err)
	}

	// A file already fully migrated (no secret-shaped exports left) should
	// no longer be reported as needing migration.
	found, err := DiscoverShellConfigs(home)
	if err != nil {
		t.Fatalf("DiscoverShellConfigs: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("DiscoverShellConfigs after migration = %v, want empty", found)
	}

	// Simulate a new secret being added by hand after the first migration.
	appendFile(t, path, "export AWS_SECRET=abc123\n")

	result, err := ApplyShellConfig(v, path)
	if err != nil {
		t.Fatalf("second ApplyShellConfig: %v", err)
	}
	if len(result.Variables) != 1 || result.Variables[0] != "AWS_SECRET" {
		t.Errorf("second run Variables = %v, want [AWS_SECRET]", result.Variables)
	}

	p, err := profile.Load(t.TempDir(), "zshrc")
	if err != nil {
		t.Fatalf("loading merged profile: %v", err)
	}
	if p["STRIPE_API_KEY"] != "zshrc/STRIPE_API_KEY" {
		t.Error("second migration should not have dropped the first run's entry")
	}
	if p["AWS_SECRET"] != "zshrc/AWS_SECRET" {
		t.Error("second migration should have added the new entry")
	}

	rewritten, err := os.ReadFile(path) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading rewritten file: %v", err)
	}
	if strings.Count(string(rewritten), "jit export --profile zshrc") != 1 {
		t.Errorf("expected exactly one eval line after two migration rounds, got:\n%s", rewritten)
	}
}

func appendFile(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
}
