// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/guard"
	"github.com/jitpass/jit/internal/keystore"
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/wrap"
)

func TestBinaryOwner(t *testing.T) {
	for path, want := range map[string]string{
		"/usr/local/bin/jit":                           "",
		"/Users/u/go/bin/jit":                          "",
		"/Applications/JitPass.app/Contents/MacOS/jit": "app",
		"/opt/homebrew/Caskroom/jitpass/1.7.0/JitPass.app/Contents/MacOS/jit": "homebrew",
		"/opt/homebrew/Cellar/jit/1.0.0/bin/jit":                              "homebrew",
	} {
		if got := binaryOwner(path); got != want {
			t.Errorf("binaryOwner(%q) = %q, want %q", path, got, want)
		}
	}
}

func writeRcWithPathLine(t *testing.T, home string) string {
	t.Helper()
	rc := filepath.Join(home, ".zshrc")
	if err := os.WriteFile(rc, []byte("alias ll='ls -l'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := wrap.EnsurePathLine(rc); err != nil {
		t.Fatal(err)
	}
	return rc
}

func TestRemoveShimPathLineWhenTheShimDirIsEmpty(t *testing.T) {
	home := t.TempDir()
	rc := writeRcWithPathLine(t, home)

	edited, err := removeShimPathLine(home, "/bin/zsh")
	if err != nil {
		t.Fatal(err)
	}
	if edited != rc {
		t.Fatalf("edited = %q, want %q", edited, rc)
	}
	data, _ := os.ReadFile(rc)
	if got := string(data); got != "alias ll='ls -l'\n" {
		t.Fatalf("rc after removal = %q, the user's own line must be all that is left", got)
	}
}

// The docker and git helpers are found by $PATH lookup alone, so the line
// has to outlive the last shim while either is still there (issue #77).
func TestRemoveShimPathLineStaysWhileAHelperLivesThere(t *testing.T) {
	home := t.TempDir()
	rc := writeRcWithPathLine(t, home)
	if err := os.MkdirAll(wrap.ShimDir(home), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(migrate.DockerHelperPath(home), []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	edited, err := removeShimPathLine(home, "/bin/zsh")
	if err != nil || edited != "" {
		t.Fatalf("edited = %q, err = %v; want the line left alone", edited, err)
	}
	data, _ := os.ReadFile(rc)
	if !strings.Contains(string(data), wrap.PathLine()) {
		t.Fatal("the PATH line was removed while docker-credential-jit still needs it")
	}
}

func TestRemoveHelperScriptsReachesOutsideTheJitDir(t *testing.T) {
	home := t.TempDir()
	paths := []string{
		migrate.TerraformHelperPath(home),
		migrate.CargoHelperPath(home),
		migrate.DockerHelperPath(home),
		migrate.GitHelperPath(home),
	}
	for _, p := range paths[:3] { // the git helper was never installed
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	neighbour := filepath.Join(home, ".cargo", "config.toml")
	if err := os.WriteFile(neighbour, []byte("[registry]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	removed, err := removeHelperScripts(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 3 {
		t.Fatalf("removed %v, want the three that existed", removed)
	}
	for _, p := range paths {
		if _, statErr := os.Lstat(p); !os.IsNotExist(statErr) {
			t.Errorf("%s is still there", p)
		}
	}
	if _, statErr := os.Stat(neighbour); statErr != nil {
		t.Errorf("the user's own %s must be left alone: %v", neighbour, statErr)
	}
}

// Secrets in the vault and no key to open them: the strict gate can never be
// satisfied, which used to make uninstall impossible.
func TestUninstallGateRelaxesOnlyWhenTheKeyIsProvablyGone(t *testing.T) {
	for _, tc := range []struct {
		name     string
		secrets  int
		presence keystore.Presence
		want     bool
	}{
		{"secrets and a key", 3, keystore.Present, true},
		{"secrets, key gone", 3, keystore.Absent, false},
		{"secrets, key unknowable", 3, keystore.Indeterminate, true},
		{"empty vault", 0, keystore.Present, false},
		{"unreadable vault", -1, keystore.Present, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubKeychain(t, tc.presence)
			if got := uninstallNeedsVaultKey(tc.secrets); got != tc.want {
				t.Fatalf("uninstallNeedsVaultKey(%d) = %v, want %v", tc.secrets, got, tc.want)
			}
		})
	}
}

// A purge, end to end against a temp home: everything jit put outside its
// own two directories is gone, the keys are asked for, and nothing the user
// owns is touched. launchd, the keychain and the presence prompt are stubs;
// --keep-binary because os.Executable() here is the test binary.
func TestUninstallPurgeLeavesNothingBehind(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/zsh")
	t.Setenv("ZDOTDIR", "")
	stubKeychain(t, keystore.Present)

	origLaunchctl, origDelete, origChallenge := launchctlRun, deleteVaultKeys, uninstallChallenge
	t.Cleanup(func() {
		launchctlRun, deleteVaultKeys, uninstallChallenge = origLaunchctl, origDelete, origChallenge
		uninstallPurge, uninstallYes, uninstallKeepBinary = false, false, false
	})
	launchctlRun = func(...string) ([]byte, error) { return nil, nil }
	keysDeleted, challenged := false, false
	deleteVaultKeys = func(keystore.Store) error { keysDeleted = true; return nil }
	uninstallChallenge = func(string) error { challenged = true; return nil }

	rc := writeRcWithPathLine(t, home)
	if _, err := guard.Install(home); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{migrate.TerraformHelperPath(home), migrate.DockerHelperPath(home)} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	root, err := vaultRootDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}

	uninstallPurge, uninstallYes, uninstallKeepBinary = true, true, true
	var out strings.Builder
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	if err := runUninstall(cmd, nil); err != nil {
		t.Fatalf("runUninstall: %v\n%s", err, out.String())
	}

	if !challenged || !keysDeleted {
		t.Errorf("challenged = %v, keysDeleted = %v; want both", challenged, keysDeleted)
	}
	for _, gone := range []string{
		filepath.Join(home, ".jit"), root,
		migrate.TerraformHelperPath(home), migrate.DockerHelperPath(home),
	} {
		if _, statErr := os.Lstat(gone); !os.IsNotExist(statErr) {
			t.Errorf("%s is still there", gone)
		}
	}
	data, _ := os.ReadFile(rc)
	if got := string(data); got != "alias ll='ls -l'\n" {
		t.Errorf("~/.zshrc after the purge = %q, want only the user's own line\n%s", got, out.String())
	}
}
