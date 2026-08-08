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

// TestJitInstallsOnPathDedupesAndOrders pins the gathering half: one entry
// per distinct resolved binary, in PATH order, named by the first hit — so
// /opt/homebrew/bin/jit and a second PATH entry reaching the same Caskroom
// file count once, and the first entry is the jit shells actually run.
func TestJitInstallsOnPathDedupesAndOrders(t *testing.T) {
	root := t.TempDir()
	mk := func(rel string) string {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil { // #nosec G306 -- a fake executable in a test fixture
			t.Fatalf("WriteFile: %v", err)
		}
		return p
	}
	curl := mk("usr-local-bin/jit")
	cask := mk("Caskroom/jitpass/0.80.1/jit")
	brewBin := filepath.Join(root, "homebrew-bin")
	if err := os.MkdirAll(brewBin, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Symlink(cask, filepath.Join(brewBin, "jit")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	empty := filepath.Join(root, "no-jit-here")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	// curl dir first (the field shape: /usr/local/bin ahead of brew), then
	// the brew bin symlink, then the Caskroom dir itself (same file again),
	// then a dir with no jit.
	pathEnv := strings.Join([]string{
		filepath.Dir(curl), brewBin, filepath.Dir(cask), empty,
	}, string(os.PathListSeparator))

	installs := jitInstallsOnPath(pathEnv)
	if len(installs) != 2 {
		t.Fatalf("jitInstallsOnPath = %d installs (%v); want 2 — the Caskroom re-hit must dedupe against the bin symlink", len(installs), installs)
	}
	if installs[0].path != curl {
		t.Errorf("installs[0].path = %s; want %s (PATH order decides which jit shells run)", installs[0].path, curl)
	}
	if installs[1].path != filepath.Join(brewBin, "jit") {
		t.Errorf("installs[1].path = %s; want the bin symlink, the first name that reached the Caskroom copy", installs[1].path)
	}
}

// TestInstallFindingsFrom pins the classification half: silent below two
// installs, one advisory finding per shadowed copy, and the action matched
// to who owns which copy.
func TestInstallFindingsFrom(t *testing.T) {
	if fs := installFindingsFrom(nil); fs != nil {
		t.Errorf("installFindingsFrom(nil) = %v; want none", fs)
	}
	one := []jitInstall{{path: "/usr/local/bin/jit", resolved: "/usr/local/bin/jit"}}
	if fs := installFindingsFrom(one); fs != nil {
		t.Errorf("installFindingsFrom(one install) = %v; want none — a single jit is the healthy state", fs)
	}

	curl := jitInstall{path: "/usr/local/bin/jit", resolved: "/usr/local/bin/jit"}
	brew := jitInstall{path: "/opt/homebrew/bin/jit", resolved: "/opt/homebrew/Caskroom/jitpass/0.80.1/jit"}

	// The field shape: the old tarball copy shadows the fresh brew install.
	// The either-or action is deliberate — this user most likely WANTS the
	// brew copy, so recommending only its removal would send them in circles.
	fs := installFindingsFrom([]jitInstall{curl, brew})
	if len(fs) != 1 {
		t.Fatalf("installFindingsFrom(curl, brew) = %d findings; want 1", len(fs))
	}
	f := fs[0]
	if f.Kind != kindInstall {
		t.Errorf("Kind = %q; want %q", f.Kind, kindInstall)
	}
	if !f.Kind.warning() {
		t.Error("kindInstall must be advisory: nothing is unreadable, doctor must not fail the run on it")
	}
	if !strings.Contains(f.Detail, curl.path) || !strings.Contains(f.Detail, brew.path) {
		t.Errorf("Detail = %q; want both copies named", f.Detail)
	}
	if !strings.Contains(f.Action, "brew uninstall jitpass") || !strings.Contains(f.Action, "sudo rm /usr/local/bin/jit") {
		t.Errorf("Action = %q; want both resolutions offered when the shadowed copy is Homebrew's", f.Action)
	}

	// Reversed PATH order: brew wins, the tarball copy is dead weight.
	fs = installFindingsFrom([]jitInstall{brew, curl})
	if len(fs) != 1 {
		t.Fatalf("installFindingsFrom(brew, curl) = %d findings; want 1", len(fs))
	}
	if want := "`sudo rm /usr/local/bin/jit` to keep the Homebrew copy in charge"; fs[0].Action != want {
		t.Errorf("Action = %q; want %q", fs[0].Action, want)
	}

	// Neither copy is brew's: plain keep-the-winner.
	local := jitInstall{path: "/Users/x/bin/jit", resolved: "/Users/x/bin/jit"}
	fs = installFindingsFrom([]jitInstall{curl, local})
	if len(fs) != 1 {
		t.Fatalf("installFindingsFrom(curl, local) = %d findings; want 1", len(fs))
	}
	if want := "`sudo rm /Users/x/bin/jit` to keep /usr/local/bin/jit"; fs[0].Action != want {
		t.Errorf("Action = %q; want %q", fs[0].Action, want)
	}
}
