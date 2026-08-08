// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// brewFixture lays out a fake Homebrew prefix: a real binary inside a
// version-numbered dir (relDir under the prefix) and the stable bin/<name>
// symlink pointing at it. Returns the canonicalized prefix, so path
// comparisons aren't tripped by /tmp resolving to /private/tmp.
func brewFixture(t *testing.T, relDir, name string) (prefix, versioned, stable string) {
	t.Helper()
	dir := t.TempDir()
	prefix, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("EvalSymlinks(%s): %v", dir, err)
	}
	versioned = filepath.Join(prefix, relDir, name)
	if err := os.MkdirAll(filepath.Dir(versioned), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(versioned, []byte("#!/bin/sh\n"), 0o755); err != nil { // #nosec G306 -- a fake executable in a test fixture
		t.Fatalf("WriteFile: %v", err)
	}
	stable = filepath.Join(prefix, "bin", name)
	if err := os.MkdirAll(filepath.Dir(stable), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Symlink(versioned, stable); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	return prefix, versioned, stable
}

// TestStableBinaryPathKeepsBrewBinSymlink pins the whole point of
// stableBinaryPath: a brew-managed jit records the bin symlink brew relinks
// on every upgrade, NOT the version-numbered Caskroom copy `brew upgrade`
// deletes. Recording the versioned path is how an upgrade used to orphan
// the service plist and dangle every wrap shim at once.
func TestStableBinaryPathKeepsBrewBinSymlink(t *testing.T) {
	_, _, stable := brewFixture(t, "Caskroom/jitpass/0.80.1", "jit")

	got, err := stableBinaryPath(stable)
	if err != nil {
		t.Fatalf("stableBinaryPath(%s): %v", stable, err)
	}
	if got != stable {
		t.Errorf("stableBinaryPath(%s) = %s; want the bin symlink kept, not resolved into the Caskroom", stable, got)
	}
}

// TestStableBinaryPathHealsDirectCaskroomInvocation covers the invocation
// with no symlink in hand: launchd re-running a plist that recorded the
// versioned path, or a shim that resolved all the way through. The stable
// name is recovered from the layout (prefix/bin/<name>), so even those
// callers repoint durable references onto the path that survives upgrades.
func TestStableBinaryPathHealsDirectCaskroomInvocation(t *testing.T) {
	_, versioned, stable := brewFixture(t, "Caskroom/jitpass/0.80.1", "jit")

	got, err := stableBinaryPath(versioned)
	if err != nil {
		t.Fatalf("stableBinaryPath(%s): %v", versioned, err)
	}
	if got != stable {
		t.Errorf("stableBinaryPath(%s) = %s; want %s recovered from the layout", versioned, got, stable)
	}
}

// TestStableBinaryPathCellarLayout: formulas unpack under Cellar with the
// binary one level deeper (<prefix>/Cellar/<name>/<version>/bin/<name>);
// the recovery is the same.
func TestStableBinaryPathCellarLayout(t *testing.T) {
	_, _, stable := brewFixture(t, "Cellar/jitpass/0.80.1/bin", "jit")

	got, err := stableBinaryPath(stable)
	if err != nil {
		t.Fatalf("stableBinaryPath(%s): %v", stable, err)
	}
	if got != stable {
		t.Errorf("stableBinaryPath(%s) = %s; want the bin symlink kept", stable, got)
	}
}

// TestStableBinaryPathOutsideBrewResolvesFully pins that everyone NOT under
// brew keeps the old behaviour exactly: full symlink resolution to the real
// file.
func TestStableBinaryPathOutsideBrewResolvesFully(t *testing.T) {
	dir := t.TempDir()
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	real := filepath.Join(root, "build", "jit")
	if err := os.MkdirAll(filepath.Dir(real), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(real, []byte("#!/bin/sh\n"), 0o755); err != nil { // #nosec G306 -- a fake executable in a test fixture
		t.Fatalf("WriteFile: %v", err)
	}
	link := filepath.Join(root, "jit-link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	for _, in := range []string{real, link} {
		got, err := stableBinaryPath(in)
		if err != nil {
			t.Fatalf("stableBinaryPath(%s): %v", in, err)
		}
		if got != real {
			t.Errorf("stableBinaryPath(%s) = %s; want %s (fully resolved)", in, got, real)
		}
	}
}

// TestStableBinaryPathRejectsMismatchedBinSymlink: when the prefix's bin
// symlink points at a DIFFERENT build than the one running (mid-upgrade,
// or a bin/jit that belongs to something else), the stable name would be a
// lie — fall back to the resolved path rather than record a name that runs
// another binary.
func TestStableBinaryPathRejectsMismatchedBinSymlink(t *testing.T) {
	prefix, versioned, stable := brewFixture(t, "Caskroom/jitpass/0.80.1", "jit")
	other := filepath.Join(prefix, "Caskroom", "jitpass", "0.80.2", "jit")
	if err := os.MkdirAll(filepath.Dir(other), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(other, []byte("#!/bin/sh\n# other\n"), 0o755); err != nil { // #nosec G306 -- a fake executable in a test fixture
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Remove(stable); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := os.Symlink(other, stable); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	got, err := stableBinaryPath(versioned)
	if err != nil {
		t.Fatalf("stableBinaryPath(%s): %v", versioned, err)
	}
	if got != versioned {
		t.Errorf("stableBinaryPath(%s) = %s; want the resolved path back when bin points elsewhere", versioned, got)
	}
}

// TestStableBinaryPathNoBinSymlink: a Caskroom copy with no bin symlink at
// all has no stable name to offer — resolved path, old behaviour.
func TestStableBinaryPathNoBinSymlink(t *testing.T) {
	_, versioned, stable := brewFixture(t, "Caskroom/jitpass/0.80.1", "jit")
	if err := os.Remove(stable); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	got, err := stableBinaryPath(versioned)
	if err != nil {
		t.Fatalf("stableBinaryPath(%s): %v", versioned, err)
	}
	if got != versioned {
		t.Errorf("stableBinaryPath(%s) = %s; want the resolved path back with no bin symlink", versioned, got)
	}
}

// TestAgentPlistOrphaned pins the self-heal trigger in ensureAgentInstalled:
// only a plist whose program binary is definitely gone counts as orphaned —
// a healthy plist and a missing plist both answer false.
func TestAgentPlistOrphaned(t *testing.T) {
	home := shortFixtureHome(t)

	if agentPlistOrphaned() {
		t.Fatal("agentPlistOrphaned = true with no plist installed; want false")
	}

	dir := filepath.Join(home, "Library", "LaunchAgents")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	plistPath := filepath.Join(dir, agentPlistLabel+".plist")

	present := filepath.Join(home, "jit")
	if err := os.WriteFile(present, []byte("#!/bin/sh\n"), 0o755); err != nil { // #nosec G306 -- a fake executable in a test fixture
		t.Fatalf("WriteFile: %v", err)
	}
	plist := fmt.Sprintf(agentPlistTemplate, agentPlistLabel, present, (5 * time.Minute).String(), "", "/x/agent.log", "/x/agent.log")
	if err := os.WriteFile(plistPath, []byte(plist), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if agentPlistOrphaned() {
		t.Error("agentPlistOrphaned = true for a plist whose binary exists; want false")
	}

	gone := filepath.Join(home, "Caskroom", "jitpass", "0.80.1", "jit")
	plist = fmt.Sprintf(agentPlistTemplate, agentPlistLabel, gone, (5 * time.Minute).String(), "", "/x/agent.log", "/x/agent.log")
	if err := os.WriteFile(plistPath, []byte(plist), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if !agentPlistOrphaned() {
		t.Error("agentPlistOrphaned = false for a plist whose binary is gone; want true")
	}
}
