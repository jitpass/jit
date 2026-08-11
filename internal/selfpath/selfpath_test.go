// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package selfpath

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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

// TestStableKeepsBrewBinSymlink pins the whole point of Stable: a
// brew-managed jit records the bin symlink brew relinks on every upgrade, NOT
// the version-numbered Caskroom copy `brew upgrade` deletes. Recording the
// versioned path is how an upgrade used to orphan the service plist and
// dangle every wrap shim at once.
func TestStableKeepsBrewBinSymlink(t *testing.T) {
	_, _, stable := brewFixture(t, "Caskroom/jitpass/0.80.1", "jit")

	got, err := Stable(stable)
	if err != nil {
		t.Fatalf("Stable(%s): %v", stable, err)
	}
	if got != stable {
		t.Errorf("Stable(%s) = %s; want the bin symlink kept, not resolved into the Caskroom", stable, got)
	}
}

// TestStableHealsADirectVersionedInvocation is the case that produced this
// package: the binary is invoked BY its versioned path (launchd re-running an
// old plist, or `jit migrate` run from the Caskroom copy), and the answer
// must still be the stable bin symlink. Recovering from the layout rather
// than from the symlink walked in hand is what makes that possible.
func TestStableHealsADirectVersionedInvocation(t *testing.T) {
	_, versioned, stable := brewFixture(t, "Caskroom/jitpass/0.84.0", "jit")

	got, err := Stable(versioned)
	if err != nil {
		t.Fatalf("Stable(%s): %v", versioned, err)
	}
	if got != stable {
		t.Errorf("Stable(%s) = %s; want %s — a versioned invocation must heal onto the bin symlink", versioned, got, stable)
	}
}

// TestStableCellarLayout: formulas unpack under Cellar with the binary one
// level deeper (<prefix>/Cellar/<name>/<version>/bin/<name>); the recovery is
// the same.
func TestStableCellarLayout(t *testing.T) {
	_, _, stable := brewFixture(t, "Cellar/jitpass/0.80.1/bin", "jit")

	got, err := Stable(stable)
	if err != nil {
		t.Fatalf("Stable(%s): %v", stable, err)
	}
	if got != stable {
		t.Errorf("Stable(%s) = %s; want the bin symlink kept", stable, got)
	}
}

// TestStableNoBinSymlink: a Caskroom copy with no bin symlink at all has no
// stable name to offer — resolved path, old behaviour. Durable is what
// refuses to RECORD that path; Stable still hands it back.
func TestStableNoBinSymlink(t *testing.T) {
	_, versioned, stable := brewFixture(t, "Caskroom/jitpass/0.84.0", "jit")
	if err := os.Remove(stable); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	got, err := Stable(versioned)
	if err != nil {
		t.Fatalf("Stable(%s): %v", versioned, err)
	}
	if got != versioned {
		t.Errorf("Stable(%s) = %s; want the resolved path back with no bin symlink", versioned, got)
	}
}

// TestStableFallsBackWhenBinPointsElsewhere: a bin symlink that resolves to a
// DIFFERENT build must not be substituted for the running one. Recording a
// path that runs someone else's binary is worse than recording a fragile one.
func TestStableFallsBackWhenBinPointsElsewhere(t *testing.T) {
	prefix, versioned, stable := brewFixture(t, "Caskroom/jitpass/0.84.0", "jit")

	other := filepath.Join(prefix, "Caskroom", "jitpass", "0.83.0", "jit")
	if err := os.MkdirAll(filepath.Dir(other), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(other, []byte("#!/bin/sh\n# a different build\n"), 0o755); err != nil { // #nosec G306 -- test fixture
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Remove(stable); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := os.Symlink(other, stable); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	got, err := Stable(versioned)
	if err != nil {
		t.Fatalf("Stable(%s): %v", versioned, err)
	}
	if got != versioned {
		t.Errorf("Stable(%s) = %s; want the running binary %s, not whatever bin/ happens to point at", versioned, got, versioned)
	}
}

// TestStableLeavesANonBrewPathFullyResolved: the common non-brew install is
// still plain EvalSymlinks, so an install symlink resolves to the real file.
func TestStableLeavesANonBrewPathFullyResolved(t *testing.T) {
	dir := t.TempDir()
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	real := filepath.Join(root, "libexec", "jit")
	if err := os.MkdirAll(filepath.Dir(real), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(real, []byte("#!/bin/sh\n"), 0o755); err != nil { // #nosec G306 -- test fixture
		t.Fatalf("WriteFile: %v", err)
	}
	link := filepath.Join(root, "jit")
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	got, err := Stable(link)
	if err != nil {
		t.Fatalf("Stable(%s): %v", link, err)
	}
	if got != real {
		t.Errorf("Stable(%s) = %s; want the fully resolved %s", link, got, real)
	}
}

// TestVersionedBrew covers the predicate `jit doctor` uses to call a path
// fragile BEFORE the upgrade that breaks it, rather than missing afterwards.
func TestVersionedBrew(t *testing.T) {
	versioned := []string{
		"/opt/homebrew/Caskroom/jitpass/0.84.0/jit",
		"/usr/local/Caskroom/jitpass/0.84.0/jit",
		"/opt/homebrew/Cellar/jitpass/0.84.0/bin/jit",
	}
	for _, p := range versioned {
		if !VersionedBrew(p) {
			t.Errorf("%q was not recognized as a version-numbered brew path", p)
		}
	}
	durable := []string{
		"/opt/homebrew/bin/jit",
		"/usr/local/bin/jit",
		"/Users/alex/go/bin/jit",
	}
	for _, p := range durable {
		if VersionedBrew(p) {
			t.Errorf("%q was treated as version-numbered", p)
		}
	}
	// A Caskroom at the filesystem root has no prefix to hang a bin dir off,
	// so there is nothing to heal onto and nothing to report.
	if VersionedBrew("/Caskroom/jitpass/0.84.0/jit") {
		t.Error("a root-level Caskroom has no recoverable prefix and must not report as one")
	}
}

// TestVolatile pins the location test behind Durable's refusal.
func TestVolatile(t *testing.T) {
	volatile := []string{
		"/tmp/jit",
		"/private/tmp/build/jit",
		"/var/folders/xy/T/go-build123/b001/exe/jit",
		"/Volumes/jit-0.82.0/jit",
	}
	// The un-installed release tarball, run in place from ~/Downloads before
	// the install step moves it onto PATH — jit's own download shape.
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		volatile = append(volatile, filepath.Join(home, "Downloads", "jit"))
	}
	for _, p := range volatile {
		if !Volatile(p) {
			t.Errorf("%q was treated as a durable install location", p)
		}
	}
	durable := []string{
		"/usr/local/bin/jit",
		"/opt/homebrew/bin/jit",
		"/Users/alex/go/bin/jit",
	}
	for _, p := range durable {
		if Volatile(p) {
			t.Errorf("%q was treated as temporary", p)
		}
	}
	// A Caskroom path is not volatile BY THIS TEST — it disappears on upgrade,
	// not on reboot, and Stable heals it onto the bin symlink first.
	// VersionedBrew is what catches it.
	if Volatile("/opt/homebrew/Caskroom/jitpass/0.84.0/jit") {
		t.Error("a Caskroom path is the VersionedBrew failure, not the Volatile one")
	}
	// A prefix must not match across a name boundary: /tmpfoo is not /tmp.
	if Volatile("/tmpfoo/jit") {
		t.Error("/tmpfoo/jit matched the /tmp root on a bare string prefix")
	}
}

// TestDurableNeverReturnsAPathThatDisappears is the guard that matters: what
// this returns is written into a config file and outlives the process, so it
// must name a binary that will still exist.
//
// The test binary itself runs from /var/folders, so this exercises the
// refusal for free — os.Executable() is volatile here by construction.
func TestDurableNeverReturnsAPathThatDisappears(t *testing.T) {
	got, err := Durable()
	if err != nil {
		// Refusing is the correct outcome when nothing durable exists, and
		// the message has to say why rather than surfacing a bare failure.
		for _, want := range []string{"temporary or removable location", "install jit"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("refusal does not explain itself (%q missing): %v", want, err)
			}
		}
		return
	}
	if Volatile(got) {
		t.Errorf("returned %q, which is inside a directory whose contents disappear", got)
	}
	if VersionedBrew(got) {
		t.Errorf("returned %q, which the next `brew upgrade` deletes", got)
	}
}
