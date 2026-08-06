// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package wrap

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateToolName(t *testing.T) {
	for _, ok := range []string{"gh", "my-tool", "a.b_c", "doctl2"} {
		if err := ValidateToolName(ok); err != nil {
			t.Errorf("ValidateToolName(%q) = %v, want nil", ok, err)
		}
	}
	// ".." and "-" used to be skipped here with a comment calling them
	// "pattern-legal", which was true and was the bug: ".." resolved to ~/.jit
	// under filepath.Join, and a leading "-" puts a flag-shaped name on PATH.
	// They are rejected now, so the table has no exceptions.
	for _, bad := range []string{"jit", "a/b", "", ".", "..", "a b", "-", "-n"} {
		if err := ValidateToolName(bad); err == nil {
			t.Errorf("ValidateToolName(%q) = nil, want error", bad)
		}
	}
}

func TestInstallShimCreatesDirAndSymlink(t *testing.T) {
	home := t.TempDir()
	link, err := InstallShim(home, "/usr/bin/true", "gh")
	if err != nil {
		t.Fatalf("InstallShim: %v", err)
	}
	if link != filepath.Join(ShimDir(home), "gh") {
		t.Errorf("shim at %q, want it inside %q", link, ShimDir(home))
	}
	info, err := os.Stat(ShimDir(home))
	if err != nil {
		t.Fatalf("shim dir: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("shim dir mode = %o, want 0700", perm)
	}
	target, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("Readlink: %v", err)
	}
	if target != "/usr/bin/true" {
		t.Errorf("shim points at %q, want /usr/bin/true", target)
	}
}

func TestInstallShimRefreshesExistingSymlink(t *testing.T) {
	home := t.TempDir()
	if _, err := InstallShim(home, "/usr/bin/true", "gh"); err != nil {
		t.Fatal(err)
	}
	link, err := InstallShim(home, "/usr/bin/false", "gh")
	if err != nil {
		t.Fatalf("re-install: %v", err)
	}
	if target, _ := os.Readlink(link); target != "/usr/bin/false" {
		t.Errorf("refreshed shim points at %q, want /usr/bin/false", target)
	}
}

func TestInstallShimRefusesNonSymlinkAndRelativeTarget(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(ShimDir(home), 0o700); err != nil {
		t.Fatal(err)
	}
	squatter := filepath.Join(ShimDir(home), "gh")
	if err := os.WriteFile(squatter, []byte("not a symlink"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallShim(home, "/usr/bin/true", "gh"); err == nil {
		t.Error("expected InstallShim to refuse replacing a regular file")
	}
	if _, err := InstallShim(home, "bin/jit", "other"); err == nil {
		t.Error("expected InstallShim to refuse a relative target")
	}
}

func TestRemoveShim(t *testing.T) {
	home := t.TempDir()
	if _, err := InstallShim(home, "/usr/bin/true", "gh"); err != nil {
		t.Fatal(err)
	}
	removed, err := RemoveShim(home, "gh")
	if err != nil || !removed {
		t.Fatalf("RemoveShim = (%v, %v), want (true, nil)", removed, err)
	}
	removed, err = RemoveShim(home, "gh")
	if err != nil || removed {
		t.Fatalf("second RemoveShim = (%v, %v), want (false, nil)", removed, err)
	}
}

func TestInstalledShimsListsOnlySymlinksSorted(t *testing.T) {
	home := t.TempDir()
	for _, tool := range []string{"stripe", "gh"} {
		if _, err := InstallShim(home, "/usr/bin/true", tool); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(ShimDir(home), "README"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := InstalledShims(home)
	if err != nil {
		t.Fatalf("InstalledShims: %v", err)
	}
	if len(got) != 2 || got[0] != "gh" || got[1] != "stripe" {
		t.Errorf("InstalledShims = %v, want [gh stripe]", got)
	}

	if empty, err := InstalledShims(t.TempDir()); err != nil || empty != nil {
		t.Errorf("missing shim dir: got (%v, %v), want (nil, nil)", empty, err)
	}
}
