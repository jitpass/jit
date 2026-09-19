// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package projectrecord

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func manifestIn(t *testing.T) (root, manifest string) {
	t.Helper()
	root = t.TempDir()
	manifest = filepath.Join(root, ".jit", "profiles", "app.yaml")
	if err := os.MkdirAll(filepath.Dir(manifest), 0o700); err != nil {
		t.Fatal(err)
	}
	return root, manifest
}

func TestRecordSitsBesideItsManifestAndNamesItsProject(t *testing.T) {
	root, manifest := manifestIn(t)
	rec := Path(manifest)
	if rec != filepath.Join(root, ".jit", "profiles", "app.mount") {
		t.Errorf("Path = %s", rec)
	}
	if got := ProjectRoot(rec); got != root {
		t.Errorf("ProjectRoot = %s, want %s", got, root)
	}
}

// The round trip a rename has to survive: written under one absolute path,
// read back under another, with only the project-relative form on disk.
func TestAddWritesRelativePathsOnly(t *testing.T) {
	root, manifest := manifestIn(t)
	if err := Add(manifest, filepath.Join(root, ".env"), "6cd2a4a5"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(Path(manifest))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), root) {
		t.Errorf("the record must hold no absolute path:\n%s", data)
	}
	r, ok, err := Read(Path(manifest))
	if err != nil || !ok {
		t.Fatalf("Read: %v ok=%v", err, ok)
	}
	if len(r.Mounts) != 1 || r.Mounts[0] != ".env" || r.Group != "6cd2a4a5" {
		t.Errorf("record = %+v", r)
	}

	// Re-running migrate must not duplicate or rewrite.
	before, _ := os.ReadFile(Path(manifest))
	if err := Add(manifest, filepath.Join(root, ".env"), "6cd2a4a5"); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(Path(manifest))
	if string(before) != string(after) {
		t.Errorf("a second Add rewrote the record:\n%s\nvs\n%s", before, after)
	}

	// A second mount on the same manifest accumulates.
	if err := Add(manifest, filepath.Join(root, ".env.local"), ""); err != nil {
		t.Fatal(err)
	}
	r, _, _ = Read(Path(manifest))
	if len(r.Mounts) != 2 || r.Mounts[1] != ".env.local" {
		t.Errorf("record = %+v", r)
	}
	if r.Group != "6cd2a4a5" {
		t.Errorf("an Add with no group must not clear the one already recorded: %+v", r)
	}
}

// A missing record is the normal state, not a failure.
func TestReadMissingRecordIsNotAnError(t *testing.T) {
	_, manifest := manifestIn(t)
	r, ok, err := Read(Path(manifest))
	if err != nil || ok || len(r.Mounts) != 0 {
		t.Errorf("Read of a missing record = %+v ok=%v err=%v", r, ok, err)
	}
}

// The gate. A record is committed, so it crosses machines and arrives in
// clones jit did not write — every one of these must refuse rather than
// resolve to something outside the project.
func TestResolveRefusesAnythingLeavingTheProject(t *testing.T) {
	root := t.TempDir()
	for _, bad := range []string{
		"",
		"/etc/passwd",
		"../outside/.env",
		"a/../../outside/.env",
		"..",
	} {
		if got, err := Resolve(root, bad); err == nil {
			t.Errorf("Resolve(%q) = %q, want a refusal", bad, got)
		}
	}
	if got, err := Resolve(root, ".env"); err != nil || got != filepath.Join(root, ".env") {
		t.Errorf("Resolve(.env) = %q, %v", got, err)
	}
	// Nested is fine; it is still inside.
	if _, err := Resolve(root, "sub/.env"); err != nil {
		t.Errorf("Resolve(sub/.env): %v", err)
	}
}

// A symlink at the mount path is refused even though it resolves inside the
// project: the 2026-07 self-review's finding #2 was a restore that followed
// one, and a mount path is a serve destination.
func TestResolveRefusesASymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "real")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, ".env")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := Resolve(root, ".env"); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Errorf("err = %v, want a symlink refusal", err)
	}
}

// A mount outside its own manifest's project cannot be described by a
// relative record, and must not be written as a `../..` escape hatch.
func TestAddRefusesAMountOutsideTheProject(t *testing.T) {
	_, manifest := manifestIn(t)
	outside := filepath.Join(t.TempDir(), ".env")
	if err := Add(manifest, outside, ""); err == nil {
		t.Error("expected a refusal for a mount outside the project")
	}
	if _, err := os.Stat(Path(manifest)); !os.IsNotExist(err) {
		t.Error("a refused Add must write no record")
	}
}
