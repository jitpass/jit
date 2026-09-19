// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/projectrecord"
)

// migratedProject builds what `jit migrate` leaves behind for one .env:
// vaulted secret, manifest, FIFO, registry entry, and the project's own
// record.
func migratedProject(t *testing.T, home, dir, name string) (mountPath, manifest string) {
	t.Helper()
	manifest = filepath.Join(dir, ".jit", "profiles", name+".yaml")
	if err := os.MkdirAll(filepath.Dir(manifest), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte("TOKEN: "+name+"/TOKEN\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mountPath = filepath.Join(dir, ".env")
	if err := mount.CreateFIFO(mountPath); err != nil {
		t.Fatal(err)
	}
	registerFixtureMount(t, home, mountPath, manifest)
	if err := projectrecord.Add(manifest, mountPath, "grp-"+name); err != nil {
		t.Fatal(err)
	}
	plantVaultSecret(t, home, name+"/TOKEN")
	return mountPath, manifest
}

func findingsOfKind(t *testing.T, kind checkKind) []checkFinding {
	t.Helper()
	outcome, err := gatherDoctorOutcome(nil, "", false)
	if err != nil {
		t.Fatal(err)
	}
	var out []checkFinding
	for _, f := range outcome.Findings {
		if f.Kind == kind {
			out = append(out, f)
		}
	}
	return out
}

func execMountRepair(t *testing.T, dir string, relocate bool) (string, error) {
	t.Helper()
	mountRelocateYes, mountRegisterYes = true, true
	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	err := runMountRepair(cmd, dir, relocate)
	return buf.String(), err
}

// Rename and move are the same event to jit — a recorded path that no longer
// resolves — and both are repaired by the project's own record.
func TestMountRelocateAfterARenameAndAMove(t *testing.T) {
	for _, tc := range []struct{ name, to string }{
		{"rename", "hibob-api"},
		{"move", filepath.Join("elsewhere", "hibob")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := withFixtureHome(t)
			withFixtureCwd(t)
			old := filepath.Join(home, "scripts", "hibob")
			migratedProject(t, home, old, "hibob")

			moved := filepath.Join(home, tc.to)
			if err := os.MkdirAll(filepath.Dir(moved), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(old, moved); err != nil {
				t.Fatal(err)
			}

			found := findingsOfKind(t, kindMountMoved)
			if len(found) != 1 {
				t.Fatalf("want one [mount: moved], got %+v", found)
			}
			if !strings.Contains(found[0].Detail, "moved to") {
				t.Errorf("detail = %q", found[0].Detail)
			}
			// It supersedes the stale row: one event, one finding.
			if stale := findingsOfKind(t, kindMountStale); len(stale) != 0 {
				t.Errorf("the stale row must be superseded, got %+v", stale)
			}

			out, err := execMountRepair(t, moved, true)
			if err != nil {
				t.Fatalf("relocate: %v\n%s", err, out)
			}
			entries, _ := mount.LoadRegistry(mount.RegistryPath(filepath.Join(home, "Library", "Application Support", "jitpass")))
			if len(entries) != 1 || entries[0].MountPath != filepath.Join(moved, ".env") {
				t.Fatalf("registry = %+v, want the new path only", entries)
			}
			if len(findingsOfKind(t, kindMountMoved)) != 0 {
				t.Error("the finding must clear once relocated")
			}
		})
	}
}

// The duplicate: the copy brings the FIFO and never the registration, so
// reading it blocks forever. Doctor said nothing about this at all before.
func TestDuplicatedProjectIsReportedAndRegisterable(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	orig := filepath.Join(home, "scripts", "hibob")
	migratedProject(t, home, orig, "hibob")

	dup := filepath.Join(home, "scripts", "hibob2")
	if err := os.MkdirAll(filepath.Join(dup, ".jit", "profiles"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		filepath.Join(".jit", "profiles", "hibob.yaml"),
		filepath.Join(".jit", "profiles", "hibob.mount"),
	} {
		data, rerr := os.ReadFile(filepath.Join(orig, name))
		if rerr != nil {
			t.Fatal(rerr)
		}
		if werr := os.WriteFile(filepath.Join(dup, name), data, 0o600); werr != nil {
			t.Fatal(werr)
		}
	}
	if err := mount.CreateFIFO(filepath.Join(dup, ".env")); err != nil {
		t.Fatal(err)
	}

	found := findingsOfKind(t, kindMountUnregistered)
	if len(found) != 1 || found[0].Path != filepath.Join(dup, ".env") {
		t.Fatalf("want one unregistered mount at the copy, got %+v", found)
	}
	if !strings.Contains(found[0].Detail, "blocks forever") {
		t.Errorf("the detail must say what actually happens: %q", found[0].Detail)
	}
	// The original keeps working and is never reported.
	if len(findingsOfKind(t, kindMountMoved)) != 0 {
		t.Error("a copy is not a move: the original is still where it was")
	}

	out, err := execMountRepair(t, dup, false)
	if err != nil {
		t.Fatalf("register: %v\n%s", err, out)
	}
	entries, _ := mount.LoadRegistry(mount.RegistryPath(filepath.Join(home, "Library", "Application Support", "jitpass")))
	if len(entries) != 2 {
		t.Fatalf("both projects must be served, got %+v", entries)
	}
	if len(findingsOfKind(t, kindMountUnregistered)) != 0 {
		t.Error("the finding must clear once registered")
	}
}

// relocate must never steal a mount from a project that is still there.
func TestMountRelocateRefusesToStealALiveMount(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	orig := filepath.Join(home, "scripts", "hibob")
	migratedProject(t, home, orig, "hibob")

	// A second project with the same profile name, its own record, and no
	// dead registration anywhere.
	other := filepath.Join(home, "other", "hibob")
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(other, ".jit", "profiles", "hibob.yaml")
	if err := os.MkdirAll(filepath.Dir(manifest), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte("TOKEN: hibob/TOKEN\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mount.CreateFIFO(filepath.Join(other, ".env")); err != nil {
		t.Fatal(err)
	}
	if err := projectrecord.Add(manifest, filepath.Join(other, ".env"), "grp-hibob"); err != nil {
		t.Fatal(err)
	}

	out, err := execMountRepair(t, other, true)
	if err != nil {
		t.Fatalf("relocate: %v\n%s", err, out)
	}
	if !strings.Contains(out, "no dead registration") {
		t.Errorf("expected a refusal to re-point a live mount, got:\n%s", out)
	}
	entries, _ := mount.LoadRegistry(mount.RegistryPath(filepath.Join(home, "Library", "Application Support", "jitpass")))
	if len(entries) != 1 || entries[0].MountPath != filepath.Join(orig, ".env") {
		t.Errorf("the live project's registration must be untouched: %+v", entries)
	}
}

// A record naming a file that is not there registers nothing: jit creates no
// FIFO on the strength of a file a repo carried in.
func TestMountRegisterCreatesNothing(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	dir := filepath.Join(home, "scripts", "ghost")
	manifest := filepath.Join(dir, ".jit", "profiles", "ghost.yaml")
	if err := os.MkdirAll(filepath.Dir(manifest), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte("TOKEN: ghost/TOKEN\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := projectrecord.Add(manifest, filepath.Join(dir, ".env"), ""); err != nil {
		t.Fatal(err)
	}

	out, err := execMountRepair(t, dir, false)
	if err != nil {
		t.Fatalf("register: %v\n%s", err, out)
	}
	if !strings.Contains(out, "none of them is there") {
		t.Errorf("expected nothing to do, got:\n%s", out)
	}
	if _, serr := os.Lstat(filepath.Join(dir, ".env")); !os.IsNotExist(serr) {
		t.Error("register must never create the file")
	}
	if len(findingsOfKind(t, kindMountUnregistered)) != 0 {
		t.Error("a record naming a file that is not there must report nothing")
	}
}
