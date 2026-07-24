// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package mount

import (
	"path/filepath"
	"testing"
)

func TestLoadRegistryMissingFile(t *testing.T) {
	entries, err := LoadRegistry(RegistryPath(t.TempDir()))
	if err != nil {
		t.Fatalf("LoadRegistry on a missing registry: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("entries = %v, want empty", entries)
	}
}

func TestAddMountAndLoad(t *testing.T) {
	path := RegistryPath(t.TempDir())
	e1 := Entry{MountPath: "/project/.env", ProfilePath: "/project/.jit/profiles/root.yaml"}
	e2 := Entry{MountPath: "/project/services/api/.env", ProfilePath: "/project/.jit/profiles/services-api.yaml"}

	if err := AddMount(path, e1); err != nil {
		t.Fatalf("AddMount e1: %v", err)
	}
	if err := AddMount(path, e2); err != nil {
		t.Fatalf("AddMount e2: %v", err)
	}

	entries, err := LoadRegistry(path)
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(entries), entries)
	}
}

func TestAddMountReplacesExistingEntryForSamePath(t *testing.T) {
	path := RegistryPath(t.TempDir())
	first := Entry{MountPath: "/project/.env", ProfilePath: "/project/.jit/profiles/root.yaml"}
	updated := Entry{MountPath: "/project/.env", ProfilePath: "/project/.jit/profiles/root-v2.yaml"}

	if err := AddMount(path, first); err != nil {
		t.Fatalf("AddMount first: %v", err)
	}
	if err := AddMount(path, updated); err != nil {
		t.Fatalf("AddMount updated: %v", err)
	}

	entries, err := LoadRegistry(path)
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want exactly 1 (replaced, not duplicated): %+v", len(entries), entries)
	}
	if entries[0].ProfilePath != "/project/.jit/profiles/root-v2.yaml" {
		t.Errorf("ProfilePath = %q, want the updated value", entries[0].ProfilePath)
	}
}

func TestFindMount(t *testing.T) {
	path := RegistryPath(t.TempDir())
	e1 := Entry{MountPath: "/project/.env", ProfilePath: "/project/.jit/profiles/root.yaml"}
	if err := AddMount(path, e1); err != nil {
		t.Fatalf("AddMount: %v", err)
	}

	found, ok, err := FindMount(path, "/project/.env")
	if err != nil {
		t.Fatalf("FindMount: %v", err)
	}
	if !ok {
		t.Fatal("FindMount ok = false, want true")
	}
	if found != e1 {
		t.Errorf("FindMount = %+v, want %+v", found, e1)
	}
}

func TestFindMountNotFound(t *testing.T) {
	path := RegistryPath(t.TempDir())
	_, ok, err := FindMount(path, "/nope")
	if err != nil {
		t.Fatalf("FindMount: %v", err)
	}
	if ok {
		t.Error("FindMount ok = true for a path never registered, want false")
	}
}

func TestRemoveMount(t *testing.T) {
	path := RegistryPath(t.TempDir())
	e1 := Entry{MountPath: "/project/.env", ProfilePath: "/project/.jit/profiles/root.yaml"}
	e2 := Entry{MountPath: "/project/services/api/.env", ProfilePath: "/project/.jit/profiles/services-api.yaml"}
	if err := AddMount(path, e1); err != nil {
		t.Fatalf("AddMount e1: %v", err)
	}
	if err := AddMount(path, e2); err != nil {
		t.Fatalf("AddMount e2: %v", err)
	}

	removed, err := RemoveMount(path, e1.MountPath)
	if err != nil {
		t.Fatalf("RemoveMount: %v", err)
	}
	if !removed {
		t.Fatal("RemoveMount removed = false, want true")
	}

	entries, err := LoadRegistry(path)
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	if len(entries) != 1 || entries[0].MountPath != e2.MountPath {
		t.Errorf("entries = %+v, want only e2 remaining", entries)
	}
}

func TestRemoveMountNotFound(t *testing.T) {
	path := RegistryPath(t.TempDir())
	removed, err := RemoveMount(path, "/nope")
	if err != nil {
		t.Fatalf("RemoveMount: %v", err)
	}
	if removed {
		t.Error("RemoveMount removed = true for a path never registered, want false")
	}
}

func TestRegistryPath(t *testing.T) {
	root := "/x/y"
	want := filepath.Join(root, "mounts.yaml")
	if got := RegistryPath(root); got != want {
		t.Errorf("RegistryPath(%q) = %q, want %q", root, got, want)
	}
}
