// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package wrap

import (
	"os"
	"strings"
	"testing"
)

func TestUndoRemovesEverythingAndReportsVaultPaths(t *testing.T) {
	home := t.TempDir()
	res := addGH(t, home)

	undo, err := Undo(home, "gh")
	if err != nil {
		t.Fatalf("Undo: %v", err)
	}
	if !undo.RemovedShim || !undo.RemovedProfile {
		t.Errorf("Undo = %+v, want shim and profile both removed", undo)
	}
	if undo.Remaining != 0 {
		t.Errorf("Remaining = %d, want 0", undo.Remaining)
	}
	if strings.Join(undo.VaultPaths, ",") != "wrap-gh/GH_HOST,wrap-gh/GH_TOKEN" {
		t.Errorf("VaultPaths = %v, want the profile's two paths sorted", undo.VaultPaths)
	}
	if _, err := os.Lstat(res.ShimPath); !os.IsNotExist(err) {
		t.Errorf("shim still present after undo: %v", err)
	}
	if _, err := os.Stat(res.ProfilePath); !os.IsNotExist(err) {
		t.Errorf("profile still present after undo: %v", err)
	}
	m, err := LoadManifest(home)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Tools["gh"]; ok {
		t.Error("manifest entry survived undo")
	}
}

func TestUndoUnknownToolErrors(t *testing.T) {
	if _, err := Undo(t.TempDir(), "gh"); err == nil {
		t.Fatal("expected an error for a tool that isn't wrap-managed")
	}
}

func TestUndoToleratesHalfInstalledWrap(t *testing.T) {
	home := t.TempDir()
	res := addGH(t, home)
	if err := os.Remove(res.ShimPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(res.ProfilePath); err != nil {
		t.Fatal(err)
	}

	undo, err := Undo(home, "gh")
	if err != nil {
		t.Fatalf("Undo of a half-installed wrap: %v", err)
	}
	if undo.RemovedShim || undo.RemovedProfile {
		t.Errorf("Undo = %+v, want nothing-to-remove reported honestly", undo)
	}
	m, _ := LoadManifest(home)
	if len(m.Tools) != 0 {
		t.Error("manifest entry survived undo")
	}
}
