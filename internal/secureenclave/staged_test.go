// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package secureenclave

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestStagedWrapperWritesBesideTheRealFile(t *testing.T) {
	root := t.TempDir()
	if got, want := NewStaged(root).path, filepath.Join(root, SealedFile)+stagedSuffix; got != want {
		t.Fatalf("staged path %q, want %q", got, want)
	}
}

// Install to the staged path, verify through it, promote: the vault's real
// sealed file then opens to the same MEK, and the staged one is gone.
func TestStageVerifyPromote(t *testing.T) {
	root := t.TempDir()
	f := newFake(t)
	staged := newWrapper(root, testTag, f)
	staged.path += stagedSuffix
	mek := testMEK(t)
	if err := staged.Install(mek); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, SealedFile)); err == nil {
		t.Fatal("staging wrote the real sealed file: the vault would switch before verification")
	}
	if got, err := staged.FetchMEK("check"); err != nil || !bytes.Equal(got, mek) {
		t.Fatalf("verify through the staged file: %v", err)
	}
	if err := PromoteStaged(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(staged.path); err == nil {
		t.Fatal("the staged file survived promotion")
	}
	real := newWrapper(root, testTag, f)
	if got, err := real.FetchMEK("open"); err != nil || !bytes.Equal(got, mek) {
		t.Fatalf("the promoted file does not open to the MEK: %v", err)
	}
}

func TestRemoveStagedLeavesTheRealFileAndKey(t *testing.T) {
	root := t.TempDir()
	f := newFake(t)
	real := newWrapper(root, testTag, f)
	if err := real.Install(testMEK(t)); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(root, SealedFile) + stagedSuffix
	if err := os.WriteFile(staged, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveStaged(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(staged); err == nil {
		t.Fatal("the staged file survived")
	}
	if real.Presence() != Present || !f.exists {
		t.Fatal("RemoveStaged touched the real sealed file or the enclave key")
	}
	if err := RemoveStaged(root); err != nil {
		t.Fatalf("removing an absent staged file: %v", err)
	}
}
