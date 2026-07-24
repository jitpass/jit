// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/mount"
)

// TestUnmountUnknownPathListsRegisteredMounts: the not-found error must
// name what IS mounted — the old pointer sent people to `jit status`,
// which only reports a count, so a typo'd path dead-ended with no way to
// learn the right one (a real, reported miss: `jit unmount ./.` from
// inside the project directory).
func TestUnmountUnknownPathListsRegisteredMounts(t *testing.T) {
	withFixtureHome(t)
	root, err := vaultRootDir()
	if err != nil {
		t.Fatalf("vaultRootDir: %v", err)
	}
	if err := mount.AddMount(mount.RegistryPath(root), mount.Entry{MountPath: "/p/a/.env", ProfilePath: "/p/a/profile.yaml"}); err != nil {
		t.Fatalf("AddMount: %v", err)
	}
	if err := mount.AddMount(mount.RegistryPath(root), mount.Entry{MountPath: "/p/b/.npmrc", ProfilePath: "/p/b/profile.yaml"}); err != nil {
		t.Fatalf("AddMount: %v", err)
	}

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"unmount", "/p/nope/.env"})
	err = rootCmd.Execute()
	if err == nil {
		t.Fatal("expected an error for an unregistered path")
	}
	for _, want := range []string{"/p/a/.env", "/p/b/.npmrc"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("expected the error to list registered mount %s, got: %v", want, err)
		}
	}

	// And with nothing registered at all, say that plainly instead of an
	// empty list.
	withFixtureHome(t)
	rootCmd.SetArgs([]string{"unmount", "/p/nope/.env"})
	err = rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "nothing is currently mounted") {
		t.Errorf("expected the empty-registry phrasing, got: %v", err)
	}
}
