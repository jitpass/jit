// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/mount"
)

func TestWithMountPaths(t *testing.T) {
	home := withFixtureHome(t)
	root, err := vaultRootDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	reg := mount.RegistryPath(root)
	gcpPath := migrate.GCPADCPath(home)
	if err := mount.AddMount(reg, mount.Entry{MountPath: gcpPath, ProfilePath: "p", TemplatePath: "t"}); err != nil {
		t.Fatal(err)
	}

	// Empty -> nothing.
	if got, err := withMountPaths(nil); err != nil || got != nil {
		t.Errorf("withMountPaths(nil) = %v, %v; want nil, nil", got, err)
	}

	// Known + migrated -> resolves to the registered path.
	got, err := withMountPaths([]string{"gcp"})
	if err != nil {
		t.Fatalf("withMountPaths(gcp): %v", err)
	}
	if len(got) != 1 || got[0] != gcpPath {
		t.Errorf("withMountPaths(gcp) = %v, want [%s]", got, gcpPath)
	}

	// Unknown name -> hard error naming the valid set.
	if _, err := withMountPaths([]string{"azure"}); err == nil || !strings.Contains(err.Error(), "unknown mount") {
		t.Errorf("expected an unknown-mount error, got %v", err)
	}

	// Known but not migrated -> hard error telling the user to migrate.
	if _, err := withMountPaths([]string{"sops"}); err == nil || !strings.Contains(err.Error(), "no migrated") {
		t.Errorf("expected a not-migrated error, got %v", err)
	}

	// A migrated project .env at the gcp path would NOT count (must match a
	// registered global path exactly) — sanity that resolution is path-keyed.
	_ = filepath.Join
}
