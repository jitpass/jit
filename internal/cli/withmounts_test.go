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
}

// TestProjectTemplateMountsExcludesGlobals is the regression guard for the
// invariant that a machine-global file-delivered mount is NEVER granted by a
// run's cwd walking into the directory it lives in — only by an explicit
// --with. The gcp ADC and sops keys live in $HOME SUBDIRECTORIES (not $HOME
// itself), so a naive "parent == $HOME" exclusion would leak them: a run
// launched under ~/.config/gcloud would grant the global ADC with no
// disclosed challenge. projectTemplateMounts must exclude them by known path.
func TestProjectTemplateMountsExcludesGlobals(t *testing.T) {
	home := withFixtureHome(t)
	root, err := vaultRootDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	reg := mount.RegistryPath(root)

	// A machine-global mount in a $HOME subdirectory (the gcp ADC), and a
	// genuine project-local template mount (a repo .npmrc).
	gcpPath := migrate.GCPADCPath(home) // ~/.config/gcloud/application_default_credentials.json
	projectDir := filepath.Join(home, "code", "myapp")
	projectNpmrc := filepath.Join(projectDir, ".npmrc")
	for _, e := range []mount.Entry{
		{MountPath: gcpPath, ProfilePath: "p", TemplatePath: "t"},
		{MountPath: projectNpmrc, ProfilePath: "p", TemplatePath: "t"},
	} {
		if err := mount.AddMount(reg, e); err != nil {
			t.Fatal(err)
		}
	}

	// A run launched inside ~/.config/gcloud must NOT pick up the global ADC.
	if got := projectTemplateMounts(filepath.Dir(gcpPath)); len(got) != 0 {
		t.Errorf("projectTemplateMounts under the gcloud dir leaked global mounts: %v", got)
	}

	// A run launched inside the project dir DOES pick up its own .npmrc.
	got := projectTemplateMounts(projectDir)
	if len(got) != 1 || got[0] != projectNpmrc {
		t.Errorf("projectTemplateMounts(%s) = %v, want [%s]", projectDir, got, projectNpmrc)
	}
}

// TestGlobalMountReminders covers the Stage 4 discoverability guidance: a
// migrated global file-delivered mount surfaces its `jit run --with` usage
// reminder, and a plain project mount surfaces nothing.
func TestGlobalMountReminders(t *testing.T) {
	home := withFixtureHome(t)
	root, err := vaultRootDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	reg := mount.RegistryPath(root)

	// No global mounts yet -> the reminder block is silent.
	var buf bytes.Buffer
	printGlobalMountReminders(&buf)
	if buf.Len() != 0 {
		t.Errorf("reminders printed with no global mounts:\n%s", buf.String())
	}

	// Register the gcp ADC and a plain project .env (which must NOT get a
	// reminder — it isn't a global file-delivered mount).
	gcpPath := migrate.GCPADCPath(home)
	if err := mount.AddMount(reg, mount.Entry{MountPath: gcpPath, ProfilePath: "p", TemplatePath: "t"}); err != nil {
		t.Fatal(err)
	}
	if err := mount.AddMount(reg, mount.Entry{MountPath: filepath.Join(home, "proj", ".env"), ProfilePath: "p"}); err != nil {
		t.Fatal(err)
	}

	buf.Reset()
	printGlobalMountReminders(&buf)
	out := buf.String()
	if !strings.Contains(out, "jit run --with gcp") {
		t.Errorf("gcp reminder missing:\n%s", out)
	}
	if strings.Contains(out, ".env") {
		t.Errorf("a plain project mount leaked into the global reminders:\n%s", out)
	}

	// The kind/tool mapping resolves for each known global path and rejects
	// an unknown one.
	if g, ok := globalMountGuidanceForPath(home, gcpPath); !ok || g.name != "gcp" {
		t.Errorf("globalMountGuidanceForPath(gcp) = %+v, %v", g, ok)
	}
	if _, ok := globalMountGuidanceForPath(home, "/nope/creds"); ok {
		t.Error("globalMountGuidanceForPath matched an unknown path")
	}
}
