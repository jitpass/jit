// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/mount"
)

// TestReferencesForPathsAndRmWarning pins the `jit vault rm` advisory: a
// path wired to a profile is named before the confirmation, a mount served
// from that profile attaches to the SAME reference (never a duplicate row),
// the remedy routes to `jit migrate remove` for the mounted file, and an
// unreferenced path stays silent. Also the lenient contract: an unloadable
// profile is skipped, never an error, because a warning must not block rm.
func TestReferencesForPathsAndRmWarning(t *testing.T) {
	home := withFixtureHome(t)
	cwd := t.TempDir()
	root := t.TempDir()

	// A project-local profile wiring one of the doomed paths.
	pdir := filepath.Join(cwd, ".jit", "profiles")
	if err := os.MkdirAll(pdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pdir, "svc.yaml"),
		[]byte("API_KEY: svc/API_KEY\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A global profile that a registered mount serves.
	gdir := filepath.Join(home, ".jit", "profiles")
	if err := os.MkdirAll(gdir, 0o755); err != nil {
		t.Fatal(err)
	}
	mountProfile := filepath.Join(gdir, "mcp-caido-2.yaml")
	if err := os.WriteFile(mountProfile,
		[]byte("CAIDO_URL: mcp-caido-2/CAIDO_URL\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mount.AddMount(mount.RegistryPath(root), mount.Entry{
		MountPath:   "/x/ws/.mcp.json",
		ProfilePath: mountProfile,
	}); err != nil {
		t.Fatal(err)
	}
	// An unparseable profile must be skipped, not fatal.
	if err := os.WriteFile(filepath.Join(pdir, "broken.yaml"),
		[]byte(":\tnot yaml"), 0o600); err != nil {
		t.Fatal(err)
	}

	refs := referencesForPaths(root, cwd,
		[]string{"svc/API_KEY", "mcp-caido-2/CAIDO_URL", "unref/KEY"})

	if got := refs["svc/API_KEY"]; len(got) != 1 || got[0].ProfileName != "svc" || got[0].MountPath != "" {
		t.Errorf("svc/API_KEY refs = %+v, want one profile ref named svc with no mount", got)
	}
	got := refs["mcp-caido-2/CAIDO_URL"]
	if len(got) != 1 {
		t.Fatalf("mcp-caido-2/CAIDO_URL refs = %+v, want exactly one (mount must attach, not duplicate)", got)
	}
	if got[0].ProfileName != "mcp-caido-2" || got[0].MountPath != "/x/ws/.mcp.json" {
		t.Errorf("mount-served ref = %+v, want profile mcp-caido-2 with its mount path", got[0])
	}
	if _, ok := refs["unref/KEY"]; ok {
		t.Errorf("unreferenced path must not appear, got %+v", refs["unref/KEY"])
	}

	var buf bytes.Buffer
	printRmReferenceWarnings(&buf, refs)
	out := buf.String()
	for _, want := range []string{
		"svc/API_KEY is wired to profile",
		"mcp-caido-2/CAIDO_URL is wired to profile",
		"served by the mount at /x/ws/.mcp.json",
		"jit migrate remove /x/ws/.mcp.json",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rm warning missing %q, got:\n%s", want, out)
		}
	}
	if strings.Contains(out, "unref/KEY") {
		t.Errorf("rm warning must not mention unreferenced paths, got:\n%s", out)
	}

	// No references at all -> total silence, the pre-existing rm experience.
	buf.Reset()
	printRmReferenceWarnings(&buf, map[string][]secretReference{})
	if buf.Len() != 0 {
		t.Errorf("no references must print nothing, got:\n%s", buf.String())
	}
}
