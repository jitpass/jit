// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/vault"
)

// ownedProfileFixture writes a global MCP profile "mcp-shared" whose one
// secret was born in the removal root's config (so the origin sweep reaches
// for it), owned by the given configs, and returns its manifest path. The
// removal root's own config launches it through jit's wrapper.
func ownedProfileFixture(t *testing.T, home, cwd string, owners ...string) (manifest, ownConfig string) {
	t.Helper()
	globalProfiles := filepath.Join(home, ".jit", "profiles")
	if err := os.MkdirAll(globalProfiles, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	manifest = filepath.Join(globalProfiles, "mcp-shared.yaml")
	if err := os.WriteFile(manifest, []byte("TOKEN: mcp-shared/TOKEN\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	ownConfig = filepath.Join(cwd, ".mcp.json")
	writeLauncherConfig(t, ownConfig)
	if err := os.WriteFile(filepath.Join(globalProfiles, "mcp-shared.source"), []byte(strings.Join(owners, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	writeVaultEnc(t, home, "mcp-shared/TOKEN",
		fmt.Sprintf(`{"version":3,"recipients":{"test":"00"},"payload":"00","origin":%q}`, filepath.ToSlash(ownConfig)))
	return manifest, ownConfig
}

// writeLauncherConfig writes an MCP config whose one server launches
// mcp-shared through jit's wrapper.
func writeLauncherConfig(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(`{"mcpServers":{"shared":{"command":"/usr/local/bin/jit","args":["run","--profile","mcp-shared","--","node","s.js"]}}}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func removalPlanFor(t *testing.T, home, cwd string) projectRemovalPlan {
	t.Helper()
	vaultRoot := filepath.Join(home, "Library", "Application Support", "jitpass")
	plan, err := buildProjectRemovalPlan(vaultRoot, home, cwd, &vault.Vault{Root: vaultRoot})
	if err != nil {
		t.Fatalf("buildProjectRemovalPlan: %v", err)
	}
	return plan
}

// assertKeptProfile checks that the plan keeps mcp-shared (and its secret)
// and leaves it owned by exactly wantOwners, while still restoring the
// removed project's own wrapped server to plaintext.
func assertKeptProfile(t *testing.T, plan projectRemovalPlan, manifest, ownConfig string, wantOwners []string) {
	t.Helper()
	if len(plan.ownedGlobal) != 0 {
		t.Errorf("ownedGlobal = %+v, want mcp-shared kept", plan.ownedGlobal)
	}
	for _, info := range plan.profileInfos {
		if info.Path == manifest {
			t.Errorf("mcp-shared listed for deletion in profileInfos: %+v", plan.profileInfos)
		}
	}
	for _, p := range plan.deletePaths {
		if p == "mcp-shared/TOKEN" {
			t.Errorf("deletePaths = %v: the kept profile's secret must stay", plan.deletePaths)
		}
	}
	if !reflect.DeepEqual(plan.keptShared, []string{"mcp-shared/TOKEN"}) {
		t.Errorf("keptShared = %v, want [mcp-shared/TOKEN]", plan.keptShared)
	}
	if len(plan.disowned) != 1 || plan.disowned[0].path != manifest || !reflect.DeepEqual(plan.disowned[0].owners, wantOwners) {
		t.Errorf("disowned = %+v, want [{%s %q}]", plan.disowned, manifest, wantOwners)
	}
	if plan.mcpRestores[ownConfig]["mcp-shared"] != manifest {
		t.Errorf("mcpRestores = %v, want this project's wrapped server restored to plaintext all the same", plan.mcpRestores)
	}
}

// Two projects own one profile (same values, one profile). Removing one takes
// only that project off the owner list: the other still launches the
// profile, so the profile and its secret stay. Deciding by the first owner
// alone deleted it whenever the removed project was listed first.
func TestBuildProjectRemovalPlanSharedOwnerKeepsProfile(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)
	other := filepath.Join(home, "projB", ".mcp.json")
	writeLauncherConfig(t, other)
	ownConfig := filepath.Join(cwd, ".mcp.json")
	manifest, _ := ownedProfileFixture(t, home, cwd, ownConfig, other)

	assertKeptProfile(t, removalPlanFor(t, home, cwd), manifest, ownConfig, []string{other})
}

// The only owner inside the removed project, nothing else launching it: the
// profile goes with the project, as it always did. An owner whose file is
// gone does not keep it alive.
func TestBuildProjectRemovalPlanSoleOwnerDeletesProfile(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)
	gone := filepath.Join(home, "deleted", ".mcp.json")
	ownConfig := filepath.Join(cwd, ".mcp.json")
	manifest, _ := ownedProfileFixture(t, home, cwd, ownConfig, gone)

	plan := removalPlanFor(t, home, cwd)
	if len(plan.ownedGlobal) != 1 || plan.ownedGlobal[0].Path != manifest {
		t.Fatalf("ownedGlobal = %+v, want mcp-shared deleted with the project", plan.ownedGlobal)
	}
	if len(plan.disowned) != 0 {
		t.Errorf("disowned = %+v, want none", plan.disowned)
	}
	if !reflect.DeepEqual(plan.deletePaths, []string{"mcp-shared/TOKEN"}) {
		t.Errorf("deletePaths = %v, want [mcp-shared/TOKEN]", plan.deletePaths)
	}
	if len(plan.keptShared) != 0 {
		t.Errorf("keptShared = %v, want none", plan.keptShared)
	}
}

// Owned only by the removed project, but launched by a config OUTSIDE it (a
// copy that never took ownership): the profile stays, unowned, because
// deleting it would stop that config's server from starting.
func TestBuildProjectRemovalPlanOutsideLauncherKeepsProfile(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)
	writeLauncherConfig(t, filepath.Join(home, "copy", ".mcp.json"))
	ownConfig := filepath.Join(cwd, ".mcp.json")
	manifest, _ := ownedProfileFixture(t, home, cwd, ownConfig)

	assertKeptProfile(t, removalPlanFor(t, home, cwd), manifest, ownConfig, nil)
}
