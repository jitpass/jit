// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
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

// A plan that keeps one profile and deletes another lists the kept one in
// its own section, with the owner that keeps it, and still takes the full
// gate: the no-Touch-ID line belongs only to an owner-list-only plan.
func TestPrintProjectRemovalPlanListsKeptProfile(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)
	other := filepath.Join(home, "projB", ".mcp.json")
	writeLauncherConfig(t, other)
	ownConfig := filepath.Join(cwd, ".mcp.json")
	ownedProfileFixture(t, home, cwd, ownConfig, other)
	writeFixtureProfile(t, cwd, "local", "API_KEY: local/API_KEY\n")

	plan := removalPlanFor(t, home, cwd)
	if plan.ownerListOnly() {
		t.Fatalf("ownerListOnly() = true for a plan that deletes a profile: %+v", plan)
	}
	var buf bytes.Buffer
	printProjectRemovalPlan(&buf, home, plan)
	out := buf.String()
	t.Logf("rendered plan:\n%s", out)

	for _, want := range []string{
		"[Profiles + their vault secrets deleted] 1\n",
		"[Profiles kept, still used outside this project] 1\n" +
			"  " + glyphBullet + " mcp-shared · still owned by ~/projB/.mcp.json\n" +
			"  this project comes off their owner list; nothing else changes\n\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("plan missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "no Touch ID needed") {
		t.Errorf("plan that deletes a profile claims no Touch ID:\n%s", out)
	}
	// The kept section sits right after the kept vault secrets.
	if strings.Index(out, "[Vault secrets KEPT") > strings.Index(out, "[Profiles kept") {
		t.Errorf("kept profiles should follow the kept vault secrets:\n%s", out)
	}
}

// Kept because a config outside the project launches it without owning it:
// the row names that launcher.
func TestPrintProjectRemovalPlanNamesOutsideLauncher(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)
	writeLauncherConfig(t, filepath.Join(home, "copy", ".mcp.json"))
	ownConfig := filepath.Join(cwd, ".mcp.json")
	ownedProfileFixture(t, home, cwd, ownConfig)

	var buf bytes.Buffer
	printProjectRemovalPlan(&buf, home, removalPlanFor(t, home, cwd))
	if want := "  " + glyphBullet + " mcp-shared · launched by ~/copy/.mcp.json\n"; !strings.Contains(buf.String(), want) {
		t.Errorf("plan missing %q:\n%s", want, buf.String())
	}
}

// ownerListOnlyFixture is a project whose only jit leftover is its line on a
// kept profile's owner list: its config was already restored to plaintext
// (`jit migrate undo`), and another project still owns the profile.
func ownerListOnlyFixture(t *testing.T) (home, cwd, sidecar, other string) {
	t.Helper()
	home = withFixtureHome(t)
	cwd = withFixtureCwd(t)
	other = filepath.Join(home, "projB", ".mcp.json")
	writeLauncherConfig(t, other)
	ownConfig := filepath.Join(cwd, ".mcp.json")
	ownedProfileFixture(t, home, cwd, ownConfig, other)
	if err := os.WriteFile(ownConfig, []byte(`{"mcpServers":{"shared":{"command":"node","args":["s.js"],"env":{"TOKEN":"plain"}}}}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	sidecar = filepath.Join(home, ".jit", "profiles", "mcp-shared.source")
	return home, cwd, sidecar, other
}

// failPresence swaps remove's fresh-auth gate for one that records the call
// and refuses, so a test reaching it neither hangs on the real keychain nor
// mutates anything past it.
func failPresence(t *testing.T) *bool {
	t.Helper()
	called := false
	orig := removeOpenVault
	removeOpenVault = func(string) (*vault.Vault, error) {
		called = true
		return nil, fmt.Errorf("test: fresh user presence requested")
	}
	t.Cleanup(func() { removeOpenVault = orig })
	return &called
}

func readSidecar(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	return string(data)
}

// A project whose only leftover is its owner-list line used to report "No
// jit artifacts found" and leave the line. It now shows the kept profile,
// confirms, and rewrites the sidecar with no vault opened and no Touch ID.
func TestMigrateRemoveOwnerListOnly(t *testing.T) {
	home, cwd, sidecar, other := ownerListOnlyFixture(t)
	called := failPresence(t)

	plan := removalPlanFor(t, home, cwd)
	if !plan.ownerListOnly() {
		t.Fatalf("ownerListOnly() = false: %+v", plan)
	}

	out, err := execMigrateRemove(t, "y\n", cwd)
	if err != nil {
		t.Fatalf("jit migrate remove: %v\n%s", err, out)
	}
	t.Logf("output:\n%s", out)
	if *called {
		t.Error("owner-list-only removal asked for fresh user presence")
	}
	if strings.Contains(out, "No jit artifacts found") {
		t.Errorf("owner-list-only project reported as empty:\n%s", out)
	}
	want := "[Profiles kept, still used outside this project] 1\n" +
		"  " + glyphBullet + " mcp-shared · still owned by ~/projB/.mcp.json\n" +
		"  this project comes off their owner list; nothing else changes\n" +
		"Nothing to decrypt or restore; no Touch ID needed.\n"
	if !strings.Contains(out, want) {
		t.Errorf("output missing %q:\n%s", want, out)
	}
	if got := readSidecar(t, sidecar); got != other+"\n" {
		t.Errorf("sidecar = %q, want only %q left", got, other)
	}
}

// Declining changes nothing, and --dry-run (refused on remove) writes
// nothing either.
func TestMigrateRemoveOwnerListOnlyDeclineAndDryRun(t *testing.T) {
	_, cwd, sidecar, _ := ownerListOnlyFixture(t)
	called := failPresence(t)
	before := readSidecar(t, sidecar)

	out, err := execMigrateRemove(t, "", cwd)
	if err != nil {
		t.Fatalf("jit migrate remove: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Aborted. Nothing was changed.") {
		t.Errorf("declined run did not abort:\n%s", out)
	}
	if got := readSidecar(t, sidecar); got != before {
		t.Errorf("declined run rewrote the sidecar: %q, want %q", got, before)
	}

	if out, err := execMigrateRemove(t, "y\n", "--dry-run", cwd); err == nil {
		t.Errorf("--dry-run: expected the refusal, got success:\n%s", out)
	}
	migrateDryRun = false
	if got := readSidecar(t, sidecar); got != before {
		t.Errorf("--dry-run rewrote the sidecar: %q, want %q", got, before)
	}
	if *called {
		t.Error("asked for fresh user presence")
	}
}

// A kept profile alongside real work (here the project's still-wrapped
// server to restore) keeps today's gate exactly: fresh user presence is
// required, and refusing it changes nothing.
func TestMigrateRemoveKeptProfileWithWorkKeepsGate(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)
	other := filepath.Join(home, "projB", ".mcp.json")
	writeLauncherConfig(t, other)
	ownConfig := filepath.Join(cwd, ".mcp.json")
	manifest, _ := ownedProfileFixture(t, home, cwd, ownConfig, other)
	called := failPresence(t)
	before := readSidecar(t, migrateSourceSidecar(manifest))

	out, err := execMigrateRemove(t, "y\n", cwd)
	if err == nil {
		t.Fatalf("expected the refused presence to fail the removal:\n%s", out)
	}
	if !*called {
		t.Error("a removal that restores a server skipped fresh user presence")
	}
	if strings.Contains(out, "no Touch ID needed") {
		t.Errorf("claims no Touch ID:\n%s", out)
	}
	if got := readSidecar(t, migrateSourceSidecar(manifest)); got != before {
		t.Errorf("sidecar rewritten before the gate: %q, want %q", got, before)
	}
}

func migrateSourceSidecar(manifest string) string {
	return strings.TrimSuffix(manifest, ".yaml") + ".source"
}

func TestMigrateRemoveHelpNamesKeptProfiles(t *testing.T) {
	long := strings.Join(strings.Fields(migrateRemoveCmd.Long), " ")
	if want := "A profile another config still owns or launches is kept; this project only comes off its owner list."; !strings.Contains(long, want) {
		t.Errorf("help missing %q", want)
	}
}
