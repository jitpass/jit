// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/mount"
)

// execMigrateRemove drives `jit migrate remove` through rootCmd, mirroring
// execMigrate's flag-reset discipline. stdin defaults to EOF (a declined
// confirmation) unless the caller sets input.
func execMigrateRemove(t *testing.T, input string, args ...string) (output string, err error) {
	t.Helper()
	migrateRemoveYes = false
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetIn(strings.NewReader(input))
	rootCmd.SetArgs(append([]string{"migrate", "remove"}, args...))
	err = rootCmd.Execute()
	return buf.String(), err
}

// A project with no jit artifacts must say so and exit clean — and, per
// the plan-before-auth ordering, never reach openVaultFreshAuth (this test
// would hang on a Touch ID prompt if it did).
func TestMigrateRemoveNothingToRemove(t *testing.T) {
	withFixtureHome(t)
	cwd := withFixtureCwd(t)

	out, err := execMigrateRemove(t, "", cwd)
	if err != nil {
		t.Fatalf("jit migrate remove: %v\n%s", err, out)
	}
	if !strings.Contains(out, "No jit artifacts found in") {
		t.Errorf("expected the empty state, got:\n%s", out)
	}
}

// A bare `jit migrate remove` with no path must error, never fall back to
// silently acting on the current directory — the whole point of the
// path-required design on the most destructive command.
func TestMigrateRemoveRequiresPath(t *testing.T) {
	withFixtureHome(t)
	withFixtureCwd(t)
	if _, err := execMigrateRemove(t, ""); err == nil {
		t.Error("jit migrate remove with no path: expected an error, got nil")
	}
}

// Naming a FILE inside a project resolves up to the .jit/ project that owns
// it and plans the whole project's removal — so `jit migrate remove
// <proj>/.env` removes the project, not just the file.
func TestMigrateRemoveFileResolvesToOwningProject(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)

	profileDir := filepath.Join(cwd, ".jit", "profiles")
	if err := os.MkdirAll(profileDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(profileDir, "myapp.yaml"), []byte("API_KEY: myapp/API_KEY\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// A file nested below the project root: removal must resolve up to cwd.
	nested := filepath.Join(cwd, "src", "app", ".env")
	if err := os.MkdirAll(filepath.Dir(nested), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(nested, []byte("placeholder"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out, err := execMigrateRemove(t, "n\n", nested) // declined: never reaches auth
	if err != nil {
		t.Fatalf("jit migrate remove <file> (declined): %v\n%s", err, out)
	}
	if !strings.Contains(out, "Removing jit from "+displayPath(home, cwd)) {
		t.Errorf("expected the plan to target the owning project %s, got:\n%s", displayPath(home, cwd), out)
	}
}

// A file with no .jit/ project above it is a loud error, not a silent no-op.
func TestMigrateRemoveFileWithoutProjectFailsLoud(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	stray := filepath.Join(home, "loose", "notes.env")
	if err := os.MkdirAll(filepath.Dir(stray), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(stray, []byte("placeholder"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := execMigrateRemove(t, "", stray)
	if err == nil {
		t.Fatal("expected an error for a file with no jit project above it, got nil")
	}
	if !strings.Contains(err.Error(), "not inside a jit project") {
		t.Errorf("expected a no-project error, got: %v", err)
	}
}

// Declining the confirmation must abort before auth and before any
// mutation — the profile manifest, the registry entry, and the mount path
// all survive untouched.
func TestMigrateRemoveDeclinedTouchesNothing(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)

	profileDir := filepath.Join(cwd, ".jit", "profiles")
	if err := os.MkdirAll(profileDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	profilePath := filepath.Join(profileDir, "myapp.yaml")
	if err := os.WriteFile(profilePath, []byte("API_KEY: myapp/API_KEY\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	mountPath := filepath.Join(cwd, ".env")
	if err := os.WriteFile(mountPath, []byte("placeholder"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	vaultRoot := filepath.Join(home, "Library", "Application Support", "jitpass")
	if err := os.MkdirAll(vaultRoot, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := mount.AddMount(mount.RegistryPath(vaultRoot), mount.Entry{MountPath: mountPath, ProfilePath: profilePath}); err != nil {
		t.Fatalf("AddMount: %v", err)
	}

	out, err := execMigrateRemove(t, "n\n", cwd)
	if err != nil {
		t.Fatalf("jit migrate remove (declined): %v\n%s", err, out)
	}
	if !strings.Contains(out, "Aborted. Nothing was changed.") {
		t.Errorf("expected the abort message, got:\n%s", out)
	}
	// The plan itself must have been shown before the prompt.
	if !strings.Contains(out, "Removing jit from") || !strings.Contains(out, `"myapp"`) {
		t.Errorf("expected the removal plan (with the profile named) before the prompt, got:\n%s", out)
	}
	if _, statErr := os.Stat(profilePath); statErr != nil {
		t.Errorf("profile manifest touched on a declined run: %v", statErr)
	}
	entries, lerr := mount.LoadRegistry(mount.RegistryPath(vaultRoot))
	if lerr != nil || len(entries) != 1 {
		t.Errorf("registry touched on a declined run (entries %v, err %v)", entries, lerr)
	}
	if data, rerr := os.ReadFile(mountPath); rerr != nil || string(data) != "placeholder" { // #nosec G304 -- test-controlled path
		t.Errorf("mount path touched on a declined run (data %q, err %v)", data, rerr)
	}
}

// The shared-path guard: a vault path another profile still references —
// a global-store profile here, exactly what a pre-GAPS.md-#55 flat vault
// produces — must land in keptShared, never deletePaths.
func TestBuildProjectRemovalPlanKeepsSharedVaultPaths(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)

	projProfiles := filepath.Join(cwd, ".jit", "profiles")
	if err := os.MkdirAll(projProfiles, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projProfiles, "myapp.yaml"),
		[]byte("SHARED: root/SHARED\nMINE: myapp/MINE\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	globalProfiles := filepath.Join(home, ".jit", "profiles")
	if err := os.MkdirAll(globalProfiles, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(globalProfiles, "shell-zshrc.yaml"),
		[]byte("SHARED: root/SHARED\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	vaultRoot := filepath.Join(home, "Library", "Application Support", "jitpass")
	plan, err := buildProjectRemovalPlan(vaultRoot, cwd)
	if err != nil {
		t.Fatalf("buildProjectRemovalPlan: %v", err)
	}
	if len(plan.deletePaths) != 1 || plan.deletePaths[0] != "myapp/MINE" {
		t.Errorf("deletePaths = %v, want [myapp/MINE]", plan.deletePaths)
	}
	if len(plan.keptShared) != 1 || plan.keptShared[0] != "root/SHARED" {
		t.Errorf("keptShared = %v, want [root/SHARED], deleting it would break the global profile", plan.keptShared)
	}
}

func TestBuildProjectRemovalPlanClaimsOwnedMCPProfiles(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)

	globalProfiles := filepath.Join(home, ".jit", "profiles")
	if err := os.MkdirAll(globalProfiles, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	// An MCP profile owned by THIS project's own .mcp.json (per its .source
	// sidecar) — part of the project, deleted with it.
	ownedManifest := filepath.Join(globalProfiles, "mcp-mine.yaml")
	if err := os.WriteFile(ownedManifest, []byte("TOKEN: mcp-mine/TOKEN\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	ownedConfig := filepath.Join(cwd, ".mcp.json")
	if err := os.WriteFile(ownedConfig, []byte(`{"mcpServers":{"mine":{"command":"/usr/local/bin/jit","args":["run","--profile","mcp-mine","--","node","s.js"]}}}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(globalProfiles, "mcp-mine.source"), []byte(ownedConfig+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// An MCP profile owned by a config OUTSIDE this project — machine-level
	// from this project's point of view, never deleted, and its vault paths
	// count as shared.
	if err := os.WriteFile(filepath.Join(globalProfiles, "mcp-other.yaml"), []byte("TOKEN: mcp-other/TOKEN\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(globalProfiles, "mcp-other.source"), []byte(filepath.Join(home, "elsewhere", "mcp.json")+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	vaultRoot := filepath.Join(home, "Library", "Application Support", "jitpass")
	plan, err := buildProjectRemovalPlan(vaultRoot, cwd)
	if err != nil {
		t.Fatalf("buildProjectRemovalPlan: %v", err)
	}
	if len(plan.ownedGlobal) != 1 || plan.ownedGlobal[0].Name != "mcp-mine" {
		t.Fatalf("ownedGlobal = %+v, want just mcp-mine", plan.ownedGlobal)
	}
	if len(plan.deletePaths) != 1 || plan.deletePaths[0] != "mcp-mine/TOKEN" {
		t.Errorf("deletePaths = %v, want [mcp-mine/TOKEN], the foreign profile's secret must never be deleted", plan.deletePaths)
	}
	if plan.mcpRestores[ownedConfig]["mcp-mine"] != ownedManifest {
		t.Errorf("mcpRestores = %v, want the still-wrapped server slated for plaintext restore", plan.mcpRestores)
	}
}
