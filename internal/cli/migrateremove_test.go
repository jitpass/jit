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

	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/vault"
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

// A file with no .jit/ project above it and no migration footprint is a loose
// target that finds nothing — it reports "nothing to remove" and exits 0,
// exactly as a project directory with no jit artifacts does. It must never
// resolve up to a project (there is none) or touch the home global store.
func TestMigrateRemoveStrayFileFindsNothing(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	stray := filepath.Join(home, "loose", "notes.env")
	if err := os.MkdirAll(filepath.Dir(stray), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(stray, []byte("placeholder"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	out, err := execMigrateRemove(t, "", stray)
	if err != nil {
		t.Fatalf("jit migrate remove <stray file>: %v\n%s", err, out)
	}
	if !strings.Contains(out, "No jit artifacts found for "+displayPath(home, stray)) {
		t.Errorf("expected a nothing-to-remove report for a stray file, got:\n%s", out)
	}
}

// Naming the home directory as a directory is refused outright: its .jit/ is
// the global profile store, not a project, so "remove that project" would
// propose wiping every machine-level and loose-file migration at once.
func TestMigrateRemoveHomeDirectoryRefused(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	if err := os.MkdirAll(filepath.Join(home, ".jit", "profiles"), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	_, err := execMigrateRemove(t, "", home)
	if err == nil {
		t.Fatal("expected `jit migrate remove ~` to be refused, got nil")
	}
	if !strings.Contains(err.Error(), "home directory") {
		t.Errorf("expected a home-directory refusal, got: %v", err)
	}
}

// A loose secret migrated at home level (a bare token.txt, no project of its
// own) is removed at FILE granularity: the plan targets just that file, its
// dedicated global-store profile, and its origin-matched secret — never the
// whole home store the file happens to sit above, and never an unrelated
// global profile. This is the footgun fix: `remove token.txt` used to resolve
// up to ~/.jit and propose deleting every global migration.
func TestMigrateRemoveLooseFileScopesToJustThatFile(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)

	// The loose file itself, currently a jit pointer file.
	looseFile := filepath.Join(home, "token.txt")
	pointer := "# jit pointer file, no secret values here, only vault paths.\n" +
		"JSON_WEB_TOKEN_JWT=jit://vault/token/JSON_WEB_TOKEN_JWT\n"
	if err := os.WriteFile(looseFile, []byte(pointer), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Its dedicated profile in the global store, plus an UNRELATED global
	// profile that must be left completely alone.
	globalProfiles := filepath.Join(home, ".jit", "profiles")
	if err := os.MkdirAll(globalProfiles, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(globalProfiles, "token.yaml"),
		[]byte("JSON_WEB_TOKEN_JWT: token/JSON_WEB_TOKEN_JWT\n"), 0o600); err != nil {
		t.Fatalf("WriteFile token.yaml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(globalProfiles, "shell.yaml"),
		[]byte("PATH: shell/PATH\n"), 0o600); err != nil {
		t.Fatalf("WriteFile shell.yaml: %v", err)
	}

	// The vault: the loose secret (origin points back at the file) and an
	// unrelated shell secret that must survive.
	vaultRoot := filepath.Join(home, "Library", "Application Support", "jitpass")
	v := &vault.Vault{Root: vaultRoot, KeyWrapper: newFakeKeyWrapper(), RecipientID: "test-device"}
	if err := v.SetWithMeta("token/JSON_WEB_TOKEN_JWT", []byte("jwt-value"),
		vault.Meta{Class: vault.ClassLooseFile, Origin: looseFile}); err != nil {
		t.Fatalf("seeding loose secret: %v", err)
	}
	if err := v.SetWithMeta("shell/PATH", []byte("/usr/bin"),
		vault.Meta{Class: vault.ClassShell, Origin: filepath.Join(home, ".zshrc")}); err != nil {
		t.Fatalf("seeding shell secret: %v", err)
	}

	// A backup record for the loose file, so the plan reports it too.
	backupYAML := "backups:\n" +
		"  - original_path: " + looseFile + "\n" +
		"    vault_path: _backups/token.txt.jit-bak-1\n" +
		"    unix_ts: 1\n"
	if err := os.WriteFile(migrate.BackupIndexPath(vaultRoot), []byte(backupYAML), 0o600); err != nil {
		t.Fatalf("WriteFile backups.yaml: %v", err)
	}

	// Decline at the prompt: the plan is built and printed, nothing mutates.
	out, err := execMigrateRemove(t, "n\n", looseFile)
	if err != nil {
		t.Fatalf("jit migrate remove token.txt (declined): %v\n%s", err, out)
	}

	if !strings.Contains(out, "Removing jit from "+displayPath(home, looseFile)) {
		t.Errorf("plan must target the loose file itself, got:\n%s", out)
	}
	for _, want := range []string{
		"token.yaml",
		"token/JSON_WEB_TOKEN_JWT",
		"_backups/token.txt.jit-bak-1",
		"delete 1 vault secret(s)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("plan missing %q, got:\n%s", want, out)
		}
	}
	// The unrelated global profile and its secret must never be swept in, and
	// the whole-project teardown language must never appear.
	for _, forbidden := range []string{"shell.yaml", "shell/PATH", "directory is removed entirely"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("plan must not touch unrelated global state, but mentioned %q:\n%s", forbidden, out)
		}
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
	plan, err := buildProjectRemovalPlan(vaultRoot, home, cwd, &vault.Vault{Root: vaultRoot})
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

// A vault secret no profile references but whose birth-time Origin falls
// inside the project tree is swept into the removal by origin — the orphan a
// path-only undo/remove used to strand. A secret whose Origin is outside the
// tree, and one with no Origin at all (a pre-provenance v2 envelope), are left
// untouched.
func TestBuildProjectRemovalPlanSweepsOriginOrphans(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)
	vaultRoot := filepath.Join(home, "Library", "Application Support", "jitpass")

	inside := filepath.ToSlash(filepath.Join(cwd, ".env"))
	writeVaultEnc(t, home, "custom_scripts-descope/DESCOPE_PROJECT_1",
		fmt.Sprintf(`{"version":3,"recipients":{"test":"00"},"payload":"00","origin":%q}`, inside))
	outside := filepath.ToSlash(filepath.Join(home, "elsewhere", ".env"))
	writeVaultEnc(t, home, "other/KEEP",
		fmt.Sprintf(`{"version":3,"recipients":{"test":"00"},"payload":"00","origin":%q}`, outside))
	writeVaultEnc(t, home, "legacy/NOORIGIN",
		`{"version":2,"recipients":{"test":"00"},"payload":"00"}`)

	plan, err := buildProjectRemovalPlan(vaultRoot, home, cwd, &vault.Vault{Root: vaultRoot})
	if err != nil {
		t.Fatalf("buildProjectRemovalPlan: %v", err)
	}
	if len(plan.deletePaths) != 1 || plan.deletePaths[0] != "custom_scripts-descope/DESCOPE_PROJECT_1" {
		t.Errorf("deletePaths = %v, want just the in-tree orphan (the out-of-tree and no-origin secrets stay)", plan.deletePaths)
	}
	if len(plan.orphanSecrets) != 1 || plan.orphanSecrets[0] != "custom_scripts-descope/DESCOPE_PROJECT_1" {
		t.Errorf("orphanSecrets = %v, want the origin-swept secret reported as an orphan", plan.orphanSecrets)
	}
}

// `jit migrate <dir>` roots every migrated .env at that FILE's own directory
// (see migrate.go's envProfilesRoot), so migrating a project with a nested
// `sub/.env` builds a SECOND store at sub/.jit. Removal used to look only at
// filepath.Join(cwd, ".jit"), so it deleted the nested store's vault secret
// (swept by Origin) while leaving its manifest on disk — `jit run` in that
// subdirectory then died with a bare "secret not found" pointing at a secret
// nothing could restore, and the project the help text promised to remove
// "completely" was still half there.
func TestBuildProjectRemovalPlanSweepsNestedProjectRoots(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)

	for dir, manifest := range map[string]string{
		filepath.Join(cwd, ".jit", "profiles"):        "TOP: myapp/TOP\n",
		filepath.Join(cwd, "sub", ".jit", "profiles"): "NESTED: sub/NESTED\n",
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		name := "myapp.yaml"
		if strings.Contains(dir, "sub") {
			name = "sub.yaml"
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(manifest), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	vaultRoot := filepath.Join(home, "Library", "Application Support", "jitpass")
	plan, err := buildProjectRemovalPlan(vaultRoot, home, cwd, &vault.Vault{Root: vaultRoot})
	if err != nil {
		t.Fatalf("buildProjectRemovalPlan: %v", err)
	}

	want := []string{filepath.Join(cwd, ".jit"), filepath.Join(cwd, "sub", ".jit")}
	if !reflect.DeepEqual(plan.jitDirs, want) {
		t.Errorf("jitDirs = %v, want both stores %v", plan.jitDirs, want)
	}
	if len(plan.deletePaths) != 2 || plan.deletePaths[0] != "myapp/TOP" || plan.deletePaths[1] != "sub/NESTED" {
		t.Errorf("deletePaths = %v, want both stores' secrets [myapp/TOP sub/NESTED]", plan.deletePaths)
	}
	var nested bool
	for _, info := range plan.profileInfos {
		if info.Name == "sub" {
			nested = true
		}
	}
	if !nested {
		t.Errorf("nested profile not in plan.profileInfos = %+v, it would survive pointing at a deleted secret", plan.profileInfos)
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
	plan, err := buildProjectRemovalPlan(vaultRoot, home, cwd, &vault.Vault{Root: vaultRoot})
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

// A migrated terraform.tfvars is rewritten IN PLACE — its secret assignments
// lifted out and replaced with a comment naming the profile that now holds
// them. It is not a mount, not a pointer file, not an MCP config, so it fell
// through every restore path removal had: the vault secrets AND the encrypted
// backup were deleted while the stripped file stayed on disk pointing at a
// profile that no longer existed. The values were then unrecoverable, and the
// confirm prompt had said "Restore 0 file(s)" on the way there.
func TestRewrittenInPlaceCoversFilesNoOtherPathRestores(t *testing.T) {
	dir := t.TempDir()
	tfvars := filepath.Join(dir, "terraform.tfvars")
	mountPath := filepath.Join(dir, ".env")
	mcpPath := filepath.Join(dir, ".mcp.json")
	for _, p := range []string{tfvars, mountPath, mcpPath} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	plan := projectRemovalPlan{
		mounts:      []mount.Entry{{MountPath: mountPath}},
		mcpRestores: map[string]map[string]string{mcpPath: {"github": "p.yaml"}},
		backups: []migrate.BackupRecord{
			{OriginalPath: tfvars, VaultPath: "_backups/tfvars", UnixTS: 1},
			{OriginalPath: mountPath, VaultPath: "_backups/env", UnixTS: 1},
			{OriginalPath: mcpPath, VaultPath: "_backups/mcp", UnixTS: 1},
		},
	}

	got := rewrittenInPlace(plan)
	if len(got) != 1 || got[0].OriginalPath != tfvars {
		t.Fatalf("rewrittenInPlace = %+v, want only the tfvars file (%s); a mount and an MCP config each have their own, better restore", got, tfvars)
	}
}

// A RemoveOnRestore record describes a file the migration CREATED, and a
// file that no longer exists has nothing to put back. Neither is something
// removal should resurrect from a backup.
func TestRewrittenInPlaceSkipsCreatedAndMissingFiles(t *testing.T) {
	dir := t.TempDir()
	created := filepath.Join(dir, "config")
	gone := filepath.Join(dir, "deleted.tfvars")
	if err := os.WriteFile(created, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	plan := projectRemovalPlan{backups: []migrate.BackupRecord{
		{OriginalPath: created, RemoveOnRestore: true, UnixTS: 1},
		{OriginalPath: gone, VaultPath: "_backups/gone", UnixTS: 1},
	}}

	if got := rewrittenInPlace(plan); len(got) != 0 {
		t.Errorf("rewrittenInPlace = %+v, want none", got)
	}
}
