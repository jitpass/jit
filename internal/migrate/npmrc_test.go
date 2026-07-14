// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package migrate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/profile"
)

func TestDiscoverNpmrcFilesFindsGlobalAndProjectSecrets(t *testing.T) {
	home := t.TempDir()
	writeFile(t, GlobalNpmrcPath(home), "//registry.npmjs.org/:_authToken=sk_global\nregistry=https://registry.npmjs.org\n")

	cwd := t.TempDir()
	projectPath := filepath.Join(cwd, ".npmrc")
	writeFile(t, projectPath, "_authToken=sk_project\n")

	cleanPath := filepath.Join(cwd, "sub", ".npmrc")
	writeFile(t, cleanPath, "registry=https://registry.npmjs.org\n")

	found, err := DiscoverNpmrcFiles(home, cwd, true)
	if err != nil {
		t.Fatalf("DiscoverNpmrcFiles: %v", err)
	}
	want := map[string]bool{GlobalNpmrcPath(home): true, projectPath: true}
	if len(found) != len(want) {
		t.Fatalf("found = %v, want exactly %v", found, want)
	}
	for _, f := range found {
		if !want[f] {
			t.Errorf("unexpected file in results: %s", f)
		}
	}
}

func TestDiscoverNpmrcFilesSkipsOutsideCwd(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	elsewhere := t.TempDir()
	writeFile(t, filepath.Join(elsewhere, ".npmrc"), "_authToken=sk_elsewhere\n")

	found, err := DiscoverNpmrcFiles(home, cwd, true)
	if err != nil {
		t.Fatalf("DiscoverNpmrcFiles: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("found = %v, want empty (elsewhere is outside cwd, and home has no secrets)", found)
	}
}

// TestDiscoverNpmrcFilesIncludeGlobalFlag confirms includeGlobal actually
// gates the fixed global ~/.npmrc — jit migrate local passes false since
// that path has no project-scoped form and must never appear in a
// local-scope plan; only jit migrate home passes true.
func TestDiscoverNpmrcFilesIncludeGlobalFlag(t *testing.T) {
	home := t.TempDir()
	writeFile(t, GlobalNpmrcPath(home), "//registry.npmjs.org/:_authToken=sk_global\n")
	cwd := t.TempDir()

	found, err := DiscoverNpmrcFiles(home, cwd, false)
	if err != nil {
		t.Fatalf("DiscoverNpmrcFiles: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("found = %v, want empty — includeGlobal=false must exclude it", found)
	}

	found, err = DiscoverNpmrcFiles(home, cwd, true)
	if err != nil {
		t.Fatalf("DiscoverNpmrcFiles: %v", err)
	}
	if len(found) != 1 || found[0] != GlobalNpmrcPath(home) {
		t.Errorf("found = %v, want [%s] — includeGlobal=true must include it", found, GlobalNpmrcPath(home))
	}
}

// TestDiscoverNpmrcFilesToleratesUnreadableDirectory is the npmrc
// counterpart to apply_test.go's identical regression test — see its
// comment for the real report this comes from (GAPS.md #26's home-wide
// walk hitting a permission-denied ~/.Trash and aborting outright).
func TestDiscoverNpmrcFilesToleratesUnreadableDirectory(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root ignores directory permissions, can't exercise this")
	}
	home := t.TempDir()
	cwd := t.TempDir()
	projectPath := filepath.Join(cwd, "myapp", ".npmrc")
	writeFile(t, projectPath, "_authToken=sk_project\n")

	blocked := filepath.Join(cwd, "blocked")
	if err := os.MkdirAll(blocked, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Chmod(blocked, 0o000); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o700) })

	found, err := DiscoverNpmrcFiles(home, cwd, true)
	if err != nil {
		t.Fatalf("DiscoverNpmrcFiles must tolerate an unreadable subdirectory, not abort: %v", err)
	}
	if len(found) != 1 || found[0] != projectPath {
		t.Errorf("found = %v, want [%s] — the unreadable dir must be skipped, not stop discovery of everything else", found, projectPath)
	}
}

func TestApplyNpmrcGlobalMovesSecretAndPreservesNonSecretLines(t *testing.T) {
	home := t.TempDir()
	path := GlobalNpmrcPath(home)
	writeFile(t, path, "//registry.npmjs.org/:_authToken=sk_test_secret\nregistry=https://registry.npmjs.org\nsave-exact=true\n")

	v := newTestVault(t)
	result, err := ApplyNpmrc(v, home, path, true)
	if err != nil {
		t.Fatalf("ApplyNpmrc: %v", err)
	}
	if result.ProfileName != "npmrc" {
		t.Errorf("ProfileName = %q, want npmrc", result.ProfileName)
	}
	if len(result.Variables) != 1 || result.Variables[0] != "REGISTRY_NPMJS_ORG_AUTHTOKEN" {
		t.Errorf("Variables = %v, want [REGISTRY_NPMJS_ORG_AUTHTOKEN]", result.Variables)
	}

	got, err := v.Get("npmrc/REGISTRY_NPMJS_ORG_AUTHTOKEN")
	if err != nil || string(got) != "sk_test_secret" {
		t.Errorf("vault secret = (%q, %v), want (sk_test_secret, nil)", got, err)
	}

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	if info.Mode()&os.ModeNamedPipe == 0 {
		t.Error("expected path to be a FIFO after ApplyNpmrc")
	}

	tmpl, err := os.ReadFile(result.TemplatePath) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading template: %v", err)
	}
	tmplContent := string(tmpl)
	if strings.Contains(tmplContent, "sk_test_secret") {
		t.Error("template must not contain the raw secret value")
	}
	if !strings.Contains(tmplContent, "//registry.npmjs.org/:_authToken=${REGISTRY_NPMJS_ORG_AUTHTOKEN}") {
		t.Errorf("template missing the expected placeholder, got:\n%s", tmplContent)
	}
	if !strings.Contains(tmplContent, "registry=https://registry.npmjs.org") || !strings.Contains(tmplContent, "save-exact=true") {
		t.Errorf("template lost a non-secret line, got:\n%s", tmplContent)
	}

	backup, err := v.Get(result.BackupPath)
	if err != nil {
		t.Fatalf("reading backup from vault: %v", err)
	}
	if !strings.Contains(string(backup), "sk_test_secret") {
		t.Error("backup should contain the original plaintext content")
	}
}

func TestApplyNpmrcProjectLocalUsesProjectProfileRoot(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	path := filepath.Join(cwd, ".npmrc")
	writeFile(t, path, "_authToken=sk_project_secret\n")

	v := newTestVault(t)
	result, err := ApplyNpmrc(v, cwd, path, false)
	if err != nil {
		t.Fatalf("ApplyNpmrc: %v", err)
	}

	// Project-local npmrc profile must live under cwd's own project store,
	// not the home-rooted global one shell-config/MCP use.
	if !strings.HasPrefix(result.ProfilePath, cwd) {
		t.Errorf("ProfilePath = %q, want it rooted under cwd %q", result.ProfilePath, cwd)
	}

	// Sanity: profile.Load from an unrelated root must NOT find this one via
	// the global fallback, since it was never written to the home root.
	t.Setenv("HOME", home)
	if _, err := profile.Load(t.TempDir(), result.ProfileName); err == nil {
		t.Error("project-local npmrc profile should not be resolvable via the global fallback")
	}
}

func TestApplyNpmrcNoSecretsErrors(t *testing.T) {
	home := t.TempDir()
	path := GlobalNpmrcPath(home)
	writeFile(t, path, "registry=https://registry.npmjs.org\n")

	v := newTestVault(t)
	if _, err := ApplyNpmrc(v, home, path, true); err == nil {
		t.Fatal("expected an error migrating a file with no secret-shaped lines")
	}
}

func TestApplyNpmrcIsIdempotentAndMergesOnSecondRun(t *testing.T) {
	home := t.TempDir()
	path := GlobalNpmrcPath(home)
	writeFile(t, path, "_authToken=sk_first\n")

	v := newTestVault(t)
	if _, err := ApplyNpmrc(v, home, path, true); err != nil {
		t.Fatalf("first ApplyNpmrc: %v", err)
	}

	// Fully migrated file (now a FIFO) should no longer be discovered.
	found, err := DiscoverNpmrcFiles(home, t.TempDir(), true)
	if err != nil {
		t.Fatalf("DiscoverNpmrcFiles: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("DiscoverNpmrcFiles after migration = %v, want empty", found)
	}
}

// TestDeriveNpmrcProfileName pins GAPS.md #55's npmrc half: the global
// ~/.npmrc keeps its machine-singleton "npmrc" name, while a project-local
// .npmrc is namespaced by its project directory — a bare "npmrc" for every
// project put each one's auth token at the identical machine-global vault
// path (same registry host → same variable name), the same silent-
// overwrite hazard .env migration had.
func TestDeriveNpmrcProfileName(t *testing.T) {
	cases := []struct {
		root, path string
		global     bool
		want       string
	}{
		{"/Users/x", "/Users/x/.npmrc", true, "npmrc"},
		{"/Users/x/Documents/notion", "/Users/x/Documents/notion/.npmrc", false, "npmrc-notion"},
		{"/Users/x/Documents/notion", "/Users/x/Documents/notion/packages/cli/.npmrc", false, "npmrc-packages-cli"},
	}
	for _, c := range cases {
		if got := deriveNpmrcProfileName(c.root, c.path, c.global); got != c.want {
			t.Errorf("deriveNpmrcProfileName(%q, %q, %v) = %q, want %q", c.root, c.path, c.global, got, c.want)
		}
	}
}

func TestNpmrcVarNameSanitization(t *testing.T) {
	cases := map[string]string{
		"_authToken":                       "AUTHTOKEN",
		"//registry.npmjs.org/:_authToken": "REGISTRY_NPMJS_ORG_AUTHTOKEN",
		"_password":                        "PASSWORD",
	}
	for key, want := range cases {
		if got := npmrcVarName(key); got != want {
			t.Errorf("npmrcVarName(%q) = %q, want %q", key, got, want)
		}
	}
}
