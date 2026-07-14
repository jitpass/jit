// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package profile

import (
	"os"
	"path/filepath"
	"testing"
)

func writeProfile(t *testing.T, root, name, content string) {
	t.Helper()
	dir := filepath.Join(root, ProfilesDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".yaml"), []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func TestLoadValidProfile(t *testing.T) {
	root := t.TempDir()
	writeProfile(t, root, "aws-admin", `
AWS_ACCESS_KEY_ID: aws/s3-access-key
AWS_SECRET_ACCESS_KEY: aws/s3-secret-key
`)

	p, err := Load(root, "aws-admin")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if p["AWS_ACCESS_KEY_ID"] != "aws/s3-access-key" {
		t.Errorf("AWS_ACCESS_KEY_ID = %q, want %q", p["AWS_ACCESS_KEY_ID"], "aws/s3-access-key")
	}
	if p["AWS_SECRET_ACCESS_KEY"] != "aws/s3-secret-key" {
		t.Errorf("AWS_SECRET_ACCESS_KEY = %q, want %q", p["AWS_SECRET_ACCESS_KEY"], "aws/s3-secret-key")
	}
}

func TestLoadMissingProfile(t *testing.T) {
	// Load falls back to GlobalRoot() (os.UserHomeDir()) on a miss — isolate
	// $HOME so this test can't accidentally pass (or flake) by finding a
	// real profile named "nope" on the machine actually running the test.
	t.Setenv("HOME", t.TempDir())
	root := t.TempDir()
	if _, err := Load(root, "nope"); err == nil {
		t.Fatal("expected an error loading a nonexistent profile, got nil")
	}
}

func TestLoadFallsBackToGlobalRoot(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeProfile(t, home, "shell", "STRIPE_API_KEY: shell/STRIPE_API_KEY\n")

	// A project root with no local profile of this name at all.
	root := t.TempDir()
	p, err := Load(root, "shell")
	if err != nil {
		t.Fatalf("Load should fall back to the home-rooted global profile: %v", err)
	}
	if p["STRIPE_API_KEY"] != "shell/STRIPE_API_KEY" {
		t.Errorf("STRIPE_API_KEY = %q, want %q", p["STRIPE_API_KEY"], "shell/STRIPE_API_KEY")
	}
}

func TestLoadPrefersProjectRootOverGlobalRoot(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeProfile(t, home, "aws-admin", "AWS_ACCESS_KEY_ID: global/wrong\n")

	root := t.TempDir()
	writeProfile(t, root, "aws-admin", "AWS_ACCESS_KEY_ID: local/right\n")

	p, err := Load(root, "aws-admin")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if p["AWS_ACCESS_KEY_ID"] != "local/right" {
		t.Errorf("AWS_ACCESS_KEY_ID = %q, want the project-local value, got the global one", p["AWS_ACCESS_KEY_ID"])
	}
}

func TestLoadEmptyProfile(t *testing.T) {
	root := t.TempDir()
	writeProfile(t, root, "empty", "{}\n")
	if _, err := Load(root, "empty"); err == nil {
		t.Fatal("expected an error for a profile with no entries, got nil")
	}
}

func TestLoadMalformedYAML(t *testing.T) {
	root := t.TempDir()
	writeProfile(t, root, "broken", "[this is not valid yaml")
	if _, err := Load(root, "broken"); err == nil {
		t.Fatal("expected an error for malformed YAML, got nil")
	}
}

func TestLoadEmptyValueRejected(t *testing.T) {
	root := t.TempDir()
	writeProfile(t, root, "blank-value", "AWS_ACCESS_KEY_ID: \"\"\n")
	if _, err := Load(root, "blank-value"); err == nil {
		t.Fatal("expected an error for an entry with an empty secret path, got nil")
	}
}

func TestLoadFileAbsolutePath(t *testing.T) {
	root := t.TempDir()
	writeProfile(t, root, "aws-admin", "AWS_ACCESS_KEY_ID: aws/s3-access-key\n")

	path := filepath.Join(root, ProfilesDir, "aws-admin.yaml")
	p, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if p["AWS_ACCESS_KEY_ID"] != "aws/s3-access-key" {
		t.Errorf("AWS_ACCESS_KEY_ID = %q, want %q", p["AWS_ACCESS_KEY_ID"], "aws/s3-access-key")
	}
}

func TestLoadFileMissing(t *testing.T) {
	if _, err := LoadFile(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("expected an error for a missing file, got nil")
	}
}

func TestPathRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	bad := []string{"../escape", "a/b", "", "a b"}
	for _, name := range bad {
		if _, err := Path(root, name); err == nil {
			t.Errorf("Path(%q) succeeded, want a rejection", name)
		}
	}
}

func TestListNamesSortedAndFiltered(t *testing.T) {
	root := t.TempDir()
	writeProfile(t, root, "stripe-webhooks-local", "A: b\n")
	writeProfile(t, root, "aws-admin", "A: b\n")
	dir := filepath.Join(root, ProfilesDir)
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("not a profile"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	names, err := ListNames(root)
	if err != nil {
		t.Fatalf("ListNames: %v", err)
	}
	want := []string{"aws-admin", "stripe-webhooks-local"}
	if len(names) != len(want) {
		t.Fatalf("ListNames = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("ListNames[%d] = %q, want %q", i, names[i], want[i])
		}
	}
}

func TestLoadWithScopeReportsProject(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	root := t.TempDir()
	writeProfile(t, root, "aws-admin", "AWS_ACCESS_KEY_ID: aws/s3-access-key\n")

	_, scope, path, err := LoadWithScope(root, "aws-admin")
	if err != nil {
		t.Fatalf("LoadWithScope: %v", err)
	}
	if scope != ScopeProject {
		t.Errorf("scope = %q, want %q", scope, ScopeProject)
	}
	want, _ := Path(root, "aws-admin")
	if path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
}

func TestLoadWithScopeReportsGlobal(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeProfile(t, home, "shell", "STRIPE_API_KEY: shell/STRIPE_API_KEY\n")

	root := t.TempDir()
	_, scope, path, err := LoadWithScope(root, "shell")
	if err != nil {
		t.Fatalf("LoadWithScope: %v", err)
	}
	if scope != ScopeGlobal {
		t.Errorf("scope = %q, want %q", scope, ScopeGlobal)
	}
	want, _ := Path(home, "shell")
	if path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
}

func TestListAllCombinesProjectAndGlobal(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeProfile(t, home, "shell", "A: b\n")

	root := t.TempDir()
	writeProfile(t, root, "aws-admin", "A: b\n")

	infos, err := ListAll(root)
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(infos) != 2 {
		t.Fatalf("ListAll = %+v, want 2 entries", infos)
	}
	if infos[0].Name != "aws-admin" || infos[0].Scope != ScopeProject {
		t.Errorf("infos[0] = %+v, want project aws-admin", infos[0])
	}
	if infos[1].Name != "shell" || infos[1].Scope != ScopeGlobal {
		t.Errorf("infos[1] = %+v, want global shell", infos[1])
	}
}

func TestListAllSkipsGlobalDuplicationWhenRootIsHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeProfile(t, home, "shell", "A: b\n")

	infos, err := ListAll(home)
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(infos) != 1 {
		t.Fatalf("ListAll = %+v, want exactly 1 entry (no duplicate global pass)", infos)
	}
}

func TestListNamesNoProfilesDir(t *testing.T) {
	root := t.TempDir()
	names, err := ListNames(root)
	if err != nil {
		t.Fatalf("ListNames on a project with no .jit/profiles/: %v", err)
	}
	if len(names) != 0 {
		t.Errorf("ListNames = %v, want empty", names)
	}
}

func TestOverlayLaterLayerWins(t *testing.T) {
	base := Profile{"API_KEY": "root/API_KEY", "DB_URL": "root/DB_URL"}
	local := Profile{"API_KEY": "root-local/API_KEY", "EXTRA": "root-local/EXTRA"}

	merged := Overlay(base, local)
	want := Profile{
		"API_KEY": "root-local/API_KEY", // local overrides base
		"DB_URL":  "root/DB_URL",        // base survives where local is silent
		"EXTRA":   "root-local/EXTRA",   // local-only additions come through
	}
	if len(merged) != len(want) {
		t.Fatalf("Overlay = %+v, want %+v", merged, want)
	}
	for k, v := range want {
		if merged[k] != v {
			t.Errorf("merged[%q] = %q, want %q", k, merged[k], v)
		}
	}
}

func TestOverlayOrderMatters(t *testing.T) {
	a := Profile{"K": "a/K"}
	b := Profile{"K": "b/K"}

	if got := Overlay(a, b)["K"]; got != "b/K" {
		t.Errorf("Overlay(a, b)[K] = %q, want b/K (later wins)", got)
	}
	if got := Overlay(b, a)["K"]; got != "a/K" {
		t.Errorf("Overlay(b, a)[K] = %q, want a/K (later wins)", got)
	}
}

func TestOverlayNilAndEmptyLayers(t *testing.T) {
	base := Profile{"K": "root/K"}

	merged := Overlay(nil, base, Profile{}, nil)
	if len(merged) != 1 || merged["K"] != "root/K" {
		t.Errorf("Overlay with nil/empty layers = %+v, want just base's entry", merged)
	}

	if got := Overlay(); len(got) != 0 {
		t.Errorf("Overlay() = %+v, want empty (never nil) map", got)
	}
}

func TestOverlayDoesNotMutateInputs(t *testing.T) {
	base := Profile{"K": "root/K"}
	local := Profile{"K": "root-local/K"}

	_ = Overlay(base, local)
	if base["K"] != "root/K" {
		t.Errorf("Overlay mutated its input layer: base[K] = %q", base["K"])
	}
}
