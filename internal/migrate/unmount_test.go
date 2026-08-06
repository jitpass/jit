// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

func TestUnmountEnvFileReversesApplyEnvFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".env")
	writeFile(t, path, "DATABASE_URL=postgres://admin:secret@db/app\nAPI_KEY=sk_test_123\n")

	v := newTestVault(t)
	applied, err := ApplyEnvFile(v, root, path)
	if err != nil {
		t.Fatalf("ApplyEnvFile: %v", err)
	}

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat after ApplyEnvFile: %v", err)
	}
	if info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatal("expected a FIFO after ApplyEnvFile, precondition for this test failed")
	}

	names, err := UnmountFile(v, applied.ProfilePath, path, "")
	if err != nil {
		t.Fatalf("UnmountEnvFile: %v", err)
	}
	// Elementwise, not just the count: these are the names the CLI echoes back
	// to the user as what it just unmounted, so ["X","Y"] passed a length-only
	// check while telling them the wrong thing.
	wantNames := []string{"API_KEY", "DATABASE_URL"}
	got := append([]string(nil), names...)
	sort.Strings(got)
	if !slices.Equal(got, wantNames) {
		t.Fatalf("names = %v, want %v", names, wantNames)
	}

	info, err = os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat after UnmountEnvFile: %v", err)
	}
	if info.Mode()&os.ModeNamedPipe != 0 {
		t.Error("expected a plain file after UnmountEnvFile, still a FIFO")
	}
	if !info.Mode().IsRegular() {
		t.Errorf("mode = %v, want a regular file", info.Mode())
	}

	data, err := os.ReadFile(path) // #nosec G304 -- test-controlled path under t.TempDir()
	if err != nil {
		t.Fatalf("reading unmounted file: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "DATABASE_URL=postgres://admin:secret@db/app") {
		t.Errorf("unmounted content missing DATABASE_URL, got:\n%s", content)
	}
	if !strings.Contains(content, "API_KEY=sk_test_123") {
		t.Errorf("unmounted content missing API_KEY, got:\n%s", content)
	}
}

func TestUnmountEnvFileLeavesVaultAndProfileIntact(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".env")
	writeFile(t, path, "GREETING=hello\n")

	v := newTestVault(t)
	applied, err := ApplyEnvFile(v, root, path)
	if err != nil {
		t.Fatalf("ApplyEnvFile: %v", err)
	}

	if _, err := UnmountFile(v, applied.ProfilePath, path, ""); err != nil {
		t.Fatalf("UnmountEnvFile: %v", err)
	}

	if _, err := os.Stat(applied.ProfilePath); err != nil {
		t.Errorf("profile manifest %s should still exist after unmount: %v", applied.ProfilePath, err)
	}
	if got, err := v.Get(applied.ProfileName + "/GREETING"); err != nil || string(got) != "hello" {
		t.Errorf("vault secret should still exist after unmount, got (%q, %v)", got, err)
	}
}

func TestUnmountEnvFileWithMissingFIFO(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".env")
	writeFile(t, path, "GREETING=hello\n")

	v := newTestVault(t)
	applied, err := ApplyEnvFile(v, root, path)
	if err != nil {
		t.Fatalf("ApplyEnvFile: %v", err)
	}

	// Simulate the mount having already been removed some other way.
	if err := os.Remove(path); err != nil {
		t.Fatalf("removing FIFO: %v", err)
	}

	if _, err := UnmountFile(v, applied.ProfilePath, path, ""); err != nil {
		t.Fatalf("UnmountEnvFile with no existing FIFO to remove: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("expected UnmountEnvFile to (re)create the plain file: %v", err)
	}
}

func TestUnmountEnvFileMissingProfile(t *testing.T) {
	v := newTestVault(t)
	if _, err := UnmountFile(v, filepath.Join(t.TempDir(), "nope.yaml"), filepath.Join(t.TempDir(), ".env"), ""); err == nil {
		t.Fatal("expected an error for a missing profile manifest, got nil")
	}
}

func TestUnmountFileWithTemplateSubstitutesPlaceholders(t *testing.T) {
	root := t.TempDir()
	v := newTestVault(t)
	if err := v.Set("npmrc/NPM_AUTH_TOKEN", []byte("sk_test_token")); err != nil {
		t.Fatalf("v.Set: %v", err)
	}
	profilePath := filepath.Join(root, "npmrc.yaml")
	writeFile(t, profilePath, "NPM_AUTH_TOKEN: npmrc/NPM_AUTH_TOKEN\n")

	templatePath := filepath.Join(root, "npmrc.template")
	writeFile(t, templatePath, "//registry.npmjs.org/:_authToken=${NPM_AUTH_TOKEN}\nregistry=https://registry.npmjs.org\n")

	mountPath := filepath.Join(root, ".npmrc")
	if err := os.WriteFile(mountPath, nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	names, err := UnmountFile(v, profilePath, mountPath, templatePath)
	if err != nil {
		t.Fatalf("UnmountFile: %v", err)
	}
	if len(names) != 1 || names[0] != "NPM_AUTH_TOKEN" {
		t.Errorf("names = %v, want [NPM_AUTH_TOKEN]", names)
	}

	data, err := os.ReadFile(mountPath) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading unmounted file: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "//registry.npmjs.org/:_authToken=sk_test_token") {
		t.Errorf("unmounted content missing the substituted token, got:\n%s", content)
	}
	if !strings.Contains(content, "registry=https://registry.npmjs.org") {
		t.Errorf("unmounted content lost the non-secret line, got:\n%s", content)
	}
}
