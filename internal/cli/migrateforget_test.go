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

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/pointerfile"
)

func writeForgetPointer(t *testing.T, path string, paths ...string) string {
	t.Helper()
	var b strings.Builder
	b.WriteString(pointerfile.Header + " — test\n")
	for _, p := range paths {
		key := p[strings.LastIndex(p, "/")+1:]
		b.WriteString(key + "=" + pointerfile.Value(p) + "\n")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func forgetOne(t *testing.T, file string, groups, mounted map[string]bool) (string, error) {
	t.Helper()
	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	err := migrateForgetOne(cmd, &buf, file, groups, mounted)
	return buf.String(), err
}

// A file jit did not write is never deleted, whatever it is named.
func TestMigrateForgetRefusesAForeignFile(t *testing.T) {
	migrateForgetYes, migrateForgetDryRun = true, false
	file := filepath.Join(t.TempDir(), ".env.pointers")
	if err := os.WriteFile(file, []byte("SECRET=hunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := forgetOne(t, file, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "not a jit pointer file") {
		t.Fatalf("err = %v, want a refusal", err)
	}
	if _, statErr := os.Stat(file); statErr != nil {
		t.Error("the file must still be there")
	}
}

// A companion beside a REGISTERED mount is live documentation of something
// that works. Refused, with the command that would retire the mount.
func TestMigrateForgetRefusesALiveMountsCompanion(t *testing.T) {
	migrateForgetYes, migrateForgetDryRun = true, false
	dir := t.TempDir()
	env := filepath.Join(dir, ".env")
	file := writeForgetPointer(t, pointerfile.CompanionPath(env), "wiz/KEY")
	mounted := map[string]bool{filepath.Clean(file): true}

	_, err := forgetOne(t, file, nil, mounted)
	if err == nil || !strings.Contains(err.Error(), "registered mount") {
		t.Fatalf("err = %v, want a refusal naming the mount", err)
	}
	if _, statErr := os.Stat(file); statErr != nil {
		t.Error("the file must still be there")
	}
}

// The group exists, so the file is CURRENT — some values simply aren't
// stored yet. Deleting it would throw away the record of what is missing.
func TestMigrateForgetRefusesWhenTheGroupExists(t *testing.T) {
	migrateForgetYes, migrateForgetDryRun = true, false
	file := writeForgetPointer(t, filepath.Join(t.TempDir(), ".env.pointers"), "hibob/TOKEN", "hibob/URL")

	_, err := forgetOne(t, file, map[string]bool{"hibob": true}, nil)
	if err == nil || !strings.Contains(err.Error(), "current, not stale") {
		t.Fatalf("err = %v, want a refusal: the vault holds that group", err)
	}
	if _, statErr := os.Stat(file); statErr != nil {
		t.Error("the file must still be there")
	}
}

// The case it exists for: jit's own file, no mount, group gone.
func TestMigrateForgetDeletesAStaleRecord(t *testing.T) {
	migrateForgetYes, migrateForgetDryRun = true, false
	file := writeForgetPointer(t, filepath.Join(t.TempDir(), ".env.pointers"), "wiz/WIZ_CLIENT_ID")

	out, err := forgetOne(t, file, map[string]bool{"other": true}, nil)
	if err != nil {
		t.Fatalf("forget: %v\n%s", err, out)
	}
	if _, statErr := os.Stat(file); !os.IsNotExist(statErr) {
		t.Error("the stale record must be gone")
	}
}

func TestMigrateForgetDryRunDeletesNothing(t *testing.T) {
	migrateForgetYes, migrateForgetDryRun = true, true
	t.Cleanup(func() { migrateForgetDryRun = false })
	file := writeForgetPointer(t, filepath.Join(t.TempDir(), ".env.pointers"), "wiz/WIZ_CLIENT_ID")

	out, err := forgetOne(t, file, nil, nil)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if !strings.Contains(out, "would delete") || !strings.Contains(out, "wiz/") {
		t.Errorf("dry run must say what it would do, got:\n%s", out)
	}
	if _, statErr := os.Stat(file); statErr != nil {
		t.Error("a dry run must not delete anything")
	}
}
