// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/jitpass/jit/internal/mount"
)

// ageKeysFixture mirrors what `age-keygen -o keys.txt` writes: two comment
// lines then the secret key, trailing newline. The round-trip test below
// depends on reproducing these exact bytes.
const ageKeysFixture = `# created: 2026-07-01T10:00:00+02:00
# public key: age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ
`

const ageKeysFixtureKey = "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"

func writeAgeKeysFixture(t *testing.T, home, rel, content string) string {
	t.Helper()
	path := filepath.Join(home, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	writeFile(t, path, content)
	return path
}

func TestDiscoverSOPSAgeFindsBothStandardLocations(t *testing.T) {
	home := t.TempDir()
	xdg := writeAgeKeysFixture(t, home, ".config/sops/age/keys.txt", ageKeysFixture)
	mac := writeAgeKeysFixture(t, home, "Library/Application Support/sops/age/keys.txt", ageKeysFixture)

	found, err := DiscoverSOPSAge(home)
	if err != nil {
		t.Fatalf("DiscoverSOPSAge: %v", err)
	}
	if len(found) != 2 {
		t.Fatalf("found = %v, want both standard locations", found)
	}
	// Application Support first — sops's own macOS resolution order.
	if found[0] != mac || found[1] != xdg {
		t.Errorf("found = %v, want [%s %s]", found, mac, xdg)
	}
}

func TestDiscoverSOPSAgeSkipsMultiKeyFile(t *testing.T) {
	home := t.TempDir()
	writeAgeKeysFixture(t, home, ".config/sops/age/keys.txt",
		ageKeysFixture+"AGE-SECRET-KEY-1WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW\n")

	found, err := DiscoverSOPSAge(home)
	if err != nil {
		t.Fatalf("DiscoverSOPSAge: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("found = %v, want empty (multi-key files are skipped, never half-migrated)", found)
	}
}

func TestDiscoverSOPSAgeSkipsCommentOnlyFile(t *testing.T) {
	home := t.TempDir()
	writeAgeKeysFixture(t, home, ".config/sops/age/keys.txt", "# public key: age1qqq\n")

	found, err := DiscoverSOPSAge(home)
	if err != nil {
		t.Fatalf("DiscoverSOPSAge: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("found = %v, want empty (no secret key line)", found)
	}
}

func TestDiscoverSOPSAgeSkipsExistingFIFO(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".config", "sops", "age")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// An already-migrated keys.txt is a FIFO; opening it for read would
	// block forever with no agent writing. If the guard regresses, this
	// test hangs rather than fails.
	if err := syscall.Mkfifo(filepath.Join(dir, "keys.txt"), 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}
	found, err := DiscoverSOPSAge(home)
	if err != nil {
		t.Fatalf("DiscoverSOPSAge: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("found = %v, want empty (already mounted)", found)
	}
}

func TestApplySOPSAgeRoundTrip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := writeAgeKeysFixture(t, home, ".config/sops/age/keys.txt", ageKeysFixture)

	v := newTestVault(t)
	result, err := ApplySOPSAge(v, home, path)
	if err != nil {
		t.Fatalf("ApplySOPSAge: %v", err)
	}
	if result.ProfileName != "sops-age" {
		t.Errorf("ProfileName = %q, want sops-age", result.ProfileName)
	}

	// Vault leaf equals manifest key (the tfvars idempotency rule) and the
	// stored value is the bare key token — exactly what sops's own
	// SOPS_AGE_KEY env var expects.
	got, err := v.Get("sops-age/SOPS_AGE_KEY")
	if err != nil || string(got) != ageKeysFixtureKey {
		t.Errorf("SOPS_AGE_KEY = (%q, %v), want the fixture's key", got, err)
	}

	tmpl, err := os.ReadFile(result.TemplatePath)
	if err != nil {
		t.Fatalf("reading template: %v", err)
	}
	if strings.Contains(string(tmpl), "AGE-SECRET-KEY-1") {
		t.Errorf("template still contains the secret key:\n%s", tmpl)
	}
	// The non-secret comment lines (public key, created date) must survive
	// verbatim — tooling and humans identify the key file by them.
	if !strings.Contains(string(tmpl), "# public key: age1qqq") {
		t.Errorf("template lost the public-key comment:\n%s", tmpl)
	}

	// The property everything else rests on: substituting the vault's
	// value back into the template reproduces the original file
	// byte-for-byte — what the agent serves during a reveal window IS the
	// file sops/kluctl used to read.
	rebuilt := mount.FormatTemplate(tmpl, map[string]string{"SOPS_AGE_KEY": string(got)})
	if string(rebuilt) != ageKeysFixture {
		t.Errorf("round trip mismatch:\n got: %q\nwant: %q", rebuilt, ageKeysFixture)
	}

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat mount: %v", err)
	}
	if info.Mode()&fs.ModeNamedPipe == 0 {
		t.Errorf("%s is not a FIFO after ApplySOPSAge", path)
	}

	if result.BackupPath == "" {
		t.Fatal("BackupPath is empty")
	}
	backup, err := v.Get(result.BackupPath)
	if err != nil || string(backup) != ageKeysFixture {
		t.Errorf("backup = (%q, %v), want original bytes", backup, err)
	}
	records, err := LoadBackupRecords(v.Root)
	if err != nil {
		t.Fatalf("LoadBackupRecords: %v", err)
	}
	foundRecord := false
	for _, r := range records {
		if r.OriginalPath == path && r.VaultPath == result.BackupPath {
			foundRecord = true
		}
	}
	if !foundRecord {
		t.Errorf("no undo-index record for %s -> %s in %v", path, result.BackupPath, records)
	}
}

func TestApplySOPSAgeMultiKeyFailsBeforeMutating(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	content := ageKeysFixture + "AGE-SECRET-KEY-1WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW\n"
	path := writeAgeKeysFixture(t, home, ".config/sops/age/keys.txt", content)

	v := newTestVault(t)
	if _, err := ApplySOPSAge(v, home, path); err == nil {
		t.Fatal("ApplySOPSAge on a multi-key file should fail")
	}

	// Fail-safe ordering: the refusal must come before any mutation — the
	// file is untouched (still a regular file, same bytes) and no backup
	// record was written.
	data, err := os.ReadFile(path)
	if err != nil || string(data) != content {
		t.Errorf("file = (%q, %v), want original bytes untouched", data, err)
	}
	records, err := LoadBackupRecords(v.Root)
	if err != nil {
		t.Fatalf("LoadBackupRecords: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("backup records = %v, want none", records)
	}
}

func TestApplySOPSAgeRerunIdempotent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := writeAgeKeysFixture(t, home, ".config/sops/age/keys.txt", ageKeysFixture)

	v := newTestVault(t)
	first, err := ApplySOPSAge(v, home, path)
	if err != nil {
		t.Fatalf("first ApplySOPSAge: %v", err)
	}

	// Simulate migrate undo's file restore then a re-run: because the vault
	// leaf equals the manifest key, claimNamespace recognizes sops-age as
	// this migration's own and reuses it instead of forking sops-age-2.
	if err := os.Remove(path); err != nil {
		t.Fatalf("removing FIFO: %v", err)
	}
	writeFile(t, path, ageKeysFixture)

	second, err := ApplySOPSAge(v, home, path)
	if err != nil {
		t.Fatalf("second ApplySOPSAge: %v", err)
	}
	if second.ProfileName != first.ProfileName {
		t.Errorf("re-run forked profile %q, want %q reused", second.ProfileName, first.ProfileName)
	}
	if second.NamespaceMovedFrom != "" {
		t.Errorf("NamespaceMovedFrom = %q, want empty on an idempotent re-run", second.NamespaceMovedFrom)
	}
}
