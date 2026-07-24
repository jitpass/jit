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

const netrcFixture = `machine api.github.com
  login alex
  password ghp_FIXTUREtoken0123456789abcdefFIXTURE

machine ftp.example.com login ftpuser password ftp_FIXTUREpass123
`

func writeNetrcFixture(t *testing.T, home, content string) string {
	t.Helper()
	path := NetrcPath(home)
	writeFile(t, path, content)
	return path
}

func TestDiscoverNetrcFindsPasswordLines(t *testing.T) {
	home := t.TempDir()
	writeNetrcFixture(t, home, netrcFixture)

	found, err := DiscoverNetrc(home)
	if err != nil {
		t.Fatalf("DiscoverNetrc: %v", err)
	}
	if len(found) != 1 || found[0] != NetrcPath(home) {
		t.Errorf("found = %v, want [%s]", found, NetrcPath(home))
	}
}

func TestDiscoverNetrcMissingFile(t *testing.T) {
	home := t.TempDir()
	found, err := DiscoverNetrc(home)
	if err != nil {
		t.Fatalf("DiscoverNetrc: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("found = %v, want empty", found)
	}
}

func TestDiscoverNetrcSkipsLoginOnlyFile(t *testing.T) {
	home := t.TempDir()
	writeNetrcFixture(t, home, "machine api.example.com\n  login alex\n")

	found, err := DiscoverNetrc(home)
	if err != nil {
		t.Fatalf("DiscoverNetrc: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("found = %v, want empty (no password line)", found)
	}
}

func TestDiscoverNetrcSkipsExistingFIFO(t *testing.T) {
	home := t.TempDir()
	// An already-migrated .netrc is a FIFO; opening it for read would block
	// forever with no agent writing. If the guard regresses, this test
	// hangs rather than fails.
	if err := syscall.Mkfifo(NetrcPath(home), 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}
	found, err := DiscoverNetrc(home)
	if err != nil {
		t.Fatalf("DiscoverNetrc: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("found = %v, want empty (already mounted)", found)
	}
}

func TestApplyNetrcRoundTrip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := writeNetrcFixture(t, home, netrcFixture)

	v := newTestVault(t)
	result, err := ApplyNetrc(v, home, path)
	if err != nil {
		t.Fatalf("ApplyNetrc: %v", err)
	}
	if result.ProfileName != "netrc" {
		t.Errorf("ProfileName = %q, want netrc", result.ProfileName)
	}
	wantVars := []string{"API_GITHUB_COM_PASSWORD", "FTP_EXAMPLE_COM_PASSWORD"}
	if strings.Join(result.Variables, ",") != strings.Join(wantVars, ",") {
		t.Errorf("Variables = %v, want %v", result.Variables, wantVars)
	}

	got, err := v.Get("netrc/API_GITHUB_COM_PASSWORD")
	if err != nil || string(got) != "ghp_FIXTUREtoken0123456789abcdefFIXTURE" {
		t.Errorf("API_GITHUB_COM_PASSWORD = (%q, %v)", got, err)
	}
	got2, err := v.Get("netrc/FTP_EXAMPLE_COM_PASSWORD")
	if err != nil || string(got2) != "ftp_FIXTUREpass123" {
		t.Errorf("FTP_EXAMPLE_COM_PASSWORD = (%q, %v)", got2, err)
	}

	tmpl, err := os.ReadFile(result.TemplatePath)
	if err != nil {
		t.Fatalf("reading template: %v", err)
	}
	if strings.Contains(string(tmpl), "ghp_FIXTUREtoken") || strings.Contains(string(tmpl), "ftp_FIXTUREpass") {
		t.Errorf("template still contains a secret:\n%s", tmpl)
	}
	// Non-secret structure — machine/login lines, blank line between
	// entries, indentation — must survive byte-for-byte.
	if !strings.Contains(string(tmpl), "login alex") || !strings.Contains(string(tmpl), "login ftpuser") {
		t.Errorf("template lost login lines:\n%s", tmpl)
	}

	// The property everything else rests on: substituting the vault's
	// values back into the template reproduces the original file
	// byte-for-byte.
	rebuilt := mount.FormatTemplate(tmpl, map[string]string{
		"API_GITHUB_COM_PASSWORD":  string(got),
		"FTP_EXAMPLE_COM_PASSWORD": string(got2),
	})
	if string(rebuilt) != netrcFixture {
		t.Errorf("round trip mismatch:\n got: %q\nwant: %q", rebuilt, netrcFixture)
	}

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat mount: %v", err)
	}
	if info.Mode()&fs.ModeNamedPipe == 0 {
		t.Errorf("%s is not a FIFO after ApplyNetrc", path)
	}

	if result.BackupPath == "" {
		t.Fatal("BackupPath is empty")
	}
	backup, err := v.Get(result.BackupPath)
	if err != nil || string(backup) != netrcFixture {
		t.Errorf("backup = (%q, %v), want original bytes", backup, err)
	}
}

func TestApplyNetrcMacdefBodyNeverParsedAsCredentials(t *testing.T) {
	// A macdef body is free-form text a user wrote for curl/ftp scripting.
	// It must never be interpreted as machine/login/password grammar, even
	// when it happens to contain those exact words — this fixture puts a
	// "password" lookalike inside the macro body and a real password
	// after it, and only the real one may be extracted.
	fixture := "machine init.example.com login bootstrap password " +
		"REAL_FIXTURE_SECRET_abc123\n\n" +
		"macdef init\n" +
		"echo password fake_value_inside_macro\n" +
		"echo done\n\n" +
		"machine second.example.com login u password " +
		"SECOND_FIXTURE_SECRET_xyz789\n"

	home := t.TempDir()
	t.Setenv("HOME", home)
	path := writeNetrcFixture(t, home, fixture)

	v := newTestVault(t)
	result, err := ApplyNetrc(v, home, path)
	if err != nil {
		t.Fatalf("ApplyNetrc: %v", err)
	}
	if len(result.Variables) != 2 {
		t.Fatalf("Variables = %v, want exactly 2 (the macro body's lookalike must not be extracted)", result.Variables)
	}

	tmpl, err := os.ReadFile(result.TemplatePath)
	if err != nil {
		t.Fatalf("reading template: %v", err)
	}
	// The macro body's own literal text, including its "password" lookalike
	// line, must survive verbatim in the template.
	if !strings.Contains(string(tmpl), "echo password fake_value_inside_macro") {
		t.Errorf("macdef body was altered:\n%s", tmpl)
	}
}

func TestApplyNetrcDuplicateMachineGetsSuffixedVarName(t *testing.T) {
	// Two `machine api.example.com` blocks (a malformed but real-world
	// possibility — e.g. a hand-edited file with a leftover stale entry).
	// netrc readers use the FIRST match, so the first occurrence must keep
	// the canonical name and the second gets a distinguishing suffix.
	fixture := "machine api.example.com login first password FIRST_FIXTURE_abc\n" +
		"machine api.example.com login second password SECOND_FIXTURE_xyz\n"

	home := t.TempDir()
	t.Setenv("HOME", home)
	path := writeNetrcFixture(t, home, fixture)

	v := newTestVault(t)
	result, err := ApplyNetrc(v, home, path)
	if err != nil {
		t.Fatalf("ApplyNetrc: %v", err)
	}
	wantVars := []string{"API_EXAMPLE_COM_PASSWORD", "API_EXAMPLE_COM_PASSWORD_2"}
	if strings.Join(result.Variables, ",") != strings.Join(wantVars, ",") {
		t.Errorf("Variables = %v, want %v", result.Variables, wantVars)
	}
	first, err := v.Get("netrc/API_EXAMPLE_COM_PASSWORD")
	if err != nil || string(first) != "FIRST_FIXTURE_abc" {
		t.Errorf("first password = (%q, %v)", first, err)
	}
	second, err := v.Get("netrc/API_EXAMPLE_COM_PASSWORD_2")
	if err != nil || string(second) != "SECOND_FIXTURE_xyz" {
		t.Errorf("second password = (%q, %v)", second, err)
	}
}

func TestApplyNetrcNoPasswordFailsBeforeMutating(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	content := "machine api.example.com\n  login alex\n"
	path := writeNetrcFixture(t, home, content)

	v := newTestVault(t)
	if _, err := ApplyNetrc(v, home, path); err == nil {
		t.Fatal("ApplyNetrc on a password-less file should fail")
	}
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

func TestApplyNetrcRerunIdempotent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := writeNetrcFixture(t, home, netrcFixture)

	v := newTestVault(t)
	first, err := ApplyNetrc(v, home, path)
	if err != nil {
		t.Fatalf("first ApplyNetrc: %v", err)
	}

	// Simulate migrate undo's file restore then a re-run.
	if err := os.Remove(path); err != nil {
		t.Fatalf("removing FIFO: %v", err)
	}
	writeFile(t, path, netrcFixture)

	second, err := ApplyNetrc(v, home, path)
	if err != nil {
		t.Fatalf("second ApplyNetrc: %v", err)
	}
	if second.ProfileName != first.ProfileName {
		t.Errorf("re-run forked profile %q, want %q reused", second.ProfileName, first.ProfileName)
	}
	if second.NamespaceMovedFrom != "" {
		t.Errorf("NamespaceMovedFrom = %q, want empty on an idempotent re-run", second.NamespaceMovedFrom)
	}
}

func TestApplyNetrcRefusesNonRegularFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Dir(NetrcPath(home)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(NetrcPath(home), 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}

	v := newTestVault(t)
	if _, err := ApplyNetrc(v, home, NetrcPath(home)); err == nil {
		t.Fatal("ApplyNetrc on an existing FIFO should refuse rather than block or clobber it")
	}
}
