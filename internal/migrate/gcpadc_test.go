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

// authorizedUserADC mirrors what `gcloud auth application-default login`
// actually writes: 2-space indent, sorted keys, trailing newline. The
// round-trip tests below depend on reproducing these exact bytes.
const authorizedUserADC = `{
  "account": "",
  "client_id": "764086051850-6qr4p6gpi6hn506pt8ejuq83di341hur.apps.googleusercontent.com",
  "client_secret": "d-FL95Q19q7MQmFpd7hHD0Ty",
  "quota_project_id": "my-project",
  "refresh_token": "1//0gExampleRefreshTokenValue-Long_random",
  "type": "authorized_user",
  "universe_domain": "googleapis.com"
}
`

// serviceAccountADC's private_key carries the JSON-escaped `\n` pairs a
// real key file holds, plus an escaped quote to exercise the value
// pattern's escape handling.
const serviceAccountADC = `{
  "type": "service_account",
  "project_id": "my-project",
  "private_key_id": "abc123",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\"kq\nhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\n",
  "client_email": "svc@my-project.iam.gserviceaccount.com"
}
`

func writeGCPADCFixture(t *testing.T, home, content string) string {
	t.Helper()
	path := GCPADCPath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	writeFile(t, path, content)
	return path
}

func TestDiscoverGCPADCFindsAuthorizedUser(t *testing.T) {
	home := t.TempDir()
	path := writeGCPADCFixture(t, home, authorizedUserADC)

	found, err := DiscoverGCPADC(home)
	if err != nil {
		t.Fatalf("DiscoverGCPADC: %v", err)
	}
	if len(found) != 1 || found[0] != path {
		t.Errorf("found = %v, want [%s]", found, path)
	}
}

func TestDiscoverGCPADCMissingFile(t *testing.T) {
	home := t.TempDir()
	found, err := DiscoverGCPADC(home)
	if err != nil {
		t.Fatalf("DiscoverGCPADC with no file: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("found = %v, want empty", found)
	}
}

func TestDiscoverGCPADCSkipsFileWithoutSecrets(t *testing.T) {
	home := t.TempDir()
	// An external_account (workload identity federation) file: real, valid
	// ADC, but nothing on disk to protect — its credential_source fetches
	// tokens at use time. Discover must leave it alone.
	writeGCPADCFixture(t, home, `{"type": "external_account", "audience": "//iam.googleapis.com/x", "credential_source": {"file": "/var/run/token"}}`)

	found, err := DiscoverGCPADC(home)
	if err != nil {
		t.Fatalf("DiscoverGCPADC: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("found = %v, want empty (no refresh_token/private_key)", found)
	}
}

func TestDiscoverGCPADCSkipsNonJSON(t *testing.T) {
	home := t.TempDir()
	writeGCPADCFixture(t, home, "not json at all")

	found, err := DiscoverGCPADC(home)
	if err != nil {
		t.Fatalf("DiscoverGCPADC: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("found = %v, want empty", found)
	}
}

func TestDiscoverGCPADCSkipsExistingFIFO(t *testing.T) {
	home := t.TempDir()
	path := GCPADCPath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}

	// Must return promptly (never open the pipe for read) and skip it.
	found, err := DiscoverGCPADC(home)
	if err != nil {
		t.Fatalf("DiscoverGCPADC: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("found = %v, want empty (already mounted)", found)
	}
}

func TestApplyGCPADCAuthorizedUserRoundTrip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := writeGCPADCFixture(t, home, authorizedUserADC)

	v := newTestVault(t)
	result, err := ApplyGCPADC(v, home, path)
	if err != nil {
		t.Fatalf("ApplyGCPADC: %v", err)
	}
	if result.ProfileName != "gcp-adc" {
		t.Errorf("ProfileName = %q, want gcp-adc", result.ProfileName)
	}
	if result.CredType != "authorized_user" {
		t.Errorf("CredType = %q, want authorized_user", result.CredType)
	}
	if len(result.Variables) != 1 || result.Variables[0] != "REFRESH_TOKEN" {
		t.Fatalf("Variables = %v, want [REFRESH_TOKEN]", result.Variables)
	}

	got, err := v.Get("gcp-adc/REFRESH_TOKEN")
	if err != nil || string(got) != "1//0gExampleRefreshTokenValue-Long_random" {
		t.Errorf("REFRESH_TOKEN = (%q, %v), want the fixture's token", got, err)
	}

	tmpl, err := os.ReadFile(result.TemplatePath)
	if err != nil {
		t.Fatalf("reading template: %v", err)
	}
	if strings.Contains(string(tmpl), "1//0g") {
		t.Errorf("template still contains the refresh token:\n%s", tmpl)
	}
	if !strings.Contains(string(tmpl), `"refresh_token": "${REFRESH_TOKEN}"`) {
		t.Errorf("template missing placeholder:\n%s", tmpl)
	}
	// client_secret is deliberately NOT vaulted (gcloud's public
	// installed-app constant) — it must survive in the template.
	if !strings.Contains(string(tmpl), "d-FL95Q19q7MQmFpd7hHD0Ty") {
		t.Errorf("template lost the non-secret client_secret:\n%s", tmpl)
	}

	// The property everything else rests on: substituting the vault's
	// values back into the template reproduces the original file
	// byte-for-byte — what the agent serves during a reveal window IS the
	// file the SDKs used to read.
	rebuilt := mount.FormatTemplate(tmpl, map[string]string{"REFRESH_TOKEN": string(got)})
	if string(rebuilt) != authorizedUserADC {
		t.Errorf("round trip mismatch:\n got: %q\nwant: %q", rebuilt, authorizedUserADC)
	}

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat mount: %v", err)
	}
	if info.Mode()&fs.ModeNamedPipe == 0 {
		t.Errorf("%s is not a FIFO after ApplyGCPADC", path)
	}

	if result.BackupPath == "" {
		t.Fatal("BackupPath is empty")
	}
	backup, err := v.Get(result.BackupPath)
	if err != nil || string(backup) != authorizedUserADC {
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

func TestApplyGCPADCServiceAccountKeepsEscapedKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := writeGCPADCFixture(t, home, serviceAccountADC)

	v := newTestVault(t)
	result, err := ApplyGCPADC(v, home, path)
	if err != nil {
		t.Fatalf("ApplyGCPADC: %v", err)
	}
	if len(result.Variables) != 1 || result.Variables[0] != "PRIVATE_KEY" {
		t.Fatalf("Variables = %v, want [PRIVATE_KEY]", result.Variables)
	}

	got, err := v.Get("gcp-adc/PRIVATE_KEY")
	if err != nil {
		t.Fatalf("Get PRIVATE_KEY: %v", err)
	}
	// The vault holds the file's RAW escaped bytes (literal backslash-n
	// pairs and the escaped quote), NOT the decoded key — byte-level
	// template substitution depends on it (see ApplyGCPADC's doc comment).
	if !strings.Contains(string(got), `\nMIIEvQIBADANBg\"kq\n`) {
		t.Errorf("PRIVATE_KEY = %q, want the raw escaped JSON string body", got)
	}
	if strings.Contains(string(got), "\n") {
		t.Errorf("PRIVATE_KEY contains a real newline, value was decoded, breaking the served JSON")
	}

	tmpl, err := os.ReadFile(result.TemplatePath)
	if err != nil {
		t.Fatalf("reading template: %v", err)
	}
	rebuilt := mount.FormatTemplate(tmpl, map[string]string{"PRIVATE_KEY": string(got)})
	if string(rebuilt) != serviceAccountADC {
		t.Errorf("round trip mismatch:\n got: %q\nwant: %q", rebuilt, serviceAccountADC)
	}
}

func TestApplyGCPADCNoSecretsFailsBeforeMutating(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := writeGCPADCFixture(t, home, `{"type": "external_account", "audience": "//iam.googleapis.com/x"}`)

	v := newTestVault(t)
	if _, err := ApplyGCPADC(v, home, path); err == nil {
		t.Fatal("ApplyGCPADC succeeded on a file with nothing to migrate")
	}
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), "external_account") {
		t.Errorf("file was mutated by a failed ApplyGCPADC: (%q, %v)", data, err)
	}
}

// The pathological shapes below are files gcloud never writes but a
// secrets tool must still never mishandle: in each, a naive
// first-occurrence byte match would vault the WRONG span and leave the
// real secret sitting in the plaintext template. locateGCPADCSecrets'
// parse-vs-bytes cross-checks must refuse them, Discover must therefore
// skip them (leaving them as audit findings), and a direct Apply must
// fail without mutating the file.

func TestGCPADCRefusesDuplicateAndNestedKeys(t *testing.T) {
	cases := map[string]string{
		// Unmarshal keeps the LAST duplicate; the pattern finds the FIRST.
		"duplicate top-level key": `{"refresh_token": "stale", "refresh_token": "1//0gREAL", "type": "authorized_user"}`,
		// The pattern finds the nested pair before the real top-level one.
		"nested key first": `{"aaa": {"refresh_token": "NESTED"}, "refresh_token": "1//0gREAL", "type": "authorized_user"}`,
		// FormatTemplate substitutes placeholders wherever they appear, so
		// pre-existing placeholder text would get the real secret at serve time.
		"pre-existing placeholder literal": `{"quota_project_id": "${REFRESH_TOKEN}", "refresh_token": "1//0gREAL", "type": "authorized_user"}`,
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			path := writeGCPADCFixture(t, home, content)

			found, err := DiscoverGCPADC(home)
			if err != nil {
				t.Fatalf("DiscoverGCPADC: %v", err)
			}
			if len(found) != 0 {
				t.Errorf("Discover accepted a file locate must refuse: %v", found)
			}

			v := newTestVault(t)
			if _, err := ApplyGCPADC(v, home, path); err == nil {
				t.Fatal("ApplyGCPADC succeeded on a file whose byte spans disagree with its parse")
			}
			data, rerr := os.ReadFile(path)
			if rerr != nil || string(data) != content {
				t.Errorf("file was mutated by a failed ApplyGCPADC: (%q, %v)", data, rerr)
			}
		})
	}
}

func TestGCPADCDiscoverSkipsUnlocatableEscapedKey(t *testing.T) {
	home := t.TempDir()
	// The map key decodes to "refresh_token", but the raw bytes spell it
	// with a \u escape the value pattern can't match. Discover must skip
	// it (audit still reports it) rather than hand Apply a file that
	// would abort a whole `jit migrate home` run mid-way.
	writeGCPADCFixture(t, home, `{"\u0072efresh_token": "1//0gX", "type": "authorized_user"}`)

	found, err := DiscoverGCPADC(home)
	if err != nil {
		t.Fatalf("DiscoverGCPADC: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("Discover accepted a file whose secret bytes can't be located: %v", found)
	}
}

func TestApplyGCPADCFailsLoudOnFIFO(t *testing.T) {
	home := t.TempDir()
	path := GCPADCPath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}

	// Must error promptly (never open the pipe for read — that would hang
	// forever with no agent writing).
	v := newTestVault(t)
	if _, err := ApplyGCPADC(v, home, path); err == nil {
		t.Fatal("ApplyGCPADC succeeded on a FIFO")
	}
}
