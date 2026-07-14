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

func writeAWSFixture(t *testing.T, home, credentials, config string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(home, ".aws"), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if credentials != "" {
		writeFile(t, AWSCredentialsPath(home), credentials)
	}
	if config != "" {
		writeFile(t, AWSConfigPath(home), config)
	}
}

func TestDiscoverAWSProfilesFindsProfilesWithSecrets(t *testing.T) {
	home := t.TempDir()
	writeAWSFixture(t, home, "[default]\naws_access_key_id = AKIA1\naws_secret_access_key = secret1\n\n[prod]\naws_access_key_id = AKIA2\naws_secret_access_key = secret2\n\n[empty]\nregion = us-east-1\n", "")

	found, err := DiscoverAWSProfiles(home)
	if err != nil {
		t.Fatalf("DiscoverAWSProfiles: %v", err)
	}
	want := []string{"default", "prod"}
	if len(found) != len(want) {
		t.Fatalf("found = %v, want %v", found, want)
	}
	for i := range want {
		if found[i] != want[i] {
			t.Errorf("found[%d] = %q, want %q", i, found[i], want[i])
		}
	}
}

func TestDiscoverAWSProfilesMissingFile(t *testing.T) {
	home := t.TempDir()
	found, err := DiscoverAWSProfiles(home)
	if err != nil {
		t.Fatalf("DiscoverAWSProfiles with no credentials file: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("found = %v, want empty", found)
	}
}

func TestApplyAWSProfileDefaultUsesBareSectionInConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeAWSFixture(t, home,
		"[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nregion = us-east-1\n",
		"")

	v := newTestVault(t)
	result, err := ApplyAWSProfile(v, home, "default")
	if err != nil {
		t.Fatalf("ApplyAWSProfile: %v", err)
	}
	if result.VaultProfileName != "aws-default" {
		t.Errorf("VaultProfileName = %q, want aws-default", result.VaultProfileName)
	}
	wantVars := []string{"ACCESS_KEY_ID", "SECRET_ACCESS_KEY"}
	if len(result.Variables) != len(wantVars) {
		t.Fatalf("Variables = %v, want %v", result.Variables, wantVars)
	}

	got, err := v.Get("aws-default/ACCESS_KEY_ID")
	if err != nil || string(got) != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("ACCESS_KEY_ID = (%q, %v), want (AKIAIOSFODNN7EXAMPLE, nil)", got, err)
	}
	got, err = v.Get("aws-default/SECRET_ACCESS_KEY")
	if err != nil || string(got) != "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" {
		t.Errorf("SECRET_ACCESS_KEY = (%q, %v), want the original secret", got, err)
	}

	credRaw, err := os.ReadFile(AWSCredentialsPath(home)) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading rewritten credentials: %v", err)
	}
	credContent := string(credRaw)
	if strings.Contains(credContent, "wJalrXUtnFEMI") {
		t.Error("rewritten credentials file must not contain the raw secret value")
	}
	if !strings.Contains(credContent, "[default]") {
		t.Error("rewritten credentials file lost the [default] section header")
	}
	if !strings.Contains(credContent, "region = us-east-1") {
		t.Error("rewritten credentials file lost an unrelated key (region)")
	}

	configRaw, err := os.ReadFile(AWSConfigPath(home)) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading rewritten config: %v", err)
	}
	configContent := string(configRaw)
	if !strings.Contains(configContent, "[default]") {
		t.Errorf("expected a bare [default] section (not [profile default]), got:\n%s", configContent)
	}
	if strings.Contains(configContent, "[profile default]") {
		t.Errorf("must never use [profile default] — AWS's own default section is always bare [default], got:\n%s", configContent)
	}
	if !strings.Contains(configContent, "credential_process") || !strings.Contains(configContent, "aws-credential-process") || !strings.Contains(configContent, "--profile aws-default") {
		t.Errorf("expected a credential_process line invoking jit aws-credential-process --profile aws-default, got:\n%s", configContent)
	}
}

func TestApplyAWSProfileNamedUsesProfilePrefixInConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeAWSFixture(t, home,
		"[prod]\naws_access_key_id = AKIAPROD\naws_secret_access_key = secretprod\n",
		"[profile other]\nregion = eu-west-1\n")

	v := newTestVault(t)
	if _, err := ApplyAWSProfile(v, home, "prod"); err != nil {
		t.Fatalf("ApplyAWSProfile: %v", err)
	}

	configRaw, err := os.ReadFile(AWSConfigPath(home)) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading rewritten config: %v", err)
	}
	configContent := string(configRaw)
	if !strings.Contains(configContent, "[profile prod]") {
		t.Errorf("expected a [profile prod] section for a non-default profile, got:\n%s", configContent)
	}
	if !strings.Contains(configContent, "[profile other]") || !strings.Contains(configContent, "region = eu-west-1") {
		t.Errorf("expected the pre-existing [profile other] section preserved untouched, got:\n%s", configContent)
	}
}

func TestApplyAWSProfileWithSessionToken(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeAWSFixture(t, home,
		"[default]\naws_access_key_id = AKIA1\naws_secret_access_key = secret1\naws_session_token = tok123\n",
		"")

	v := newTestVault(t)
	result, err := ApplyAWSProfile(v, home, "default")
	if err != nil {
		t.Fatalf("ApplyAWSProfile: %v", err)
	}
	found := false
	for _, name := range result.Variables {
		if name == "SESSION_TOKEN" {
			found = true
		}
	}
	if !found {
		t.Errorf("Variables = %v, want it to include SESSION_TOKEN", result.Variables)
	}
	got, err := v.Get("aws-default/SESSION_TOKEN")
	if err != nil || string(got) != "tok123" {
		t.Errorf("SESSION_TOKEN = (%q, %v), want (tok123, nil)", got, err)
	}
}

func TestApplyAWSProfileWritesBackups(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	originalCreds := "[default]\naws_access_key_id = AKIA1\naws_secret_access_key = secret1\n"
	originalConfig := "[default]\nregion = us-east-1\n"
	writeAWSFixture(t, home, originalCreds, originalConfig)

	v := newTestVault(t)
	result, err := ApplyAWSProfile(v, home, "default")
	if err != nil {
		t.Fatalf("ApplyAWSProfile: %v", err)
	}

	credBackup, err := v.Get(result.CredentialsBackup)
	if err != nil {
		t.Fatalf("reading credentials backup from vault: %v", err)
	}
	if string(credBackup) != originalCreds {
		t.Errorf("credentials backup = %q, want %q", credBackup, originalCreds)
	}

	configBackup, err := v.Get(result.ConfigBackup)
	if err != nil {
		t.Fatalf("reading config backup from vault: %v", err)
	}
	if string(configBackup) != originalConfig {
		t.Errorf("config backup = %q, want %q", configBackup, originalConfig)
	}
}

func TestApplyAWSProfileNoConfigFileYet(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeAWSFixture(t, home, "[default]\naws_access_key_id = AKIA1\naws_secret_access_key = secret1\n", "")

	v := newTestVault(t)
	result, err := ApplyAWSProfile(v, home, "default")
	if err != nil {
		t.Fatalf("ApplyAWSProfile with no pre-existing ~/.aws/config: %v", err)
	}
	if result.ConfigBackup != "" {
		t.Errorf("ConfigBackup = %q, want empty since there was nothing to back up", result.ConfigBackup)
	}
	if _, err := os.Stat(AWSConfigPath(home)); err != nil {
		t.Errorf("expected ~/.aws/config to be created: %v", err)
	}

	// The created-fresh config must be recorded as RemoveOnRestore so undo
	// deletes it — otherwise undo restores ~/.aws/credentials but leaves a
	// dangling credential_process in the jit-created config.
	recs, err := LoadBackupRecords(v.Root)
	if err != nil {
		t.Fatalf("LoadBackupRecords: %v", err)
	}
	absConfig, _ := filepath.Abs(AWSConfigPath(home))
	var removeRec *BackupRecord
	for i := range recs {
		if recs[i].OriginalPath == absConfig && recs[i].RemoveOnRestore {
			removeRec = &recs[i]
		}
	}
	if removeRec == nil {
		t.Fatalf("expected a RemoveOnRestore record for the created %s; records: %+v", absConfig, recs)
	}

	// Undoing that record removes the created config.
	if err := RestoreFromBackup(v, *removeRec); err != nil {
		t.Fatalf("RestoreFromBackup(RemoveOnRestore): %v", err)
	}
	if _, err := os.Stat(AWSConfigPath(home)); !os.IsNotExist(err) {
		t.Errorf("expected ~/.aws/config to be removed by undo, stat err = %v", err)
	}
	// Idempotent: a second undo of the same record (file already gone) is
	// not an error.
	if err := RestoreFromBackup(v, *removeRec); err != nil {
		t.Errorf("RestoreFromBackup on an already-removed file should be a no-op, got: %v", err)
	}
}

// TestApplyAWSMultiProfileUndoRestoresPristine is the regression test for
// GAPS.md #65: migrating two profiles out of one ~/.aws/credentials and then
// undoing must restore the pristine file with BOTH profiles' keys, not the
// last, most-stripped intermediate snapshot. Before the shared BackupTracker,
// each profile's Apply backed the file up again after the previous profile
// was already stripped from it, and undo (LatestBackups: most-recent per
// path) restored the degraded copy — the first profile's keys came back gone.
func TestApplyAWSMultiProfileUndoRestoresPristine(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	originalCreds := "[default]\naws_access_key_id = AKIAFIRST\naws_secret_access_key = secretfirst\n\n[staging]\naws_access_key_id = AKIASECOND\naws_secret_access_key = secretsecond\n"
	writeAWSFixture(t, home, originalCreds, "") // no pre-existing config

	v := newTestVault(t)
	tracker := NewBackupTracker() // one tracker for the run, exactly as the CLI does
	for _, name := range []string{"default", "staging"} {
		if _, err := ApplyAWSProfile(v, home, name, tracker); err != nil {
			t.Fatalf("ApplyAWSProfile(%s): %v", name, err)
		}
	}

	recs, err := LoadBackupRecords(v.Root)
	if err != nil {
		t.Fatalf("LoadBackupRecords: %v", err)
	}

	// Exactly one pristine credentials backup, not one per profile.
	absCreds, _ := filepath.Abs(AWSCredentialsPath(home))
	credBackups := 0
	for _, r := range recs {
		if r.OriginalPath == absCreds && !r.RemoveOnRestore {
			credBackups++
		}
	}
	if credBackups != 1 {
		t.Errorf("expected exactly 1 pristine credentials backup for a 2-profile run, got %d", credBackups)
	}

	// Simulate `jit migrate undo`: restore the record undo would pick per path.
	for _, rec := range LatestBackups(recs) {
		if err := RestoreFromBackup(v, rec); err != nil {
			t.Fatalf("RestoreFromBackup(%s): %v", rec.OriginalPath, err)
		}
	}

	got, err := os.ReadFile(AWSCredentialsPath(home))
	if err != nil {
		t.Fatalf("reading restored credentials: %v", err)
	}
	if string(got) != originalCreds {
		t.Errorf("restored credentials not pristine:\n got: %q\nwant: %q", got, originalCreds)
	}

	// The jit-created config is removed, not left behind with dangling
	// credential_process lines.
	if _, err := os.Stat(AWSConfigPath(home)); !os.IsNotExist(err) {
		t.Errorf("expected jit-created ~/.aws/config to be removed by undo, stat err = %v", err)
	}
}

// TestApplyAWSMultiProfileExistingConfigUndoRestoresPristine is the sibling
// of the above for the case where ~/.aws/config already existed: it too must
// be backed up once (pristine) and restored to that state, not to an
// intermediate snapshot carrying only the first profile's credential_process.
func TestApplyAWSMultiProfileExistingConfigUndoRestoresPristine(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	originalCreds := "[default]\naws_access_key_id = AKIAFIRST\naws_secret_access_key = secretfirst\n\n[staging]\naws_access_key_id = AKIASECOND\naws_secret_access_key = secretsecond\n"
	originalConfig := "[default]\nregion = us-east-1\n"
	writeAWSFixture(t, home, originalCreds, originalConfig)

	v := newTestVault(t)
	tracker := NewBackupTracker()
	for _, name := range []string{"default", "staging"} {
		if _, err := ApplyAWSProfile(v, home, name, tracker); err != nil {
			t.Fatalf("ApplyAWSProfile(%s): %v", name, err)
		}
	}

	recs, err := LoadBackupRecords(v.Root)
	if err != nil {
		t.Fatalf("LoadBackupRecords: %v", err)
	}
	for _, rec := range LatestBackups(recs) {
		if err := RestoreFromBackup(v, rec); err != nil {
			t.Fatalf("RestoreFromBackup(%s): %v", rec.OriginalPath, err)
		}
	}

	gotCreds, _ := os.ReadFile(AWSCredentialsPath(home))
	if string(gotCreds) != originalCreds {
		t.Errorf("restored credentials not pristine:\n got: %q\nwant: %q", gotCreds, originalCreds)
	}
	gotConfig, err := os.ReadFile(AWSConfigPath(home))
	if err != nil {
		t.Fatalf("reading restored config: %v", err)
	}
	if string(gotConfig) != originalConfig {
		t.Errorf("restored config not pristine:\n got: %q\nwant: %q", gotConfig, originalConfig)
	}
}

func TestApplyAWSProfileMissingProfileErrors(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeAWSFixture(t, home, "[default]\naws_access_key_id = AKIA1\naws_secret_access_key = secret1\n", "")

	v := newTestVault(t)
	if _, err := ApplyAWSProfile(v, home, "nonexistent"); err == nil {
		t.Fatal("expected an error migrating a profile that doesn't exist")
	}
}

func TestApplyAWSProfileVaultProfileResolvableViaGlobalFallback(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeAWSFixture(t, home, "[default]\naws_access_key_id = AKIA1\naws_secret_access_key = secret1\n", "")

	v := newTestVault(t)
	result, err := ApplyAWSProfile(v, home, "default")
	if err != nil {
		t.Fatalf("ApplyAWSProfile: %v", err)
	}

	// AWS CLI invokes credential_process from an arbitrary cwd, not any
	// jit project directory — the profile must resolve via the global
	// fallback regardless.
	p, err := profile.Load(t.TempDir(), result.VaultProfileName)
	if err != nil {
		t.Fatalf("loading migrated profile via the global fallback: %v", err)
	}
	if p["ACCESS_KEY_ID"] != "aws-default/ACCESS_KEY_ID" {
		t.Errorf("profile entry = %q, want aws-default/ACCESS_KEY_ID", p["ACCESS_KEY_ID"])
	}
}
