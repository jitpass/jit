// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package migrate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/profile"
)

func writeTerraformCredentials(t *testing.T, home, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(home, ".terraform.d"), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	writeFile(t, TerraformCredentialsPath(home), content)
}

const tfrcTwoHosts = `{
  "credentials": {
    "app.terraform.io": {
      "token": "atlasv1.secret-token-A"
    },
    "tfe.corp.example": {
      "token": "atlasv1.secret-token-B"
    }
  }
}`

func TestDiscoverTerraformHostsSortedNonEmptyOnly(t *testing.T) {
	home := t.TempDir()
	writeTerraformCredentials(t, home, `{
  "credentials": {
    "tfe.corp.example": {"token": "atlasv1.b"},
    "app.terraform.io": {"token": "atlasv1.a"},
    "empty.example": {"token": ""}
  }
}`)

	hosts, err := DiscoverTerraformHosts(home)
	if err != nil {
		t.Fatalf("DiscoverTerraformHosts: %v", err)
	}
	want := []string{"app.terraform.io", "tfe.corp.example"}
	if len(hosts) != len(want) {
		t.Fatalf("hosts = %v, want %v", hosts, want)
	}
	for i := range want {
		if hosts[i] != want[i] {
			t.Errorf("hosts[%d] = %q, want %q", i, hosts[i], want[i])
		}
	}
}

func TestDiscoverTerraformHostsMissingFile(t *testing.T) {
	hosts, err := DiscoverTerraformHosts(t.TempDir())
	if err != nil {
		t.Fatalf("DiscoverTerraformHosts with no credentials file: %v", err)
	}
	if len(hosts) != 0 {
		t.Errorf("hosts = %v, want empty", hosts)
	}
}

// A file jit can't parse is also one it could never safely rewrite —
// discovery yields nothing rather than killing a whole `jit migrate
// home` sweep over one malformed file.
func TestDiscoverTerraformHostsMalformedFile(t *testing.T) {
	home := t.TempDir()
	writeTerraformCredentials(t, home, "not json at all")

	hosts, err := DiscoverTerraformHosts(home)
	if err != nil {
		t.Fatalf("DiscoverTerraformHosts with a malformed file: %v", err)
	}
	if len(hosts) != 0 {
		t.Errorf("hosts = %v, want empty for an unparseable file", hosts)
	}
}

func TestApplyTerraformHostEndToEnd(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeTerraformCredentials(t, home, tfrcTwoHosts)

	v := newTestVault(t)
	result, err := ApplyTerraformHost(v, home, "app.terraform.io")
	if err != nil {
		t.Fatalf("ApplyTerraformHost: %v", err)
	}
	if result.VaultProfileName != "terraform-app.terraform.io" {
		t.Errorf("VaultProfileName = %q, want terraform-app.terraform.io", result.VaultProfileName)
	}

	got, err := v.Get("terraform-app.terraform.io/TOKEN")
	if err != nil || string(got) != "atlasv1.secret-token-A" {
		t.Errorf("TOKEN = (%q, %v), want the original token", got, err)
	}

	p, err := profile.LoadFile(result.VaultProfilePath)
	if err != nil {
		t.Fatalf("loading written profile: %v", err)
	}
	if p["TOKEN"] != "terraform-app.terraform.io/TOKEN" {
		t.Errorf("profile TOKEN = %q, want terraform-app.terraform.io/TOKEN", p["TOKEN"])
	}

	// The migrated host's token is gone; the other host's entry survives
	// byte-relevant intact.
	credRaw, err := os.ReadFile(TerraformCredentialsPath(home)) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading rewritten credentials: %v", err)
	}
	if strings.Contains(string(credRaw), "atlasv1.secret-token-A") {
		t.Error("rewritten credentials file must not contain the migrated token")
	}
	var reparsed struct {
		Credentials map[string]struct {
			Token string `json:"token"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal(credRaw, &reparsed); err != nil {
		t.Fatalf("rewritten credentials file is not valid JSON: %v", err)
	}
	if _, ok := reparsed.Credentials["app.terraform.io"]; ok {
		t.Error("migrated host still present in rewritten credentials file")
	}
	if reparsed.Credentials["tfe.corp.example"].Token != "atlasv1.secret-token-B" {
		t.Error("unrelated host's token was not preserved")
	}

	// The helper wiring: an executable script exec-ing jit, and the
	// credentials_helper block in a freshly-created ~/.terraformrc.
	helperRaw, err := os.ReadFile(result.HelperPath) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading helper script: %v", err)
	}
	if !strings.Contains(string(helperRaw), "terraform-credentials \"$@\"") {
		t.Errorf("helper script = %q, want it to exec `jit terraform-credentials`", helperRaw)
	}
	info, err := os.Stat(result.HelperPath)
	if err != nil {
		t.Fatalf("stat helper: %v", err)
	}
	if info.Mode().Perm()&0o100 == 0 {
		t.Errorf("helper script mode = %v, want owner-executable, terraform discovers helpers as executables", info.Mode())
	}

	rcRaw, err := os.ReadFile(TerraformRCPath(home)) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading .terraformrc: %v", err)
	}
	if !strings.Contains(string(rcRaw), `credentials_helper "jit"`) {
		t.Errorf(".terraformrc = %q, want a credentials_helper \"jit\" block", rcRaw)
	}
	if result.RCBackup != "" {
		t.Errorf("RCBackup = %q, want empty when ~/.terraformrc didn't exist before", result.RCBackup)
	}
	if result.CredentialsBackup == "" {
		t.Error("CredentialsBackup is empty, the pre-rewrite backup must be recorded")
	}
}

// A second host migrated after the first must merge into the state the
// first run left (helper block already present — not duplicated) and
// leave the credentials file empty of both.
func TestApplyTerraformHostSecondHostIdempotentWiring(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeTerraformCredentials(t, home, tfrcTwoHosts)
	v := newTestVault(t)

	if _, err := ApplyTerraformHost(v, home, "app.terraform.io"); err != nil {
		t.Fatalf("first ApplyTerraformHost: %v", err)
	}
	result, err := ApplyTerraformHost(v, home, "tfe.corp.example")
	if err != nil {
		t.Fatalf("second ApplyTerraformHost: %v", err)
	}
	if result.RCBackup == "" {
		t.Error("RCBackup empty on the second run, ~/.terraformrc existed by then and must be backed up before any rewrite")
	}

	rcRaw, err := os.ReadFile(TerraformRCPath(home)) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading .terraformrc: %v", err)
	}
	if n := strings.Count(string(rcRaw), "credentials_helper"); n != 1 {
		t.Errorf("credentials_helper appears %d time(s) after two migrations, want exactly 1:\n%s", n, rcRaw)
	}

	got, err := v.Get("terraform-tfe.corp.example/TOKEN")
	if err != nil || string(got) != "atlasv1.secret-token-B" {
		t.Errorf("second host's TOKEN = (%q, %v), want the original token", got, err)
	}
}

// TestApplyTerraformMultiHostUndoRestoresPristine is the terraform sibling of
// the AWS multi-profile regression (GAPS.md #65): with a shared BackupTracker
// (as the CLI uses), migrating two hosts out of one credentials.tfrc.json and
// undoing restores the pristine file with BOTH tokens, and the jit-created
// ~/.terraformrc is removed rather than left behind with jit's helper block.
func TestApplyTerraformMultiHostUndoRestoresPristine(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeTerraformCredentials(t, home, tfrcTwoHosts)
	originalCreds, err := os.ReadFile(TerraformCredentialsPath(home)) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading original credentials: %v", err)
	}

	v := newTestVault(t)
	tracker := NewBackupTracker() // one tracker for the run, exactly as the CLI does
	for _, host := range []string{"app.terraform.io", "tfe.corp.example"} {
		if _, err := ApplyTerraformHost(v, home, host, tracker); err != nil {
			t.Fatalf("ApplyTerraformHost(%s): %v", host, err)
		}
	}

	recs, err := LoadBackupRecords(v.Root)
	if err != nil {
		t.Fatalf("LoadBackupRecords: %v", err)
	}
	// Exactly one pristine credentials backup, not one per host.
	absCreds, _ := filepath.Abs(TerraformCredentialsPath(home))
	credBackups := 0
	for _, r := range recs {
		if r.OriginalPath == absCreds && !r.RemoveOnRestore {
			credBackups++
		}
	}
	if credBackups != 1 {
		t.Errorf("expected exactly 1 pristine credentials backup for a 2-host run, got %d", credBackups)
	}

	for _, rec := range LatestBackups(recs) {
		if err := RestoreFromBackup(v, rec); err != nil {
			t.Fatalf("RestoreFromBackup(%s): %v", rec.OriginalPath, err)
		}
	}

	gotCreds, _ := os.ReadFile(TerraformCredentialsPath(home)) // #nosec G304 -- test-controlled path
	if string(gotCreds) != string(originalCreds) {
		t.Errorf("restored credentials not pristine:\n got: %q\nwant: %q", gotCreds, originalCreds)
	}
	if _, err := os.Stat(TerraformRCPath(home)); !os.IsNotExist(err) {
		t.Errorf("expected jit-created ~/.terraformrc to be removed by undo, stat err = %v", err)
	}
}

// An existing ~/.terraformrc with the user's own content must keep it;
// one already configuring a DIFFERENT credentials helper is a hard stop
// before anything is mutated — Terraform allows only one helper, and
// replacing the user's own deliberate configuration is not jit's call.
func TestApplyTerraformHostPreservesExistingRCAndRefusesConflict(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeTerraformCredentials(t, home, tfrcTwoHosts)
	writeFile(t, TerraformRCPath(home), "plugin_cache_dir = \"$HOME/.terraform.d/plugin-cache\"\n")
	v := newTestVault(t)

	if _, err := ApplyTerraformHost(v, home, "app.terraform.io"); err != nil {
		t.Fatalf("ApplyTerraformHost: %v", err)
	}
	rcRaw, err := os.ReadFile(TerraformRCPath(home)) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading .terraformrc: %v", err)
	}
	if !strings.Contains(string(rcRaw), "plugin_cache_dir") {
		t.Errorf(".terraformrc lost the user's existing content:\n%s", rcRaw)
	}
	if !strings.Contains(string(rcRaw), `credentials_helper "jit"`) {
		t.Errorf(".terraformrc missing jit's helper block:\n%s", rcRaw)
	}

	// Conflict case, from scratch.
	home2 := t.TempDir()
	t.Setenv("HOME", home2)
	writeTerraformCredentials(t, home2, tfrcTwoHosts)
	writeFile(t, TerraformRCPath(home2), "credentials_helper \"keychain\" {\n  args = []\n}\n")

	_, err = ApplyTerraformHost(v, home2, "app.terraform.io")
	if err == nil || !strings.Contains(err.Error(), "keychain") {
		t.Fatalf("expected a conflict error naming the existing helper, got %v", err)
	}
	credRaw, err := os.ReadFile(TerraformCredentialsPath(home2)) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading credentials after refused run: %v", err)
	}
	if !strings.Contains(string(credRaw), "atlasv1.secret-token-A") {
		t.Error("a refused (conflicting) run must leave the credentials file untouched")
	}
}

func TestStoreAndForgetTerraformToken(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	v := newTestVault(t)

	if err := StoreTerraformToken(v, "app.terraform.io", "atlasv1.fresh"); err != nil {
		t.Fatalf("StoreTerraformToken: %v", err)
	}
	got, err := v.Get("terraform-app.terraform.io/TOKEN")
	if err != nil || string(got) != "atlasv1.fresh" {
		t.Errorf("TOKEN after store = (%q, %v), want atlasv1.fresh", got, err)
	}
	globalRoot, _ := profile.GlobalRoot()
	manifestPath, _ := profile.Path(globalRoot, "terraform-app.terraform.io")
	if _, err := os.Stat(manifestPath); err != nil {
		t.Errorf("profile manifest missing after store: %v", err)
	}

	if err := ForgetTerraformToken(v, "app.terraform.io"); err != nil {
		t.Fatalf("ForgetTerraformToken: %v", err)
	}
	if exists, _ := v.Exists("terraform-app.terraform.io/TOKEN"); exists {
		t.Error("TOKEN still in vault after forget")
	}
	if _, err := os.Stat(manifestPath); !os.IsNotExist(err) {
		t.Errorf("profile manifest still present after forget: %v", err)
	}

	// Forgetting a host that was never stored is a no-op, matching how
	// terraform treats a logout with nothing saved.
	if err := ForgetTerraformToken(v, "never.example"); err != nil {
		t.Errorf("ForgetTerraformToken on an unknown host: %v", err)
	}
}
