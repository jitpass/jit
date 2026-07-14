// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/vault"
)

// withFixtureCwd chdirs into a fresh temp directory for the duration of the
// test and restores the real working directory afterward — doctor resolves
// profiles relative to os.Getwd(), so tests must never touch the real cwd.
func withFixtureCwd(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	original, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("os.Chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(original) })
	return dir
}

func writeFixtureProfile(t *testing.T, cwd, name, content string) {
	t.Helper()
	dir := filepath.Join(cwd, ".jit", "profiles")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".yaml"), []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

// plantVaultSecret writes a vault-shaped file directly rather than going
// through vault.Vault.Set, since Set requires a real KeyWrapper —
// doctor only ever checks existence (Vault.Exists), which is oblivious to
// the file's actual contents.
func plantVaultSecret(t *testing.T, home, path string) {
	t.Helper()
	full := filepath.Join(home, "Library", "Application Support", "jitpass", "vault", path+".enc")
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(full, []byte("{}"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func execDoctor(t *testing.T, args ...string) (stdout string, err error) {
	t.Helper()
	doctorProfile = ""
	doctorFormat = "text"
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetArgs(append([]string{"doctor"}, args...))
	err = rootCmd.Execute()
	return buf.String(), err
}

func TestDoctorNoProfiles(t *testing.T) {
	withFixtureHome(t)
	withFixtureCwd(t)

	out, err := execDoctor(t)
	if err != nil {
		t.Fatalf("jit doctor: %v", err)
	}
	if !strings.Contains(out, "nothing to check") {
		t.Errorf("expected a nothing-to-check message, got:\n%s", out)
	}
}

func TestDoctorAllSecretsResolve(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)
	writeFixtureProfile(t, cwd, "aws-admin", "AWS_ACCESS_KEY_ID: aws/s3-access-key\n")
	plantVaultSecret(t, home, "aws/s3-access-key")

	out, err := execDoctor(t)
	if err != nil {
		t.Fatalf("jit doctor: %v", err)
	}
	if !strings.Contains(out, "✓ 1 profile(s), 1 secret reference(s) all resolve cleanly") {
		t.Errorf("expected a clean success message, got:\n%s", out)
	}
}

func TestDoctorMissingSecretFailsLoud(t *testing.T) {
	_ = withFixtureHome(t)
	cwd := withFixtureCwd(t)
	writeFixtureProfile(t, cwd, "aws-admin", "AWS_ACCESS_KEY_ID: aws/s3-access-key\n")
	// No plantVaultSecret call — the referenced path doesn't exist.

	out, err := execDoctor(t)
	if err == nil {
		t.Fatal("expected an error when a profile references a missing secret, got nil")
	}
	if !strings.Contains(out, "AWS_ACCESS_KEY_ID") || !strings.Contains(out, "aws/s3-access-key") {
		t.Errorf("expected the output to name the missing variable and path, got:\n%s", out)
	}
	if !strings.Contains(out, "not in the vault") {
		t.Errorf("expected an explicit missing-from-vault reason, got:\n%s", out)
	}
	if !strings.Contains(out, "jit vault set aws/s3-access-key") {
		t.Errorf("expected a remediation hint naming the fix command, got:\n%s", out)
	}
}

// TestDoctorChecksGlobalScopeProfilesByDefault locks in a real, reported
// bug fix: a bare `jit doctor` used to call profile.ListNames(cwd)
// (project-local only), so a home-rooted global profile — the kind jit
// migrate writes for shell-config/MCP/AWS/kubeconfig/npmrc secrets — was
// invisible unless you already knew to pass --profile by name. jit
// status and jit profile list both counted it; doctor silently didn't.
func TestDoctorChecksGlobalScopeProfilesByDefault(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t) // no project-local profile at all — only the global one below
	writeFixtureProfile(t, home, "shell", "STRIPE_KEY: stripe/dev-key\n")
	// stripe/dev-key deliberately not planted in the vault.

	out, err := execDoctor(t)
	if err == nil {
		t.Fatal("expected an error — the global-scope profile's secret is missing, got nil")
	}
	if !strings.Contains(out, "STRIPE_KEY") || !strings.Contains(out, "stripe/dev-key") {
		t.Errorf("expected the global-scope profile's missing variable to be reported, got:\n%s", out)
	}
}

func TestDoctorSpecificProfileFlag(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)
	writeFixtureProfile(t, cwd, "aws-admin", "AWS_ACCESS_KEY_ID: aws/s3-access-key\n")
	writeFixtureProfile(t, cwd, "stripe", "STRIPE_KEY: stripe/dev-key\n")
	plantVaultSecret(t, home, "aws/s3-access-key")
	// stripe/dev-key deliberately not planted — would fail doctor if checked.

	out, err := execDoctor(t, "--profile", "aws-admin")
	if err != nil {
		t.Fatalf("jit doctor --profile aws-admin: %v", err)
	}
	if !strings.Contains(out, "1 profile(s)") {
		t.Errorf("expected only the named profile to be checked, got:\n%s", out)
	}
}

func TestDoctorMalformedProfileFailsLoud(t *testing.T) {
	withFixtureHome(t)
	cwd := withFixtureCwd(t)
	writeFixtureProfile(t, cwd, "broken", "[not valid yaml")

	_, err := execDoctor(t)
	if err == nil {
		t.Fatal("expected an error for a malformed profile, got nil")
	}
}

// TestDoctorFormatJSONAllSecretsResolve confirms GAPS.md #22: --format json
// emits a parseable snapshot with ok=true and an empty problems list on a
// clean fixture, still exiting zero.
func TestDoctorFormatJSONAllSecretsResolve(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)
	writeFixtureProfile(t, cwd, "aws-admin", "AWS_ACCESS_KEY_ID: aws/s3-access-key\n")
	plantVaultSecret(t, home, "aws/s3-access-key")

	out, err := execDoctor(t, "--format", "json")
	if err != nil {
		t.Fatalf("jit doctor --format json: %v", err)
	}
	var result doctorResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshaling output %q: %v", out, err)
	}
	if !result.OK || result.ProfilesChecked != 1 || result.SecretsChecked != 1 || len(result.Problems) != 0 {
		t.Errorf("unexpected result: %+v", result)
	}
}

// TestDoctorFormatJSONMissingSecretStillFailsLoud confirms JSON mode keeps
// doctor's non-zero-exit-on-problem behavior — a CI health check consuming
// this needs both the parseable body AND a reliable exit code, not one or
// the other.
func TestDoctorFormatJSONMissingSecretStillFailsLoud(t *testing.T) {
	withFixtureHome(t)
	cwd := withFixtureCwd(t)
	writeFixtureProfile(t, cwd, "aws-admin", "AWS_ACCESS_KEY_ID: aws/s3-access-key\n")

	out, err := execDoctor(t, "--format", "json")
	if err == nil {
		t.Fatal("expected a non-zero exit for a missing secret in JSON mode too, got nil")
	}
	var result doctorResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshaling output %q: %v", out, err)
	}
	if result.OK || len(result.Problems) != 1 {
		t.Errorf("unexpected result: %+v", result)
	}
	if !strings.Contains(result.Problems[0], "aws/s3-access-key") {
		t.Errorf("expected the missing path in the JSON problems list, got: %+v", result.Problems)
	}
}

func TestDoctorFormatRejectsUnknownValue(t *testing.T) {
	withFixtureHome(t)
	withFixtureCwd(t)

	_, err := execDoctor(t, "--format", "yaml")
	if err == nil {
		t.Fatal("expected an error for an unknown --format value, got nil")
	}
}

// TestDoctorNeverCallsKeyWrapper confirms doctor's Vault has no KeyWrapper
// and still works — Exists must never touch it.
func TestDoctorNeverCallsKeyWrapper(t *testing.T) {
	home := withFixtureHome(t)
	v := &vault.Vault{Root: filepath.Join(home, "Library", "Application Support", "jitpass"), RecipientID: "test"}
	if _, err := v.Exists("does/not-exist"); err != nil {
		t.Fatalf("Exists with a nil KeyWrapper: %v", err)
	}
}
