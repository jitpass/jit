// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

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
// through vault.Vault.Set, since Set requires a real KeyWrapper. The bytes
// are a structurally valid v2 envelope (a known version, a hex-decodable
// wrapped key and payload) so it passes not just Vault.Exists but doctor's
// auth-free Vault.Verify integrity check — it stops short of anything that
// actually decrypts, so the payload need not be real ciphertext. Use
// plantCorruptSecret for the it-exists-but-won't-read case.
func plantVaultSecret(t *testing.T, home, path string) {
	t.Helper()
	writeVaultEnc(t, home, path, `{"version":2,"recipients":{"test":"00"},"payload":"00"}`)
}

// plantCorruptSecret writes a file that exists but whose envelope this jit
// can't read — here, an envelope version from the future — so a bare
// existence check passes yet Verify fails, exercising doctor's [corrupt]
// path.
func plantCorruptSecret(t *testing.T, home, path string) {
	t.Helper()
	writeVaultEnc(t, home, path, `{"version":999,"recipients":{"test":"00"},"payload":"00"}`)
}

func writeVaultEnc(t *testing.T, home, path, content string) {
	t.Helper()
	full := filepath.Join(home, "Library", "Application Support", "jitpass", "vault", path+".enc")
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func execDoctor(t *testing.T, args ...string) (stdout string, err error) {
	t.Helper()
	doctorProfile = ""
	doctorFormat = "text"
	doctorVerbose = false
	doctorOrphans = false
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
	if !strings.Contains(out, "No profiles found") {
		t.Errorf("expected a no-profiles message, got:\n%s", out)
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
	if !strings.Contains(out, "✓ 1 profile, 1 secret reference all resolve cleanly") {
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
	if !strings.Contains(unwrap(out), "not in the vault") {
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
	withFixtureCwd(t) // no project-local profile at all, only the global one below
	writeFixtureProfile(t, home, "shell", "STRIPE_KEY: stripe/dev-key\n")
	// stripe/dev-key deliberately not planted in the vault.

	out, err := execDoctor(t)
	if err == nil {
		t.Fatal("expected an error, the global-scope profile's secret is missing, got nil")
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
	if !strings.Contains(out, "1 profile,") {
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
	if result.Problems[0].Kind != kindMissing || result.Problems[0].Path != "aws/s3-access-key" || result.Problems[0].Variable != "AWS_ACCESS_KEY_ID" {
		t.Errorf("expected a structured missing finding naming the variable and path, got: %+v", result.Problems)
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

// TestDoctorCorruptEnvelopeFailsLoud is the capability a bare Exists() check
// couldn't provide: a secret whose file is present but whose envelope this
// jit can't read is caught at diagnosis time, not when an app tries to use
// it. Integrity checking is auth-free, so this passes without a KeyWrapper.
func TestDoctorCorruptEnvelopeFailsLoud(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)
	writeFixtureProfile(t, cwd, "aws-admin", "AWS_ACCESS_KEY_ID: aws/s3-access-key\n")
	plantCorruptSecret(t, home, "aws/s3-access-key") // exists, but a future envelope version

	out, err := execDoctor(t)
	if err == nil {
		t.Fatal("expected a non-zero exit for a corrupt envelope, got nil")
	}
	if !strings.Contains(out, "[corrupt]") || !strings.Contains(out, "aws/s3-access-key") {
		t.Errorf("expected a [corrupt] finding naming the secret, got:\n%s", out)
	}
}

// TestDoctorCorruptEnvelopeIsAProblemInJSON confirms the corrupt case is a
// hard problem (ok=false, non-zero exit), structured with kind "corrupt".
func TestDoctorCorruptEnvelopeIsAProblemInJSON(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)
	writeFixtureProfile(t, cwd, "aws-admin", "AWS_ACCESS_KEY_ID: aws/s3-access-key\n")
	plantCorruptSecret(t, home, "aws/s3-access-key")

	out, err := execDoctor(t, "--format", "json")
	if err == nil {
		t.Fatal("expected a non-zero exit for a corrupt envelope in JSON mode, got nil")
	}
	var result doctorResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshaling output %q: %v", out, err)
	}
	if result.OK || len(result.Problems) != 1 || result.Problems[0].Kind != kindCorrupt {
		t.Errorf("expected one structured corrupt problem, got: %+v", result)
	}
}

// TestDoctorOrphansAreAdvisory locks in that a vault secret no profile
// references surfaces under --orphans as a warning — reported, but never a
// reason to fail the run (a clean profile set with an extra secret still
// exits zero).
func TestDoctorOrphansAreAdvisory(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)
	writeFixtureProfile(t, cwd, "aws-admin", "AWS_ACCESS_KEY_ID: aws/s3-access-key\n")
	plantVaultSecret(t, home, "aws/s3-access-key")
	plantVaultSecret(t, home, "stripe/unused-key") // referenced by nothing

	out, err := execDoctor(t, "--orphans")
	if err != nil {
		t.Fatalf("orphans are advisory and must not fail the run: %v", err)
	}
	if !strings.Contains(out, "[orphan]") || !strings.Contains(out, "stripe/unused-key") {
		t.Errorf("expected an orphan warning naming the unused secret, got:\n%s", out)
	}
}

// TestDoctorOrphansOffByDefault confirms the sweep is opt-in: without
// --orphans, an unreferenced secret is silent.
func TestDoctorOrphansOffByDefault(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)
	writeFixtureProfile(t, cwd, "aws-admin", "AWS_ACCESS_KEY_ID: aws/s3-access-key\n")
	plantVaultSecret(t, home, "aws/s3-access-key")
	plantVaultSecret(t, home, "stripe/unused-key")

	out, err := execDoctor(t)
	if err != nil {
		t.Fatalf("jit doctor: %v", err)
	}
	if strings.Contains(out, "orphan") {
		t.Errorf("expected no orphan output without --orphans, got:\n%s", out)
	}
}

// TestDoctorVerboseListsEachReference confirms --verbose turns a passing
// run's bare count into a per-reference listing.
func TestDoctorVerboseListsEachReference(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)
	writeFixtureProfile(t, cwd, "aws-admin", "AWS_ACCESS_KEY_ID: aws/s3-access-key\n")
	plantVaultSecret(t, home, "aws/s3-access-key")

	out, err := execDoctor(t, "--verbose")
	if err != nil {
		t.Fatalf("jit doctor --verbose: %v", err)
	}
	if !strings.Contains(out, "Checked") || !strings.Contains(out, "AWS_ACCESS_KEY_ID → aws/s3-access-key") {
		t.Errorf("expected a per-reference listing under --verbose, got:\n%s", out)
	}
}

// TestDoctorShadowedProfileWarns confirms a profile name present in both
// project and global scope produces a [shadowed] warning (the project copy
// wins; the global one is silently ignored, the "why isn't my global profile
// taking effect" trap). Advisory: it must not fail the run.
func TestDoctorShadowedProfileWarns(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)
	writeFixtureProfile(t, cwd, "shell", "TOKEN: shared/token\n")  // project
	writeFixtureProfile(t, home, "shell", "TOKEN: shared/token\n") // global, same name
	plantVaultSecret(t, home, "shared/token")

	out, err := execDoctor(t)
	if err != nil {
		t.Fatalf("a shadowed profile is advisory and must not fail the run: %v", err)
	}
	if !strings.Contains(out, "[shadowed]") || !strings.Contains(out, "shell") {
		t.Errorf("expected a [shadowed] warning naming the profile, got:\n%s", out)
	}
}

// TestDoctorBackupWarningOnFullRun confirms the absorbed backup section fires:
// a populated vault with no recorded export gets a [backup] warning, without
// failing the run.
func TestDoctorBackupWarningOnFullRun(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)
	writeFixtureProfile(t, cwd, "aws-admin", "AWS_ACCESS_KEY_ID: aws/s3-access-key\n")
	plantVaultSecret(t, home, "aws/s3-access-key")

	out, err := execDoctor(t)
	if err != nil {
		t.Fatalf("a backup warning is advisory and must not fail the run: %v", err)
	}
	if !strings.Contains(out, "[backup]") || !strings.Contains(out, "vault export") {
		t.Errorf("expected a [backup] warning on a populated, never-exported vault, got:\n%s", out)
	}
}

// TestDoctorProfileFlagSkipsSystemSections confirms --profile narrows to the
// one profile and does NOT emit the agent/backup/wrap health warnings the
// full sweep would — otherwise the focused query becomes surprising noise.
func TestDoctorProfileFlagSkipsSystemSections(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)
	writeFixtureProfile(t, cwd, "aws-admin", "AWS_ACCESS_KEY_ID: aws/s3-access-key\n")
	plantVaultSecret(t, home, "aws/s3-access-key") // populated vault, no export -> would warn on a full run

	out, err := execDoctor(t, "--profile", "aws-admin")
	if err != nil {
		t.Fatalf("jit doctor --profile aws-admin: %v", err)
	}
	if strings.Contains(out, "[backup]") || strings.Contains(out, "[service]") || strings.Contains(out, "[wrap]") {
		t.Errorf("expected no system-health warnings under --profile, got:\n%s", out)
	}
}
