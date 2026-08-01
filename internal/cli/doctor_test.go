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

	"github.com/spf13/pflag"

	"github.com/jitpass/jit/internal/mount"
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

// registerFixtureMount records a mount in the registry the way jit migrate
// does, so the mount-registry sweep is exercised through the real writer
// rather than a hand-rolled YAML file.
func registerFixtureMount(t *testing.T, home, mountPath, profilePath string) {
	t.Helper()
	root := filepath.Join(home, "Library", "Application Support", "jitpass")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := mount.AddMount(mount.RegistryPath(root), mount.Entry{
		MountPath:   mountPath,
		ProfilePath: profilePath,
	}); err != nil {
		t.Fatalf("AddMount: %v", err)
	}
}

// writeProfileAt writes a manifest at an arbitrary absolute path — for the
// mount case, whose profile deliberately lives outside both cwd and the
// global store.
func writeProfileAt(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func execDoctor(t *testing.T, args ...string) (stdout string, err error) {
	t.Helper()
	doctorProfile = ""
	doctorFormat = "text"
	doctorVerbose = false
	doctorOrphans = false
	doctorWrap = false
	// Cobra remembers which flags were SET across Execute calls in the same
	// process, and MarkFlagsMutuallyExclusive checks Changed, not the value —
	// so without this a test that passed --wrap makes every later test that
	// passes --profile fail on an exclusivity error it never triggered.
	doctorCmd.Flags().Visit(func(f *pflag.Flag) { f.Changed = false })
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
	// "all resolve cleanly" lost its "all": the summary speaks only for the
	// secret references it checked, and printing an unqualified all-clear
	// directly beneath a [backup] or [mount] warning contradicted the lines
	// above it.
	if !strings.Contains(out, "✓ 1 profile, 1 secret reference resolve cleanly") {
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
	if !strings.Contains(out, "[checked]") || !strings.Contains(out, "AWS_ACCESS_KEY_ID → aws/s3-access-key") {
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

// TestDoctorChecksMountRegistryProfiles is the false NEGATIVE half of the
// mount-registry gap, and the worse half: a registered mount's profile
// referenced a secret that had gone from the vault, and doctor printed
// "all resolve cleanly" and exited 0 while the mount could serve nothing.
// The manifest deliberately lives outside both cwd and the global store,
// which is exactly why the old cwd-only sweep never saw it.
func TestDoctorChecksMountRegistryProfiles(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	elsewhere := filepath.Join(t.TempDir(), "other-project", ".jit", "profiles", "npmrc.yaml")
	writeProfileAt(t, elsewhere, "NPM_TOKEN: npm/token\n")
	registerFixtureMount(t, home, filepath.Join(home, ".npmrc"), elsewhere)
	// npm/token deliberately not planted: the mount points at a secret that
	// isn't there.

	out, err := execDoctor(t)
	if err == nil {
		t.Fatal("expected a non-zero exit: a registered mount references a missing secret")
	}
	if !strings.Contains(out, "NPM_TOKEN") || !strings.Contains(out, "npm/token") {
		t.Errorf("expected the mount profile's broken reference to be named, got:\n%s", out)
	}
}

// TestDoctorMountReferencedSecretIsNotAnOrphan is the false POSITIVE half.
// `jit vault orphans` and `jit status` both read the mount registry and
// correctly called this secret in use; doctor alone did not, and reported a
// live mount's credential as dead weight — the kind of disagreement between
// two jit commands that costs more trust than the number is worth.
func TestDoctorMountReferencedSecretIsNotAnOrphan(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)
	writeFixtureProfile(t, cwd, "app", "APP_KEY: app/key\n")
	plantVaultSecret(t, home, "app/key")

	elsewhere := filepath.Join(t.TempDir(), "other-project", ".jit", "profiles", "npmrc.yaml")
	writeProfileAt(t, elsewhere, "NPM_TOKEN: npm/token\n")
	registerFixtureMount(t, home, filepath.Join(home, ".npmrc"), elsewhere)
	plantVaultSecret(t, home, "npm/token") // referenced ONLY by the mount

	out, err := execDoctor(t, "--orphans")
	if err != nil {
		t.Fatalf("jit doctor --orphans: %v", err)
	}
	if strings.Contains(out, "npm/token") {
		t.Errorf("a secret a registered mount references must never be called an orphan, got:\n%s", out)
	}
}

// TestDoctorUnloadableMountProfileIsAdvisory: a registry entry whose manifest
// won't load is a broken mount worth reporting, but it is not a statement
// about the profiles the user asked about — and the registry can outlive a
// project directory legitimately. Advisory, so it must not fail the run. It
// must also suppress the orphan sweep: that profile's references are now
// unknown, so calling its secrets orphaned would be the same lie an
// unreadable project manifest would tell.
func TestDoctorUnloadableMountProfileIsAdvisory(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)
	writeFixtureProfile(t, cwd, "app", "APP_KEY: app/key\n")
	plantVaultSecret(t, home, "app/key")

	elsewhere := filepath.Join(t.TempDir(), "other-project", ".jit", "profiles", "npmrc.yaml")
	writeProfileAt(t, elsewhere, "[not valid yaml")
	registerFixtureMount(t, home, filepath.Join(home, ".npmrc"), elsewhere)
	plantVaultSecret(t, home, "npm/token")

	out, err := execDoctor(t, "--orphans")
	if err != nil {
		t.Fatalf("an unloadable mount profile is advisory and must not fail the run: %v", err)
	}
	if !strings.Contains(out, "[mount]") {
		t.Errorf("expected a [mount] warning naming the broken mount, got:\n%s", out)
	}
	if strings.Contains(out, "[orphan]") {
		t.Errorf("the orphan sweep must be suppressed when a mount manifest is unreadable, got:\n%s", out)
	}
}

// TestDoctorCorruptMountRegistryIsReported: mount.LoadRegistry returns no
// error for a MISSING registry, so an error from it always means the file
// exists and is malformed — the agent can no longer tell what it is meant to
// serve. Reported, not swallowed.
func TestDoctorCorruptMountRegistryIsReported(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)
	writeFixtureProfile(t, cwd, "app", "APP_KEY: app/key\n")
	plantVaultSecret(t, home, "app/key")

	root := filepath.Join(home, "Library", "Application Support", "jitpass")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(mount.RegistryPath(root), []byte("[not valid yaml"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out, err := execDoctor(t)
	if err != nil {
		t.Fatalf("a corrupt registry is advisory and must not fail the run: %v", err)
	}
	if !strings.Contains(out, "[mount]") || !strings.Contains(out, "registry") {
		t.Errorf("expected a [mount] warning about the unreadable registry, got:\n%s", out)
	}
}

// TestDoctorMountProfileNotDoubleCounted: the common case is a mount pointing
// straight at a global profile ListAll already returned. Checking it twice
// would inflate both counts and print every finding about it twice.
func TestDoctorMountProfileNotDoubleCounted(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	writeFixtureProfile(t, home, "npmrc", "NPM_TOKEN: npm/token\n")
	plantVaultSecret(t, home, "npm/token")
	registerFixtureMount(t, home, filepath.Join(home, ".npmrc"),
		filepath.Join(home, ".jit", "profiles", "npmrc.yaml"))

	out, err := execDoctor(t, "--format", "json")
	if err != nil {
		t.Fatalf("jit doctor --format json: %v", err)
	}
	var result doctorResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshaling output %q: %v", out, err)
	}
	if result.ProfilesChecked != 1 || result.SecretsChecked != 1 {
		t.Errorf("a mount pointing at an already-visible profile must be counted once, got %+v", result)
	}
}

// TestDoctorProfileNotFoundIsItsOwnKind: a typo'd --profile and broken YAML
// are different problems with different fixes. They used to share the kind
// "parse", so a JSON consumer could not tell them apart.
func TestDoctorProfileNotFoundIsItsOwnKind(t *testing.T) {
	withFixtureHome(t)
	withFixtureCwd(t)

	out, err := execDoctor(t, "--profile", "nope", "--format", "json")
	if err == nil {
		t.Fatal("expected a non-zero exit for an unknown profile")
	}
	var result doctorResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshaling output %q: %v", out, err)
	}
	if len(result.Problems) != 1 || result.Problems[0].Kind != kindNotFound {
		t.Errorf("expected one not_found problem, got %+v", result.Problems)
	}
}

// TestDoctorGroupsFindingsUnderOneHeader pins the report shape: findings of
// one kind sit under a single `[kind]  count` header, and the kind tag appears
// exactly once no matter how many findings share it. Before grouping, five
// missing secrets meant five `[missing]` tags and five copies of the same
// remediation sentence.
func TestDoctorGroupsFindingsUnderOneHeader(t *testing.T) {
	withFixtureHome(t)
	cwd := withFixtureCwd(t)
	writeFixtureProfile(t, cwd, "app", "A_KEY: a/one\nB_KEY: b/two\nC_KEY: c/three\n")

	out, _ := execDoctor(t)
	if got := strings.Count(out, "[missing]"); got != 1 {
		t.Errorf("expected the kind tag exactly once as a group header, saw it %d times:\n%s", got, out)
	}
	if !strings.Contains(out, "[missing]  3") {
		t.Errorf("expected a dim count beside the header, got:\n%s", out)
	}
	// One arrow for the group, not one per finding.
	if got := strings.Count(out, "→ jit vault set"); got != 1 {
		t.Errorf("expected the shared action stated once, saw it %d times:\n%s", got, out)
	}
}

// TestDoctorSingleFindingHasNoCount: "[rekey] 1" invites the reader to compare
// a number against nothing, so a group of one prints no count — and keeps its
// path-specific action rather than the group template.
func TestDoctorSingleFindingHasNoCount(t *testing.T) {
	withFixtureHome(t)
	cwd := withFixtureCwd(t)
	writeFixtureProfile(t, cwd, "app", "A_KEY: a/one\n")

	out, _ := execDoctor(t)
	if strings.Contains(out, "[missing]  1") {
		t.Errorf("a single finding must not print a count, got:\n%s", out)
	}
	if !strings.Contains(out, "→ jit vault set a/one") {
		t.Errorf("a lone finding keeps its path-specific action, got:\n%s", out)
	}
}

// TestDoctorJSONCarriesStructuredAction: the fix used to be a clause buried in
// an English sentence that a regexp recovered at render time. It is a field
// now, so a consumer can act on it without parsing prose.
func TestDoctorJSONCarriesStructuredAction(t *testing.T) {
	withFixtureHome(t)
	cwd := withFixtureCwd(t)
	writeFixtureProfile(t, cwd, "app", "A_KEY: a/one\n")

	out, err := execDoctor(t, "--format", "json")
	if err == nil {
		t.Fatal("expected a non-zero exit for a missing secret")
	}
	var result doctorResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshaling output %q: %v", out, err)
	}
	if len(result.Problems) != 1 {
		t.Fatalf("expected one problem, got %+v", result.Problems)
	}
	if !strings.Contains(result.Problems[0].Action, "jit vault set a/one") {
		t.Errorf("expected a structured action naming the fix, got %q", result.Problems[0].Action)
	}
	// The detail is now purely what IS wrong; the fix lives in Action.
	if strings.Contains(result.Problems[0].Detail, "jit vault set") {
		t.Errorf("the remediation must not be duplicated into detail, got %q", result.Problems[0].Detail)
	}
}

// TestDoctorWrapNeverOpensTheVault: --wrap replaces `jit wrap doctor`, and
// the state you most often want a shim check in is one where the vault itself
// is broken. A vault root that can't even be read must not stop it.
func TestDoctorWrapNeverOpensTheVault(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	// A file where the vault directory belongs: any attempt to open or list
	// the vault from here fails.
	root := filepath.Join(home, "Library", "Application Support", "jitpass")
	if err := os.MkdirAll(filepath.Dir(root), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(root, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out, err := execDoctor(t, "--wrap")
	if err != nil {
		t.Fatalf("--wrap must not need the vault: %v\n%s", err, out)
	}
	if strings.Contains(out, "No profiles found") {
		t.Errorf("a --wrap run swept no profiles and must not report on them, got:\n%s", out)
	}
}

// TestDoctorWrapRejectsProfileFlag: the two narrow the run in incompatible
// directions, and silently honouring one would be worse than refusing.
func TestDoctorWrapRejectsProfileFlag(t *testing.T) {
	withFixtureHome(t)
	withFixtureCwd(t)
	if _, err := execDoctor(t, "--wrap", "--profile", "app"); err == nil {
		t.Fatal("expected --wrap and --profile to be mutually exclusive")
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
