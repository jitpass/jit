// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestScanAWSCredentials(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, ".aws"))
	writeFile(t, filepath.Join(home, ".aws", "credentials"), `[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY

[staging]
aws_access_key_id = AKIASTAGINGEXAMPLE
aws_secret_access_key = stagingsecretexamplevalue
`)
	findings, err := scanAWSCredentials(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("scanAWSCredentials: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (one per profile's secret)", len(findings))
	}
	byKey := map[string]Finding{}
	for _, f := range findings {
		byKey[*f.KeyName] = f
	}
	if _, ok := byKey["default/aws_secret_access_key"]; !ok {
		t.Error("expected finding for default/aws_secret_access_key")
	}
	if _, ok := byKey["staging/aws_secret_access_key"]; !ok {
		t.Error("expected finding for staging/aws_secret_access_key")
	}
	for _, f := range findings {
		if f.Severity != SeverityHigh {
			t.Errorf("severity = %q, want %q", f.Severity, SeverityHigh)
		}
	}
}

// TestScanAWSCredentialsProdProfileEscalates locks in a real-world-observed
// behavior: a profile literally named "prod" (real anonymized scan data,
// 2026-07-06, showed exactly this: "profiles: peach,prod") should escalate
// to Critical via the shared cross-cutting production-indicator signal,
// same as any other category.
func TestScanAWSCredentialsProdProfileEscalates(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, ".aws"))
	writeFile(t, filepath.Join(home, ".aws", "credentials"), `[prod]
aws_secret_access_key = prodsecretexamplevalue
`)
	findings, err := scanAWSCredentials(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("scanAWSCredentials: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("severity = %q, want %q (profile name 'prod' should escalate)", findings[0].Severity, SeverityCritical)
	}
	if !findings[0].ProductionIndicatorMatch {
		t.Error("expected ProductionIndicatorMatch = true")
	}
}

func TestScanAWSCredentialsTemporarySessionEvidence(t *testing.T) {
	// A profile with an aws_expiration stamp was minted by an SSO tool
	// (clisso et al.) that rewrites the file on each login. The evidence
	// must say so — otherwise the user migrates, sees a clean scan, and
	// has no way to understand why the finding returns the next morning.
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, ".aws"))
	writeFile(t, filepath.Join(home, ".aws", "credentials"), `[live]
aws_access_key_id = ASIALIVEEXAMPLE
aws_secret_access_key = livesecretexamplevalue
aws_session_token = tok123
aws_expiration = 2999-01-01T00:00:00Z

[stale]
aws_access_key_id = ASIASTALEEXAMPLE
aws_secret_access_key = stalesecretexamplevalue
aws_session_token = tok456
aws_expiration = 2020-01-01T00:00:00Z
`)
	findings, err := scanAWSCredentials(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("scanAWSCredentials: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
	byKey := map[string]Finding{}
	for _, f := range findings {
		byKey[*f.KeyName] = f
	}
	live := byKey["live/aws_secret_access_key"]
	if !strings.Contains(live.Evidence, "temporary session") || !strings.Contains(live.Evidence, "2999-01-01T00:00:00Z") {
		t.Errorf("live evidence should name the temporary session and its expiry, got: %s", live.Evidence)
	}
	if !strings.Contains(live.Evidence, "rewrites this file") {
		t.Errorf("live evidence should warn the minting tool rewrites the file, got: %s", live.Evidence)
	}
	stale := byKey["stale/aws_secret_access_key"]
	if !strings.Contains(stale.Evidence, "expired at 2020-01-01T00:00:00Z") {
		t.Errorf("stale evidence should say the token already expired, got: %s", stale.Evidence)
	}
}

func TestScanAWSCredentialsNotPresent(t *testing.T) {
	home := t.TempDir()
	findings, err := scanAWSCredentials(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("scanAWSCredentials on missing file should not error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestScanKubeconfig(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, ".kube"))
	writeFile(t, filepath.Join(home, ".kube", "config"), `users:
- name: cluster-admin
  user:
    token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.example
- name: no-secret-user
  user:
    username: alice
`)
	findings, err := scanKubeconfig(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("scanKubeconfig: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if *findings[0].KeyName != "cluster-admin/token" {
		t.Errorf("KeyName = %q, want %q", *findings[0].KeyName, "cluster-admin/token")
	}
}

func TestScanNpmrc(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".npmrc"), `registry=https://registry.npmjs.org/
//registry.npmjs.org/:_authToken=npm_abc123exampletoken
save-exact=true
`)
	mkdirAll(t, filepath.Join(home, "code", "myproject"))
	writeFile(t, filepath.Join(home, "code", "myproject", ".npmrc"), `//registry.blockaidpypi.example/:_password=projectsecret
`)

	// Through ScanCredentialFiles, not one npmrc function: the two halves of
	// the npm check live apart now (scanGlobalNpmrc probes the fixed
	// ~/.npmrc, classifyProjectNpmrc is fed project-local ones by the shared
	// walk), and what matters is that the category as a whole still reports
	// both. Nothing else in this temp home can produce a finding.
	findings, err := ScanCredentialFiles(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanCredentialFiles: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (global + project-local)", len(findings))
	}
}

func TestScanTerraformCloud(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, ".terraform.d"))
	writeFile(t, filepath.Join(home, ".terraform.d", "credentials.tfrc.json"), `{
  "credentials": {
    "app.terraform.io": {
      "token": "example.atlasv1.exampletoken"
    }
  }
}
`)
	findings, err := scanTerraformCloud(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("scanTerraformCloud: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if *findings[0].KeyName != "app.terraform.io" {
		t.Errorf("KeyName = %q, want %q", *findings[0].KeyName, "app.terraform.io")
	}
}

func TestScanGCPApplicationDefaultCredentials(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, ".config", "gcloud"))
	writeFile(t, filepath.Join(home, ".config", "gcloud", "application_default_credentials.json"), `{
  "type": "authorized_user",
  "client_id": "example.apps.googleusercontent.com",
  "client_secret": "example-secret",
  "refresh_token": "1//exampleRefreshToken"
}
`)
	findings, err := scanGCPApplicationDefaultCredentials(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("scanGCPApplicationDefaultCredentials: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if *findings[0].KeyName != "refresh_token" {
		t.Errorf("KeyName = %q, want %q", *findings[0].KeyName, "refresh_token")
	}
}

func TestScanGCPApplicationDefaultCredentialsSkipsFIFO(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, ".config", "gcloud"))
	path := filepath.Join(home, ".config", "gcloud", "application_default_credentials.json")
	// jit migrate <path> --only gcp turns the ADC file into a live-mount
	// FIFO. The scanner must skip it without ever opening it for read —
	// a bare os.Open here blocks forever when no agent is writing. If the
	// guard regresses, this test hangs rather than fails; the go test
	// timeout is what surfaces it.
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}
	findings, err := scanGCPApplicationDefaultCredentials(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("scanGCPApplicationDefaultCredentials: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings for a FIFO mount, want 0", len(findings))
	}
}

func TestScanNetrc(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".netrc"), `machine api.github.com
  login alex
  password ghp_exampletoken1234567890

machine ftp.example.com login bob password ftpsecretexample
`)
	findings, err := scanNetrc(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("scanNetrc: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (one per password)", len(findings))
	}
	byKey := map[string]Finding{}
	for _, f := range findings {
		byKey[*f.KeyName] = f
	}
	if _, ok := byKey["api.github.com"]; !ok {
		t.Error("expected a finding keyed by machine api.github.com")
	}
	if _, ok := byKey["ftp.example.com"]; !ok {
		t.Error("expected a finding keyed by machine ftp.example.com")
	}
}

func TestScanGitCredentials(t *testing.T) {
	home := t.TempDir()
	// Two plaintext logins in the classic store, a malformed line and a
	// password-less line (both skipped), plus one login in the XDG store.
	writeFile(t, filepath.Join(home, ".git-credentials"), strings.Join([]string{
		"https://octocat:ghp_exampletoken@github.com",
		"https://bob:s3cret@ghe.example.com",
		"https://noPasswordHere@nopass.example.com",
		"not a url",
		"",
	}, "\n"))
	mkdirAll(t, filepath.Join(home, ".config", "git"))
	writeFile(t, filepath.Join(home, ".config", "git", "credentials"), "https://carol:tok@gitlab.example.com\n")

	findings, err := scanGitCredentials(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("scanGitCredentials: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("got %d findings, want 3 (two hosts in ~/.git-credentials, one in the XDG store)", len(findings))
	}
	byKey := map[string]Finding{}
	for _, f := range findings {
		byKey[*f.KeyName] = f
	}
	for _, host := range []string{"github.com", "ghe.example.com", "gitlab.example.com"} {
		if _, ok := byKey[host]; !ok {
			t.Errorf("expected a finding keyed by host %q", host)
		}
	}
	if f := byKey["github.com"]; f.FindingType != FindingTypeCredentialFile || !strings.Contains(f.Evidence, "jit wrap git") {
		t.Errorf("github.com finding = %+v, want a credential-file finding whose evidence points at `jit wrap git`", f)
	}
}

func TestScanGitCredentialsMissing(t *testing.T) {
	if findings, err := scanGitCredentials(Config{HomeDir: t.TempDir()}); err != nil || len(findings) != 0 {
		t.Fatalf("missing files: findings=%v err=%v, want none", findings, err)
	}
}

// TestScanNetrcSkipsMacdefBodies is the audit half of the agreement with
// internal/migrate's TestApplyNetrcMacdefBodyNeverParsedAsCredentials: a
// "password" word inside a macro body must not be reported, so audit flags
// exactly what migrate will convert — never a false finding migrate then
// refuses to touch. Exercises netrcPasswords directly (the finding only
// carries a redacted ValuePreview, so the raw values are asserted here).
func TestScanNetrcSkipsMacdefBodies(t *testing.T) {
	data := []byte(`machine real.example.com login u password REAL_secret_value

macdef init
echo password fake_value_inside_macro
quit

machine second.example.com login v password SECOND_secret_value
`)
	got := netrcPasswords(data)
	if len(got) != 2 {
		t.Fatalf("got %d passwords, want 2 (the macro body's lookalike must be ignored): %+v", len(got), got)
	}
	for _, pw := range got {
		if pw.value == "fake_value_inside_macro" {
			t.Error("extracted a password from inside a macdef body")
		}
	}
	if got[0].value != "REAL_secret_value" || got[0].machine != "real.example.com" {
		t.Errorf("first password = %+v, want real.example.com/REAL_secret_value", got[0])
	}
	if got[1].value != "SECOND_secret_value" || got[1].machine != "second.example.com" {
		t.Errorf("second password = %+v, want second.example.com/SECOND_secret_value", got[1])
	}
}

func TestScanNetrcSkipsFIFO(t *testing.T) {
	home := t.TempDir()
	// jit migrate <path> --only netrc turns ~/.netrc into a live-mount FIFO.
	// The scanner must skip it without opening it for read — a bare open
	// blocks forever with no agent writing. If the guard regresses, this
	// test hangs rather than fails; the go test timeout surfaces it.
	if err := syscall.Mkfifo(filepath.Join(home, ".netrc"), 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}
	findings, err := scanNetrc(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("scanNetrc: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings for a FIFO mount, want 0", len(findings))
	}
}

func TestScanCredentialFilesAggregatesAll(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, ".aws"))
	writeFile(t, filepath.Join(home, ".aws", "credentials"), `[default]
aws_secret_access_key = examplesecret
`)
	findings, err := ScanCredentialFiles(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanCredentialFiles: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].FindingType != FindingTypeCredentialFile {
		t.Errorf("FindingType = %q, want %q", findings[0].FindingType, FindingTypeCredentialFile)
	}
}

// The global ~/.npmrc is a fixed path checked outside walkHomeDir, so it
// needs its own regular-file guard: `jit migrate <path>` can turn it into a
// live template mount (a named pipe), and opening that for read would hang
// the scan with no agent writing, or report agent-served decoy content as an
// exposed credential.
func TestScanNpmrcSkipsGlobalLiveMountFIFO(t *testing.T) {
	home := t.TempDir()
	mkfifo(t, filepath.Join(home, ".npmrc"))
	mkdirAll(t, filepath.Join(home, "proj"))
	writeFile(t, filepath.Join(home, "proj", ".npmrc"), "//registry.npmjs.org/:_authToken=npm_abc123def456\n")

	findings, err := ScanCredentialFiles(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanCredentialFiles: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want exactly 1 (the project .npmrc, not the global FIFO)", len(findings))
	}
	if findings[0].FilePath != filepath.Join(home, "proj", ".npmrc") {
		t.Errorf("FilePath = %q, want the project .npmrc", findings[0].FilePath)
	}
}

func TestScanDockerConfig(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, ".docker"))
	// One base64 auth entry, one empty marker ({} — what docker leaves once
	// a credential store holds the secret), one entry with only an email:
	// exactly one finding, for the entry that actually carries a secret.
	writeFile(t, filepath.Join(home, ".docker", "config.json"), `{
  "auths": {
    "registry.example.com": {
      "auth": "YWxpY2U6czNjcmV0LXBhc3M="
    },
    "https://index.docker.io/v1/": {},
    "ghcr.io": {"email": "alice@example.com"}
  },
  "credsStore": "osxkeychain"
}
`)
	findings, err := scanDockerConfig(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("scanDockerConfig: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if *findings[0].KeyName != "registry.example.com" {
		t.Errorf("KeyName = %q, want %q", *findings[0].KeyName, "registry.example.com")
	}
	if findings[0].FindingType != FindingTypeCredentialFile {
		t.Errorf("FindingType = %q, want %q", findings[0].FindingType, FindingTypeCredentialFile)
	}
}

func TestScanDockerConfigIdentityToken(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, ".docker"))
	writeFile(t, filepath.Join(home, ".docker", "config.json"), `{
  "auths": {
    "https://index.docker.io/v1/": {
      "auth": "YWxpY2U6czNjcmV0LXBhc3M=",
      "identitytoken": "eyJhbGciOi.example.token"
    }
  }
}
`)
	findings, err := scanDockerConfig(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("scanDockerConfig: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
}

func TestScanDockerConfigMissingOrMalformed(t *testing.T) {
	if findings, err := scanDockerConfig(Config{HomeDir: t.TempDir()}); err != nil || len(findings) != 0 {
		t.Fatalf("missing file: findings=%v err=%v, want none", findings, err)
	}
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, ".docker"))
	writeFile(t, filepath.Join(home, ".docker", "config.json"), "not json at all")
	if findings, err := scanDockerConfig(Config{HomeDir: home}); err != nil || len(findings) != 0 {
		t.Fatalf("malformed file: findings=%v err=%v, want none", findings, err)
	}
}

// TestScanCargoCredentials covers the crates.io publish token in both the
// modern and legacy file names, and both table shapes cargo writes:
// [registry] for crates.io itself and [registries.<name>] for an alternate.
func TestScanCargoCredentials(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, ".cargo"))
	writeFile(t, filepath.Join(home, ".cargo", "credentials.toml"), `[registry]
token = "cio2ExampleCratesIoTokenValue"

[registries.internal]
token = "altExampleRegistryTokenValue"
`)

	findings, err := scanCargoCredentials(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("scanCargoCredentials: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (crates.io + the alternate registry): %+v", len(findings), findings)
	}
	// Sorted key order: "registries.internal" sorts before "registry".
	if *findings[0].KeyName != "registries.internal/token" {
		t.Errorf("KeyName[0] = %q, want %q", *findings[0].KeyName, "registries.internal/token")
	}
	if !strings.Contains(findings[0].Evidence, "internal") {
		t.Errorf("evidence should name the alternate registry, got %q", findings[0].Evidence)
	}
	if !strings.Contains(findings[1].Evidence, "crates.io") {
		t.Errorf("evidence should name crates.io, got %q", findings[1].Evidence)
	}
	for _, f := range findings {
		if f.Severity != SeverityHigh {
			t.Errorf("severity = %q, want high (it publishes crates as you)", f.Severity)
		}
		if f.ValuePreview == nil || strings.Contains(*f.ValuePreview, "TokenValue") {
			t.Errorf("value must be masked, got %v", f.ValuePreview)
		}
	}
}

// TestScanCargoCredentialsLegacyFileName: cargo still honors the
// extensionless name for anyone who logged in before 1.39.
func TestScanCargoCredentialsLegacyFileName(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, ".cargo"))
	writeFile(t, filepath.Join(home, ".cargo", "credentials"), "[registry]\ntoken = \"cio2LegacyExampleTokenValue\"\n")

	findings, err := scanCargoCredentials(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("scanCargoCredentials: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
}

// TestScanFindsCargoTokenDespitePrunedCargoDir is the whole point of making
// this a fixed-path check: ~/.cargo is in noiseDirs, so a discovery walk never
// descends into it. A machine-wide Scan must still report the token sitting at
// the top of that pruned tree — and must not report the vendored crate source
// underneath it.
func TestScanFindsCargoTokenDespitePrunedCargoDir(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, ".cargo", "registry", "src", "somecrate"))
	writeFile(t, filepath.Join(home, ".cargo", "credentials.toml"), "[registry]\ntoken = \"cio2ExampleCratesIoTokenValue\"\n")
	// A vendored crate's own fixture .env: pruned, must never be reported.
	writeFile(t, filepath.Join(home, ".cargo", "registry", "src", "somecrate", ".env"), "API_KEY=vendoredfixturevalue\n")

	findings, _, err := Scan(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got := countByType(findings, FindingTypeCredentialFile); got != 1 {
		t.Fatalf("credential_file = %d, want 1 (the cargo token): %+v", got, findings)
	}
	if got := countByType(findings, FindingTypeEnvFilePresent); got != 0 {
		t.Errorf("env_file_present = %d, want 0 — .cargo is pruned, vendored crate fixtures must stay invisible", got)
	}
}

// TestScanPypirc covers the Python half of the publish-credential class
// scanCargoCredentials and scanGlobalNpmrc already handle. Added after real
// developer scans (2026-07-28) showed Python packaging credentials on most
// machines — Poetry and uv private-index passwords in shell configs, which
// share ~/.pypirc's repository sections.
func TestScanPypirc(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".pypirc"), `[distutils]
index-servers =
    pypi
    internal

[pypi]
username = __token__
password = pypi-AgEIcHlwaS5vcmcCJDk0YTUxZmE0LTFhMmItNGMzZFabcdef

[internal]
repository = https://pypi.internal.example/simple
username = ci-publisher
password = Xk92QmPl4TzWhuCmu2qcwnu9PnWfMKNA
`)

	findings, err := scanPypirc(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("scanPypirc: %v", err)
	}
	// [distutils] is the index-servers list, not a credential holder.
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (pypi + the private index), [distutils] excluded: %+v", len(findings), findings)
	}
	// Sorted key order: "internal" sorts before "pypi".
	if *findings[0].KeyName != "internal/password" {
		t.Errorf("KeyName[0] = %q, want %q", *findings[0].KeyName, "internal/password")
	}
	// Two evidence paths, both correct: the private index's password matches no
	// vendor format, so it falls back to this scanner's own wording — which is
	// per-section, because a company index's password is not a "PyPI upload
	// token" and cannot publish to PyPI, only to that index; the pypi
	// section's value DOES match, so ValueFinding upgrades the evidence to name
	// the format it recognized.
	if !strings.Contains(findings[0].Evidence, "package-index password") ||
		!strings.Contains(findings[0].Evidence, "publish to that index") {
		t.Errorf("evidence should name what the credential is and what it can reach, got %q", findings[0].Evidence)
	}
	if !strings.Contains(findings[1].Evidence, "PyPI Upload Token") {
		t.Errorf("evidence should name the recognized format, got %q", findings[1].Evidence)
	}
	for _, f := range findings {
		if f.Severity != SeverityHigh {
			t.Errorf("severity = %q, want %q — a publish credential", f.Severity, SeverityHigh)
		}
	}
}

// TestScanPypircSkipsMaskedAndMissing confirms the two quiet paths: no file at
// all, and a file jit already migrated (whose value reads back masked).
func TestScanPypircSkipsMaskedAndMissing(t *testing.T) {
	empty := t.TempDir()
	findings, err := scanPypirc(Config{HomeDir: empty})
	if err != nil || len(findings) != 0 {
		t.Errorf("no ~/.pypirc should yield nothing, got %d findings, err=%v", len(findings), err)
	}

	masked := t.TempDir()
	writeFile(t, filepath.Join(masked, ".pypirc"), `[pypi]
username = __token__
password = ***
`)
	findings, err = scanPypirc(Config{HomeDir: masked})
	if err != nil || len(findings) != 0 {
		t.Errorf("a masked password should yield nothing, got %d findings, err=%v", len(findings), err)
	}
}

// TestClassifyStreamlitSecrets covers a total blind spot found in real
// developer scans (2026-07-28): a .streamlit/secrets.toml holding a live
// sk-proj- OpenAI key, a database password and a Snowflake password scanned as
// "This machine looks clean". Nothing matched it — not a .env name, not a
// tfvars/Secret-yaml name, and the content sweep only runs on explicitly-named
// files.
func TestClassifyStreamlitSecrets(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "proj", ".streamlit")
	mkdirAll(t, dir)
	path := filepath.Join(dir, "secrets.toml")
	writeFile(t, path, `# Streamlit secrets
OPENAI_API_KEY = "sk-proj-Ab3xKq9ZmPq2LrTvWn5cUd8eFg1hJk0uf4"
db_password = "Tr0ub4dor3xKq9ZmPq2Lr"

[connections.snowflake]
account = "ACME-PROD"
user = "analyst"
port = 443
password = "Xk92QmPl4TzWhuCmu2qcwnu9PnWfMKNA"
`)

	findings := classifyStreamlitSecrets(Config{HomeDir: home}, path, "secrets.toml")
	if len(findings) != 3 {
		var keys []string
		for _, f := range findings {
			keys = append(keys, *f.KeyName)
		}
		t.Fatalf("got %d findings %v, want 3 (the API key, db_password, password) — account/user/port are settings", len(findings), keys)
	}
	for _, f := range findings {
		if f.Severity != SeverityHigh {
			t.Errorf("%s: severity = %q, want %q", *f.KeyName, f.Severity, SeverityHigh)
		}
		if f.ValuePreview == nil || strings.Contains(*f.ValuePreview, "Tr0ub4dor3xKq9ZmPq2Lr") {
			t.Errorf("%s: value must be masked in the preview, got %v", *f.KeyName, f.ValuePreview)
		}
	}
}

// TestClassifyStreamlitSecretsGate pins the two-part name gate. "secrets.toml"
// is a common enough filename (Rust config, Helm values) that matching it
// anywhere would report files with no Streamlit involvement.
func TestClassifyStreamlitSecretsGate(t *testing.T) {
	home := t.TempDir()
	cfg := Config{HomeDir: home}

	// Right name, wrong directory.
	loose := filepath.Join(home, "proj", "secrets.toml")
	mkdirAll(t, filepath.Dir(loose))
	writeFile(t, loose, `api_key = "Xk92QmPl4TzWhuCmu2qcwnu9PnWfMKNA"`)
	if got := classifyStreamlitSecrets(cfg, loose, "secrets.toml"); len(got) != 0 {
		t.Errorf("secrets.toml outside .streamlit/ should not match, got %d findings", len(got))
	}

	// Right directory, wrong name.
	other := filepath.Join(home, "proj", ".streamlit", "config.toml")
	mkdirAll(t, filepath.Dir(other))
	writeFile(t, other, `api_key = "Xk92QmPl4TzWhuCmu2qcwnu9PnWfMKNA"`)
	if got := classifyStreamlitSecrets(cfg, other, "config.toml"); len(got) != 0 {
		t.Errorf(".streamlit/config.toml holds settings, not secrets; got %d findings", len(got))
	}
}

// TestScanMCPAuthTokens covers the remote-MCP OAuth token store mcp-remote
// keeps in ~/.mcp-auth. Detection-only by design: mcp-remote rotates and
// rewrites these files itself, so the finding's job is to say "revoke this",
// not to offer a migration that the tool would immediately fight.
func TestScanMCPAuthTokens(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".mcp-auth", "mcp-remote-0.1.37")
	mkdirAll(t, dir)
	writeFile(t, filepath.Join(dir, "fcc436b0_tokens.json"),
		`{"access_token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0.abc","refresh_token":"rt_Ab3xKq9ZmPq2LrTvWn5cUd8eFg1h","expires_in":3600}`)
	// Sibling files mcp-remote writes that are not token stores.
	writeFile(t, filepath.Join(dir, "fcc436b0_debug.log"), "some log output\n")

	findings, err := scanMCPAuthTokens(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("scanMCPAuthTokens: %v", err)
	}
	// One finding, not two: the short-lived access_token is deliberately not
	// reported (see mcpAuthTokens' doc comment).
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (refresh_token only): %+v", len(findings), findings)
	}
	if *findings[0].KeyName != "refresh_token" {
		t.Errorf("KeyName = %q, want refresh_token", *findings[0].KeyName)
	}
	if findings[0].Severity != SeverityMedium {
		t.Errorf("severity = %q, want %q — the remedy is revocation, not migration", findings[0].Severity, SeverityMedium)
	}
	if !strings.Contains(findings[0].Evidence, "revoke") {
		t.Errorf("evidence should tell the reader to revoke, got %q", findings[0].Evidence)
	}
}

func TestScanMCPAuthTokensQuietCases(t *testing.T) {
	t.Run("no directory", func(t *testing.T) {
		findings, err := scanMCPAuthTokens(Config{HomeDir: t.TempDir()})
		if err != nil || len(findings) != 0 {
			t.Errorf("got (%d findings, %v), want (0, nil)", len(findings), err)
		}
	})

	t.Run("no refresh token", func(t *testing.T) {
		home := t.TempDir()
		dir := filepath.Join(home, ".mcp-auth", "mcp-remote-0.1.37")
		mkdirAll(t, dir)
		writeFile(t, filepath.Join(dir, "abc_tokens.json"), `{"access_token":"short-lived-only"}`)
		findings, err := scanMCPAuthTokens(Config{HomeDir: home})
		if err != nil || len(findings) != 0 {
			t.Errorf("got (%d findings, %v), want (0, nil) — nothing durable to report", len(findings), err)
		}
	})

	t.Run("malformed json", func(t *testing.T) {
		home := t.TempDir()
		dir := filepath.Join(home, ".mcp-auth", "mcp-remote-0.1.37")
		mkdirAll(t, dir)
		writeFile(t, filepath.Join(dir, "abc_tokens.json"), `not json at all`)
		findings, err := scanMCPAuthTokens(Config{HomeDir: home})
		if err != nil || len(findings) != 0 {
			t.Errorf("malformed file should be skipped, got (%d findings, %v)", len(findings), err)
		}
	})
}

func TestScanClissoConfig(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".clisso.yaml"), `apps:
    prod:
        app-id: "2181527"
        duration: "43200"
        provider: acme
global:
    output: ~/.aws/credentials
providers:
    acme:
        client-id: abc123exampleclientid
        client-secret: def456exampleclientsecret
        subdomain: acme
        type: onelogin
        username: alex@example.com
    backup:
        base-url: https://example.oktapreview.com
        type: okta
        username: alex@example.com
`)
	findings, err := scanClissoConfig(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("scanClissoConfig: %v", err)
	}
	// Exactly one: the OneLogin provider's client-secret. The Okta provider
	// keeps no secret in this file (its password goes to the OS keychain).
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	f := findings[0]
	if *f.KeyName != "acme/client-secret" {
		t.Errorf("KeyName = %q, want acme/client-secret", *f.KeyName)
	}
	if f.Severity != SeverityHigh {
		t.Errorf("severity = %q, want %q", f.Severity, SeverityHigh)
	}
	// The scanner sets the wrap remedy itself (like every wrappable
	// finding), and annotateRemedies must respect it — the
	// selfRotatingCaches entry for this file exists for OTHER findings,
	// not to override this one.
	annotateRemedies(findings, home, nil)
	f = findings[0]
	if f.Remedy != RemedyWrap {
		t.Errorf("Remedy = %q, want %q", f.Remedy, RemedyWrap)
	}
	if f.FixCommand != "jit wrap clisso" {
		t.Errorf("FixCommand = %q, want %q", f.FixCommand, "jit wrap clisso")
	}
	if !strings.Contains(f.Evidence, "long-lived") {
		t.Errorf("evidence should say the secret is long-lived, got: %s", f.Evidence)
	}
	if len(f.ClaimedValuePreviews) != 1 {
		t.Errorf("expected the client-id claimed for sweep dedup, got: %v", f.ClaimedValuePreviews)
	}
}

func TestScanClissoConfigNotPresent(t *testing.T) {
	home := t.TempDir()
	findings, err := scanClissoConfig(Config{HomeDir: home})
	if err != nil || len(findings) != 0 {
		t.Errorf("got (%d findings, %v), want (0, nil)", len(findings), err)
	}
}

func TestScanClissoConfigPointerIsProtectedNotReported(t *testing.T) {
	// After `jit wrap clisso` the file holds a jit://vault pointer, not a
	// secret — reporting it would tell the user their protection is an
	// exposure.
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".clisso.yaml"), `providers:
    acme:
        client-id: abc123
        client-secret: jit://vault/wrap-clisso/acme-client-secret
        type: onelogin
`)
	findings, err := scanClissoConfig(Config{HomeDir: home})
	if err != nil || len(findings) != 0 {
		t.Errorf("got (%d findings, %v), want (0, nil) — a pointer is protection, not plaintext", len(findings), err)
	}
}

func TestScanClissoConfigEmptySecretSkipped(t *testing.T) {
	// clisso's initConfig creates the file empty; a provider block with a
	// blank client-secret (or a malformed file) must produce nothing.
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".clisso.yaml"), `providers:
    acme:
        client-id: abc123
        client-secret: ""
        type: onelogin
`)
	findings, err := scanClissoConfig(Config{HomeDir: home})
	if err != nil || len(findings) != 0 {
		t.Errorf("blank secret: got (%d findings, %v), want (0, nil)", len(findings), err)
	}

	writeFile(t, filepath.Join(home, ".clisso.yaml"), "")
	findings, err = scanClissoConfig(Config{HomeDir: home})
	if err != nil || len(findings) != 0 {
		t.Errorf("empty file: got (%d findings, %v), want (0, nil)", len(findings), err)
	}
}
