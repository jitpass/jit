// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

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

	findings, err := scanNpmrc(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("scanNpmrc: %v", err)
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

	findings, err := scanNpmrc(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("scanNpmrc: %v", err)
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
