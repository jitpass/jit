// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"path/filepath"
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
	// jit migrate home --only gcp turns the ADC file into a live-mount
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
// needs its own regular-file guard: `jit migrate home` can turn it into a
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
