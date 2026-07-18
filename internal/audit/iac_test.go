// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestScanIACFilesTerraformTfvars(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, "code", "infra"))
	writeFile(t, filepath.Join(home, "code", "infra", "terraform.tfvars"), `region = "us-east-1"
instance_type = "t3.micro"
`)
	findings, err := ScanIACFiles(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanIACFiles: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Severity != SeverityInfo {
		t.Errorf("severity = %q, want %q", findings[0].Severity, SeverityInfo)
	}
	// The Terraform half of this category has an automated fix (jit
	// migrate's tfvars category) and the advisory must say so, unlike the
	// Kubernetes half's detection-only text.
	if !strings.Contains(findings[0].Evidence, "jit migrate") {
		t.Errorf("evidence = %q, want it to point at jit migrate", findings[0].Evidence)
	}
}

func TestScanIACFilesAutoTfvarsAndEscalation(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, "code", "infra"))
	writeFile(t, filepath.Join(home, "code", "infra", "prod.auto.tfvars"), `db_host = "prod-db.internal.example.com"
`)
	findings, err := ScanIACFiles(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanIACFiles: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("severity = %q, want %q (production-indicator match)", findings[0].Severity, SeverityCritical)
	}
}

func TestScanIACFilesK8sSecretsConfirmedByContent(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, "code", "k8s"))
	writeFile(t, filepath.Join(home, "code", "k8s", "secrets.yaml"), `apiVersion: v1
kind: Secret
metadata:
  name: my-secret
data:
  password: aHVudGVyMg==
`)
	findings, err := ScanIACFiles(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanIACFiles: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if !strings.Contains(findings[0].Evidence, "detection only") {
		t.Errorf("evidence = %q, want the k8s detection-only advisory", findings[0].Evidence)
	}
}

func TestScanIACFilesK8sLookingNameWithoutSecretKindNotFlagged(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, "code", "someapp"))
	// Named "secrets.yaml" but not actually a Kubernetes Secret manifest —
	// content confirmation should prevent a false positive here.
	writeFile(t, filepath.Join(home, "code", "someapp", "secrets.yaml"), `feature_flags:
  new_dashboard: true
`)
	findings, err := ScanIACFiles(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanIACFiles: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0 (no 'kind: Secret' content)", len(findings))
	}
}

func TestScanIACFilesNoneFound(t *testing.T) {
	home := t.TempDir()
	findings, err := ScanIACFiles(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanIACFiles on empty home dir should not error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}
