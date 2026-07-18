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

func TestScanIACFilesK8sBase64ProdValueEscalates(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, "code", "k8s"))
	// "postgres://admin:pw@db.prod.example.com:5432/app" — the exact shape
	// that sat at Info forever when the scanner judged the raw base64 line.
	writeFile(t, filepath.Join(home, "code", "k8s", "secret.yaml"), `apiVersion: v1
kind: Secret
metadata:
  name: db
data:
  url: cG9zdGdyZXM6Ly9hZG1pbjpwd0BkYi5wcm9kLmV4YW1wbGUuY29tOjU0MzIvYXBw
`)
	findings, err := ScanIACFiles(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanIACFiles: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("severity = %q, want %q (decoded production-indicator match)", findings[0].Severity, SeverityCritical)
	}
	if !findings[0].ProductionIndicatorMatch {
		t.Errorf("ProductionIndicatorMatch = false, want true")
	}
}

func TestScanIACFilesK8sWidenedFilenameGate(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, "code", "k8s"))
	// Neither exact name matched the old gate; both are common in real repos.
	writeFile(t, filepath.Join(home, "code", "k8s", "postgres-secret.yml"), `apiVersion: v1
kind: Secret
metadata:
  name: pg
stringData:
  password: hunter2
`)
	findings, err := ScanIACFiles(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanIACFiles: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (widened *secret*.yml gate)", len(findings))
	}
}

func TestScanIACFilesK8sExportedSecretIsCritical(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, "code", "k8s"))
	// metadata.uid/resourceVersion only ever appear in `kubectl get secret
	// -o yaml` output — a live credential by definition.
	writeFile(t, filepath.Join(home, "code", "k8s", "dumped-secret.yaml"), `apiVersion: v1
kind: Secret
metadata:
  name: live
  uid: 6a1c84f2-9f10-4c1e-8f9f-000000000001
  resourceVersion: "123456"
data:
  token: c29tZS10b2tlbg==
`)
	findings, err := ScanIACFiles(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanIACFiles: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("severity = %q, want %q", findings[0].Severity, SeverityCritical)
	}
	if !strings.Contains(findings[0].Evidence, "exported from a live cluster") {
		t.Errorf("evidence = %q, want the cluster-export explanation", findings[0].Evidence)
	}
}

func TestScanIACFilesK8sTypeBasedSeverity(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, "code", "k8s"))
	writeFile(t, filepath.Join(home, "code", "k8s", "tls-secret.yaml"), `apiVersion: v1
kind: Secret
metadata:
  name: tls
type: kubernetes.io/tls
data:
  tls.crt: Zm9v
  tls.key: YmFy
`)
	findings, err := ScanIACFiles(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanIACFiles: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Severity != SeverityHigh {
		t.Errorf("severity = %q, want %q (tls type implies a private key)", findings[0].Severity, SeverityHigh)
	}
	if !strings.Contains(findings[0].Evidence, "TLS private key") {
		t.Errorf("evidence = %q, want the TLS private key explanation", findings[0].Evidence)
	}
}

func TestScanIACFilesSealedSecretNotFlagged(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, "code", "k8s"))
	// The old substring check matched "kind: Secret" inside "kind:
	// SealedSecret" — the protected form must never be flagged.
	writeFile(t, filepath.Join(home, "code", "k8s", "sealed-secret.yaml"), `apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: sealed
spec:
  encryptedData:
    password: AgBy8hCi...
`)
	findings, err := ScanIACFiles(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanIACFiles: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0 (SealedSecret is already protected)", len(findings))
	}
}

func TestScanIACFilesSOPSEncryptedSecretNotFlagged(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, "code", "k8s"))
	writeFile(t, filepath.Join(home, "code", "k8s", "secret.yaml"), `apiVersion: v1
kind: Secret
metadata:
  name: enc
stringData:
  password: ENC[AES256_GCM,data:aaaa,iv:bbbb,tag:cccc,type:str]
sops:
  version: 3.10.0
`)
	findings, err := ScanIACFiles(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanIACFiles: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0 (fully SOPS-encrypted)", len(findings))
	}
}

func TestScanIACFilesPartiallySOPSEncryptedFlagged(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, "code", "k8s"))
	writeFile(t, filepath.Join(home, "code", "k8s", "secret.yaml"), `apiVersion: v1
kind: Secret
metadata:
  name: mixed
stringData:
  password: ENC[AES256_GCM,data:aaaa,iv:bbbb,tag:cccc,type:str]
  api_key: still-plaintext-oops
sops:
  version: 3.10.0
`)
	findings, err := ScanIACFiles(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanIACFiles: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Severity != SeverityHigh {
		t.Errorf("severity = %q, want %q", findings[0].Severity, SeverityHigh)
	}
	if !strings.Contains(findings[0].Evidence, "partially SOPS-encrypted") {
		t.Errorf("evidence = %q, want the partial-encryption warning", findings[0].Evidence)
	}
}

func TestScanIACFilesMultiDocOneBadSecret(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, "code", "k8s"))
	writeFile(t, filepath.Join(home, "code", "k8s", "app-secrets.yaml"), `apiVersion: v1
kind: ConfigMap
metadata:
  name: cfg
data:
  LOG_LEVEL: debug
---
apiVersion: v1
kind: Secret
metadata:
  name: real
data:
  password: aHVudGVyMg==
`)
	findings, err := ScanIACFiles(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanIACFiles: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (the Secret doc behind the ConfigMap)", len(findings))
	}
}

func TestScanIACFilesEmptySecretScaffoldNotFlagged(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, "code", "k8s"))
	writeFile(t, filepath.Join(home, "code", "k8s", "secret.yaml"), `apiVersion: v1
kind: Secret
metadata:
  name: scaffold
`)
	findings, err := ScanIACFiles(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanIACFiles: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0 (no data at all, nothing exposed)", len(findings))
	}
}

func TestScanIACFilesMalformedYAMLFallsBackToLegacyScan(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, "code", "k8s"))
	// Broken YAML (bad indentation with a tab) that still clearly says
	// kind: Secret — the fallback substring path must keep flagging it.
	writeFile(t, filepath.Join(home, "code", "k8s", "secret.yaml"), "kind: Secret\n\tdata:\n  password: prod-db-password\n")
	findings, err := ScanIACFiles(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanIACFiles: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (legacy fallback)", len(findings))
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("severity = %q, want %q (raw-line prod match in fallback)", findings[0].Severity, SeverityCritical)
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
