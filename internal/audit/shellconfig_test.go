// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("writeFile(%q): %v", path, err)
	}
}

func TestScanShellConfigs(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".zshrc"), `# comment, not an export
export PATH="/usr/local/bin:$PATH"
export EDITOR=vim
export AWS_SECRET_ACCESS_KEY=AKIAABCDEFGHIJKLMNOP
export PROD_DB_URL="postgres://admin:hunter2@db.internal/prod"
  export   STRIPE_TOKEN = sk_test_51Mz9x2yZvKQ
`)
	cfg := Config{HomeDir: home, RunID: "test-run", ScannerVersion: "test", Endpoint: Endpoint{}}

	findings, err := ScanShellConfigs(cfg)
	if err != nil {
		t.Fatalf("ScanShellConfigs: %v", err)
	}

	// Expect exactly 3 findings: AWS_SECRET_ACCESS_KEY, PROD_DB_URL, STRIPE_TOKEN.
	// PATH and EDITOR must NOT be flagged (LooksLikeSecretKey gate).
	if len(findings) != 3 {
		t.Fatalf("got %d findings, want 3: %+v", len(findings), findings)
	}

	byKey := map[string]Finding{}
	for _, f := range findings {
		if f.KeyName == nil {
			t.Fatalf("finding missing KeyName: %+v", f)
		}
		byKey[*f.KeyName] = f
	}

	awsFinding, ok := byKey["AWS_SECRET_ACCESS_KEY"]
	if !ok {
		t.Fatal("expected a finding for AWS_SECRET_ACCESS_KEY")
	}
	if awsFinding.Severity != SeverityHigh {
		t.Errorf("AWS_SECRET_ACCESS_KEY severity = %q, want %q (no cross-cutting signal)", awsFinding.Severity, SeverityHigh)
	}
	if awsFinding.Line == nil || *awsFinding.Line != 4 {
		t.Errorf("AWS_SECRET_ACCESS_KEY line = %v, want 4", awsFinding.Line)
	}
	if awsFinding.ValuePreview == nil || *awsFinding.ValuePreview == "AKIAABCDEFGHIJKLMNOP" {
		t.Errorf("AWS_SECRET_ACCESS_KEY value_preview must be masked, got %v", awsFinding.ValuePreview)
	}

	prodFinding, ok := byKey["PROD_DB_URL"]
	if !ok {
		t.Fatal("expected a finding for PROD_DB_URL")
	}
	if prodFinding.Severity != SeverityCritical {
		t.Errorf("PROD_DB_URL severity = %q, want %q (key name matches production-indicator)", prodFinding.Severity, SeverityCritical)
	}
	if !prodFinding.ProductionIndicatorMatch {
		t.Error("PROD_DB_URL should have ProductionIndicatorMatch = true")
	}

	stripeFinding, ok := byKey["STRIPE_TOKEN"]
	if !ok {
		t.Fatal("expected a finding for STRIPE_TOKEN (whitespace around export/=/value must still parse)")
	}
	if stripeFinding.ValuePreview == nil || *stripeFinding.ValuePreview != "sk_t"+maskSuffix {
		t.Errorf("STRIPE_TOKEN value_preview = %v, want %q", stripeFinding.ValuePreview, "sk_t"+maskSuffix)
	}

	for key := range byKey {
		if key == "PATH" || key == "EDITOR" {
			t.Errorf("non-secret-looking key %q should not have been flagged", key)
		}
	}
}

func TestScanShellConfigsNoFilesPresent(t *testing.T) {
	home := t.TempDir() // deliberately empty — no shell config files at all
	cfg := Config{HomeDir: home}

	findings, err := ScanShellConfigs(cfg)
	if err != nil {
		t.Fatalf("ScanShellConfigs on empty home dir should not error, got: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings on empty home dir, want 0", len(findings))
	}
}

func TestScanShellConfigsAlreadyMaskedValue(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".bashrc"), `export API_TOKEN=****
`)
	cfg := Config{HomeDir: home}

	findings, err := ScanShellConfigs(cfg)
	if err != nil {
		t.Fatalf("ScanShellConfigs: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	if !f.AlreadyMasked {
		t.Error("expected AlreadyMasked = true for an already-masked value")
	}
	if f.Severity != SeverityLow {
		t.Errorf("already-masked finding severity = %q, want %q", f.Severity, SeverityLow)
	}
	if f.ProductionIndicatorMatch {
		t.Error("already-masked value must not be evaluated for production-indicator match")
	}
}
