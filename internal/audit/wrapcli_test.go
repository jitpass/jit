// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeWrapFixture(t *testing.T, home, rel, content string) {
	t.Helper()
	path := filepath.Join(home, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestScanWrappableCLITokensFindsAndNamesTheFix(t *testing.T) {
	home := t.TempDir()
	token := "gho_AUDITfixture1234567890abcdefAUDIT"
	writeWrapFixture(t, home, ".config/gh/hosts.yml", "github.com:\n    oauth_token: "+token+"\n")

	findings, err := ScanWrappableCLITokens(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanWrappableCLITokens: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.FindingType != FindingTypeWrappableCLIToken || f.Severity != SeverityHigh {
		t.Errorf("type/severity = %s/%s", f.FindingType, f.Severity)
	}
	if !strings.Contains(f.Evidence, "jit wrap gh") {
		t.Errorf("evidence doesn't name the fix: %s", f.Evidence)
	}
	if f.KeyName == nil || *f.KeyName != "oauth_token" {
		t.Errorf("KeyName = %v", f.KeyName)
	}
	if f.ValuePreview == nil || strings.Contains(*f.ValuePreview, token) {
		t.Errorf("value preview must be masked, got %v", f.ValuePreview)
	}
	if f.FilePath != filepath.Join(home, ".config/gh/hosts.yml") {
		t.Errorf("FilePath = %s", f.FilePath)
	}
}

func TestScanWrappableCLITokensQuietWhenNothingExposed(t *testing.T) {
	findings, err := ScanWrappableCLITokens(Config{HomeDir: t.TempDir()})
	if err != nil {
		t.Fatalf("ScanWrappableCLITokens: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("empty home produced findings: %+v", findings)
	}
}

func TestScanWrappableCLITokensOneFindingPerTool(t *testing.T) {
	home := t.TempDir()
	// ngrok's v3 and v2 selectors both match this file; only the first
	// (the live token wrap would take) may be reported.
	writeWrapFixture(t, home, "Library/Application Support/ngrok/ngrok.yml",
		"version: 3\nagent:\n    authtoken: tok_wrapclitest_1234567890\nauthtoken: tok_wrapclitest_1234567890\n")

	findings, err := ScanWrappableCLITokens(Config{HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings for one tool, want 1", len(findings))
	}
}
