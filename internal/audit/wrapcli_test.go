// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

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

func TestScanWrappableCLITokensSkipsEnvFamilySources(t *testing.T) {
	// gemini's catalog Sources point at ~/.env and ~/.gemini/.env, which
	// ScanEnvFiles already owns. This scanner must skip them so the same
	// at-rest key isn't double-counted under two finding types (once as
	// env_file_present, once as wrappable_cli_token) — the inflation the
	// native-entry skip in this scanner exists to prevent.
	home := t.TempDir()
	key := "AIzaSyFIXTUREgeminiKey0123456789abcdefFIXTURE"
	writeWrapFixture(t, home, ".gemini/.env", "GEMINI_API_KEY="+key+"\n")

	findings, err := ScanWrappableCLITokens(Config{HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("wrappable-CLI scanner must not report a .env-family source (ScanEnvFiles owns it); got %+v", findings)
	}

	// And the whole scan reports that key exactly once, via ScanEnvFiles.
	all, _, err := Scan(Config{HomeDir: home, ScannerVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	target := filepath.Join(home, ".gemini/.env")
	var surviving Finding
	for _, f := range all {
		if f.FilePath == target {
			n++
			surviving = f
		}
	}
	if n != 1 {
		t.Errorf("gemini key at %s reported %d times across the scan, want 1", target, n)
	}
	// The surviving finding must still carry the wrap remediation the skipped
	// wrappable_cli_token finding used to provide — losing it was a real
	// regression (a user with GEMINI_API_KEY in ~/.gemini/.env no longer being
	// told `jit wrap gemini` fixes it).
	if !strings.Contains(surviving.Evidence, "jit wrap gemini") {
		t.Errorf("surviving finding lost the wrap hint; evidence = %q", surviving.Evidence)
	}
}

// Cline's providers.json sits in BOTH scanners' territory: ScanAgentStores
// sweeps it with the vendor patterns (an sk-ant- key matches) and
// ScanWrappableCLITokens extracts from it by catalog selector. The whole
// scan must report the key once, as the wrap finding — the sweep's
// exposed_secret duplicate for the same file+value falls to
// dropRedundantExposedSecrets, exactly the seam codex's auth.json has
// composed through since both scanners existed. This test pins that the
// NEW overlap rides the same rails rather than assuming it.
func TestScanWrappableCLITokensAndAgentStoreSweepDontDoubleReport(t *testing.T) {
	home := t.TempDir()
	// A value the Anthropic vendor pattern genuinely matches, so the
	// collision is real, not hypothetical.
	key := "sk-ant-api03-FIXTUREclineOverlap0123456789abcdefFIXTURE"
	writeWrapFixture(t, home, ".cline/settings/providers.json",
		`{
  "version": 1,
  "providers": {
    "anthropic": {
      "settings": {
        "provider": "anthropic",
        "apiKey": "`+key+`",
        "model": "claude-sonnet-5"
      }
    }
  }
}
`)

	all, _, err := Scan(Config{HomeDir: home, ScannerVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, ".cline/settings/providers.json")
	var got []Finding
	for _, f := range all {
		if f.FilePath == target {
			got = append(got, f)
		}
	}
	if len(got) != 1 {
		t.Fatalf("cline's providers.json reported %d times across the scan, want 1: %+v", len(got), got)
	}
	if got[0].FindingType != FindingTypeWrappableCLIToken {
		t.Errorf("the surviving finding is %s, want the actionable %s",
			got[0].FindingType, FindingTypeWrappableCLIToken)
	}
	if !strings.Contains(got[0].Evidence, "jit wrap cline") {
		t.Errorf("surviving finding doesn't name the fix; evidence = %q", got[0].Evidence)
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
