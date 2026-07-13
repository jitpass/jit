// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"path/filepath"
	"testing"
)

func TestScanSuspiciousFilenames(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, "code", "oldproject"))
	writeFile(t, filepath.Join(home, "code", "oldproject", ".env.bak"), "STRIPE_KEY=sk_test_example\n")
	writeFile(t, filepath.Join(home, "code", "oldproject", "credentials.json"), "{}")
	mkdirAll(t, filepath.Join(home, "Downloads"))
	writeFile(t, filepath.Join(home, "Downloads", "1Password Emergency Kit A3-XXXXXX-example.pdf"), "fake pdf content")

	findings, err := ScanSuspiciousFilenames(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanSuspiciousFilenames: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("got %d findings, want 3: %+v", len(findings), findings)
	}

	var sawEmergencyKit bool
	for _, f := range findings {
		if filepath.Base(f.FilePath) == "1Password Emergency Kit A3-XXXXXX-example.pdf" {
			sawEmergencyKit = true
			if f.Severity != SeverityMedium {
				t.Errorf("1Password Emergency Kit severity = %q, want %q", f.Severity, SeverityMedium)
			}
			if f.Confidence != ConfidenceHigh {
				t.Errorf("1Password Emergency Kit confidence = %q, want %q", f.Confidence, ConfidenceHigh)
			}
		}
	}
	if !sawEmergencyKit {
		t.Error("expected a finding for the 1Password Emergency Kit PDF")
	}
}

// TestScanSuspiciousFilenamesAvoidsNoiseFromRealWorldExample locks in the
// precision lesson from real-world review (2026-07-06): a naive "token"
// substring match would flag all of these, none of which are actually
// secrets. This is exactly the false-positive pattern that motivated
// keeping this scanner's rule set narrow.
func TestScanSuspiciousFilenamesAvoidsNoiseFromRealWorldExample(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, "code", "analytics"))
	noise := []string{
		"token_validation.py",
		"eth_and_token_balances_20250710_161654.csv",
		"Add_Bulk_To_Token_Details_API.json",
		"solana_analysis_Tokenkeg.json",
	}
	for _, name := range noise {
		writeFile(t, filepath.Join(home, "code", "analytics", name), "irrelevant content")
	}

	findings, err := ScanSuspiciousFilenames(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanSuspiciousFilenames: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("got %d false-positive findings on non-secret 'token'-named files, want 0: %+v", len(findings), findings)
	}
}

func TestScanSuspiciousFilenamesNoneFound(t *testing.T) {
	home := t.TempDir()
	findings, err := ScanSuspiciousFilenames(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanSuspiciousFilenames on empty home dir should not error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

// TestScannersSkipInPlacePointerFiles is the regression test for GAPS.md #66:
// after `jit migrate`, a backup-suffixed .env file (.env.bak) is replaced in
// place with jit pointer content while keeping its name. Neither the env-file
// scanner nor the suspicious-filename scanner should re-report it — it holds
// only `KEY=jit://vault/...` lines, never a real value.
func TestScannersSkipInPlacePointerFiles(t *testing.T) {
	home := t.TempDir()
	pointer := "# jit pointer file — no secret values here, only vault paths.\n" +
		"# Real values come from the live mount or `jit vault get`, never this file.\n" +
		"API_KEY=jit://vault/oldproject-bak/API_KEY\n"
	mkdirAll(t, filepath.Join(home, "proj"))
	writeFile(t, filepath.Join(home, "proj", ".env.bak"), pointer)

	suspicious, err := ScanSuspiciousFilenames(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanSuspiciousFilenames: %v", err)
	}
	if len(suspicious) != 0 {
		t.Errorf("suspicious findings = %+v, want none — an in-place pointer file is not a stray backup", suspicious)
	}

	env, err := ScanEnvFiles(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanEnvFiles: %v", err)
	}
	if len(env) != 0 {
		t.Errorf("env findings = %+v, want none — a pointer file holds no real secret", env)
	}
}
