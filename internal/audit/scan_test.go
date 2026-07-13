// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"path/filepath"
	"testing"
)

func findingOfType(ft string) Finding {
	return Finding{FindingType: ft, Severity: SeverityLow, Confidence: ConfidenceMedium}
}

func findingWithSeverity(ft, severity string) Finding {
	return Finding{FindingType: ft, Severity: severity, Confidence: ConfidenceMedium}
}

func TestComputeRiskLevel(t *testing.T) {
	ipStr := "8.8.8.8"

	cases := []struct {
		name     string
		findings []Finding
		want     string
	}{
		{"clean, zero findings", nil, RiskLevelClean},
		{"one low-signal finding", []Finding{findingOfType(FindingTypeEnvFilePresent)}, RiskLevelLow},
		{"two low-signal findings", []Finding{findingOfType(FindingTypeEnvFilePresent), findingOfType(FindingTypeIACVariableFile)}, RiskLevelLow},
		{"three findings -> medium", []Finding{
			findingOfType(FindingTypeEnvFilePresent),
			findingOfType(FindingTypeIACVariableFile),
			findingOfType(FindingTypeSuspiciousFilename),
		}, RiskLevelMedium},
		{"five low-severity findings, none individually High -> high via count", []Finding{
			findingOfType(FindingTypeEnvFilePresent),
			findingOfType(FindingTypeEnvFilePresent),
			findingOfType(FindingTypeIACVariableFile),
			findingOfType(FindingTypeSuspiciousFilename),
			findingOfType(FindingTypeIACVariableFile),
		}, RiskLevelHigh},
		{"single shell-config finding (Severity: High, as the real scanner produces) -> high regardless of count",
			[]Finding{findingWithSeverity(FindingTypeShellConfigSecret, SeverityHigh)}, RiskLevelHigh},
		{"single MCP finding (Severity: High) -> high regardless of count",
			[]Finding{findingWithSeverity(FindingTypeMCPEmbeddedSecret, SeverityHigh)}, RiskLevelHigh},
		{"single private-key finding (Severity: High) -> high regardless of count",
			[]Finding{findingWithSeverity(FindingTypePrivateKeyRisk, SeverityHigh)}, RiskLevelHigh},
		{"single credential-file finding (Severity: High) -> high regardless of count " +
			"— this is the real gap the Severity-based generalization fixed: credential_file " +
			"was missing from the old hardcoded FindingType switch entirely",
			[]Finding{findingWithSeverity(FindingTypeCredentialFile, SeverityHigh)}, RiskLevelHigh},
		{"production-indicator match anywhere -> critical, overrides everything", []Finding{
			{FindingType: FindingTypeEnvFilePresent, ProductionIndicatorMatch: true},
		}, RiskLevelCritical},
		{"public IP match anywhere -> critical, overrides everything", []Finding{
			{FindingType: FindingTypeEnvFilePresent, PublicIPMatch: &ipStr},
		}, RiskLevelCritical},
		{"critical overrides a high-trigger category too", []Finding{
			{FindingType: FindingTypeShellConfigSecret, Severity: SeverityHigh, ProductionIndicatorMatch: true},
		}, RiskLevelCritical},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ComputeRiskLevel(c.findings)
			if got != c.want {
				t.Errorf("ComputeRiskLevel() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestScanIntegration(t *testing.T) {
	home := t.TempDir()

	// Plant findings across several categories, including one that should
	// escalate the whole scan to Critical.
	writeFile(t, filepath.Join(home, ".zshrc"), "export STRIPE_API_KEY=sk_test_example\n")
	mkdirAll(t, filepath.Join(home, "code", "app"))
	writeFile(t, filepath.Join(home, "code", "app", ".env"), "PROD_DATABASE_URL=postgres://admin:x@db.internal/prod\n")

	findings, summary, err := Scan(Config{
		HomeDir:        home,
		RunID:          "test-run-id",
		ScannerVersion: "test",
		Endpoint:       Endpoint{Hostname: "test-host", OS: "darwin"},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if len(findings) != summary.TotalFindings {
		t.Errorf("len(findings) = %d, summary.TotalFindings = %d, want equal", len(findings), summary.TotalFindings)
	}
	if summary.TotalFindings < 2 {
		t.Fatalf("expected at least 2 findings (shell config + .env), got %d", summary.TotalFindings)
	}
	if summary.RiskLevel != RiskLevelCritical {
		t.Errorf("RiskLevel = %q, want %q (planted a production-indicator match)", summary.RiskLevel, RiskLevelCritical)
	}
	if summary.ProductionIndicatorCount < 1 {
		t.Errorf("ProductionIndicatorCount = %d, want >= 1", summary.ProductionIndicatorCount)
	}
	if summary.RecordType != RecordTypeScanSummary {
		t.Errorf("RecordType = %q, want %q", summary.RecordType, RecordTypeScanSummary)
	}
	if summary.RecordID != nil {
		t.Errorf("RecordID = %v, want nil (always null per RFC.md §4)", summary.RecordID)
	}
	if summary.RunID != "test-run-id" {
		t.Errorf("RunID = %q, want %q", summary.RunID, "test-run-id")
	}

	// All seven categories must always be present in the map, even at zero.
	if len(summary.FindingsByCategory) != len(AllFindingTypes) {
		t.Errorf("FindingsByCategory has %d keys, want %d (all categories always present)", len(summary.FindingsByCategory), len(AllFindingTypes))
	}
	for _, ft := range AllFindingTypes {
		if _, ok := summary.FindingsByCategory[ft]; !ok {
			t.Errorf("FindingsByCategory missing key %q", ft)
		}
	}
}

func TestScanCleanHomeDir(t *testing.T) {
	home := t.TempDir()
	findings, summary, err := Scan(Config{HomeDir: home, RunID: "r", ScannerVersion: "test"})
	if err != nil {
		t.Fatalf("Scan on empty home dir: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings on empty home dir, want 0", len(findings))
	}
	if summary.RiskLevel != RiskLevelClean {
		t.Errorf("RiskLevel = %q, want %q", summary.RiskLevel, RiskLevelClean)
	}
	if summary.TotalFindings != 0 {
		t.Errorf("TotalFindings = %d, want 0", summary.TotalFindings)
	}
}
