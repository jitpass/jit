// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"bytes"
	"strings"
	"testing"
)

func TestLooksTestFixture(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/Users/alex/jit/internal/audit/tokenpatterns_test.go", true},
		{"/Users/alex/jit/internal/wrap/testdata/gemini/env", true},
		{"/Users/alex/app/spec/fixtures/creds.yml", true},
		{"/Users/alex/app/src/__tests__/auth.js", true},
		{"/Users/alex/app/tests/test_client.py", true},
		{"/Users/alex/app/src/auth.spec.ts", true},
		{"/Users/alex/app/src/auth.test.tsx", true},
		// Ordinary source and config must stay ordinary: a narrow rule is the
		// whole point, since anything this matches stops being counted.
		{"/Users/alex/jit/internal/audit/tokenpatterns.go", false},
		{"/Users/alex/app/src/auth.ts", false},
		{"/Users/alex/app/.env", false},
		{"/Users/alex/app/tests/.env", false},
		{"/Users/alex/latest.py", false},
	}
	for _, tc := range cases {
		if got := LooksTestFixture(tc.path); got != tc.want {
			t.Errorf("LooksTestFixture(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// TestFixtureNotChargedToLedger is the dogfooding regression: scanning jit's
// own repository reported five "credentials" in the scanner's own pattern
// fixtures, counted them against the coverage score, and recommended
// replacing that git-tracked Go file with a live mount.
func TestFixtureNotChargedToLedger(t *testing.T) {
	str := func(s string) *string { return &s }
	fixture := Finding{
		RecordID: "f1", FindingType: FindingTypeExposedSecret, Severity: SeverityHigh,
		FilePath: "/Users/alex/jit/internal/audit/tokenpatterns_test.go",
		KeyName:  str("GitHub Personal Access Token"), ValuePreview: str("ghp_**********"),
		TestFixture: true,
	}
	real := Finding{
		RecordID: "r1", FindingType: FindingTypeEnvFilePresent, Severity: SeverityHigh,
		FilePath: "/Users/alex/app/.env", KeyName: str("STRIPE_KEY"),
		ValuePreview: str("sk_l**********"),
	}

	if CountedAsSecret(fixture) {
		t.Error("a test fixture is counted as a secret; nobody owns it to rotate")
	}
	if !CountedAsSecret(real) {
		t.Error("a real .env secret stopped counting")
	}

	findings := []Finding{fixture, real}
	annotateRemedies(findings, "/Users/alex")
	cov := ComputeCoverage("", "", findings)
	if cov.Exposed != 1 {
		t.Errorf("exposed = %d, want 1 (the fixture must not inflate the ledger)", cov.Exposed)
	}

	// It stays visible: the report says what it saw, it just does not bill
	// the user for it.
	summary := buildScanSummary(Config{Endpoint: Endpoint{Username: "alex", Hostname: "mbp"}}, findings, 0, 10)
	var buf bytes.Buffer
	WriteTriageReport(&buf, findings, summary, "/Users/alex", cov)
	out := buf.String()
	if !strings.Contains(out, "test fixture") {
		t.Errorf("report never mentions the fixture sighting:\n%s", out)
	}
	if strings.Contains(out, "tokenpatterns_test.go --mount") {
		t.Errorf("report still offers to mount a test fixture:\n%s", out)
	}
}
