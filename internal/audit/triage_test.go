// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"bytes"
	"strings"
	"testing"
)

// triageFixture builds the finding set the triage design review was shaped
// on, in miniature: one secret copied across three dump files (manual,
// production), one migratable .env secret, one wrappable CLI token, one
// low-confidence sighting, and one archived migratable.
func triageFixture() ([]Finding, ScanSummary, Coverage) {
	str := func(s string) *string { return &s }
	findings := []Finding{
		{RecordID: "d1", FindingType: FindingTypeExposedSecret, Severity: SeverityCritical,
			FilePath: "/Users/alex/exports/dump1.html", KeyName: str("Database connection string"),
			ValuePreview: str("sui_**********"), ProductionIndicatorMatch: true},
		{RecordID: "d2", FindingType: FindingTypeExposedSecret, Severity: SeverityCritical,
			FilePath: "/Users/alex/Downloads/dump2.html", KeyName: str("Database connection string"),
			ValuePreview: str("sui_**********"), ProductionIndicatorMatch: true},
		{RecordID: "d3", FindingType: FindingTypeExposedSecret, Severity: SeverityCritical,
			FilePath: "/Users/alex/Repos/dump3.html", KeyName: str("Database connection string"),
			ValuePreview: str("sui_**********"), ProductionIndicatorMatch: true},
		{RecordID: "e1", FindingType: FindingTypeEnvFilePresent, Severity: SeverityHigh,
			FilePath: "/Users/alex/code/app/.env", KeyName: str("JAMF_CLIENT_SECRET"),
			ValuePreview: str("o95k**********")},
		{RecordID: "w1", FindingType: FindingTypeWrappableCLIToken, Severity: SeverityHigh,
			FilePath: "/Users/alex/.config/gh/hosts.yml", KeyName: str("oauth_token"),
			ValuePreview: str("gho_**********"), Remedy: RemedyWrap, FixCommand: "jit wrap gh"},
		{RecordID: "q1", FindingType: FindingTypeEnvFilePresent, Severity: SeverityLow,
			FilePath: "/Users/alex/code/web/.env"},
		{RecordID: "a1", FindingType: FindingTypeEnvFilePresent, Severity: SeverityHigh,
			FilePath: "/Users/alex/Documents/archive/old/.env", KeyName: str("OLD_KEY"),
			ValuePreview: str("xk92**********"), Archived: true},
	}
	annotateRemedies(findings, "/Users/alex")
	cov := ComputeCoverage("", "", findings)
	summary := buildScanSummary(Config{Endpoint: Endpoint{Username: "alex", Hostname: "mbp"}}, findings, 0, 2300)
	summary.FilesScanned = 47312
	return findings, summary, cov
}

func TestWriteTriageReportShape(t *testing.T) {
	findings, summary, cov := triageFixture()

	var buf bytes.Buffer
	WriteTriageReport(&buf, findings, summary, "/Users/alex", cov)
	out := buf.String()

	for _, want := range []string{
		// Header: who, where, how much.
		"alex@mbp", "scanned ~/ (47,312 files)",
		// The ledger: 1 dump secret + env + wrap = 3 counted (archived and
		// Low excluded from migratable/counted respectively: exposed=4
		// including archived).
		"YOUR SECRETS: 4",
		// Green section: bare command, manifest rows with labels, wrap note.
		"jit will protect these",
		"→ jit migrate",
		"~/code/app/.env",
		"JAMF_CLIENT_SECRET",
		"· wraps gh",
		"jit migrate undo",
		// Red section: the three copies collapse to one problem, with the
		// user-world action.
		"only you can protect these",
		"in 3 copies of a file",
		"rotate",
		// The honesty tally. Seven lines of dim prose explaining what jit
		// declined to count now collapse to one "Not counted:" line plus the
		// command that shows them, so these assert the tally's terms.
		"Not counted:",
		"1 low-confidence sighting",
		"in archived folders",
		"→ jit scan --full",
		"No secret values are ever printed in full.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("triage report missing %q:\n%s", want, out)
		}
	}

	for _, reject := range []string{
		// Scanner vocabulary must not leak into the default view.
		"CRITICAL", "HIGH", "LOW", "INFO",
		"finding_type", "[Credential Files]", "[Exposed Secrets]",
		// The archived file is not in the green manifest (bare migrate
		// skips it) and dump paths appear once, not three times.
		"~/Documents/archive/old/.env  ",
	} {
		if strings.Contains(out, reject) {
			t.Errorf("triage report must not contain %q:\n%s", reject, out)
		}
	}

	// The copies' paths: exactly one exemplar, not the full list.
	if strings.Count(out, "dump") != 1 {
		t.Errorf("want exactly one dump path exemplar, got %d:\n%s", strings.Count(out, "dump"), out)
	}
}

// TestWriteTriageReportNeverLeaksRawValue mirrors the human report's core
// guarantee on the new renderer.
func TestWriteTriageReportNeverLeaksRawValue(t *testing.T) {
	raw := "AKIAABCDEFGHIJKLMNOPQRSTUVWXYZ12"
	preview := MaskValue(raw)
	key := "aws"
	findings := []Finding{{
		RecordID: "x", FindingType: FindingTypeExposedSecret, Severity: SeverityHigh,
		FilePath: "/Users/alex/creds.txt", KeyName: &key, ValuePreview: &preview,
	}}
	annotateRemedies(findings, "/Users/alex")
	cov := ComputeCoverage("", "", findings)
	summary := buildScanSummary(Config{}, findings, 0, 0)

	var buf bytes.Buffer
	WriteTriageReport(&buf, findings, summary, "/Users/alex", cov)
	if strings.Contains(buf.String(), raw) {
		t.Fatal("triage report must never contain the raw secret value")
	}
	if !strings.Contains(buf.String(), preview) && !strings.Contains(buf.String(), "creds.txt") {
		t.Error("triage report should still reference the finding")
	}
}

// TestWriteTriageReportCleanMachine: nothing exposed, some protection.
func TestWriteTriageReportCleanMachine(t *testing.T) {
	cov := Coverage{Protected: 9}
	summary := buildScanSummary(Config{Endpoint: Endpoint{Username: "alex", Hostname: "mbp"}}, nil, 9, 100)

	var buf bytes.Buffer
	WriteTriageReport(&buf, nil, summary, "/Users/alex", cov)
	out := buf.String()
	for _, want := range []string{"9 protected by jit (100%)", "Nothing exposed"} {
		if !strings.Contains(out, want) {
			t.Errorf("clean-machine report missing %q:\n%s", want, out)
		}
	}
}
