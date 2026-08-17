// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"strings"
	"testing"
)

// TestManualActionAgreesPerFile is the contradiction a real scan printed
// (2026-07-29): one report file held a production-flagged credential AND an
// ordinary database password, so the same path was told both "rotate them
// now, then delete every copy" and "protect in place: jit migrate … --mount".
// The two secrets landed in different problems (their file SETS differ), and
// the action was decided from one sample finding that knew nothing about its
// neighbours.
func TestManualActionAgreesPerFile(t *testing.T) {
	str := func(s string) *string { return &s }
	shared := "/Users/alex/reports/dump-a.html"
	findings := []Finding{
		// The production secret, copied across three reports.
		{RecordID: "p1", FindingType: FindingTypeExposedSecret, Severity: SeverityCritical,
			FilePath: shared, KeyName: str("Database connection string"),
			ValuePreview: str("prod**********"), ProductionIndicatorMatch: true},
		{RecordID: "p2", FindingType: FindingTypeExposedSecret, Severity: SeverityCritical,
			FilePath: "/Users/alex/reports/dump-b.html", KeyName: str("Database connection string"),
			ValuePreview: str("prod**********"), ProductionIndicatorMatch: true},
		{RecordID: "p3", FindingType: FindingTypeExposedSecret, Severity: SeverityCritical,
			FilePath: "/Users/alex/reports/dump-c.html", KeyName: str("Database connection string"),
			ValuePreview: str("prod**********"), ProductionIndicatorMatch: true},
		// A second, non-production secret living in a SUBSET of those files,
		// so it forms its own problem — including the file above.
		{RecordID: "s1", FindingType: FindingTypeExposedSecret, Severity: SeverityHigh,
			FilePath: shared, KeyName: str("JSON Web Token"),
			ValuePreview: str("eyJh**********")},
		{RecordID: "s2", FindingType: FindingTypeExposedSecret, Severity: SeverityHigh,
			FilePath: "/Users/alex/reports/dump-b.html", KeyName: str("JSON Web Token"),
			ValuePreview: str("eyJh**********")},
	}
	annotateRemedies(findings, "/Users/alex", nil)

	groups := triageGroupManual(findings, "/Users/alex")
	if len(groups) != 2 {
		t.Fatalf("got %d problems, want 2 (the two file sets differ)", len(groups))
	}
	for _, g := range groups {
		if strings.Contains(g.action, "--mount") {
			t.Errorf("a file known to have carried a production credential is still "+
				"offered in-place protection: %q", g.action)
		}
		if !strings.Contains(g.action, "rotate") {
			t.Errorf("action = %q, want rotation", g.action)
		}
	}
}

// TestManualActionCopiesBeatMount: mounting one path cannot fix a secret that
// spread. The other copies stay plaintext, so the offer would describe a
// protection the user does not actually get.
func TestManualActionCopiesBeatMount(t *testing.T) {
	str := func(s string) *string { return &s }
	var findings []Finding
	for i, p := range []string{
		"/Users/alex/scripts/a.sh", "/Users/alex/scripts/b.sh", "/Users/alex/scripts/c.sh",
	} {
		findings = append(findings, Finding{
			RecordID: string(rune('a' + i)), FindingType: FindingTypeExposedSecret,
			Severity: SeverityHigh, FilePath: p, KeyName: str("Database connection string"),
			ValuePreview: str("pgpw**********"),
		})
	}
	annotateRemedies(findings, "/Users/alex", nil)

	groups := triageGroupManual(findings, "/Users/alex")
	if len(groups) != 1 {
		t.Fatalf("got %d problems, want 1", len(groups))
	}
	if strings.Contains(groups[0].action, "--mount") {
		t.Errorf("offered to mount one of three copies: %q", groups[0].action)
	}
	// The action must still be about the copies rather than about one of
	// them, and must lead with rotation — the wording moved off "then delete
	// every copy" (which restated the group header verbatim) onto the fact
	// the header cannot carry: deleting them does not undo the exposure.
	if !strings.Contains(groups[0].action, "copies") {
		t.Errorf("action = %q, want it to speak about the copies", groups[0].action)
	}
	if !strings.HasPrefix(groups[0].action, "rotate") {
		t.Errorf("action = %q, want rotation to lead", groups[0].action)
	}
}

// TestManualActionStillOffersMountWhereItWorks guards the other direction:
// the --mount offer exists for a real case — one live script that mixes a
// secret with content bare `jit migrate` will not touch — and the new gates
// must not swallow it.
func TestManualActionStillOffersMountWhereItWorks(t *testing.T) {
	str := func(s string) *string { return &s }
	findings := []Finding{
		{RecordID: "m1", FindingType: FindingTypeExposedSecret, Severity: SeverityHigh,
			FilePath: "/Users/alex/bin/deploy.sh", KeyName: str("Database connection string"),
			ValuePreview: str("pgpw**********")},
	}
	annotateRemedies(findings, "/Users/alex", nil)

	groups := triageGroupManual(findings, "/Users/alex")
	if len(groups) != 1 {
		t.Fatalf("got %d problems, want 1", len(groups))
	}
	if !strings.Contains(groups[0].action, "jit migrate ~/bin/deploy.sh --mount") {
		t.Errorf("action = %q, want the in-place mount offer", groups[0].action)
	}
}
