// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// renderTriage renders the triage view the way a real run does, so these
// tests judge what a reader actually sees rather than an intermediate struct.
func renderTriage(t *testing.T, findings []Finding, home string) string {
	t.Helper()
	annotateCauseGroups(findings)
	var buf bytes.Buffer
	WriteTriageReport(&buf, findings, ScanSummary{}, home, ComputeCoverage(home, "", findings))
	return buf.String()
}

// TestProtectInPlaceCommandSurvivesNarrowTerminals is the regression guard for
// the bug this whole pass started from: kindProtectInPlace's arrow is
// `jit migrate <path> --mount`, and the renderer used to truncate it because
// it asked `kind == kindArchived` instead of asking whether the action was a
// command. At 80 columns the path was cut mid-component and --mount vanished
// silently, which is worse than a cut command — it reads as complete and does
// something else.
func TestProtectInPlaceCommandSurvivesNarrowTerminals(t *testing.T) {
	const home = "/Users/alex"
	const path = home + "/.cursor/plugins/cache/cursor-public/snowflake-cursor-plugin/60fbf039c5c3b8dcddc9a07618cc154072b1d5e1/mcp.json"
	key := "Snowflake/header:Authorization"
	out := renderTriage(t, []Finding{{
		RecordID: "s", FindingType: FindingTypeMCPEmbeddedSecret,
		KeyName: &key, Severity: SeverityHigh, Remedy: RemedyManual,
		FilePath: path, Evidence: "credential in a header block",
	}}, home)

	if !strings.Contains(out, "--mount") {
		t.Errorf("the --mount flag was truncated off the command:\n%s", out)
	}
	// The whole path, not a prefix of it. Asserted on the un-flattened output
	// because the command prints as one logical line.
	if !strings.Contains(out, "~/.cursor/plugins/cache/cursor-public/snowflake-cursor-plugin/60fbf039c5c3b8dcddc9a07618cc154072b1d5e1/mcp.json --mount") {
		t.Errorf("command is not intact:\n%s", out)
	}
}

// TestSentenceArrowsWrapInsteadOfLosingTheirTail guards the other half of the
// same renderer. Prose arrows used to truncate on the theory that they merely
// restated the group header; the ones that did have been rewritten to carry
// what the header cannot, so a cut tail now loses meaning rather than
// repetition.
func TestSentenceArrowsWrapInsteadOfLosingTheirTail(t *testing.T) {
	const home = "/Users/alex"
	name := "OpenSSH Private Key"
	line := 2866
	out := renderTriage(t, []Finding{{
		RecordID: "h", FindingType: FindingTypeShellHistorySecret,
		KeyName: &name, Line: &line,
		Severity: SeverityCritical, Remedy: RemedyManual,
		FilePath: home + "/.zsh_history",
		Evidence: "private key material typed at the shell",
	}}, home)

	if strings.Contains(out, "delet…") || strings.Contains(out, "authorized, then…") {
		t.Errorf("a prose arrow was truncated mid-sentence:\n%s", out)
	}
	flat := strings.Join(strings.Fields(out), " ")
	if !strings.Contains(flat, "then delete those lines by hand") {
		t.Errorf("the arrow lost its closing clause:\n%s", out)
	}
}

// TestIdenticalArchivedFindingsRenderOnce covers the six-line stutter: six
// findings identical in every field that matters (type, nil key name,
// severity, remedy) differing only by path rendered as six consecutive
// "! An exposed credential" items, because mergeManualGroups keyed on an
// action that names the file and so was unique per finding.
func TestIdenticalArchivedFindingsRenderOnce(t *testing.T) {
	const home = "/Users/alex"
	const root = home + "/Documents/archive/workspace"
	paths := []string{
		root + "/.env",
		root + "/tooling/falcon/.env",
		root + "/tooling/okta/.env",
		root + "/tooling/urlscan/.env",
		root + "/scripts/descope/.env",
		root + "/scripts/jamf/.env",
	}
	var findings []Finding
	for i, p := range paths {
		findings = append(findings, Finding{
			RecordID: string(rune('a' + i)), FindingType: FindingTypeEnvFilePresent,
			Severity: SeverityHigh, Remedy: RemedyMigrate, Archived: true,
			FilePath: p, Evidence: "secret-shaped",
		})
	}
	out := renderTriage(t, findings, home)

	if got := strings.Count(out, "An exposed credential"); got != 1 {
		t.Errorf("rendered the same finding %d times, want 1:\n%s", got, out)
	}
	// Merging must not cost the reader an address: all six still print.
	for _, p := range paths {
		tail := p[len(home):]
		if !strings.Contains(strings.Join(strings.Fields(out), " "), tail[strings.LastIndex(tail, "/"):]) {
			t.Errorf("address for %s disappeared in the merge:\n%s", p, out)
		}
	}
	// And the one command must cover the whole group, not the sample it was
	// built from — the failure mode groupManualByAction's shortening exists
	// to prevent, which the merge briefly reintroduced by collapsing the
	// items the shortening iterates.
	if !strings.Contains(out, "jit migrate ~/Documents/archive/workspace") {
		t.Errorf("group command does not name the common archived parent:\n%s", out)
	}
}

// TestEnvFileReferenceIsNotASecondSecret pins the ledger half: an MCP config
// that reaches a credential file with --env-file is a link, and the .env it
// names is where the credential is counted. Counting both scored two secrets
// for one credential.
func TestEnvFileReferenceIsNotASecondSecret(t *testing.T) {
	const home = "/Users/alex"
	const envPath = home + "/work/mcp/okta/.env"
	server := "okta-mcp-server"

	envFinding := Finding{
		RecordID: "e", FindingType: FindingTypeEnvFilePresent,
		Severity: SeverityHigh, Remedy: RemedyMigrate,
		FilePath: envPath, Evidence: "contains a PKCS8 private key",
	}
	reference := Finding{
		RecordID: "m", FindingType: FindingTypeMCPEmbeddedSecret,
		KeyName: &server, Severity: SeverityHigh, Remedy: RemedyMigrate,
		FilePath: home + "/work/.mcp.json", OriginPath: envPath,
		Evidence: "reads credentials from ~/work/mcp/okta/.env",
	}

	both := ComputeCoverage(home, "", []Finding{envFinding, reference})
	if both.Exposed != 1 {
		t.Errorf("exposed = %d, want 1: the reference and its target are one credential", both.Exposed)
	}

	// The other direction is the reason the finding exists at all: a target
	// the .env name gate never reported has no finding of its own, so the
	// reference is the only evidence and must still count.
	alone := ComputeCoverage(home, "", []Finding{reference})
	if alone.Exposed != 1 {
		t.Errorf("exposed = %d, want 1: an unreported target leaves the reference as the only evidence", alone.Exposed)
	}
}

// TestLedgerExclusionsAreAllReadableFromTheRecord is the NDJSON-parity guard.
// A consumer recomputing coverage needs every exclusion the tally applies to
// be visible in the serialized record; source_example was not, which left the
// stream unable to reproduce secrets_total.
func TestLedgerExclusionsAreAllReadableFromTheRecord(t *testing.T) {
	raw, err := json.Marshal(Finding{
		RecordType: RecordTypeFinding, FindingType: FindingTypeExposedSecret,
		Severity: SeverityHigh, FilePath: "/Users/alex/src/patterns.go",
		SourceExample: true, OriginPath: "/Users/alex/work/.env",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, field := range []string{"source_example", "origin_path", "test_fixture", "severity"} {
		if _, ok := decoded[field]; !ok {
			t.Errorf("%q is not in the record, so a consumer cannot reproduce the ledger: %s", field, raw)
		}
	}
	if decoded["source_example"] != true {
		t.Errorf("source_example did not round-trip: %s", raw)
	}
}
