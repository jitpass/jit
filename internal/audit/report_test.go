// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriteHumanReportNeverLeaksRawValue(t *testing.T) {
	key := "AWS_SECRET_ACCESS_KEY"
	rawSecretForComparisonOnly := "AKIAABCDEFGHIJKLMNOPQRSTUVWXYZ12"
	preview := MaskValue(rawSecretForComparisonOnly)
	line := 12

	findings := []Finding{
		{
			FindingType:              FindingTypeShellConfigSecret,
			Severity:                 SeverityCritical,
			ProductionIndicatorMatch: true,
			FilePath:                 "/Users/alex/.zshrc",
			Line:                     &line,
			KeyName:                  &key,
			ValuePreview:             &preview,
			Evidence:                 "key name matches production-indicator pattern",
		},
	}
	summary := buildScanSummary(Config{Endpoint: Endpoint{Username: "alex", Hostname: "Alexs-MacBook-Pro"}}, findings, 0, 0)

	var buf bytes.Buffer
	WriteHumanReport(&buf, findings, summary, "")
	out := buf.String()

	if strings.Contains(out, rawSecretForComparisonOnly) {
		t.Fatal("human report must never contain the raw secret value")
	}
	for _, want := range []string{
		"alex@Alexs-MacBook-Pro",
		"RISK LEVEL: CRITICAL",
		"Shell Configs",
		"/Users/alex/.zshrc",
		":12",
		"CRITICAL  AWS_SECRET_ACCESS_KEY",
		preview,
		"key name matches production-indicator pattern",
		"jit scan --format ndjson",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report output missing expected substring %q\n--- full output ---\n%s", want, out)
		}
	}
}

// TestWriteHumanReportTagsArchivedFindings: a finding under an archived/
// backup-looking directory used to be illegible from the audit side (a real,
// reported confusion: audit showed a HIGH finding under ~/Documents/
// archive/, and nothing explained how to act on it). The report must tag the
// path and explain the tag once — naming such a file explicitly is what
// converts it; a report with no archived finding must show neither.
func TestWriteHumanReportTagsArchivedFindings(t *testing.T) {
	archived := Finding{
		FindingType: FindingTypeMCPEmbeddedSecret,
		Severity:    SeverityHigh,
		FilePath:    "/Users/alex/Documents/archive/oldproj/.mcp.json",
		Evidence:    "embedded directly in MCP server \"jamf\"'s env block",
	}
	active := Finding{
		FindingType: FindingTypeEnvFilePresent,
		Severity:    SeverityMedium,
		FilePath:    "/Users/alex/code/myapp/.env",
		Evidence:    "plaintext .env file",
	}
	findings := []Finding{archived, active}
	summary := buildScanSummary(Config{}, findings, 0, 0)

	var buf bytes.Buffer
	WriteHumanReport(&buf, findings, summary, "")
	out := buf.String()

	if !strings.Contains(out, archived.FilePath+" [archived]") {
		t.Errorf("expected the archived path to carry the [archived] tag, got:\n%s", out)
	}
	if strings.Contains(out, active.FilePath+" [archived]") {
		t.Errorf("expected the active path to carry no tag, got:\n%s", out)
	}
	if !strings.Contains(out, "name such a file explicitly to convert it") {
		t.Errorf("expected the [archived] legend explaining how to convert a named archived file, got:\n%s", out)
	}

	buf.Reset()
	WriteHumanReport(&buf, []Finding{active}, buildScanSummary(Config{}, []Finding{active}, 0, 0), "")
	if strings.Contains(buf.String(), "[archived]") {
		t.Errorf("expected no [archived] tag or legend without an archived finding, got:\n%s", buf.String())
	}
}

// TestWriteHumanReportEscapesSpacesInPaths: a real support case — a user
// copy-pasted the report's `~/Library/Application Support/Claude/
// claude_desktop_config.json` finding into `cat`, the unquoted space split
// it into two arguments, and the resulting "No such file or directory"
// read as a false positive. Terminal-report paths must paste into a shell
// verbatim.
func TestWriteHumanReportEscapesSpacesInPaths(t *testing.T) {
	f := Finding{
		FindingType: FindingTypeMCPEmbeddedSecret,
		Severity:    SeverityHigh,
		FilePath:    "/Users/alex/Library/Application Support/Claude/claude_desktop_config.json",
		Evidence:    "embedded directly in MCP server \"jamf\"'s env block",
	}
	findings := []Finding{f}

	var buf bytes.Buffer
	WriteHumanReport(&buf, findings, buildScanSummary(Config{}, findings, 0, 0), "/Users/alex")
	out := buf.String()

	if !strings.Contains(out, `~/Library/Application\ Support/Claude/claude_desktop_config.json`) {
		t.Errorf("expected the space in the path to be backslash-escaped for shell copy-paste, got:\n%s", out)
	}
	if strings.Contains(out, "Application Support/Claude") {
		t.Errorf("expected no unescaped variant of the path, got:\n%s", out)
	}
}

// TestWriteHumanReportShowsKeyName guards against exactly the gap a real
// user found (2026-07-06): an MCP-embedded-secret finding showing a masked
// value and "why" text but never which variable it actually was, forcing a
// developer to go open the file themselves to find out what to act on.
func TestWriteHumanReportShowsKeyName(t *testing.T) {
	key := "jamf/JAMF_API_TOKEN"
	preview := "o95k" + maskSuffix
	findings := []Finding{
		{
			FindingType:  FindingTypeMCPEmbeddedSecret,
			Severity:     SeverityHigh,
			FilePath:     "/Users/alex/.mcp.json",
			KeyName:      &key,
			ValuePreview: &preview,
			Evidence:     `embedded directly in MCP server "jamf"'s env block`,
		},
	}
	summary := buildScanSummary(Config{Endpoint: Endpoint{Username: "alex", Hostname: "host"}}, findings, 0, 0)

	var buf bytes.Buffer
	WriteHumanReport(&buf, findings, summary, "")
	out := buf.String()

	if !strings.Contains(out, "jamf/JAMF_API_TOKEN") {
		t.Errorf("report must show the finding's KeyName so a reader knows which variable to act on, got:\n%s", out)
	}
}

// TestWriteHumanReportGroupsMultipleFindingsInSameFile guards against
// exactly the other gap a real user found (2026-07-06): two secrets in one
// MCP config's env block showed the full file path twice, reading as if
// two separate files were broken instead of one file with two things to fix.
func TestWriteHumanReportGroupsMultipleFindingsInSameFile(t *testing.T) {
	keyA, keyB := "jamf/JAMF_PRO_CLIENT_ID", "jamf/JAMF_PRO_CLIENT_SECRET"
	previewA, previewB := "9c99"+maskSuffix, "o95k"+maskSuffix
	findings := []Finding{
		{FindingType: FindingTypeMCPEmbeddedSecret, Severity: SeverityHigh, FilePath: "/Users/alex/config.json", KeyName: &keyA, ValuePreview: &previewA, Evidence: "e"},
		{FindingType: FindingTypeMCPEmbeddedSecret, Severity: SeverityHigh, FilePath: "/Users/alex/config.json", KeyName: &keyB, ValuePreview: &previewB, Evidence: "e"},
	}
	summary := buildScanSummary(Config{Endpoint: Endpoint{Username: "alex", Hostname: "host"}}, findings, 0, 0)

	var buf bytes.Buffer
	WriteHumanReport(&buf, findings, summary, "")
	out := buf.String()

	// Count within the findings body only: the migrate trailer intentionally
	// names a flagged path once more as a copy-pasteable fix command, which is
	// a separate concern from the "one file, listed once" guarantee here.
	if got := strings.Count(reportBody(out), "/Users/alex/config.json"); got != 1 {
		t.Errorf("file path should appear exactly once even with 2 findings in it, appeared %d times:\n%s", got, out)
	}
	if !strings.Contains(out, "jamf/JAMF_PRO_CLIENT_ID") || !strings.Contains(out, "jamf/JAMF_PRO_CLIENT_SECRET") {
		t.Errorf("both findings' key names should still be shown, got:\n%s", out)
	}
}

// TestWriteHumanReportGroupsMixedSeverityFindingsInSameFile guards against a
// regression introduced by worst-severity-first sorting (2026-07-08): a
// file with a high-severity finding AND a low-severity finding (e.g. an MCP
// config with one embedded token plus one plain-URL finding) got split into
// two disjoint blocks — its high finding sorted to the top of the category,
// its low finding sorted to the bottom — printing the same path twice,
// exactly the bug TestWriteHumanReportGroupsMultipleFindingsInSameFile
// above already guards against for the same-severity case.
func TestWriteHumanReportGroupsMixedSeverityFindingsInSameFile(t *testing.T) {
	// Each finding here has a distinct key+evidence combo, deliberately not
	// repeated in any other file — this isolates the "one file, mixed
	// severities" case from collapsing (see
	// TestWriteHumanReportCollapsesDuplicatePatternAcrossFiles below for
	// that), so a bare path-count check unambiguously exercises only the
	// bug this test was written to catch.
	keyHigh, keyLow, keyOther := "jamf/JAMF_PRO_CLIENT_ID", "caido/CAIDO_URL", "other/OTHER_KEY"
	findings := []Finding{
		{FindingType: FindingTypeMCPEmbeddedSecret, Severity: SeverityLow, FilePath: "/Users/alex/config.json", KeyName: &keyLow, Evidence: "low finding"},
		{FindingType: FindingTypeMCPEmbeddedSecret, Severity: SeverityHigh, FilePath: "/Users/alex/other.json", KeyName: &keyOther, Evidence: "other file's finding"},
		{FindingType: FindingTypeMCPEmbeddedSecret, Severity: SeverityHigh, FilePath: "/Users/alex/config.json", KeyName: &keyHigh, Evidence: "high finding"},
	}
	summary := buildScanSummary(Config{Endpoint: Endpoint{Username: "alex", Hostname: "host"}}, findings, 0, 0)

	var buf bytes.Buffer
	WriteHumanReport(&buf, findings, summary, "")
	out := buf.String()

	if got := strings.Count(reportBody(out), "/Users/alex/config.json"); got != 1 {
		t.Errorf("file path should appear exactly once even when its findings span severities, appeared %d times:\n%s", got, out)
	}
}

// reportBody returns everything in a human report above the migrate trailer,
// so path-count assertions exercise the findings listing without tripping over
// the trailer's copy-pasteable `jit migrate <flagged path>` example.
func reportBody(out string) string {
	if i := strings.Index(out, "Run `jit migrate"); i >= 0 {
		return out[:i]
	}
	return out
}

// TestWriteHumanReportCollapsesDuplicatePatternAcrossFiles guards the
// density fix (2026-07-08): the same severity/key/evidence/value repeated
// across many files (dogfooding found the same MCP server's credentials
// embedded in 3 separate config files, and the same secret-shaped variable
// name across 7 unrelated .env files) must collapse into one block with a
// file list, not repeat an identical explanation once per file.
func TestWriteHumanReportCollapsesDuplicatePatternAcrossFiles(t *testing.T) {
	key := "jamf/JAMF_PRO_CLIENT_ID"
	preview := "9c99" + maskSuffix
	findings := []Finding{
		{FindingType: FindingTypeMCPEmbeddedSecret, Severity: SeverityHigh, FilePath: "/Users/alex/b.json", KeyName: &key, ValuePreview: &preview, Evidence: "embedded directly in MCP server \"jamf\"'s env block"},
		{FindingType: FindingTypeMCPEmbeddedSecret, Severity: SeverityHigh, FilePath: "/Users/alex/a.json", KeyName: &key, ValuePreview: &preview, Evidence: "embedded directly in MCP server \"jamf\"'s env block"},
	}
	summary := buildScanSummary(Config{Endpoint: Endpoint{Username: "alex", Hostname: "host"}}, findings, 0, 0)

	var buf bytes.Buffer
	WriteHumanReport(&buf, findings, summary, "")
	out := buf.String()

	if strings.Count(out, "embedded directly in MCP server") != 1 {
		t.Errorf("identical evidence shared by 2 files must be printed once, not once per file, got:\n%s", out)
	}
	if !strings.Contains(out, "jamf/JAMF_PRO_CLIENT_ID (same value in 2 files):") {
		t.Errorf("expected a collapsed block header naming the key and file count, got:\n%s", out)
	}
	if !strings.Contains(out, "- /Users/alex/a.json") || !strings.Contains(out, "- /Users/alex/b.json") {
		t.Errorf("expected both affected paths listed, got:\n%s", out)
	}
}

// TestWriteHumanReportDoesNotCollapseDifferentValuesSameKey guards against
// over-collapsing: two files with the same key name but a DIFFERENT actual
// value are two distinct secrets, not one pattern repeated — collapsing
// them would wrongly imply they're interchangeable copies of each other.
func TestWriteHumanReportDoesNotCollapseDifferentValuesSameKey(t *testing.T) {
	key := "jamf/JAMF_PRO_CLIENT_ID"
	previewA, previewB := "9c99"+maskSuffix, "zz11"+maskSuffix
	findings := []Finding{
		{FindingType: FindingTypeMCPEmbeddedSecret, Severity: SeverityHigh, FilePath: "/Users/alex/a.json", KeyName: &key, ValuePreview: &previewA, Evidence: "e"},
		{FindingType: FindingTypeMCPEmbeddedSecret, Severity: SeverityHigh, FilePath: "/Users/alex/b.json", KeyName: &key, ValuePreview: &previewB, Evidence: "e"},
	}
	summary := buildScanSummary(Config{Endpoint: Endpoint{Username: "alex", Hostname: "host"}}, findings, 0, 0)

	var buf bytes.Buffer
	WriteHumanReport(&buf, findings, summary, "")
	out := buf.String()

	if strings.Contains(out, "same value in 2 files") {
		t.Errorf("different values under the same key must NOT collapse, got:\n%s", out)
	}
	if !strings.Contains(out, previewA) || !strings.Contains(out, previewB) {
		t.Errorf("both distinct values should still be shown, got:\n%s", out)
	}
}

// TestWriteHumanReportDoesNotCollapseUnrelatedIACFiles guards against a
// real dogfooding case (2026-07-08): IaC's unescalated tier always uses the
// exact same fixed advisory text ("detection only, no automated fix yet")
// regardless of file content, so two completely unrelated Secret.yaml
// manifests from different, unrelated repos collapsed into one block that
// wrongly implied they were related. IaC/Suspicious Filenames evidence is
// rule-level boilerplate, not a specific secret or variable name, so they
// must never collapse (see collapsibleFindingTypes).
func TestWriteHumanReportDoesNotCollapseUnrelatedIACFiles(t *testing.T) {
	findings := []Finding{
		{FindingType: FindingTypeIACVariableFile, Severity: SeverityInfo, FilePath: "/Users/alex/project-a/secrets.yaml", Evidence: "infrastructure-as-code variable file: detection only, no automated fix yet"},
		{FindingType: FindingTypeIACVariableFile, Severity: SeverityInfo, FilePath: "/Users/alex/unrelated-repo/Secret.yaml", Evidence: "infrastructure-as-code variable file: detection only, no automated fix yet"},
	}
	summary := buildScanSummary(Config{Endpoint: Endpoint{Username: "alex", Hostname: "host"}}, findings, 0, 0)

	var buf bytes.Buffer
	WriteHumanReport(&buf, findings, summary, "")
	out := buf.String()

	if strings.Contains(out, "files:") {
		t.Errorf("unrelated IaC files sharing only generic boilerplate must not collapse, got:\n%s", out)
	}
	if !strings.Contains(out, "/Users/alex/project-a/secrets.yaml") || !strings.Contains(out, "/Users/alex/unrelated-repo/Secret.yaml") {
		t.Errorf("both files should still be listed individually, got:\n%s", out)
	}
}

func TestWriteHumanReportCleanScan(t *testing.T) {
	summary := buildScanSummary(Config{Endpoint: Endpoint{Username: "alex", Hostname: "host"}}, nil, 0, 0)
	var buf bytes.Buffer
	WriteHumanReport(&buf, nil, summary, "")
	out := buf.String()
	if !strings.Contains(out, "RISK LEVEL: CLEAN") {
		t.Errorf("expected CLEAN risk level in output, got:\n%s", out)
	}
	if !strings.Contains(out, "looks clean") {
		t.Errorf("expected a clean-scan message, got:\n%s", out)
	}
}

func TestWriteHumanReportAllCategoriesAlwaysListed(t *testing.T) {
	summary := buildScanSummary(Config{Endpoint: Endpoint{Username: "a", Hostname: "h"}}, nil, 0, 0)
	var buf bytes.Buffer
	WriteHumanReport(&buf, nil, summary, "")
	out := buf.String()
	for _, label := range findingTypeLabels {
		if !strings.Contains(out, label) {
			t.Errorf("expected category label %q in the per-category count summary, got:\n%s", label, out)
		}
	}
}

// TestWriteHumanReportShortensHomePaths pins the "~"-shortening as a pure
// function of the home argument — never of the ambient $HOME. The fixture
// home is passed explicitly, so this test behaves identically on any
// machine (a runner whose real home happened to prefix the fixture paths
// once made the absolute-path assertions above environment-dependent).
func TestWriteHumanReportShortensHomePaths(t *testing.T) {
	line := 3
	findings := []Finding{
		{
			FindingType: FindingTypeEnvFilePresent,
			Severity:    SeverityHigh,
			FilePath:    "/Users/alex/proj/.env",
			Line:        &line,
			Evidence:    "plaintext .env file",
		},
	}
	summary := buildScanSummary(Config{Endpoint: Endpoint{Username: "alex", Hostname: "host"}}, findings, 0, 0)
	var buf bytes.Buffer
	WriteHumanReport(&buf, findings, summary, "/Users/alex")
	out := buf.String()
	if !strings.Contains(out, "~/proj/.env") {
		t.Errorf("expected the finding path shortened to ~/proj/.env, got:\n%s", out)
	}
	if strings.Contains(out, "/Users/alex/proj/.env") {
		t.Errorf("expected no absolute path once home is supplied, got:\n%s", out)
	}
}

func TestShortenHome(t *testing.T) {
	cases := []struct {
		home, path, want string
	}{
		{"/Users/alex", "/Users/alex/proj/.env", "~/proj/.env"},
		{"/Users/alex", "/Users/alex", "~"},
		{"/Users/alex", "/Users/alexandra/.env", "/Users/alexandra/.env"}, // prefix of a longer username must not match
		{"/Users/alex", "/tmp/other/.env", "/tmp/other/.env"},
		{"", "/Users/alex/proj/.env", "/Users/alex/proj/.env"}, // empty home disables shortening
	}
	for _, c := range cases {
		if got := ShortenHome(c.home, c.path); got != c.want {
			t.Errorf("ShortenHome(%q, %q) = %q, want %q", c.home, c.path, got, c.want)
		}
	}
}

func TestReportsShowProtectedCountOnlyWhenNonZero(t *testing.T) {
	base := ScanSummary{RiskLevel: RiskLevelClean, FindingsByCategory: map[string]int{}}

	withCount := base
	withCount.JitProtectedCount = 3
	var human, md bytes.Buffer
	WriteHumanReport(&human, nil, withCount, "")
	WriteMarkdownReport(&md, nil, withCount)
	for name, out := range map[string]string{"human": human.String(), "markdown": md.String()} {
		if !strings.Contains(out, "Already protected by jit: 3") {
			t.Errorf("%s report missing the protected-by-jit line:\n%s", name, out)
		}
	}

	var humanZero, mdZero bytes.Buffer
	WriteHumanReport(&humanZero, nil, base, "")
	WriteMarkdownReport(&mdZero, nil, base)
	for name, out := range map[string]string{"human": humanZero.String(), "markdown": mdZero.String()} {
		if strings.Contains(out, "Already protected") {
			t.Errorf("%s report shows a protected line at zero count:\n%s", name, out)
		}
	}
}
