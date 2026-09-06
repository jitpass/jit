// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

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
		// The header carries the COMMAND and what it covered, not the reader's
		// own username and hostname — dropped 2026-08-06 so this view shares
		// the triage header's shape. Machine identity lives in `jit doctor`
		// and NDJSON's endpoint block, which is where it earns its place.
		"jit scan",
		"✗ CRITICAL — exposure",
		"Shell Configs",
		"/Users/alex/.zshrc",
		":12",
		"CRITICAL  AWS_SECRET_ACCESS_KEY",
		preview,
		"key name matches production-indicator pattern",
		"--format ndjson",
		// The way back to the action-first view. Without it a reader who lands
		// in the inventory has no pointer to the view the product leads with.
		"the action-first view",
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
	// A short phrase from the legend's head: the tail can land on a wrapped
	// continuation line, so a longer substring would break on window width.
	if !strings.Contains(out, "lives under an archived/backup-looking folder") {
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
// wrongly implied they were related. That tier's evidence is rule-level
// boilerplate, not a specific secret or variable name, so it must never
// collapse (see collapsibleFindingTypes).
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
	if !strings.Contains(out, "● CLEAN — exposure 0/100") {
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
	if !strings.Contains(human.String(), "3 live mounts already protected") {
		t.Errorf("human report missing the protected-by-jit line:\n%s", human.String())
	}
	if !strings.Contains(md.String(), "Already protected by jit: 3") {
		t.Errorf("markdown report missing the protected-by-jit line:\n%s", md.String())
	}

	var humanZero, mdZero bytes.Buffer
	WriteHumanReport(&humanZero, nil, base, "")
	WriteMarkdownReport(&mdZero, nil, base)
	for name, out := range map[string]string{"human": humanZero.String(), "markdown": mdZero.String()} {
		if strings.Contains(out, "lready protected") {
			t.Errorf("%s report shows a protected line at zero count:\n%s", name, out)
		}
	}
}

// TestReportsShowIncompleteScanBanner pins parity with the triage view: a
// partial scan must never be able to look like a complete one in ANY
// renderer. The banner sits above the counts because it changes what they
// mean — "0 findings" from a run that could not read ~/.aws is not the
// same claim as "0 findings".
func TestReportsShowIncompleteScanBanner(t *testing.T) {
	degraded := buildScanSummary(Config{}, nil, 0, 0)
	degraded.DegradedScanners = []ScannerFailure{
		{Scanner: "credential files", Error: "open /Users/alex/.aws/credentials: permission denied"},
	}

	var human, md bytes.Buffer
	WriteHumanReport(&human, nil, degraded, "")
	WriteMarkdownReport(&md, nil, degraded)
	for name, out := range map[string]string{"human": human.String(), "markdown": md.String()} {
		if !strings.Contains(out, "INCOMPLETE SCAN") {
			t.Errorf("%s report missing the incomplete-scan banner:\n%s", name, out)
		}
		if !strings.Contains(out, "permission denied") {
			t.Errorf("%s report missing the degraded scanner's reason:\n%s", name, out)
		}
	}

	complete := buildScanSummary(Config{}, nil, 0, 0)
	var humanOK, mdOK bytes.Buffer
	WriteHumanReport(&humanOK, nil, complete, "")
	WriteMarkdownReport(&mdOK, nil, complete)
	for name, out := range map[string]string{"human": humanOK.String(), "markdown": mdOK.String()} {
		if strings.Contains(out, "INCOMPLETE") {
			t.Errorf("%s report shows an incomplete-scan banner on a complete run:\n%s", name, out)
		}
	}
}

// TestFirstFindingPathSkipsUnfixable guards the report trailer's promise: the
// copy-pasteable `jit migrate <path>` it prints must name a file migrate can
// actually act on. hasAutoFix now delegates to the Remedy annotation (the
// single source of truth for who can act), so findings are annotated first —
// exactly as they are before any renderer runs.
func TestFirstFindingPathSkipsUnfixable(t *testing.T) {
	key := "k"
	unfixable := []Finding{
		{FindingType: FindingTypePrivateKeyRisk, FilePath: "/home/u/.ssh/id_ed25519", KeyName: &key},
		{FindingType: FindingTypeCredentialFile, FilePath: "/home/u/.mcp-auth/mcp-remote-0.1.37/abc_tokens.json", KeyName: &key},
	}
	annotateRemedies(unfixable, "/home/u", nil, nil)
	if got := firstFindingPath(unfixable); got != "" {
		t.Errorf("firstFindingPath = %q, want \"\" so the trailer falls back to its <path> placeholder", got)
	}

	// A real, fixable finding is preferred even when an unfixable one sorts
	// ahead of it.
	mixed := append(unfixable, Finding{
		FindingType: FindingTypeCredentialFile,
		FilePath:    "/home/u/proj/.streamlit/secrets.toml",
		KeyName:     &key,
	})
	annotateRemedies(mixed, "/home/u", nil, nil)
	if got := firstFindingPath(mixed); got != "/home/u/proj/.streamlit/secrets.toml" {
		t.Errorf("firstFindingPath = %q, want the migratable file", got)
	}
}

// TestBuildRenderItemsSortsLiveBeforeArchived covers report ordering on a
// machine with many deleted-but-not-purged secrets: one real scan
// (2026-07-28) had ~40 findings under ~/.Trash and a handful of live ones,
// and the live ones — the only actionable findings — sorted last.
//
// Ordering only. Severity and the exposure score are untouched: a credential
// in ~/.Trash is still on disk and still works, so discounting its risk would
// under-report a real exposure. Rank follows actionability, not exposure.
func TestBuildRenderItemsSortsLiveBeforeArchived(t *testing.T) {
	key := "AWS_SECRET_ACCESS_KEY"
	liveKey := "MONGO_PASSWORD"
	group := []Finding{
		// Archived, and more severe — it still sorts second.
		{FindingType: FindingTypeEnvFilePresent, FilePath: "/home/u/.Trash/a/.env",
			Severity: SeverityCritical, KeyName: &key, Archived: true},
		{FindingType: FindingTypeEnvFilePresent, FilePath: "/home/u/live/.env",
			Severity: SeverityHigh, KeyName: &liveKey},
	}

	items := buildRenderItems(group)
	if len(items) != 2 {
		t.Fatalf("got %d items, want 2", len(items))
	}
	if items[0].rep.FilePath != "/home/u/live/.env" {
		t.Errorf("first item = %q, want the live finding — archived findings must never bury actionable ones",
			items[0].rep.FilePath)
	}
}

// TestScanScopeLabelNamesTheTargets is the regression test for the header
// claiming "~/" regardless of what was scanned: `jit scan token.txt` opened
// with "jit scan  ~/", overstating what was checked and understating where
// the findings came from — on the first line of the report.
func TestScanScopeLabelNamesTheTargets(t *testing.T) {
	home := "/Users/x"
	cases := []struct {
		name    string
		targets []string
		want    string
	}{
		{"machine-wide", nil, "~/"},
		{"one file", []string{"/Users/x/proj/.env"}, "~/proj/.env"},
		{"two files", []string{"/Users/x/a", "/Users/x/b"}, "~/a, ~/b"},
		{"many files truncate", []string{"/Users/x/a", "/Users/x/b", "/Users/x/c", "/Users/x/d"}, "~/a, ~/b +2 more"},
		{"outside home stays absolute", []string{"/srv/app/.env"}, "/srv/app/.env"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := scanScopeLabel(ScanSummary{Targets: c.targets}, home)
			if got != c.want {
				t.Errorf("scanScopeLabel(%v) = %q, want %q", c.targets, got, c.want)
			}
		})
	}
}

// TestCollapsedHeaderClaimsOnlyWhatWasSeen: the collapse key
// (findingDedupKey) compares ValuePreview, but two findings with NIL previews
// collapse on severity+key+evidence alone. For those, "same value in N files"
// asserts something the scanner never captured — and it is the claim that
// decides, in the reader's head, whether rotating one credential fixes all N.
// Review finding, 2026-08-06.
func TestCollapsedHeaderClaimsOnlyWhatWasSeen(t *testing.T) {
	key := "GitHub Personal Access Token"
	preview := "ghp_**********"
	locs := []findingLocation{{Path: "/a"}, {Path: "/b"}}

	withValue := renderItem{collapsed: true, rep: Finding{KeyName: &key, ValuePreview: &preview}, locations: locs}
	if got := collapsedHeader(withValue); !strings.Contains(got, "same value") {
		t.Errorf("captured-value item = %q, want a same-value claim", got)
	}
	noValue := renderItem{collapsed: true, rep: Finding{KeyName: &key}, locations: locs}
	if got := collapsedHeader(noValue); strings.Contains(got, "value") {
		t.Errorf("nil-preview item = %q; it claims a value the scanner never saw", got)
	}
	anonymous := renderItem{collapsed: true, rep: Finding{}, locations: locs}
	if got := collapsedHeader(anonymous); strings.Contains(got, "value") {
		t.Errorf("anonymous nil-preview item = %q; same overclaim", got)
	}
	anonWithValue := renderItem{collapsed: true, rep: Finding{ValuePreview: &preview}, locations: locs}
	if got := collapsedHeader(anonWithValue); !strings.Contains(got, "same value") {
		t.Errorf("anonymous captured-value item = %q, want a same-value claim", got)
	}
}

// Every scan outcome closes on something to do except one: a clean report over
// a NAMED path said "clean" about a folder, returned before both trailers, and
// left the reader believing the claim covered the machine. `jit --help` opens
// with "Start with `jit scan`", so this is where a tidy first-time user lands.
func TestCleanReportsEndOnAnAction(t *testing.T) {
	targeted := buildScanSummary(Config{}, nil, 0, 0)
	targeted.Targets = []string{"/tmp/tidy-folder"}
	var buf bytes.Buffer
	WriteHumanReport(&buf, nil, targeted, "")
	out := buf.String()
	if strings.Contains(out, "this machine looks clean") {
		t.Errorf("a targeted scan claims the whole machine is clean:\n%s", out)
	}
	if !strings.Contains(out, "scan the whole machine") {
		t.Errorf("clean targeted report has no next step:\n%s", out)
	}

	// Machine-wide and clean: nothing to fix, so prevention is the only thing
	// left to offer, and it was withheld from exactly these users.
	buf.Reset()
	WriteHumanReport(&buf, nil, buildScanSummary(Config{}, nil, 0, 0), "")
	if out := buf.String(); !strings.Contains(out, "jit guard history") {
		t.Errorf("clean machine-wide report offers no prevention:\n%s", out)
	}

	// A targeted scan never offers the history guard: it did not look there.
	buf.Reset()
	WriteHumanReport(&buf, nil, targeted, "")
	if out := buf.String(); strings.Contains(out, "jit guard history") {
		t.Errorf("targeted scan offers a fix for something it never examined:\n%s", out)
	}
}
