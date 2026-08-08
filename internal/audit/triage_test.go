// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
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
		// Header: the command, then what it covered. No user@host — machine
		// identity belongs on the diagnostic surfaces, not on the report's
		// most prominent line.
		"jit scan", "~/ · 47,312 files",
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
		// One grammar for the file spread, tool-wide: "in N files", never
		// "in N copies of a file" (which reads as one file duplicated).
		"in 3 files",
		"rotate",
		// The honesty tally. Seven lines of dim prose explaining what jit
		// declined to count now collapse to one "Not counted:" line plus the
		// command that shows them, so these assert the tally's terms.
		"Not counted:",
		"1 low-confidence sighting",
		// Archived secrets are NOT in that tally. They are counted by
		// ComputeCoverage, so they get a group of their own naming the one
		// command that reaches them — the sweep skips archived directories,
		// an explicit path does not.
		"the sweep skips archived folders",
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
		// The footer must never claim archived findings went uncounted while
		// the ledger above has them in "only you can protect these".
		"in archived folders",
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

// The three percentages a reader sees on the ledger must sum to 100, asserted
// against the RENDER rather than against the formula.
//
// The formula version of this test was a tautology — pct + (after-pct) +
// (100-after) is 100 for any two integers — so it stayed green no matter what
// WriteTriageReport printed, including the pctOf() form that shipped a visible
// 53 + 12 + 34 = 99. Parsing the numbers back off the rendered line is the
// only version that can fail when the render regresses.
func TestLedgerPercentagesSumTo100InTheRender(t *testing.T) {
	findings, summary, _ := triageFixture()
	// The fixture's own ledger divides evenly (0/50/50) and so cannot see a
	// rounding bug at all. These are the real numbers off the machine that
	// reported it — 50 protected, 11 migratable, 32 manual of 93 — where
	// three independent floors printed 53 + 12 + 34. Coverage is a separate
	// argument from findings precisely so the arithmetic can be driven like
	// this.
	cov := Coverage{Protected: 50, Exposed: 43, Migratable: 11}
	var buf bytes.Buffer
	WriteTriageReport(&buf, findings, summary, "/Users/alex", cov)
	out := regexp.MustCompile("\x1b\\[[0-9;]*m").ReplaceAllString(buf.String(), "")

	var protected, gain, remainder int
	for _, line := range strings.Split(out, "\n") {
		if m := regexp.MustCompile(`\((\d+)%\)`).FindStringSubmatch(line); m != nil && protected == 0 {
			protected, _ = strconv.Atoi(m[1])
		}
		if strings.Contains(line, "to 100%:") {
			plus := regexp.MustCompile(`\+(\d+)%`).FindAllStringSubmatch(line, -1)
			if len(plus) != 2 {
				t.Fatalf("ledger line has %d increments, want 2 (migrate + manual):\n%s", len(plus), line)
			}
			gain, _ = strconv.Atoi(plus[0][1])
			remainder, _ = strconv.Atoi(plus[1][1])
		}
	}
	if sum := protected + gain + remainder; sum != 100 {
		t.Errorf("rendered ledger reads %d%% + %d%% + %d%% = %d%%, want 100:\n%s",
			protected, gain, remainder, sum, out)
	}
	// And the red header's promise has to be the same arithmetic.
	if !strings.Contains(out, fmt.Sprintf("%d%% → 100%%", protected+gain)) {
		t.Errorf("red header does not continue from %d%%:\n%s", protected+gain, out)
	}
}

// The red section's headline number must equal the number of secrets it
// actually shows. This is the bug that motivated the archived group: a real
// scan printed "only you can protect these — 32 secrets" above thirteen items
// whose own badges summed to 25, because ComputeCoverage put archived
// findings in manualRemainder and triageGroupManual admitted only
// RemedyManual ones, so seven secrets were charged to a bucket that rendered
// none of them.
//
// Asserted against the rendered groups rather than a string, because the
// failure mode is precisely that a secret is counted somewhere and displayed
// nowhere — only a comparison of the two sides catches it.
func TestManualGroupsAccountForEveryManualSecret(t *testing.T) {
	findings, _, cov := triageFixture()
	groups := triageGroupManual(findings, "/Users/alex")

	shown := 0
	for _, ag := range groupManualByAction(groups, "/Users/alex") {
		sum := 0
		for _, it := range ag.items {
			sum += it.secrets
		}
		if sum != ag.secrets {
			t.Errorf("[%s] header says %d, items sum to %d", ag.kind, ag.secrets, sum)
		}
		shown += ag.secrets
	}
	if shown != cov.manualRemainder() {
		t.Errorf("red section shows %d secrets, ledger charges it %d — the difference is counted and rendered nowhere",
			shown, cov.manualRemainder())
	}
}

// One arrow per group is only honest if that arrow covers the whole group.
// Regenerating the archived command from the worst item alone printed one
// path under two items; naming every path was honest but grew unreadable
// (six ~70-char paths on one line, 2026-08-07). The command is now the
// deepest archived directory when naming it rediscovers every file, and the
// full path list — never truncated — when it would not.
func TestArchivedActionCoversItsWholeGroup(t *testing.T) {
	mk := func(id, ftype, path string) Finding {
		return Finding{
			RecordID: id, FindingType: ftype,
			Severity: SeverityHigh, Remedy: RemedyMigrate, Archived: true,
			FilePath: path, Evidence: "secret-shaped",
		}
	}
	archivedAction := func(t *testing.T, findings []Finding) string {
		t.Helper()
		annotateCauseGroups(findings)
		groups := groupManualByAction(triageGroupManual(findings, "/Users/alex"), "/Users/alex")
		for i := range groups {
			if groups[i].kind == kindArchived {
				return groups[i].action
			}
		}
		t.Fatalf("no archived group: %+v", groups)
		return ""
	}

	t.Run("one archived parent covers the group", func(t *testing.T) {
		action := archivedAction(t, []Finding{
			mk("a", FindingTypeEnvFilePresent, "/Users/alex/Documents/archive/one/.env"),
			mk("b", FindingTypeEnvFilePresent, "/Users/alex/Documents/archive/two/.env"),
		})
		if want := "jit migrate ~/Documents/archive"; action != want {
			t.Errorf("action = %q, want %q", action, want)
		}
	})

	t.Run("two archives fall back to full paths", func(t *testing.T) {
		// The common ancestor is ~/Documents, which is NOT archived —
		// naming it would sweep live projects the reader never consented to.
		action := archivedAction(t, []Finding{
			mk("a", FindingTypeEnvFilePresent, "/Users/alex/Documents/archive/one/.env"),
			mk("b", FindingTypeEnvFilePresent, "/Users/alex/Documents/backups/two/.env"),
		})
		for _, want := range []string{"archive/one/.env", "backups/two/.env"} {
			if !strings.Contains(action, want) {
				t.Errorf("action %q does not name %q", action, want)
			}
		}
	})

	t.Run("a non-dir-discoverable file falls back to full paths", func(t *testing.T) {
		// A loose token file is reached only by its explicit path — the dir
		// walk finds project files, so the shortened command would silently
		// drop it.
		action := archivedAction(t, []Finding{
			mk("a", FindingTypeEnvFilePresent, "/Users/alex/Documents/archive/one/.env"),
			mk("b", FindingTypeExposedSecret, "/Users/alex/Documents/archive/two/token.txt"),
		})
		for _, want := range []string{"archive/one/.env", "archive/two/token.txt"} {
			if !strings.Contains(action, want) {
				t.Errorf("action %q does not name %q", action, want)
			}
		}
	})
}

// The rendered arrow line must carry the archived command WHOLE. TruncTail
// used to apply here, and its ellipsis ate half the targets of a real scan's
// six-path command (2026-08-07) — the pre-render action string was complete,
// so only a rendered-output assertion can hold the line.
func TestArchivedCommandRendersUntruncated(t *testing.T) {
	long := "/Users/alex/Documents/archive/a-project-directory-name-well-past-eighty-columns-of-terminal/deeper-still/.env"
	findings := []Finding{{
		RecordID: "a", FindingType: FindingTypeEnvFilePresent,
		Severity: SeverityHigh, Remedy: RemedyMigrate, Archived: true,
		FilePath: long, Evidence: "secret-shaped",
	}}
	annotateCauseGroups(findings)

	var buf bytes.Buffer
	WriteTriageReport(&buf, findings, ScanSummary{}, "/Users/alex", ComputeCoverage("/Users/alex", "", findings))
	want := "jit migrate ~/Documents/archive/a-project-directory-name-well-past-eighty-columns-of-terminal/deeper-still/.env"
	if !strings.Contains(buf.String(), want) {
		t.Errorf("rendered report cut the archived command; want it whole:\n%s", buf.String())
	}
}

// Every problem is filed under the remedy it is actually told to perform, and
// each remedy is stated once. The flat list printed "rotate them now, then
// delete every copy" five times on a real machine.
func TestActionGroupsStateEachRemedyOnce(t *testing.T) {
	findings, _, _ := triageFixture()
	groups := triageGroupManual(findings, "/Users/alex")
	seen := map[string]bool{}
	for _, ag := range groupManualByAction(groups, "/Users/alex") {
		if seen[ag.kind] {
			t.Errorf("kind %q got two blocks", ag.kind)
		}
		seen[ag.kind] = true
		if ag.action == "" {
			t.Errorf("[%s] has no action", ag.kind)
		}
		for _, it := range ag.items {
			if it.kind != ag.kind {
				t.Errorf("[%s] contains an item filed under %q", ag.kind, it.kind)
			}
		}
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
