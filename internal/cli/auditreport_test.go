// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func reportEntry(t time.Time, subject, parent, status string) auditEntry {
	return auditEntry{t: t, kind: "cmd", status: status, subject: subject, parent: parent}
}

func renderReport(entries []auditEntry) string {
	var buf bytes.Buffer
	printAuditReport(&buf, entries, false, auditScaleOf(entries))
	return buf.String()
}

// The report's whole reason to exist: the facts a person needs, without the
// key=value scaffolding the machine form carries.
func TestAuditReportDropsLogfmtScaffolding(t *testing.T) {
	now := time.Now()
	out := renderReport([]auditEntry{
		reportEntry(now, "jit status", "claude", "ok"),
	})
	for _, gone := range []string{"kind=", "level=", "user=", "pid=", "dur=", "status="} {
		if strings.Contains(out, gone) {
			t.Errorf("report still carries %q:\n%s", gone, out)
		}
	}
	if !strings.Contains(out, "jit status") || !strings.Contains(out, "claude") {
		t.Errorf("report lost the command or its launcher:\n%s", out)
	}
}

// Shell completion fires three times per keystroke. Unfolded, those rows push
// the events that matter off the screen.
func TestAuditReportCollapsesRepeatsWithinAMinute(t *testing.T) {
	// Anchored mid-minute, not at time.Now(): three events a second apart
	// straddle a minute boundary roughly one run in twenty, and the test would
	// then correctly refuse to collapse them and wrongly report a failure.
	base := time.Date(2026, 7, 29, 19, 50, 30, 0, time.Local)
	out := renderReport([]auditEntry{
		reportEntry(base, "jit completion zsh", "iTerm", "ok"),
		reportEntry(base.Add(-time.Second), "jit completion zsh", "iTerm", "ok"),
		reportEntry(base.Add(-2*time.Second), "jit completion zsh", "iTerm", "ok"),
	})
	if !strings.Contains(out, "×3") {
		t.Errorf("expected a ×3 count, got:\n%s", out)
	}
	if n := strings.Count(out, "jit completion zsh"); n != 1 {
		t.Errorf("expected one collapsed row, got %d:\n%s", n, out)
	}
}

// Collapsing may compress the display; it may never rewrite the timeline.
func TestAuditReportDoesNotCollapseAcrossMinutes(t *testing.T) {
	now := time.Now()
	out := renderReport([]auditEntry{
		reportEntry(now, "jit status", "claude", "ok"),
		reportEntry(now.Add(-5*time.Minute), "jit status", "claude", "ok"),
	})
	if n := strings.Count(out, "jit status"); n != 2 {
		t.Errorf("expected 2 rows five minutes apart, got %d:\n%s", n, out)
	}
}

func TestAuditReportDoesNotCollapseDifferentOutcomes(t *testing.T) {
	now := time.Now()
	out := renderReport([]auditEntry{
		reportEntry(now, "jit scan", "claude", "failed"),
		reportEntry(now, "jit scan", "claude", "ok"),
	})
	if strings.Contains(out, "×2") {
		t.Errorf("a failure and a success must stay separate rows:\n%s", out)
	}
}

// A failure has to be findable without reading: the glyph, the message, and
// the command that fixes it, each in its own place.
func TestAuditReportShowsFailureDetailAndFix(t *testing.T) {
	e := reportEntry(time.Now(), "jit clisso-capture -- get prod", "claude", "failed")
	e.detail = "clisso exited cleanly but printed no credentials"
	e.action = "fake-clisso get prod --output credential_process"
	out := renderReport([]auditEntry{e})

	if !strings.Contains(out, glyphRisk) {
		t.Errorf("failed row not marked with %q:\n%s", glyphRisk, out)
	}
	if !strings.Contains(out, "clisso exited cleanly") {
		t.Errorf("error detail missing:\n%s", out)
	}
	if !strings.Contains(out, "→ fake-clisso get prod") {
		t.Errorf("fix not on an arrow line:\n%s", out)
	}
	if !strings.Contains(out, "1 failed") {
		t.Errorf("header did not count the failure:\n%s", out)
	}
}

// splitAuditError is what turns a one-line error into those two pieces.
func TestSplitAuditErrorSeparatesMessageFromFix(t *testing.T) {
	detail, action := splitAuditError(
		"jit clisso-capture: clisso exited cleanly but printed no credentials — run `fake-clisso get prod --output credential_process` to see its raw output")
	if strings.Contains(detail, "jit clisso-capture:") {
		t.Errorf("command prefix not stripped: %q", detail)
	}
	if detail != "clisso exited cleanly but printed no credentials" {
		t.Errorf("detail = %q", detail)
	}
	if action != "fake-clisso get prod --output credential_process" {
		t.Errorf("action = %q", action)
	}
}

func TestSplitAuditErrorLeavesAPlainMessageAlone(t *testing.T) {
	detail, action := splitAuditError("jit audit: unknown --format \"yaml\"")
	if action != "" {
		t.Errorf("invented an action: %q", action)
	}
	if detail != `unknown --format "yaml"` {
		t.Errorf("detail = %q", detail)
	}
}

// A secret name an unlock touched is the one detail that answers "what did
// that actually reach".
func TestAuditReportKeepsTheSecretsAnUnlockTouched(t *testing.T) {
	e := auditEntry{
		t: time.Now(), kind: "unlock", status: "ok",
		subject: "session unlocked (Touch ID)", parent: "claude",
		labels: []string{"mcp-jamf/JAMF_PRO_CLIENT_ID", "mcp-jamf/JAMF_PRO_URL"},
	}
	out := renderReport([]auditEntry{e})
	for _, want := range e.labels {
		if !strings.Contains(out, want) {
			t.Errorf("report dropped %q:\n%s", want, out)
		}
	}
}

// Two uses that fold into one ×N row can have touched DIFFERENT secrets; the
// collapsed row must name all of them, not just the first's.
func TestAuditReportUnionsLabelsAcrossCollapsedRows(t *testing.T) {
	base := time.Date(2026, 7, 29, 19, 50, 30, 0, time.Local)
	use := func(at time.Time, labels []string) auditEntry {
		return auditEntry{t: at, kind: "use", subject: "credential served", parent: "claude", labels: labels}
	}
	out := renderReport([]auditEntry{
		use(base, []string{"stripe/live-key"}),
		use(base.Add(-time.Second), []string{"aws/deploy-role"}),
	})
	if !strings.Contains(out, "×2") {
		t.Fatalf("expected the two uses to collapse into one row:\n%s", out)
	}
	for _, want := range []string{"stripe/live-key", "aws/deploy-role"} {
		if !strings.Contains(out, want) {
			t.Errorf("collapsed row dropped the secret %q:\n%s", want, out)
		}
	}
}

// The header counts failed commands and denied unlocks separately, because
// they are separate statuses the reader can filter on — lumping denials into
// "failed" made the header disagree with the --status failed it points at.
func TestAuditReportHeaderSeparatesFailedFromDenied(t *testing.T) {
	now := time.Now()
	out := renderReport([]auditEntry{
		reportEntry(now, "jit vault get x", "claude", "failed"),
		{t: now.Add(-time.Minute), kind: "unlock", status: "denied", subject: "unlock DENIED (Touch ID)"},
	})
	if !strings.Contains(out, "1 failed") || !strings.Contains(out, "1 denied") {
		t.Errorf("header should count the failure and the denial separately:\n%s", out)
	}
	if strings.Contains(out, "2 failed") {
		t.Errorf("the denial was lumped into 'failed':\n%s", out)
	}
	if !strings.Contains(out, "--status denied") {
		t.Errorf("footer should offer --status denied when a denial is present:\n%s", out)
	}
}

func TestAuditReportMarksALockAsAStateNotAFailure(t *testing.T) {
	e := auditEntry{t: time.Now(), kind: "lock", subject: "session locked (5m0s idle timeout)"}
	out := renderReport([]auditEntry{e})
	if !strings.Contains(out, glyphWarn) {
		t.Errorf("expected a lock marked %q, got:\n%s", glyphWarn, out)
	}
	if strings.Contains(out, glyphRisk) {
		t.Errorf("a routine lock must not read as a failure:\n%s", out)
	}
}

func TestAuditReportEmptyStates(t *testing.T) {
	var filtered, fresh bytes.Buffer
	printAuditReport(&filtered, nil, true, auditScale{})
	printAuditReport(&fresh, nil, false, auditScale{})
	if !strings.Contains(filtered.String(), "match those filters") {
		t.Errorf("filtered empty state: %q", filtered.String())
	}
	if !strings.Contains(fresh.String(), "No audit log yet") {
		t.Errorf("fresh empty state: %q", fresh.String())
	}
}

func TestShortLauncherTrimsTheITermVersion(t *testing.T) {
	if got := shortLauncher("iTermServer-3.6.11"); got != "iTerm" {
		t.Errorf("got %q", got)
	}
	if got := shortLauncher("claude"); got != "claude" {
		t.Errorf("got %q", got)
	}
}

// No row may overflow the window at any width — the property the whole
// redesign turns on.
func TestAuditReportRowsFitTheWindow(t *testing.T) {
	now := time.Now()
	entries := []auditEntry{
		reportEntry(now, "jit clisso-capture --real /private/tmp/very/long/path/fake-clisso -- get prod --cache-enable", "claude", "failed"),
		reportEntry(now.Add(-time.Hour), "jit status", "iTermServer-3.6.11", "ok"),
	}
	entries[0].detail = "clisso exited cleanly but printed no credentials and left nothing behind"

	out := renderReport(entries)
	for _, line := range strings.Split(out, "\n") {
		// 80 is what Width() reports when stdout isn't a terminal, which is
		// every test run.
		if n := len([]rune(line)); n > 80 {
			t.Errorf("row is %d columns, want <= 80: %q", n, line)
		}
	}
}

// A capped report must say so. The header describes the full match set (its
// count, span, and outcome tallies), never the printed page alone — a header
// that reported 50 events over one afternoon against a --since 3d query read
// as "the older history was deleted".
func TestAuditReportCappedHeaderSpeaksForTheFullMatchSet(t *testing.T) {
	base := time.Date(2026, 8, 12, 17, 0, 0, 0, time.Local)
	full := []auditEntry{
		reportEntry(base, "jit status", "iTerm", "ok"),
		reportEntry(base.Add(-time.Hour), "jit run -- true", "claude", "failed"),
		{t: base.Add(-2 * time.Hour), kind: "serve", status: "decoy", subject: "decoy served to node"},
		reportEntry(base.Add(-72*time.Hour), "jit vault list", "iTerm", "ok"),
	}
	scale := auditScaleOf(full)

	var buf bytes.Buffer
	printAuditReport(&buf, full[:2], false, scale)
	out := buf.String()

	if !strings.Contains(out, "2 of 4 events") {
		t.Errorf("capped header must count shown-of-matched:\n%s", out)
	}
	// The span covers the whole match set (multi-day), not the printed page's
	// single afternoon.
	if !strings.Contains(out, " – ") {
		t.Errorf("capped header must span the full match set's days:\n%s", out)
	}
	// The failed command is on the page, the decoy row is not — both still
	// belong to the header's tallies.
	if !strings.Contains(out, "1 failed") || !strings.Contains(out, "1 decoy read") {
		t.Errorf("header tallies must cover rows the cap cut:\n%s", out)
	}
	// And the way out is named: the trailer leads with --limit 0 and carries
	// the full count, plus the decoy filter the cut row earns.
	if !strings.Contains(out, "--limit 0") || !strings.Contains(out, "all 4 events") {
		t.Errorf("capped trailer must point at --limit 0:\n%s", out)
	}
	if !strings.Contains(out, "--status decoy") {
		t.Errorf("a decoy the cap cut must still earn its filter hint:\n%s", out)
	}
}

// An uncapped report keeps today's exact shape: a plain count, no
// shown-of-matched, no --limit hint.
func TestAuditReportUncappedHeaderUnchanged(t *testing.T) {
	now := time.Now()
	out := renderReport([]auditEntry{
		reportEntry(now, "jit status", "iTerm", "ok"),
		reportEntry(now.Add(-time.Minute), "jit vault list", "iTerm", "ok"),
	})
	if !strings.Contains(out, "2 events") || strings.Contains(out, " of ") {
		t.Errorf("uncapped header must stay a plain count:\n%s", out)
	}
	if strings.Contains(out, "--limit") {
		t.Errorf("uncapped trailer must not hint at --limit:\n%s", out)
	}
}
