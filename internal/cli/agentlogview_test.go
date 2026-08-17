// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"strings"
	"testing"
)

const sweep = `2026-07-28 15:12:28 jit service: mount /Users/x/proj/a/.env: reader connected (not identified, best-effort scan missed it)
2026-07-28 15:12:28 jit service: mount /Users/x/proj/b/.env: reader connected (not identified, best-effort scan missed it)
2026-07-28 15:12:28 jit service: mount /Users/x/proj/c/.env: reader connected (not identified, best-effort scan missed it)
`

// One reader sweep writes one line per mount. Eight lines that differ only in
// a path are one event, and printing them separately is what made the log
// unreadable at any window size.
func TestAgentLogCollapsesARunOfIdenticalEvents(t *testing.T) {
	var buf bytes.Buffer
	writeAgentLog(&buf, []byte(sweep), "/Users/x")
	out := buf.String()
	if !strings.Contains(out, "3 mounts  reader connected") {
		t.Errorf("expected the sweep collapsed into one row, got:\n%s", out)
	}
	if n := strings.Count(out, "reader connected"); n != 1 {
		t.Errorf("expected 1 collapsed row, got %d:\n%s", n, out)
	}
}

// Two sweeps at different times are two events. Collapsing across them would
// rewrite the timeline, which is the one thing a log may not do.
func TestAgentLogDoesNotCollapseAcrossTimes(t *testing.T) {
	in := sweep + `2026-07-28 16:00:00 jit service: mount /Users/x/proj/a/.env: reader connected (not identified, best-effort scan missed it)
`
	var buf bytes.Buffer
	writeAgentLog(&buf, []byte(in), "/Users/x")
	if n := strings.Count(buf.String(), "reader connected"); n != 2 {
		t.Errorf("expected 2 rows across 2 times, got %d:\n%s", n, buf.String())
	}
}

func TestAgentLogCollapsesTheReadsNoteIntoACount(t *testing.T) {
	// The raw suffix counts what was SUPPRESSED since the last logged read,
	// so 205 suppressed + the logged one = 206 occurrences. ×N means "N
	// times" everywhere else in jit, so the row must say ×206 — rendering
	// the suppressed count verbatim understated every row by one.
	in := "2026-07-28 11:49:30 jit service: mount /Users/x/w/.env: reader pid=6067 (Code) (+205 reads since the last logged one)\n"
	var buf bytes.Buffer
	writeAgentLog(&buf, []byte(in), "/Users/x")
	out := buf.String()
	if !strings.Contains(out, "×206") {
		t.Errorf("expected the reads note as ×206 (205 suppressed + 1 logged), got:\n%s", out)
	}
	if strings.Contains(out, "since the last logged one") {
		t.Errorf("expected the prose form gone, got:\n%s", out)
	}
}

func TestAgentLogShortensHomePaths(t *testing.T) {
	in := "2026-07-28 18:09:06 jit service listening on /Users/x/Library/Application Support/jitpass/agent.sock (session TTL 5m0s)\n"
	var buf bytes.Buffer
	writeAgentLog(&buf, []byte(in), "/Users/x")
	out := buf.String()
	if strings.Contains(out, "/Users/x/Library") {
		t.Errorf("expected the home prefix shortened, got:\n%s", out)
	}
	if !strings.Contains(out, "~/Library") {
		t.Errorf("expected a ~-rooted path, got:\n%s", out)
	}
}

// A failure must not be rendered as routine narration; the glyph is what the
// reader scans for.
func TestAgentLogMarksFailuresAndDegradedStatesDistinctly(t *testing.T) {
	in := "2026-07-28 11:49:29 jit service: mount /Users/x/a/.env: writing: broken pipe (still serving)\n" +
		"2026-07-28 11:54:29 jit service: mounts now serving decoy content only\n" +
		"2026-07-28 18:09:03 jit service stopped.\n"
	var buf bytes.Buffer
	writeAgentLog(&buf, []byte(in), "/Users/x")
	out := buf.String()
	for glyph, want := range map[string]string{
		glyphRisk: "broken pipe",
		glyphWarn: "decoy content only",
		glyphOK:   "stopped.",
	} {
		found := false
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, want) && strings.Contains(line, glyph) {
				found = true
			}
		}
		if !found {
			t.Errorf("expected %q marked with %q, got:\n%s", want, glyph, out)
		}
	}
}

// An unrecognised line is the one someone is grepping for. It survives.
func TestAgentLogPassesThroughUnparsedLines(t *testing.T) {
	in := "panic: runtime error: invalid memory address\n"
	var buf bytes.Buffer
	writeAgentLog(&buf, []byte(in), "/Users/x")
	if !strings.Contains(buf.String(), "panic: runtime error") {
		t.Errorf("expected the raw line preserved, got:\n%s", buf.String())
	}
}

func TestAgentLogHandlesEmptyInput(t *testing.T) {
	var buf bytes.Buffer
	writeAgentLog(&buf, nil, "/Users/x")
	if buf.Len() != 0 {
		t.Errorf("expected no output for an empty log, got %q", buf.String())
	}
}

// TestAgentLogRendererKeepsDayStateAcrossChunks pins --follow's chunk fix:
// every polled chunk renders through ONE renderer, so a chunk continuing the
// same day must not re-print the date header (a fresh stateless pass per
// chunk used to print it once per poll that carried rows).
func TestAgentLogRendererKeepsDayStateAcrossChunks(t *testing.T) {
	var buf bytes.Buffer
	r := &agentLogRenderer{home: "/Users/x"}
	r.write(&buf, []byte("2026-08-17 10:00:00 jit service: stopped.\n"))
	r.write(&buf, []byte("2026-08-17 10:01:00 jit service: stopped.\n"))
	if got := strings.Count(buf.String(), "2026-08-17"); got != 1 {
		t.Errorf("the day header printed %d times across two same-day chunks, want 1:\n%s", got, buf.String())
	}
	r.write(&buf, []byte("2026-08-18 09:00:00 jit service: stopped.\n"))
	if got := strings.Count(buf.String(), "2026-08-18"); got != 1 {
		t.Errorf("a genuinely new day must print its header once, got %d:\n%s", got, buf.String())
	}
}

// TestAgentLogRendersSkipsAsDegraded drives the 2026-08-17 incident's exact
// line shapes through the renderer: a mount the service cannot serve or
// resolve must read as degraded (amber), fold like any other mount row, and
// the recovery line must read as routine (green). The old "skipping mount"
// shape — still present in logs written before the transition-logging fix —
// gets the amber glyph too, even though it predates the foldable format.
func TestAgentLogRendersSkipsAsDegraded(t *testing.T) {
	in := "2026-08-17 11:38:12 jit service: mount /Users/x/pt2/proj/.env: skipped, reading profile /Users/x/pt2/proj/.jit/profiles/proj-2.yaml: open: no such file or directory\n" +
		"2026-08-17 12:33:01 jit service: mount /Users/x/e2e/.env: skipped, resolving MATCHED_SECRET: secret has envelope version 4, newer than this jit understands (max 3), upgrade jit to read it\n" +
		"2026-08-17 12:34:40 jit service: mount /Users/x/e2e/.env: recovered, serving again (14 skipped attempts before this)\n" +
		"2026-08-17 12:36:02 jit service: skipping mount /Users/x/old/.env: legacy line from an older build\n"
	var buf bytes.Buffer
	writeAgentLog(&buf, []byte(in), "/Users/x")
	out := buf.String()

	// The glyph sits on a row's FIRST line; long reasons wrap onto
	// continuation lines, so assert against the substring that shares the
	// glyph's line (the row lead, not the wrapped tail).
	for glyph, want := range map[string]string{
		glyphWarn: "skipped, reading profile",
		glyphOK:   "recovered, serving again",
	} {
		found := false
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, want) && strings.Contains(line, glyph) {
				found = true
			}
		}
		if !found {
			t.Errorf("expected %q marked with %q, got:\n%s", want, glyph, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "skipped, resolving") && !strings.Contains(line, glyphWarn) {
			t.Errorf("an envelope-version skip must be amber, got: %s", line)
		}
		if strings.Contains(line, "skipping mount") && !strings.Contains(line, glyphWarn) {
			t.Errorf("the pre-fix 'skipping mount' shape must be amber too, got: %s", line)
		}
	}
	if !strings.Contains(out, "…") && !strings.Contains(out, "~/pt2/proj/.env") {
		t.Errorf("the skip row must go through the mount-row path shortening, got:\n%s", out)
	}
}

// TestAgentLogFoldsSimilarSuffix: the serve-error rate-limit suffix is the
// reads suffix in different words, and folds to the same ×N motif.
func TestAgentLogFoldsSimilarSuffix(t *testing.T) {
	in := "2026-08-17 12:36:02 jit service: mount /Users/x/a/.env: writing: broken pipe (still serving) (+3 similar since the last logged one)\n"
	var buf bytes.Buffer
	writeAgentLog(&buf, []byte(in), "/Users/x")
	out := buf.String()
	if !strings.Contains(out, "×4") {
		t.Errorf("the similar-suffix must fold to ×4 (3 suppressed + 1 logged), got:\n%s", out)
	}
	if strings.Contains(out, "since the last logged one") {
		t.Errorf("the prose suffix must not survive the fold, got:\n%s", out)
	}
}
