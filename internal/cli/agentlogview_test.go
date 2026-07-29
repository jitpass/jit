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
	in := "2026-07-28 11:49:30 jit service: mount /Users/x/w/.env: reader pid=6067 (Code) (+205 reads since the last logged one)\n"
	var buf bytes.Buffer
	writeAgentLog(&buf, []byte(in), "/Users/x")
	out := buf.String()
	if !strings.Contains(out, "×205") {
		t.Errorf("expected the reads note as ×205, got:\n%s", out)
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
