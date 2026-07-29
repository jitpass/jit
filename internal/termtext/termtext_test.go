// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package termtext

import (
	"bytes"
	"strings"
	"testing"
)

// The property every caller depends on: no rendered line is wider than the
// window. A dashboard whose continuation spills past the edge is exactly the
// bug this package exists to prevent, and it only shows up at widths the
// non-TTY default (80) never exercises.
func TestWrapNeverExceedsWidth(t *testing.T) {
	body := "the background service is running a different build than this " +
		"command and recent changes may not take effect until they match"
	for _, width := range []int{40, 50, 60, 72, 80, 100} {
		var buf bytes.Buffer
		WrapTo(&buf, width, 8, "        ", body)
		for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
			// The first line carries 8 columns the caller already wrote.
			got := VisibleWidth(line)
			if strings.HasPrefix(line, "        ") {
				got = VisibleWidth(line)
			} else {
				got += 8
			}
			if got > width {
				t.Errorf("width %d: line is %d columns: %q", width, got, line)
			}
		}
	}
}

func TestWrapIndentsContinuationsNotColumnZero(t *testing.T) {
	var buf bytes.Buffer
	WrapTo(&buf, 50, 8, "        ", "one two three four five six seven eight nine ten")
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected a wrapped body, got %q", buf.String())
	}
	for _, line := range lines[1:] {
		if !strings.HasPrefix(line, "        ") {
			t.Errorf("continuation resumed at column 0: %q", line)
		}
	}
}

// Color codes occupy no columns. Measuring the raw string would make a
// colored line wrap early and a colored column misalign.
func TestVisibleWidthDiscountsColorAndCountsRunes(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"plain", 5},
		{"\x1b[36mjit migrate\x1b[0m", 11},
		{"● running", 9},
		{"→ jit vault export — a copy", 27},
	}
	for _, c := range cases {
		if got := VisibleWidth(c.in); got != c.want {
			t.Errorf("VisibleWidth(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestWrapKeepsColorSpansIntact(t *testing.T) {
	var buf bytes.Buffer
	WrapTo(&buf, 40, 6, "      ", "run \x1b[36mjit service restart\x1b[0m to move it over now")
	got := buf.String()
	if !strings.Contains(got, "\x1b[36m") || !strings.Contains(got, "\x1b[0m") {
		t.Errorf("wrapping dropped a color span: %q", got)
	}
}

// A path has no spaces to break on. Emitting it whole (and letting the caller
// shorten it deliberately) beats chopping it at an arbitrary column.
func TestWrapDoesNotChopAnUnbreakableToken(t *testing.T) {
	path := "~/Documents/ai_security_workspace/custom_scripts/jamf/.env"
	var buf bytes.Buffer
	WrapTo(&buf, 40, 6, "      ", path)
	if !strings.Contains(buf.String(), path) {
		t.Errorf("token was split: %q", buf.String())
	}
}

func TestTruncHeadKeepsTheIdentifyingTail(t *testing.T) {
	p := "~/Library/Application Support/Claude/claude_desktop_config.json"
	got := TruncHead(p, 40)
	if VisibleWidth(got) > 40 {
		t.Errorf("TruncHead returned %d columns: %q", VisibleWidth(got), got)
	}
	if !strings.HasSuffix(got, "claude_desktop_config.json") {
		t.Errorf("lost the file name: %q", got)
	}
	if !strings.HasPrefix(got, "…") {
		t.Errorf("no cut marker: %q", got)
	}
}

// Snapping to a separator is what makes the result read as whole path
// components instead of a severed word.
func TestTruncHeadSnapsToAPathSeparator(t *testing.T) {
	p := "~/export-scripts/claude-inventory-export/.env"
	got := TruncHead(p, 36)
	if strings.HasPrefix(got, "…") && !strings.HasPrefix(got, "…/") {
		t.Errorf("cut landed mid-component: %q", got)
	}
}

func TestTruncHeadLeavesAShortPathAlone(t *testing.T) {
	if got := TruncHead("~/token.txt", 40); got != "~/token.txt" {
		t.Errorf("got %q", got)
	}
}

// Two clisso invocations differ only in their trailing flags; a tail cut would
// render them identically and the log would stop distinguishing them.
func TestTruncMidKeepsBothEnds(t *testing.T) {
	a := "jit clisso-capture --real /tmp/fake-clisso -- get prod --cache-enable"
	b := "jit clisso-capture --real /tmp/fake-clisso -- get prod -w /tmp/creds"
	ta, tb := TruncMid(a, 44), TruncMid(b, 44)
	if ta == tb {
		t.Errorf("distinct commands truncated to the same text: %q", ta)
	}
	for _, got := range []string{ta, tb} {
		if VisibleWidth(got) > 44 {
			t.Errorf("TruncMid returned %d columns: %q", VisibleWidth(got), got)
		}
		if !strings.HasPrefix(got, "jit clisso-capture") {
			t.Errorf("lost the subcommand: %q", got)
		}
	}
}

func TestTruncTailBounds(t *testing.T) {
	if got := TruncTail("secret-shaped values", 10); VisibleWidth(got) > 10 {
		t.Errorf("got %q (%d columns)", got, VisibleWidth(got))
	}
	if got := TruncTail("short", 10); got != "short" {
		t.Errorf("got %q", got)
	}
}
