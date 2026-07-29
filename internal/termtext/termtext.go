// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// Package termtext holds the width-aware text primitives jit's reports share:
// how wide the window is, how wide a colored string actually displays, how to
// wrap prose so a continuation line stays inside its own column, and how to
// shorten a path or a command that cannot fit.
//
// It exists as its own package because both renderers need it and neither can
// import the other: `internal/cli` draws the dashboards, `internal/audit`
// draws the scan report, and cli already imports audit. Putting these four
// functions here keeps ONE implementation of the wrapping rule instead of a
// copy on each side that could drift.
//
// The rule the package encodes, from design/output-style.md: structure comes
// from whitespace, so a line that runs past the window must break at a word
// and resume at an indent the caller chooses — never at column 0, where the
// terminal would put it. A continuation that resumes at column 0 reads as a
// new row, which is precisely how a dashboard's glyph column stops being a
// summary.
package termtext

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"
)

// DefaultWidth is the assumed window width when stdout isn't a terminal
// (pipes, CI, tests) — 80 keeps piped output deterministic for golden tests
// and is the conventional terminal default.
const DefaultWidth = 80

// MinWidth is the floor Width reports. Below this a two-column layout is
// hopeless anyway, and callers that divide by the width need a value that
// can't collapse to something absurd.
const MinWidth = 40

// sgr matches an ANSI select-graphic-rendition escape — the color and weight
// codes fatih/color emits. They occupy zero columns, so every width
// measurement in this package has to skip them; measuring the raw string is
// what silently misaligns a colored column.
var sgr = regexp.MustCompile("\x1b\\[[0-9;]*m")

// Width reports the usable column count for laying out stdout. It reads the
// real terminal when stdout is a TTY and falls back to DefaultWidth
// otherwise, clamped to MinWidth so a very narrow window still lays out
// sanely rather than one character wide.
func Width() int {
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 {
		if w < MinWidth {
			return MinWidth
		}
		return w
	}
	return DefaultWidth
}

// VisibleWidth is the number of columns s occupies once its color escapes are
// discounted. Runes, not bytes: jit prints "—", "→" and "●", each of which is
// three bytes and one column.
func VisibleWidth(s string) int {
	return utf8.RuneCountInString(sgr.ReplaceAllString(s, ""))
}

// Wrap writes body to w, breaking it on spaces so no line exceeds width.
//
// used is the number of columns the caller has ALREADY written on the current
// line (its indent, plus any glyph and label), so the first line gets only the
// remaining room. cont prefixes every line after the first — pass the indent
// that keeps the text under the column it belongs to.
//
// Color spans inside body survive a break: an SGR code stays in effect across
// a newline, and the continuation indent it bleeds onto is whitespace, which
// has no visible foreground. A trailing newline is always written.
//
// A body with no spaces long enough to overflow (a path, a URL) is emitted
// whole rather than chopped mid-token — shortening that is TruncHead's job,
// and a caller who wanted it cut should have cut it.
func Wrap(w io.Writer, used int, cont, body string) {
	writeWrapped(w, width(), used, cont, body)
}

// WrapTo is Wrap against an explicit width, for tests and for callers that
// have already decided the measure.
func WrapTo(w io.Writer, width, used int, cont, body string) {
	writeWrapped(w, width, used, cont, body)
}

// width is a seam so tests can pin the measure; production reads the terminal.
var width = Width

func writeWrapped(w io.Writer, width, used int, cont, body string) {
	words := strings.Split(body, " ")
	var line strings.Builder
	col := used
	first := true
	flush := func() {
		fmt.Fprintln(w, strings.TrimRight(line.String(), " "))
		line.Reset()
	}
	for _, word := range words {
		n := VisibleWidth(word)
		if !first && col+1+n > width && col > VisibleWidth(cont) {
			flush()
			line.WriteString(cont)
			col = VisibleWidth(cont)
			line.WriteString(word)
			col += n
			continue
		}
		if first {
			// The caller already wrote `used` columns; the first word joins
			// them directly, with no separator of our own.
			if col+n > width && col > used {
				flush()
				line.WriteString(cont)
				col = VisibleWidth(cont)
			}
			line.WriteString(word)
			col += n
			first = false
			continue
		}
		line.WriteString(" ")
		line.WriteString(word)
		col += 1 + n
	}
	flush()
}

// TruncTail cuts the END of s to at most n columns, marking the cut with "…".
// For text whose beginning identifies it — a message, a label.
func TruncTail(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// TruncHead cuts the FRONT of a path to at most n columns. The tail is what
// identifies a file, so "~/a/very/long/prefix/config.json" must lose its
// prefix, not its name. The cut snaps forward to the next "/" when that costs
// only a few columns, so the result reads as whole path components rather than
// a severed word.
func TruncHead(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	cut := r[len(r)-(n-1):]
	if i := strings.IndexByte(string(cut), '/'); i >= 0 {
		if snapped := []rune(string(cut)[i:]); len(cut)-len(snapped) <= snapBudget {
			cut = snapped
		}
	}
	return "…" + string(cut)
}

// snapBudget is how many columns TruncHead will give up to land the cut on a
// path separator. Beyond this the saving isn't worth the lost characters, and
// a mid-component cut is clearer than an over-short path.
const snapBudget = 12

// TruncMid cuts the MIDDLE of s to at most n columns. For a command line,
// where both ends carry identity: the subcommand at the head, and at the tail
// the arguments that distinguish two otherwise identical invocations.
func TruncMid(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	keep := n - 1
	head := keep * 2 / 3
	return string(r[:head]) + "…" + string(r[len(r)-(keep-head):])
}
