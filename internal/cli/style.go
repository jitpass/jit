// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"

	"github.com/jitpass/jit/internal/termtext"
)

// This file is jit's shared output vocabulary — the one place the house
// style is defined so every command reads as one tool (see
// design/output-style.md). The instincts are borrowed from gh and docker:
// structure comes from whitespace and weight, not box-rules; a leading
// glyph carries the state so the eye finds it before the words; and color
// is strictly semantic, never decorative.
//
// Three report shapes share this vocabulary rather than one rigid layout:
//   - report   (jit scan, jit migrate): a bold [Category] over its items,
//   - dashboard (jit status, jit doctor): aligned label/value rows,
//   - tree     (jit vault list): light bold-name/dim-count group headers.
// Each fits the shape of its data; what they share is the palette, the
// glyphs, the dim-secondary rule, and the column flow below.

// Status glyphs. Unicode by deliberate choice: jit already prints ✓ and •,
// and its darwin-only terminals (SF Mono / Menlo) render these single-width.
// If a terminal ever mis-widths them, this is the single block to swap for
// ASCII ("+", "!", "x", "-") — nothing else references the symbols directly.
const (
	glyphOK   = "●" // green: healthy / running / wired
	glyphWarn = "○" // amber: needs a look / unreferenced / decoy
	glyphRisk = "✗" // red: a real problem the reader must act on
	glyphDone = "✓" // green: an action completed
)

// Semantic colors, named by MEANING not by hue, so a call site says what it
// intends and a future palette change happens here. faint = secondary,
// bold = the one primary thing on a line, cyan = a path or command the
// reader can act on. fatih/color already no-ops these when the writer isn't
// a terminal, so piped/test output stays byte-clean automatically.
var (
	cDim  = color.New(color.Faint)
	cBold = color.New(color.Bold)
	cPath = color.New(color.FgCyan)  // a path or a runnable command
	cOK   = color.New(color.FgGreen) // healthy / done
	cWarn = color.New(color.FgYellow)
	cRisk = color.New(color.FgRed)
)

// defaultWidth is the fallback line width when stdout isn't a terminal
// (pipes, CI, tests) — 80 keeps column flow deterministic for tests and is
// the conventional terminal default.
const defaultWidth = termtext.DefaultWidth

// outputWidth reports the usable column count for laying out this package's
// output. A thin delegate so the CLI's dashboards and audit's scan report
// measure the window the same way — see internal/termtext.
func outputWidth() int { return termtext.Width() }

// wrapBody writes body wrapped to the window, continuing a line the caller has
// already started. used is how many columns are already on that line (indent
// plus any glyph and label); cont prefixes every line after the first.
//
// Every prose line in this package goes through here rather than a bare
// Fprintf. A line printed at its natural length is not "unwrapped", it is
// wrapped by the terminal at column 0 — which drops the continuation to the
// left of the glyph that owns it and turns one row into what reads as two.
func wrapBody(w io.Writer, used int, cont, body string) {
	termtext.Wrap(w, used, cont, body)
}

// hlCmds highlights the `backtick`-delimited command spans in a user-facing
// message: each is rendered cyan (the house color for something the reader can
// run) and its backticks dropped. When color is off — piped output, TERM=dumb,
// tests — cPath.Sprint returns the text unchanged, so the backticks are simply
// removed and the line reads as clean plain text. Use it on directive lines
// ("run `jit x` to …"), not on every incidental mention, so cyan stays a
// signal rather than noise.
func hlCmds(s string) string {
	var b strings.Builder
	for {
		i := strings.IndexByte(s, '`')
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		j := strings.IndexByte(s[i+1:], '`')
		if j < 0 {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(s[:i])
		b.WriteString(cPath.Sprint(s[i+1 : i+1+j]))
		s = s[i+1+j+1:]
	}
}

// maxFlowWidth caps how wide flowNames lays out, and maxFlowCols how many
// columns, regardless of how wide the terminal is. Flowing to the full width
// of a very wide window produced a dense six-or-more-column wall that was
// harder to scan than the stack it replaced; a comfortable reading measure
// and a low column cap keep it tidy — a few short rows, generous gutters.
const (
	maxFlowWidth = 88
	maxFlowCols  = 4
)

// flowNames prints names packed into aligned whitespace columns beneath a
// group header — the docker/gh instinct that turns a 12-item vertical stack
// into a few tidy rows. Every column is padded to the widest name plus a
// two-space gutter so names line up down the page; the last column in a row
// isn't padded so there's no trailing whitespace. indent leads every row.
// Column count is bounded (see maxFlowWidth/maxFlowCols) so a wide terminal
// stays readable rather than sprawling. A no-op on empty input.
func flowNames(w io.Writer, names []string, indent string) {
	if len(names) == 0 {
		return
	}
	longest := 0
	for _, n := range names {
		if len(n) > longest {
			longest = len(n)
		}
	}
	colW := longest + 2
	width := outputWidth()
	if width > maxFlowWidth {
		width = maxFlowWidth
	}
	cols := (width - len(indent)) / colW
	if cols > maxFlowCols {
		cols = maxFlowCols
	}
	if cols < 1 {
		cols = 1
	}
	for i := 0; i < len(names); i += cols {
		end := i + cols
		if end > len(names) {
			end = len(names)
		}
		var b strings.Builder
		b.WriteString(indent)
		for j := i; j < end; j++ {
			if j == end-1 {
				b.WriteString(names[j])
			} else {
				fmt.Fprintf(&b, "%-*s", colW, names[j])
			}
		}
		fmt.Fprintln(w, b.String())
	}
}
