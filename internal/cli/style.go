// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/jitpass/jit/internal/style"
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
//   - report    (jit scan, jit migrate, jit doctor): a [Category] in default
//     weight with a plain count, over its items,
//   - dashboard (jit status): aligned label/value rows,
//   - tree      (jit vault list): [name] plain-count group headers.
//
// Corrected 2026-08-06 on three counts, each of which this file had outlived:
// the report header is not bold (rule 1 — the brackets delimit it); jit doctor
// is a REPORT, a findings list, not a dashboard, which design/output-style.md
// and CLAUDE.md both retract explicitly and doctor.go already renders
// correctly; and tree's headers follow rule 1 too, not the pre-rule-1
// "bold-name" shape described here.
// Each fits the shape of its data; what they share is the palette, the
// glyphs, the plain-secondary rule, and the column flow below.

// Status glyphs, re-exported from internal/style under this package's
// lowercase names so the ~200 existing call sites keep reading as they do.
// internal/style is where a symbol actually changes.
const (
	glyphOK     = style.GlyphOK
	glyphWarn   = style.GlyphWarn
	glyphRisk   = style.GlyphRisk
	glyphDone   = style.GlyphDone
	glyphAction = style.GlyphAction
	glyphBullet = style.GlyphBullet
	glyphBranch = style.GlyphBranch
	glyphMark   = style.GlyphMark
	glyphRule   = style.GlyphRule
	glyphLock   = style.GlyphLock
)

// The palette, re-exported from internal/style under this package's short
// names. The definitions — and the rules for when each ink applies, including
// why there is no dim/faint — live there.
var (
	cBold = style.Bold
	cPath = style.Path // a path or a runnable command
	cOK   = style.OK   // healthy / done
	cWarn = style.Warn
	cRisk = style.Risk

	// Bold variants, for the one PRIMARY runnable or completed thing on a
	// line (rule 3: bold is reserved for that) — the headline action a
	// report is steering toward, the "done" line that closes a run.
	cPathBold = style.PathBold
	cOKBold   = style.OKBold
	cWarnBold = style.WarnBold
)

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
func hlCmds(s string) string { return style.HighlightCommands(s) }

// FormatError renders an error the way this package renders every other line
// it prints. Errors return through main.go, which printed them raw, so the
// whole error surface showed its backticks literally — "run `jit service
// restart`" — with no color at all. That is the drift output-style rule 5
// names, and it applied to essentially every remedy jit offers at the moment
// the user most needs to read one. One place to fix, since every command's
// error arrives here.
func FormatError(err error) string {
	if err == nil {
		return ""
	}
	return hlCmds(err.Error())
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
