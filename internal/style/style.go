// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// Package style is jit's terminal look, in one place: every ink the tool
// prints and every glyph it draws. It exists so a palette change is one edit
// rather than a hunt.
//
// It was a hunt, once. The house style claimed a single vocabulary in
// internal/cli/style.go, but internal/audit and internal/ui each built their
// own colors with color.New, so removing the dim/faint attribute on
// 2026-08-06 meant tracking down twelve constructors across three packages —
// and the two the grep nearly missed were the ones rendering the report a
// user actually reads. internal/cli imports internal/audit, so audit could
// never import the cli vocabulary; the vocabulary had to move below both.
//
// Rules for adding to this file:
//
//   - Name by MEANING, never by hue. A call site says what it intends
//     (Risk), not which color it picked (red), so the intent survives a
//     repaint.
//   - Nothing here is decorative. Every ink means one thing and every glyph
//     carries state or structure; if a new line needs to stand apart and
//     nothing here fits, the answer is whitespace or fewer words.
//   - There is no dim/faint, deliberately. See Plain below.
//
// The full contract, with the when/where for each entry, is
// design/output-style.md. Keep the two in step.
package style

import "github.com/fatih/color"

// The palette: six inks and one attribute, and nothing else. No blue, no
// magenta, no backgrounds, no 256-color or truecolor.
//
// fatih/color no-ops each of these when the writer isn't a terminal, so
// piped output and tests stay byte-clean without a call site checking.
var (
	// Bold is the ONE primary thing on a line — a group name, a finding
	// title, a headline number. Two bold spans on a line means neither is
	// primary.
	Bold = color.New(color.Bold)

	// Path is cyan: something the reader can type or open. It is the only
	// color a command ever takes, on every surface, and commands reach it
	// through hlCmds rather than by hand. A path the report merely
	// describes is not cyan — it is Plain.
	Path = color.New(color.FgCyan)

	// OK is green: this is fine, this is done, this is protected.
	OK = color.New(color.FgGreen)

	// Warn is amber: needs a look, nothing is broken. It reports STATE — it
	// belongs on a glyph, a header or a number, never on a sentence of
	// advice, which reads as a warning it isn't.
	Warn = color.New(color.FgYellow)

	// Risk is red: a real problem the reader must act on. Never used for
	// something the reader can do nothing about.
	Risk = color.New(color.FgRed)

	// Bold variants, for the single headline instance of a state on a line:
	// the action a report is steering toward, the section naming what only
	// the user can fix, the marker that has to be found before the words
	// around it.
	PathBold = color.New(color.FgCyan, color.Bold)
	OKBold   = color.New(color.FgGreen, color.Bold)
	WarnBold = color.New(color.FgYellow, color.Bold)
	RiskBold = color.New(color.FgRed, color.Bold)
)

// Plain is the absence of styling, named so a call site can say it MEANT
// this rather than looking like someone forgot. Secondary text — counts,
// origins, timestamps, paths in a manifest, explanations, footers — is
// written with a bare fmt call and inherits the terminal's own foreground.
//
// jit dimmed all of that with ESC[2m until 2026-08-06. Most terminals draw
// faint at around half opacity, and secondary text is the MAJORITY of a
// report, so the tool's main surface was the part the user had to squint at.
// Hierarchy now comes from Bold and from the semantic inks; everything else
// recedes by contrast with them.
//
// Do not reintroduce faint for one line. It only reads as a level of
// hierarchy when applied consistently, and applied consistently it is the
// readability problem again. TestNoFaintText enforces this repo-wide.
const Plain = ""

// The glyphs. Unicode by deliberate choice: jit is darwin-only and its
// terminals (SF Mono / Menlo) render these single-width. If one ever
// mis-widths, this block is the only place to swap it for ASCII — no
// rendering site writes the symbol directly.
//
// Each carries the color named in its comment. The pairing is not decoration:
// the glyph tells the eye where to look and the ink tells it what it found,
// so a glyph in the wrong ink is a line that lies at a glance.
const (
	// State glyphs, one per line that HAS a state. A line without a state
	// gets no glyph — see GlyphMark for the distinction that matters.
	GlyphOK   = "●" // OK green:   healthy / running / wired / serving real
	GlyphWarn = "○" // Warn amber: needs a look / unreferenced / decoy
	GlyphRisk = "✗" // Risk red:   a real problem the reader must act on
	GlyphDone = "✓" // OK green:   an action that completed (✓ Scanned …)

	// GlyphMark leads an ITEM in a findings list that the reader has to fix
	// themselves — amber bold normally, red bold when the finding is
	// critical. Distinct from GlyphWarn, which marks the state of a row on a
	// dashboard: a findings item is work, a state is a condition.
	GlyphMark = "!"

	// GlyphAction introduces the one thing to type. Always cyan, always the
	// last line of its block, at most one per state — a reader given three
	// next steps takes none.
	GlyphAction = "→"

	// GlyphBullet is a plain list marker for items with no state of their
	// own. Plain, never colored: coloring it would claim a state.
	GlyphBullet = "•"

	// GlyphBranch attaches evidence to the item above it (the matched rule,
	// the reason a finding survived a gate). Plain.
	GlyphBranch = "└"

	// The coverage bar's cells: filled is OK green, empty is Plain. Ten
	// cells, one per 10%.
	GlyphBarFilled = "▰"
	GlyphBarEmpty  = "▱"

	// GlyphRule draws the single subtotal line under a numeric table — the
	// one box-rule the house style keeps, because a table total is where a
	// rule earns its keep. Never a border, never a section divider.
	GlyphRule = "─"

	// GlyphLock announces a blocking Touch ID prompt on stderr. The one
	// emoji jit prints to a terminal, and it is deliberate: this line fires
	// when the process is about to sit there waiting, so it has to be
	// findable in a scrollback at a glance. Nothing else earns an emoji.
	GlyphLock = "🔐"
)

// SpinnerFrames animates a step that is still running; the step is replaced
// by "GlyphDone <text>" when it settles. Plain, so a transient frame never
// competes with the report it precedes.
var SpinnerFrames = []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'}
