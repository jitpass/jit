// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/fatih/color"

	"github.com/jitpass/jit/internal/termtext"
)

// `jit audit`'s default view. The trail is still logfmt underneath, and
// `--format logfmt` prints exactly what this command used to — but logfmt is
// a shape for machines, and this is the view a person reads.
//
// What the logfmt line spends columns on that a human doesn't need: `user=`
// on every row (it is always you — the filter still takes --user, and JSON
// still carries it), `pid=`, `dur=`, `level=` (the glyph says it), and `kind=`
// (the subject says it). On this machine that is 115–415 columns per line,
// most of it identical to the line above.
//
// What it adds: a state glyph, day grouping, a count on repeated events, and
// the error broken out under the row it belongs to with its fix on an arrow
// line — the same action motif every other jit surface uses.

// Column widths for the report's fixed left margin: two spaces, "HH:MM", a
// space, the glyph, a space.
const (
	auditTimeCol = 5
	// Rows indent one level past the day header they belong to, so the
	// grouping is visible as structure rather than only as a word.
	auditRowIndent = 4
	auditRowLead   = auditRowIndent + auditTimeCol + 1 + 1 + 1
)

// auditHangIndent is where a row's continuation, its detail and its arrow
// line all hang — clear of the glyph column, so nothing under a row reads as
// a row of its own.
var auditHangIndent = strings.Repeat(" ", auditRowLead)

// printAuditReport renders the merged trail as the human report. Entries
// arrive newest-first and already filtered and limited.
func printAuditReport(w io.Writer, entries []auditEntry, filtered bool) {
	if len(entries) == 0 {
		printAuditEmpty(w, filtered)
		return
	}
	writeAuditHeader(w, entries)
	groups := groupAuditEntries(entries)
	cols := auditColumns(groups)

	day := ""
	for _, g := range groups {
		if d := g.e.t.Format("2006-01-02"); d != day {
			if day != "" {
				fmt.Fprintln(w)
			}
			day = d
			_, _ = cDim.Fprintf(w, "  %s\n", auditDayLabel(g.e.t))
		}
		writeAuditRow(w, g, cols)
	}

	fmt.Fprintln(w)
	fmt.Fprint(w, "  ")
	_, _ = cPath.Fprint(w, "→ ")
	// Point at the most useful next filter. When any unlock was refused, name
	// --status denied too, since it is now a distinct count in the header above.
	hint := cPath.Sprint("jit audit --status failed") +
		cDim.Sprint("   only what went wrong")
	if _, denied := auditOutcomeCounts(entries); denied > 0 {
		hint += cDim.Sprint(" · ") + cPath.Sprint("--status denied") + cDim.Sprint(" for refusals")
	}
	hint += cDim.Sprint(" · --format logfmt for the machine form")
	termtext.Wrap(w, 4, "    ", hint)
}

func printAuditEmpty(w io.Writer, filtered bool) {
	if filtered {
		fmt.Fprintln(w, "No audit entries match those filters.")
		return
	}
	fmt.Fprintln(w, hlCmds("No audit log yet. It fills in as you run jit commands; if the service has never run, there are no unlocks to show either."))
}

// writeAuditHeader states the scale of what follows: how many events, over
// what span, and how many of them failed. The logfmt view had no summary at
// all, so "did anything go wrong today?" meant reading every line.
func writeAuditHeader(w io.Writer, entries []auditEntry) {
	// Count the two bad outcomes separately: they are distinct statuses a reader
	// can filter on (--status failed vs --status denied), so collapsing them
	// into one "failed" made the header disagree with the filter it points at.
	failed, denied := auditOutcomeCounts(entries)
	// Entries are newest-first.
	newest, oldest := entries[0].t, entries[len(entries)-1].t
	span := fmt.Sprintf("%s–%s", oldest.Format("15:04"), newest.Format("15:04"))
	if !sameDay(oldest, newest) {
		span = fmt.Sprintf("%s – %s", auditDayLabel(oldest), auditDayLabel(newest))
	}
	head := fmt.Sprintf("jit audit — %s · %s", countWord(len(entries), "event", "events"), span)
	if failed > 0 {
		head += fmt.Sprintf(" · %d failed", failed)
	}
	if denied > 0 {
		head += fmt.Sprintf(" · %d denied", denied)
	}
	_, _ = cDim.Fprintln(w, head)
	fmt.Fprintln(w)
}

// auditOutcomeCounts tallies failed commands and denied unlocks — the two
// statuses the header calls out and the footer offers a filter for.
func auditOutcomeCounts(entries []auditEntry) (failed, denied int) {
	for _, e := range entries {
		switch e.status {
		case "failed":
			failed++
		case "denied":
			denied++
		}
	}
	return failed, denied
}

func sameDay(a, b time.Time) bool {
	return a.Format("2006-01-02") == b.Format("2006-01-02")
}

// auditDayLabel names a day the way someone scanning a log thinks of it.
func auditDayLabel(t time.Time) string {
	now := time.Now()
	switch {
	case sameDay(t, now):
		return "Today"
	case sameDay(t, now.AddDate(0, 0, -1)):
		return "Yesterday"
	default:
		return t.Format("Mon 2 Jan")
	}
}

// auditGroup is one rendered row: an entry, plus how many identical events
// collapsed into it.
type auditGroup struct {
	e     auditEntry
	count int
}

// groupAuditEntries folds RUNS of the same event into one row. Shell
// completion fires three times per keystroke and a health check runs four
// commands in the same second; unfolded, they push the events that matter off
// the screen. Only adjacent, same-minute, same-subject, same-outcome events
// fold, so the timeline is never reordered or thinned across time.
func groupAuditEntries(entries []auditEntry) []auditGroup {
	var out []auditGroup
	for _, e := range entries {
		if n := len(out); n > 0 {
			p := out[n-1].e
			if p.subject == e.subject && p.parent == e.parent &&
				p.status == e.status && p.kind == e.kind &&
				p.t.Format("2006-01-02 15:04") == e.t.Format("2006-01-02 15:04") {
				out[n-1].count++
				// Fold in this event's secret names too: the rows share a
				// subject but can have touched DIFFERENT secrets, and the
				// labels are the one fact that answers "what did that ×N
				// actually reach". Keeping only the first row's understated it.
				out[n-1].e.labels = unionLabels(out[n-1].e.labels, e.labels)
				continue
			}
		}
		out = append(out, auditGroup{e: e, count: 1})
	}
	return out
}

// unionLabels returns the secret names in a followed by any in b not already
// present, order-preserving and deduped. It never aliases either input, so
// folding into a group can't mutate the backing entry's slice.
func unionLabels(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, l := range append(append([]string{}, a...), b...) {
		if !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	return out
}

// auditCols are the report's two variable column widths, plus whether the
// window can hold them side by side at all.
type auditCols struct {
	subject, parent int
	stacked         bool
}

// auditColumns sizes both columns to their widest ACTUAL content, bounded by
// the window. Sizing the subject column to the leftover space instead pushed
// the launcher to the far edge of a wide terminal, with a corridor of blank
// between it and the command it belongs to.
func auditColumns(groups []auditGroup) auditCols {
	var c auditCols
	for _, g := range groups {
		if n := len(g.e.subject); n > c.subject {
			c.subject = n
		}
		if n := len(shortLauncher(g.e.parent)); n > c.parent {
			c.parent = n
		}
	}
	// The repeat gutter is written as "  %3s  " — two spaces, three columns
	// for the count, two more — so it costs 7, not 6. Budgeting 6 let the
	// widest row overrun the window by exactly one column.
	fixed := auditRowLead + 7
	if c.parent > 0 {
		fixed += c.parent
	}
	// Stacking is a decision about the WINDOW, not about the content. Keying
	// it off the chosen column width instead meant a screen full of short
	// commands — the case a table handles best — got stacked onto two lines
	// each, because "no subject is longer than 24" was read as "no room".
	room := termtext.Width() - fixed
	c.stacked = room < 24
	if c.subject > room {
		c.subject = room
	}
	return c
}

// shortLauncher shortens a launcher name to what identifies it. iTerm reports
// itself as "iTermServer-3.6.11"; the version is noise in a column whose job
// is to say which app was responsible.
func shortLauncher(p string) string {
	if strings.HasPrefix(p, "iTermServer") {
		return "iTerm"
	}
	return p
}

// writeAuditRow renders one row and anything that hangs beneath it.
func writeAuditRow(w io.Writer, g auditGroup, cols auditCols) {
	glyph, c := auditGlyph(g.e)
	parent := shortLauncher(g.e.parent)
	repeat := ""
	if g.count > 1 {
		repeat = fmt.Sprintf("×%d", g.count)
	}

	// Below a usable subject column the row stops being a table: the launcher
	// moves to its own line rather than squeezing two truncated columns that
	// each say nothing.
	stacked := cols.stacked

	fmt.Fprint(w, strings.Repeat(" ", auditRowIndent))
	_, _ = cDim.Fprintf(w, "%s ", g.e.t.Format("15:04"))
	_, _ = c.Fprintf(w, "%s ", glyph)

	if stacked {
		fmt.Fprintln(w, termtext.TruncMid(g.e.subject, termtext.Width()-auditRowLead))
		if parent != "" || repeat != "" {
			_, _ = cDim.Fprintf(w, "%s%s\n", auditHangIndent,
				strings.TrimSpace(repeat+" "+parent))
		}
	} else {
		fmt.Fprintf(w, "%-*s", cols.subject, termtext.TruncMid(g.e.subject, cols.subject))
		_, _ = cDim.Fprintf(w, "  %3s  %s\n", repeat, parent)
	}

	// The secret names an unlock or a use touched: the one detail that
	// answers "what did that actually reach", so it stays on the report.
	if len(g.e.labels) > 0 {
		fmt.Fprint(w, auditHangIndent)
		termtext.Wrap(w, auditRowLead, auditHangIndent,
			cDim.Sprint(strings.Join(g.e.labels, ", ")))
	}
	if g.e.detail != "" {
		fmt.Fprint(w, auditHangIndent)
		termtext.Wrap(w, auditRowLead, auditHangIndent, g.e.detail)
	}
	if g.e.action != "" {
		fmt.Fprint(w, auditHangIndent)
		_, _ = cPath.Fprint(w, "→ ")
		termtext.Wrap(w, auditRowLead+2, auditHangIndent+"  ", cPath.Sprint(g.e.action))
	}
}

// auditGlyph maps an entry to the mark that carries its state. A failure and
// a denial are the two things worth finding without reading, so they get the
// two marks that stop the eye.
func auditGlyph(e auditEntry) (string, *color.Color) {
	switch {
	case e.status == "failed":
		return glyphRisk, cRisk
	case e.status == "denied":
		return glyphWarn, cWarn
	case e.kind == "lock":
		return glyphWarn, cWarn
	default:
		return glyphOK, cOK
	}
}

// validateAuditOutputFormat is `jit audit`'s --format check. It accepts one
// value the shared validator doesn't: "logfmt", the key=value stream this
// command printed by default before the report existed. Keeping it is the
// point — the trail is still a real service log, and anything that grepped
// it, or pipes it somewhere, keeps working by naming the format explicitly.
func validateAuditOutputFormat(format string) error {
	switch format {
	case "", "text", "logfmt", "json":
		return nil
	default:
		return fmt.Errorf(`unknown --format %q (want "text", "logfmt" or "json")`, format)
	}
}

// auditFollowColumns sizes a following stream's columns from the tail it
// opens with. A live feed can't measure entries that haven't happened yet,
// and re-measuring per batch would make the columns jump as it scrolls.
func auditFollowColumns(entries []auditEntry) auditCols {
	groups := make([]auditGroup, 0, len(entries))
	for _, e := range entries {
		groups = append(groups, auditGroup{e: e, count: 1})
	}
	return auditColumns(groups)
}

// writeAuditFollowRow renders one streamed row. --follow prints no day
// headers and collapses nothing: it is a live feed, and a reader watching it
// wants each event as it lands, in the order it landed.
func writeAuditFollowRow(w io.Writer, e auditEntry, cols auditCols) {
	if auditFormat == "logfmt" {
		fmt.Fprintln(w, e.line)
		return
	}
	writeAuditRow(w, auditGroup{e: e, count: 1}, cols)
}
