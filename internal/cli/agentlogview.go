// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/fatih/color"

	"github.com/jitpass/jit/internal/termtext"
)

// The service log is the last surface written entirely for the writer rather
// than the reader: one line per event, each repeating the date, the words
// "jit service", and the absolute path of the mount it concerns. On this
// machine that runs to 296 columns, of which the first ~90 are identical to
// the line above.
//
// This file renders the same events on the house style — a date header per
// day, a time column, a state glyph, and the message wrapped inside the
// window with its repeated prefixes removed. Nothing is dropped: `--raw`
// prints the file's bytes exactly as before, for grep and for pasting into a
// bug report.

// logLineRe splits a service log line into its timestamp and its message.
// Two shapes exist: "… jit service: <message>" for operational notes and
// "… jit service <verb>" for lifecycle lines (stopped, listening on …).
var logLineRe = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) jit service(?::)? (.*)$`)

// readsRe collapses the log's own rate-limiting notes. "(+207 reads since
// the last logged one)" is 38 columns to say a number the "×207" motif
// already carries everywhere else in jit; the serve-error suffix ("+3
// similar since the last logged one") is the same note in different words
// and folds the same way.
var readsRe = regexp.MustCompile(`\s*\(\+(\d+) (?:reads?|similar) since the last logged one\)`)

// mountRe pulls the mount path out of a mount note so it can be shortened to
// its tail. Every one of these lines opens with the same ~50 characters of
// home directory.
var mountRe = regexp.MustCompile(`^mount ([^:]+): (.*)$`)

// writeAgentLog renders the log for humans. home is used to shorten paths;
// pass "" to leave them absolute.
func writeAgentLog(w io.Writer, data []byte, home string) {
	(&agentLogRenderer{home: home}).write(w, data)
}

// agentLogRenderer renders chunks of the log through one continuous state,
// so --follow's polled chunks read like a single document: the day header
// prints on day CHANGES only. Each chunk used to go through a fresh
// stateless pass, so every poll that carried rows re-printed the date
// header. Folding still happens within a chunk only — a run spanning a poll
// boundary stays two rows, the same "timeline is never rewritten" trade the
// collapse already makes at minute boundaries.
type agentLogRenderer struct {
	home string
	day  string
}

func (r *agentLogRenderer) write(w io.Writer, data []byte) {
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return
	}

	for _, e := range collapseAgentLog(lines, r.home) {
		if e.raw != "" {
			// A panic, a stack frame, anything the daemon printed that isn't
			// one of its own timestamped notes. It goes through byte-exact —
			// not indented, not wrapped. An unrecognised line in a debug log
			// is precisely the line someone is grepping for or pasting into a
			// bug report, and reformatting it would be this view editing
			// evidence it does not understand.
			fmt.Fprintln(w, e.raw)
			continue
		}
		if e.date != r.day {
			if r.day != "" {
				fmt.Fprintln(w)
			}
			r.day = e.date
			_, _ = fmt.Fprintf(w, "  %s\n", e.date)
		}
		writeAgentLogEntry(w, e)
	}
}

// logBodyIndent is where a row's continuation hangs: clear of the glyph, so
// a wrapped message never resumes under the state mark that owns it. Derived
// from the row's parts rather than hand-counted — counting it by eye is how
// it came to be one column short, which let the longest rows overrun the
// window by exactly one character.
const (
	logRowIndent = 4                            // margin
	logRowLead   = logRowIndent + 5 + 1 + 1 + 1 // + "HH:MM" + " " + glyph + " "
)

var logBodyIndent = strings.Repeat(" ", logRowLead)

// logEntry is one rendered row. subject is the mount path (empty for a
// lifecycle line), detail the message about it, and count how many identical
// events collapsed into this row.
type logEntry struct {
	date, clock     string
	subject, detail string
	count           int
	raw             string // set only for a line that didn't parse
}

// collapseAgentLog parses the log and folds RUNS of identical events into one
// row each. The daemon logs one line per mount, so a single reader sweep
// writes eight lines that differ only in the path — the same event, eight
// times, filling a screen. Collapsed, the row says how many mounts it was.
//
// Only consecutive same-minute, same-detail events fold, so two sweeps an
// hour apart stay two rows and the timeline is never rewritten.
func collapseAgentLog(lines []string, home string) []logEntry {
	var out []logEntry
	for _, raw := range lines {
		m := logLineRe.FindStringSubmatch(raw)
		if m == nil {
			out = append(out, logEntry{raw: raw})
			continue
		}
		e := logEntry{date: m[1], clock: m[2][:5], count: 1, detail: m[3]}
		if r := readsRe.FindStringSubmatch(e.detail); r != nil {
			// The raw suffix counts what was SUPPRESSED ("+3 since the last
			// logged one"), so the total occurrences are one more — the
			// logged one plus the three. ×N means "N times" everywhere else
			// in jit, so rendering the suppressed count verbatim understated
			// every row by one (and "×1" claimed a single occurrence for a
			// line that actually happened twice).
			if n, err := strconv.Atoi(r[1]); err == nil {
				e.detail = readsRe.ReplaceAllString(e.detail, "") + " ×" + strconv.Itoa(n+1)
			}
		}
		if mm := mountRe.FindStringSubmatch(e.detail); mm != nil {
			e.subject, e.detail = mm[1], mm[2]
		}
		// Home-shorten whatever paths remain: the socket path on every
		// "listening on …" line is as repetitive as any mount's.
		if home != "" {
			e.subject = displayPath(home, e.subject)
			e.detail = strings.ReplaceAll(e.detail, home+"/", "~/")
		}
		if n := len(out); n > 0 && out[n-1].raw == "" &&
			out[n-1].clock == e.clock && out[n-1].detail == e.detail &&
			out[n-1].subject != "" && e.subject != "" {
			out[n-1].count++
			continue
		}
		out = append(out, e)
	}
	return out
}

// writeAgentLogEntry renders one row: time, state glyph, subject, detail.
func writeAgentLogEntry(w io.Writer, e logEntry) {
	body := e.detail
	switch {
	case e.count > 1:
		body = fmt.Sprintf("%s  %s", countWord(e.count, "mount", "mounts"), e.detail)
	case e.subject != "":
		// Bound the path so the detail that explains it still lands on the
		// same line at a normal width; the tail is what names the file.
		budget := max(24, termtext.Width()-len(logBodyIndent)-len(e.detail)-2)
		body = termtext.TruncHead(e.subject, budget) + "  " + e.detail
	}

	glyph, c := agentLogGlyph(e.detail)
	fmt.Fprint(w, strings.Repeat(" ", logRowIndent))
	_, _ = fmt.Fprintf(w, "%s ", e.clock) // HH:MM — seconds live in --raw
	_, _ = c.Fprintf(w, "%s ", glyph)
	termtext.Wrap(w, len(logBodyIndent), logBodyIndent, body)
}

// agentLogGlyph classifies a message by what the reader should do about it:
// red when the service failed at something, amber when it is reporting a
// degraded or unidentified state, green when it is just narrating its life.
func agentLogGlyph(msg string) (string, *color.Color) {
	l := strings.ToLower(msg)
	switch {
	case strings.Contains(l, "broken pipe"),
		strings.Contains(l, "error"),
		strings.Contains(l, "failed"),
		strings.Contains(l, "refused"),
		strings.Contains(l, "panic"):
		return glyphRisk, cRisk
	case strings.Contains(l, "decoy"),
		strings.Contains(l, "not identified"),
		strings.Contains(l, "missed"),
		strings.Contains(l, "denied"),
		// A mount the service cannot serve or resolve is degraded, not
		// narration: "skipped," is the current write shape, "skipping
		// mount" the one older logs still carry. Both rendered green
		// through an entire afternoon of the 2026-08-17 incident.
		strings.Contains(l, "skipped,"),
		strings.Contains(l, "skipping mount"):
		return glyphWarn, cWarn
	default:
		return glyphOK, cOK
	}
}
