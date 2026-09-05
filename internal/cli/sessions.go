// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jitpass/jit/internal/migrate"
)

// statusSession is one vaulted temporary credential with a known end, as
// `jit status` reports it (design/sessions-and-path-repair.md). It is the
// JSON shape and the row's input alike, so a script and the eye read the
// same facts.
type statusSession struct {
	Profile string `json:"profile"`
	// Origin names the tool that minted it, by the config it was captured
	// from ("~/.clisso.yaml"); empty when the secrets predate provenance.
	Origin string `json:"origin,omitempty"`
	// ExpiresUnix is 0 when the stamp is unknown — a capture stored before
	// the vault recorded expiry, healed by its next login — never 1970.
	ExpiresUnix int64 `json:"expires_unix,omitempty"`
	// Live is the listing's verdict at report time; a session with no
	// known stamp is reported live (see migrate.Session.Live).
	Live             bool  `json:"live"`
	RemainingSeconds int64 `json:"remaining_seconds,omitempty"`
	// Mint is the command that mints a fresh session, when jit can name it
	// — an app ~/.clisso.yaml defines gets "clisso get <app>". Empty when
	// the minting tool is unknown; jit does not guess.
	Mint string `json:"mint,omitempty"`
}

// sessionsStatusFrom shapes the listing for the report. clissoApps is
// what ~/.clisso.yaml defines; a session whose app is among them is
// clisso's to re-mint.
func sessionsStatusFrom(sessions []migrate.Session, clissoApps map[string]bool, now time.Time) []statusSession {
	out := make([]statusSession, 0, len(sessions))
	for _, s := range sessions {
		entry := statusSession{
			Profile:          s.Profile,
			Origin:           s.Origin,
			ExpiresUnix:      s.ExpiresUnix,
			Live:             s.Live(now),
			RemainingSeconds: int64(s.Remaining(now).Seconds()),
		}
		entry.Mint = clissoMint(s.Profile, clissoApps)
		out = append(out, entry)
	}
	return out
}

// sessionApp is the name the minting tool knows a session by: the capture
// stores "aws-<app>", and `clisso get <app>` is what mints it again.
func sessionApp(profile string) string {
	return strings.TrimPrefix(profile, "aws-")
}

// clissoMint is the command that mints profile afresh when its app is one
// clissoApps (what ~/.clisso.yaml defines) knows, "" otherwise: jit names a
// command only when it can be sure which tool the session belongs to.
func clissoMint(profile string, clissoApps map[string]bool) string {
	if app := sessionApp(profile); clissoApps[app] {
		return "clisso get " + app
	}
	return ""
}

// sessionClock renders an expiry as a full local date and time. Not the
// today/tomorrow axis grants use: a session's end is a fact to compare
// against a clock, and the reader asked for the actual date.
func sessionClock(unix int64) string {
	return time.Unix(unix, 0).Local().Format("2006-01-02 15:04")
}

// clauseSpace joins the words of one clause so the window wraps the row
// only between clauses, never inside one: termtext.Wrap breaks on the
// plain space alone, and "stage expires 2026-09-05" / "21:00" split
// across two lines reads as two facts. A non-breaking space is one column
// and renders as a space; the JSON carries the same facts for anything
// that greps.
const clauseSpace = "\u00a0"

func atomicClause(s string) string { return strings.ReplaceAll(s, " ", clauseSpace) }

// printSessionsSection is the dashboard's last row. Omitted entirely when
// nothing on this machine is a session: unlike grants, there is no on-ramp
// to offer — a session exists only once a wrapped SSO tool has minted one.
//
// The glyph carries the rollup (all live, some expired, all expired); each
// session gets one clause; the action names the mint command for every
// expired session that has one (sessionsStatusFrom sets it from clisso's
// own app list), and stays silent otherwise rather than guess.
func printSessionsSection(w io.Writer, sessions []statusSession, now time.Time) {
	if len(sessions) == 0 {
		return
	}
	statusLabel(w, "sessions")
	live, expired := 0, 0
	clauses := make([]string, 0, len(sessions))
	var remint []string
	for _, s := range sessions {
		switch {
		case s.ExpiresUnix == 0:
			live++
			clauses = append(clauses, sessionApp(s.Profile)+" expiry unknown until its next login")
		case s.Live:
			live++
			clauses = append(clauses, fmt.Sprintf("%s expires %s", sessionApp(s.Profile), sessionClock(s.ExpiresUnix)))
		default:
			expired++
			clauses = append(clauses, fmt.Sprintf("%s expired %s ago", sessionApp(s.Profile), humanAgo(now.Sub(time.Unix(s.ExpiresUnix, 0)))))
			if s.Mint != "" {
				remint = append(remint, s.Mint)
			}
		}
	}
	var rollup string
	switch {
	case expired == 0:
		_, _ = cOK.Fprint(w, glyphOK+" ")
		rollup = fmt.Sprintf("%d live", live)
	case live == 0:
		_, _ = cRisk.Fprint(w, glyphRisk+" ")
		rollup = fmt.Sprintf("%d expired", expired)
	default:
		_, _ = cWarn.Fprint(w, glyphWarn+" ")
		rollup = fmt.Sprintf("%d live, %d expired", live, expired)
	}
	for i, c := range clauses {
		clauses[i] = atomicClause(c)
	}
	printStatusGlyphValue(w, "%s · %s", atomicClause(rollup), strings.Join(clauses, " · "))
	switch len(remint) {
	case 0:
	case 1:
		printStatusAction(w, "`"+remint[0]+"`")
	default:
		// One command to type, then the rest by app name: every mint here
		// is the same tool, so repeating it would only cost the line room.
		rest := make([]string, 0, len(remint)-1)
		for _, m := range remint[1:] {
			rest = append(rest, m[strings.LastIndex(m, " ")+1:])
		}
		printStatusAction(w, "`"+remint[0]+"`, then "+strings.Join(rest, ", "))
	}
}

// clissoStatusRow is one line of the wrapped `clisso status` table.
type clissoStatusRow struct {
	App       string
	ExpireAt  string
	Remaining string
}

// clissoStatusRows selects what the wrapped `clisso status` reports: the
// apps ~/.clisso.yaml defines, live, with a known end. A pre-stamp capture
// is left out on purpose — a script that saw it would skip the login,
// while one that doesn't logs in once and stamps it.
func clissoStatusRows(sessions []migrate.Session, clissoApps map[string]bool, now time.Time) []clissoStatusRow {
	var rows []clissoStatusRow
	for _, s := range sessions {
		if !clissoApps[sessionApp(s.Profile)] || s.ExpiresUnix == 0 || !s.Live(now) {
			continue
		}
		rows = append(rows, clissoStatusRow{
			App:       sessionApp(s.Profile),
			ExpireAt:  sessionClock(s.ExpiresUnix),
			Remaining: remainingUnits(s.Remaining(now)),
		})
	}
	return rows
}

// renderClissoStatusTable prints rows in the shape clisso's own status
// draws (its tablewriter defaults: +- borders, centered headers, left-
// aligned cells, one space of padding), so `clisso status | grep -qw
// stage` and every script like it keeps working. House style does not
// apply here on purpose: this is clisso's output, imitated. The one
// departure is the EXPIRE AT column — a date and time instead of the raw
// epoch clisso prints, which no script keys on and no human can read.
func renderClissoStatusTable(w io.Writer, rows []clissoStatusRow) {
	if len(rows) == 0 {
		fmt.Fprintln(w, "No apps with valid credentials")
		return
	}
	headers := [3]string{"APP", "EXPIRE AT", "REMAINING"}
	widths := [3]int{len(headers[0]), len(headers[1]), len(headers[2])}
	for _, r := range rows {
		for i, cell := range [3]string{r.App, r.ExpireAt, r.Remaining} {
			if n := len(cell); n > widths[i] {
				widths[i] = n
			}
		}
	}
	border := "+"
	for _, wd := range widths {
		border += strings.Repeat("-", wd+2) + "+"
	}
	center := func(s string, wd int) string {
		left := (wd - len(s)) / 2
		return strings.Repeat(" ", left) + s + strings.Repeat(" ", wd-len(s)-left)
	}
	fmt.Fprintln(w, border)
	fmt.Fprintf(w, "| %s | %s | %s |\n", center(headers[0], widths[0]), center(headers[1], widths[1]), center(headers[2], widths[2]))
	fmt.Fprintln(w, border)
	for _, r := range rows {
		fmt.Fprintf(w, "| %-*s | %-*s | %-*s |\n", widths[0], r.App, widths[1], r.ExpireAt, widths[2], r.Remaining)
	}
	fmt.Fprintln(w, border)
}

// remainingUnits renders a duration in at most two units ("6h12m", "3d2h",
// "45m"), the way a TTL is typed rather than time.Duration's seconds.
func remainingUnits(d time.Duration) string {
	if d <= 0 {
		return "0m"
	}
	d = d.Round(time.Minute)
	days := d / (24 * time.Hour)
	hours := (d % (24 * time.Hour)) / time.Hour
	mins := (d % time.Hour) / time.Minute
	switch {
	case days > 0 && hours > 0:
		return fmt.Sprintf("%dd%dh", days, hours)
	case days > 0:
		return fmt.Sprintf("%dd", days)
	case hours > 0 && mins > 0:
		return fmt.Sprintf("%dh%02dm", hours, mins)
	case hours > 0:
		return fmt.Sprintf("%dh", hours)
	default:
		return fmt.Sprintf("%dm", mins)
	}
}
