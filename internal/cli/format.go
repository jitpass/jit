// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/jitpass/jit/internal/audit"
	"github.com/jitpass/jit/internal/ui"
)

// newProgress builds the shared status-trail tracker for a long-running
// command, applying the one gating policy every command should use so the
// decision lives in exactly one place:
//
//   - Output goes to stderr (cmd.ErrOrStderr()), never stdout — stdout stays
//     byte-clean for pipes, captured reports, and --output files.
//   - It's silent unless stderr is a real terminal, so piped/CI/test runs are
//     byte-for-byte unchanged (this is the repo's existing decoration rule,
//     see printVaultGetFooter in vault.go).
//   - --quiet and any machine-readable mode (JSON/NDJSON/--output, passed as
//     machineMode) silence it even on a terminal.
//   - A TERM=dumb terminal still gets a plain step-per-line trail, just no
//     spinner animation or ANSI redraw.
func newProgress(cmd *cobra.Command, machineMode bool) *ui.Tracker {
	tty := term.IsTerminal(int(os.Stderr.Fd()))
	enabled := tty && !quietFlag && !machineMode
	animate := enabled && os.Getenv("TERM") != "dumb"
	return ui.New(cmd.ErrOrStderr(), enabled, animate)
}

// validateOutputFormat is the shared --format check for commands whose
// machine-readable output is a single JSON snapshot rather than a stream
// of records — doctor, vault list, agent status, and jit status
// (GAPS.md #22). audit's own --format is richer (markdown, ndjson) and
// validates independently (validateAuditFormat) since it's reporting a
// list of findings, not one snapshot; keep that command's flag as-is
// rather than folding it into this smaller vocabulary.
func validateOutputFormat(format string) error {
	for _, f := range outputFormats {
		if format == "" || format == f {
			return nil
		}
	}
	return fmt.Errorf(`unknown --format %q (want "text" or "json")`, format)
}

// outputFormats is the vocabulary validateOutputFormat accepts AND the one
// completeOutputFormat offers, in one place: a --format that the command
// takes but tab never mentions is the same drift the palette and the history
// admit rule are centralised to prevent.
var outputFormats = []string{"text", "json"}

// writeJSON encodes v as indented JSON, terminated by a newline (Encode's
// own behavior) — readable directly by a human piping through `jq` or
// redirecting to a file, and just as parseable for a script either way.
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// displayPath shortens an absolute path for human-readable reports by
// replacing a leading home directory with "~" — on a real machine every
// migrate/undo plan line otherwise starts with the same dozens of
// /Users/<name>/... characters before the part that matters. Display
// only: JSON/NDJSON output and anything re-consumed programmatically
// keeps the full absolute path. A thin delegate so audit's reports and
// this package's plans share ONE implementation of the shortening rule
// instead of two copies that could drift.
func displayPath(home, path string) string {
	return audit.ShortenHome(home, path)
}

// shortPath is displayPath for the callers that don't already hold the home
// directory — the diagnostic surfaces, which print absolute paths that a
// report has no business spending 40 columns on. A home that can't be
// resolved simply leaves the path alone.
func shortPath(path string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return displayPath(home, path)
}

// shortHome collapses the home directory anywhere inside already-rendered
// text — for the wrapped errors that embed an absolute path mid-sentence,
// where displayPath's path-shaped input doesn't apply. Display only, and only
// on text jit itself composed.
func shortHome(s string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return s
	}
	return strings.ReplaceAll(s, home, "~")
}

// pluralWord returns singular when n is 1, plural otherwise — for the
// "N category/categories" style messages several reports share, so the
// three-line count check isn't hand-copied per message.
func pluralWord(n int, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
}

// countWord renders "1 secret" / "92 secrets" — the count and its correctly
// inflected noun together, since that pairing is what call sites actually
// want and writing it out by hand is what produced the "92 secret(s)"
// form-letter style the reports had drifted into.
func countWord(n int, singular, plural string) string {
	return fmt.Sprintf("%d %s", n, pluralWord(n, singular, plural))
}

// humanAgo renders an elapsed duration at the precision a human scanning
// a status or plan line wants ("37s", "2m", "3h", "12d") — never "2m0s".
// Shared with jit migrate undo's backup ages, where "3d" vs "2m" is what
// tells a human whether edits-since-backup are plausible.
func humanAgo(d time.Duration) string {
	switch {
	case d < 0:
		// An event stamped ahead of the reader's clock (durable history
		// crossing an NTP step-back) would otherwise render as "-3s ago".
		return "0s"
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}
