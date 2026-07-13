// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/jitpass/jit/internal/audit"
)

// validateOutputFormat is the shared --format check for commands whose
// machine-readable output is a single JSON snapshot rather than a stream
// of records — doctor, vault list, agent status, and jit status
// (GAPS.md #22). audit's own --format is richer (markdown, ndjson) and
// validates independently (validateAuditFormat) since it's reporting a
// list of findings, not one snapshot; keep that command's flag as-is
// rather than folding it into this smaller vocabulary.
func validateOutputFormat(format string) error {
	switch format {
	case "", "text", "json":
		return nil
	default:
		return fmt.Errorf(`unknown --format %q (want "text" or "json")`, format)
	}
}

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

// pluralWord returns singular when n is 1, plural otherwise — for the
// "N category/categories" style messages several reports share, so the
// three-line count check isn't hand-copied per message.
func pluralWord(n int, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
}
