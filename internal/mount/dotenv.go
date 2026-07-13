// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package mount

import (
	"sort"
	"strings"
)

// FormatDotenv renders values as dotenv-format content (KEY=value lines,
// sorted for determinism) suitable for serving over a mounted .env FIFO —
// the actual file format standard loaders (python-dotenv, Node's dotenv,
// etc.) expect, which is NOT shell `export` syntax. A value is left bare
// when that's unambiguous; otherwise it's double-quoted with internal
// quotes/backslashes escaped, matching the common convention those
// loaders already support.
func FormatDotenv(values map[string]string) []byte {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	for _, name := range names {
		b.WriteString(name)
		b.WriteByte('=')
		b.WriteString(dotenvQuote(values[name]))
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

func dotenvQuote(v string) string {
	if isBareSafe(v) {
		return v
	}
	escaped := strings.ReplaceAll(v, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	escaped = strings.ReplaceAll(escaped, "\n", `\n`)
	return `"` + escaped + `"`
}

// isBareSafe reports whether v can be written without quoting: no
// whitespace, newlines, quotes, '#' (a comment marker to dotenv parsers),
// or a leading/trailing state that would change meaning unquoted.
func isBareSafe(v string) bool {
	if v == "" {
		return false
	}
	for _, r := range v {
		switch r {
		case ' ', '\t', '\n', '\r', '"', '\'', '#', '\\', '$':
			return false
		}
	}
	return true
}
