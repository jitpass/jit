// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package mount

import (
	"sort"
	"strings"
)

// FormatDotenv renders values as dotenv-format content (KEY=value lines)
// suitable for serving over a mounted .env FIFO — the actual file format
// standard loaders (python-dotenv, Node's dotenv, etc.) expect, which is
// NOT shell `export` syntax. A value is left bare when that's unambiguous;
// otherwise it's double-quoted with internal quotes/backslashes escaped,
// matching the common convention those loaders already support.
//
// order carries the source file's original variable order (issue #4: a
// mounted .env used to serve alphabetically, breaking visual/byte fidelity
// against the file it replaced) — names appear in that order first, then
// any names values has that order doesn't, sorted for determinism. A nil
// order is the old fully-sorted rendering.
func FormatDotenv(values map[string]string, order []string) []byte {
	names := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, name := range order {
		if _, ok := values[name]; ok && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	rest := make([]string, 0, len(values)-len(names))
	for name := range values {
		if !seen[name] {
			rest = append(rest, name)
		}
	}
	sort.Strings(rest)
	names = append(names, rest...)

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
