// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package wrap

import (
	"strings"
)

// extractTOML handles the line-oriented subset of TOML the cataloged config
// files actually use: [section] headers (also [a.b] dotted and [[array]]
// headers, matched by their first segment) and key = "value" pairs. A
// deliberate non-dependency: pulling in a full TOML parser for flat
// section/key lookups isn't worth a new module; if a future catalog entry
// needs real TOML (multiline strings, inline tables), that's the moment to
// add one.
//
// Selector: "section/key", or just "key" for a top-level pair.
func extractTOML(data []byte, selector string) (string, bool) {
	parts := selectorParts(selector)
	var wantSection, wantKey string
	switch len(parts) {
	case 1:
		wantKey = parts[0]
	case 2:
		wantSection, wantKey = parts[0], parts[1]
	default:
		return "", false
	}

	section := ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			if i := strings.IndexByte(section, '.'); i >= 0 {
				section = section[:i]
			}
			continue
		}
		key, rawValue, ok := strings.Cut(line, "=")
		if !ok || section != wantSection {
			continue
		}
		if strings.TrimSpace(key) != wantKey {
			continue
		}
		value := strings.TrimSpace(rawValue)
		if i := strings.Index(value, " #"); i >= 0 { // trailing comment
			value = strings.TrimSpace(value[:i])
		}
		value = strings.Trim(value, `"'`)
		if value == "" {
			return "", false
		}
		return value, true
	}
	return "", false
}
