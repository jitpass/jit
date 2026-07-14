// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package migrate

import (
	"bytes"
	"encoding/json"
)

// marshalJSONNoEscape encodes v as JSON without encoding/json's default
// HTML-escaping of <, >, and &. Every JSON file this package REWRITES
// (package.json, mcp.json/claude_desktop_config.json,
// credentials.tfrc.json) is a file the developer owns, reads, and diffs —
// and a predev hook written as "2>/dev/null &&" is valid
// JSON that npm parses fine but reads as mangled garbage in exactly the
// file where a mutating tool most needs to look trustworthy (a real
// dogfooding report: the first thing the user did after migrating was
// open package.json and recoil). HTML-escaping exists to protect JSON
// embedded in <script> tags; none of these files is ever that.
// indent is "" for a compact fragment, "  " for a whole pretty file.
func marshalJSONNoEscape(v any, indent string) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if indent != "" {
		enc.SetIndent("", indent)
	}
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	// Encoder.Encode appends a newline MarshalIndent wouldn't — trim it so
	// call sites keep their existing byte-for-byte output conventions.
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
