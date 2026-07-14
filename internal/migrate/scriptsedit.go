// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"bytes"
	"encoding/json"
	"strings"
)

// scriptEntry is one package.json "scripts" member with its source position
// preserved. encoding/json's map decoding loses member order, which is what
// used to make the reveal-hook rewrite alphabetize the whole file (issue #2)
// — an ordered slice keeps the file's own order through the edit.
type scriptEntry struct {
	key   string
	value string
}

// parseScriptEntries decodes a "scripts" object into its members in source
// order. ok is false when raw isn't an object of string values — the same
// shapes the old map[string]string unmarshal rejected.
func parseScriptEntries(raw []byte) (entries []scriptEntry, ok bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, false
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, false
		}
		key, isStr := keyTok.(string)
		if !isStr {
			return nil, false
		}
		var val string
		if err := dec.Decode(&val); err != nil {
			return nil, false
		}
		entries = append(entries, scriptEntry{key: key, value: val})
	}
	return entries, true
}

func indexOfScript(entries []scriptEntry, key string) int {
	for i, e := range entries {
		if e.key == key {
			return i
		}
	}
	return -1
}

func leadingWhitespace(s string) string {
	return s[:len(s)-len(strings.TrimLeft(s, " \t"))]
}

// renderScriptEntries re-serializes scripts members in order, mimicking the
// original block's own indentation (member lines and closing brace) so the
// splice back into package.json reads as a minimal diff even in files that
// use tabs or 4-space indents.
func renderScriptEntries(entries []scriptEntry, original []byte) ([]byte, error) {
	if len(entries) == 0 {
		return []byte("{}"), nil
	}
	memberIndent, closeIndent := "    ", "  "
	if lines := strings.Split(string(original), "\n"); len(lines) >= 2 {
		memberIndent = leadingWhitespace(lines[1])
		closeIndent = leadingWhitespace(lines[len(lines)-1])
	}
	var b bytes.Buffer
	b.WriteString("{\n")
	for i, e := range entries {
		k, err := marshalJSONNoEscape(e.key, "")
		if err != nil {
			return nil, err
		}
		v, err := marshalJSONNoEscape(e.value, "")
		if err != nil {
			return nil, err
		}
		b.WriteString(memberIndent)
		b.Write(k)
		b.WriteString(": ")
		b.Write(v)
		if i < len(entries)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString(closeIndent)
	b.WriteString("}")
	return b.Bytes(), nil
}

// replaceTopLevelValue returns data with the top-level object member key's
// value replaced by newVal, leaving every other byte — member order,
// indentation, trailing newline — exactly as it was. ok is false when the
// member isn't found or the value's byte range can't be pinned down, in
// which case the caller falls back to a whole-file re-marshal.
func replaceTopLevelValue(data []byte, key string, newVal []byte) (out []byte, ok bool) {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, false
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, false
		}
		k, isStr := keyTok.(string)
		if !isStr {
			return nil, false
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, false
		}
		if k != key {
			continue
		}
		// Decoder hands RawMessage the value's verbatim input bytes, so the
		// value occupies [InputOffset-len(raw), InputOffset). The equality
		// check makes that assumption safe: if it ever doesn't hold, bail to
		// the re-marshal fallback rather than splice at a wrong offset.
		end := dec.InputOffset()
		start := end - int64(len(raw))
		if start < 0 || !bytes.Equal(data[start:end], raw) {
			return nil, false
		}
		spliced := make([]byte, 0, len(data)-len(raw)+len(newVal))
		spliced = append(spliced, data[:start]...)
		spliced = append(spliced, newVal...)
		spliced = append(spliced, data[end:]...)
		return spliced, true
	}
	return nil, false
}
