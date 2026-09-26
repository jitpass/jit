// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
)

// The edit `jit mcp install` and `jit mcp uninstall` make to an AI app's
// config, as a splice of the file's own bytes. The help says only the "jit"
// entry changes, and decoding the file into a map and encoding it again made
// that false on every run: keys came back sorted, the file's own indentation
// was replaced, and "&", "<" and ">" in any string came back as &,
// < and > (pre-release review, 2026-09-26). Here the file is
// located, not re-encoded: the jit member is replaced, inserted after the
// last member of its object, or cut out with its separator, and every other
// byte is copied through. Install then uninstall on a file with no jit entry
// gives back the file byte for byte.
//
// The splicer assumes a document json.Unmarshal has already accepted, and the
// caller checks what it produced decodes to what a map edit would have, so a
// mistake here refuses the edit rather than damaging the file.

// jsonMember is one "key": value pair of a JSON object, as offsets into the
// document.
type jsonMember struct {
	key                  string // decoded
	keyStart, keyEnd     int    // the quoted key, quotes included
	valueStart, valueEnd int
}

// jsonObject is an object's braces and members, as offsets into the document.
type jsonObject struct {
	open, close int
	members     []jsonMember
}

var (
	errSplice          = errors.New("unexpected JSON")
	errRepeatedServers = errors.New("it names mcpServers more than once")
)

func isJSONSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

func skipJSONSpace(s []byte, i int) int {
	for i < len(s) && isJSONSpace(s[i]) {
		i++
	}
	return i
}

// skipJSONString returns the offset just past the string starting at s[i].
func skipJSONString(s []byte, i int) (int, error) {
	if i >= len(s) || s[i] != '"' {
		return 0, errSplice
	}
	for j := i + 1; j < len(s); j++ {
		switch s[j] {
		case '\\':
			j++
		case '"':
			return j + 1, nil
		}
	}
	return 0, errSplice
}

// skipJSONValue returns the offset just past the value starting at s[i].
func skipJSONValue(s []byte, i int) (int, error) {
	if i >= len(s) {
		return 0, errSplice
	}
	switch s[i] {
	case '"':
		return skipJSONString(s, i)
	case '{', '[':
		depth := 0
		for j := i; j < len(s); j++ {
			switch s[j] {
			case '"':
				end, err := skipJSONString(s, j)
				if err != nil {
					return 0, err
				}
				j = end - 1
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					return j + 1, nil
				}
			}
		}
		return 0, errSplice
	default: // a number, true, false or null
		j := i
		for j < len(s) && !isJSONSpace(s[j]) && s[j] != ',' && s[j] != '}' && s[j] != ']' {
			j++
		}
		if j == i {
			return 0, errSplice
		}
		return j, nil
	}
}

// parseJSONObject reads the object whose '{' is at s[i].
func parseJSONObject(s []byte, i int) (jsonObject, error) {
	if i >= len(s) || s[i] != '{' {
		return jsonObject{}, errSplice
	}
	obj := jsonObject{open: i}
	j := skipJSONSpace(s, i+1)
	if j < len(s) && s[j] == '}' {
		obj.close = j
		return obj, nil
	}
	for {
		var m jsonMember
		var err error
		m.keyStart = j
		if m.keyEnd, err = skipJSONString(s, j); err != nil {
			return jsonObject{}, err
		}
		if err := json.Unmarshal(s[m.keyStart:m.keyEnd], &m.key); err != nil {
			return jsonObject{}, errSplice
		}
		j = skipJSONSpace(s, m.keyEnd)
		if j >= len(s) || s[j] != ':' {
			return jsonObject{}, errSplice
		}
		m.valueStart = skipJSONSpace(s, j+1)
		if m.valueEnd, err = skipJSONValue(s, m.valueStart); err != nil {
			return jsonObject{}, err
		}
		obj.members = append(obj.members, m)
		j = skipJSONSpace(s, m.valueEnd)
		if j >= len(s) {
			return jsonObject{}, errSplice
		}
		switch s[j] {
		case ',':
			j = skipJSONSpace(s, j+1)
		case '}':
			obj.close = j
			return obj, nil
		default:
			return jsonObject{}, errSplice
		}
	}
}

// lastMember returns the index of the last member named key, or -1. The
// last, because that is the one json.Unmarshal keeps when a key repeats.
func (o jsonObject) lastMember(key string) int {
	for i := len(o.members) - 1; i >= 0; i-- {
		if o.members[i].key == key {
			return i
		}
	}
	return -1
}

func splice(s []byte, start, end int, with []byte) []byte {
	out := make([]byte, 0, len(s)-(end-start)+len(with))
	out = append(out, s[:start]...)
	out = append(out, with...)
	return append(out, s[end:]...)
}

// lineIndent is the run of spaces and tabs that starts the line holding s[i].
func lineIndent(s []byte, i int) string {
	start := bytes.LastIndexByte(s[:i], '\n') + 1
	end := start
	for end < len(s) && (s[end] == ' ' || s[end] == '\t') {
		end++
	}
	return string(s[start:end])
}

// memberLayout is how the members of an object are laid out: whether each
// starts on its own line, at what indent, one indent step deeper than the
// object's own line, and what sits between a key and its value.
type memberLayout struct {
	multiline bool
	indent    string // a member's indent, when multiline
	step      string // one level of indentation
	colon     string // ":" with whatever space the file puts around it
}

// layoutOf reads obj's layout from its last member, or, for an empty object,
// from the document's top-level object.
func layoutOf(s []byte, obj jsonObject) memberLayout {
	l := memberLayout{step: "  ", colon: ": "}
	if len(obj.members) == 0 {
		l.multiline = true
		if top, err := parseJSONObject(s, skipJSONSpace(s, 0)); err == nil && top.open != obj.open {
			if tl := layoutOf(s, top); tl.multiline {
				l.step = tl.step
			}
		}
		l.indent = lineIndent(s, obj.open) + l.step
		return l
	}
	last := obj.members[len(obj.members)-1]
	ws := last.keyStart
	for ws > 0 && isJSONSpace(s[ws-1]) {
		ws--
	}
	lead := s[ws:last.keyStart]
	l.colon = string(s[last.keyEnd:last.valueStart])
	if nl := bytes.LastIndexByte(lead, '\n'); nl >= 0 {
		l.multiline = true
		l.indent = string(lead[nl+1:])
		outer := lineIndent(s, obj.open)
		if len(l.indent) > len(outer) && l.indent[:len(outer)] == outer {
			l.step = l.indent[len(outer):]
		}
	} else {
		l.indent = string(lead) // the space, if any, after the comma
	}
	return l
}

// encodeJSONValue encodes v for a member laid out as l: indented to match,
// or compact on a one-line object, and never escaping &, < or >.
func encodeJSONValue(v any, l memberLayout) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if l.multiline {
		enc.SetIndent(l.indent, l.step)
	}
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// insertMember adds key: value as obj's last member, laid out like the
// members already there.
func insertMember(s []byte, obj jsonObject, key string, value any) ([]byte, error) {
	l := layoutOf(s, obj)
	k, _ := json.Marshal(key)
	v, err := encodeJSONValue(value, l)
	if err != nil {
		return nil, err
	}
	if len(obj.members) == 0 {
		// {} becomes a block, closed on its own line at the object's indent.
		body := "\n" + l.indent + string(k) + l.colon + string(v) + "\n" + lineIndent(s, obj.open)
		return splice(s, obj.open+1, obj.close, []byte(body)), nil
	}
	last := obj.members[len(obj.members)-1]
	sep := l.indent
	if l.multiline {
		sep = "\n" + l.indent
	}
	return splice(s, last.valueEnd, last.valueEnd, []byte(","+sep+string(k)+l.colon+string(v))), nil
}

// removeMember cuts obj's member i out with the separator that joined it to
// its neighbour, so the members around it keep their own spacing.
func removeMember(s []byte, obj jsonObject, i int) []byte {
	switch {
	case len(obj.members) == 1:
		return splice(s, obj.open+1, obj.close, nil)
	case i == 0:
		return splice(s, obj.members[0].keyStart, obj.members[1].keyStart, nil)
	default:
		return splice(s, obj.members[i-1].valueEnd, obj.members[i].valueEnd, nil)
	}
}

// spliceMCPEntry sets (entry non-nil) or removes the "jit" member of the
// document's mcpServers object, changing no other byte. It does not decide
// whether an edit is needed; setMCPEntry does.
func spliceMCPEntry(doc []byte, entry *mcpServerEntry) ([]byte, error) {
	topAt := func(s []byte) (jsonObject, error) { return parseJSONObject(s, skipJSONSpace(s, 0)) }
	top, err := topAt(doc)
	if err != nil {
		return nil, err
	}
	n := 0
	for _, m := range top.members {
		if m.key == "mcpServers" {
			n++
		}
	}
	if n > 1 {
		// Which copy an app reads is its parser's choice, and cutting one
		// can bring another back into force: not a file to edit by guess.
		return nil, errRepeatedServers
	}
	si := top.lastMember("mcpServers")
	if si < 0 {
		if entry == nil {
			return doc, nil
		}
		return insertMember(doc, top, "mcpServers", map[string]*mcpServerEntry{mcpServerName: entry})
	}
	if doc[top.members[si].valueStart] != '{' { // null: the map edit makes it an object
		if entry == nil {
			return doc, nil
		}
		m := top.members[si]
		v, err := encodeJSONValue(map[string]*mcpServerEntry{mcpServerName: entry}, layoutOf(doc, top))
		if err != nil {
			return nil, err
		}
		return splice(doc, m.valueStart, m.valueEnd, v), nil
	}
	servers := func(s []byte) (jsonObject, jsonObject, error) {
		t, err := topAt(s)
		if err != nil {
			return jsonObject{}, jsonObject{}, err
		}
		i := t.lastMember("mcpServers")
		if i < 0 {
			return jsonObject{}, jsonObject{}, errSplice
		}
		o, err := parseJSONObject(s, t.members[i].valueStart)
		return t, o, err
	}

	// A repeated "jit" key is cut down to its last, one at a time, re-reading
	// the offsets after each cut.
	for {
		t, obj, err := servers(doc)
		if err != nil {
			return nil, err
		}
		n := 0
		first := -1
		for i, m := range obj.members {
			if m.key == mcpServerName {
				if first < 0 {
					first = i
				}
				n++
			}
		}
		switch {
		case n == 0 && entry == nil:
			return doc, nil
		case n == 0:
			return insertMember(doc, obj, mcpServerName, entry)
		case entry == nil && len(obj.members) == n:
			// jit was its only server: the map edit drops mcpServers, and so
			// does this, which is what makes install-then-uninstall exact.
			return removeMember(doc, t, t.lastMember("mcpServers")), nil
		case entry == nil || n > 1:
			doc = removeMember(doc, obj, first)
		default:
			m := obj.members[first]
			l := layoutOf(doc, obj)
			if l.multiline {
				l.indent = lineIndent(doc, m.keyStart)
			}
			v, err := encodeJSONValue(entry, l)
			if err != nil {
				return nil, err
			}
			return splice(doc, m.valueStart, m.valueEnd, v), nil
		}
	}
}
