// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package job

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// MinHidden is the shortest value hidden in every form. Below it the
// encodings are skipped: a short value's base64 or hex is short too, and
// matching it would turn unrelated output into noise.
const MinHidden = 8

// MinHiddenRaw is the shortest value hidden at all, as typed. Anything
// shorter ("443", "on") cannot be hidden without hiding half the output, so it
// is not hidden, and the run says so (ShortValues) instead of pretending.
const MinHiddenRaw = 4

// ShortValues names the hidden values too short to hide at all, sorted, for
// the note a run returns.
func ShortValues(hidden map[string]string) []string {
	var out []string
	for name, v := range hidden {
		if v != "" && len(v) < MinHiddenRaw {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// form is one byte sequence to replace, and whose value it is.
type form struct {
	b    []byte
	name string
}

// Masker is an io.Writer that replaces every hidden value, and its common
// encodings, with [hidden: NAME] before passing output on. It holds back the
// last (longest form − 1) bytes between writes, so a value split across two
// reads is still caught; Flush releases them at the end.
//
// It hides the accident: a script that prints its key, or logs a request
// with the key in a header. It cannot hide a value printed split in two,
// reversed, or encrypted. That is the fingerprint's and the human's job.
type Masker struct {
	mu     sync.Mutex
	w      io.Writer
	forms  []form
	hold   int
	buf    []byte
	counts map[string]int
	err    error
}

// NewMasker hides each value in hidden (name → value): as typed from
// MinHiddenRaw characters, and in every encoding from MinHidden.
func NewMasker(w io.Writer, hidden map[string]string) *Masker {
	m := &Masker{w: w, counts: map[string]int{}}
	seen := map[string]bool{}
	for name, v := range hidden {
		if len(v) < MinHiddenRaw {
			continue
		}
		forms := []string{v}
		if len(v) >= MinHidden {
			forms = encodings(v)
		}
		for _, f := range forms {
			if seen[f] {
				continue
			}
			seen[f] = true
			m.forms = append(m.forms, form{b: []byte(f), name: name})
		}
	}
	// Longest first, so a form that contains another wins at the same
	// position (a value and its URL-escaped superset).
	sort.Slice(m.forms, func(a, b int) bool { return len(m.forms[a].b) > len(m.forms[b].b) })
	if len(m.forms) > 0 {
		m.hold = len(m.forms[0].b) - 1
	}
	return m
}

// encodings are the forms a value commonly takes in output: as is, base64
// (standard and URL-safe, padded and not, since an Authorization header or a
// JWT segment carries one of them), hex, and URL-escaped.
func encodings(v string) []string {
	b := []byte(v)
	out := []string{
		v,
		base64.StdEncoding.EncodeToString(b),
		base64.RawStdEncoding.EncodeToString(b),
		base64.URLEncoding.EncodeToString(b),
		base64.RawURLEncoding.EncodeToString(b),
		hex.EncodeToString(b),
		strings.ToUpper(hex.EncodeToString(b)),
		url.QueryEscape(v),
		url.PathEscape(v),
	}
	return out
}

func replacement(name string) []byte { return []byte("[hidden: " + name + "]") }

// Write never reports a short write: the command's output is not the
// caller's to refuse. An error from the underlying writer is kept and
// returned on this and every later call.
func (m *Masker) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return 0, m.err
	}
	m.buf = append(m.buf, p...)
	m.drain(false)
	if m.err != nil {
		return 0, m.err
	}
	return len(p), nil
}

// Flush writes whatever was held back. Call it once, after the command ends.
func (m *Masker) Flush() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err == nil {
		m.drain(true)
	}
	return m.err
}

// Counts returns how many times each name was hidden so far.
func (m *Masker) Counts() map[string]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]int, len(m.counts))
	for k, v := range m.counts {
		out[k] = v
	}
	return out
}

// drain replaces every complete match in buf and writes out everything that
// can no longer be the start of one. With final set, it writes all of it.
func (m *Masker) drain(final bool) {
	var out bytes.Buffer
	i := 0
	for {
		pos, f := m.next(m.buf[i:])
		if f == nil {
			break
		}
		out.Write(m.buf[i : i+pos])
		out.Write(replacement(f.name))
		m.counts[f.name]++
		i += pos + len(f.b)
	}
	// Past the last match, keep back `hold` bytes: they could be the start of
	// a value whose rest has not arrived yet.
	keep := 0
	if !final {
		keep = m.hold
		if rem := len(m.buf) - i; keep > rem {
			keep = rem
		}
	}
	cut := len(m.buf) - keep
	out.Write(m.buf[i:cut])
	m.buf = append(m.buf[:0], m.buf[cut:]...)
	if out.Len() > 0 {
		if _, err := m.w.Write(out.Bytes()); err != nil {
			m.err = err
		}
	}
}

// next finds the earliest match in b; among matches at the same position the
// longest wins, which the sort order gives for free.
func (m *Masker) next(b []byte) (int, *form) {
	best, bestPos := -1, len(b)
	for k := range m.forms {
		if p := bytes.Index(b, m.forms[k].b); p >= 0 && p < bestPos {
			best, bestPos = k, p
		}
	}
	if best < 0 {
		return 0, nil
	}
	return bestPos, &m.forms[best]
}
