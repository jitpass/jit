// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// Package jsonkeep writes a record back with the fields this build does not
// know. jit's state files (grants.json, jobs.json) are read by every copy of
// jit a user runs, old and new, and each one saves the whole file back: a
// field a newer jit added, dropped by an older one's save, is gone for good,
// and so is whatever it meant. Marshal keeps it.
//
// Standard library only, so any package can use it.
package jsonkeep

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// Marshal is json.Marshal(v), plus every field of raw that v's type does not
// name, unchanged. raw is the object v was read from; empty (a record made
// by this build) gives exactly json.Marshal(v).
//
// Known fields come from v: a field v's type names is written as v holds it,
// never from raw, even when v omits it (omitempty), so a value this build
// cleared stays cleared. Names are matched without regard to case, as
// encoding/json reads them. A known field whose type is a struct is merged
// the same way, one level down and further, so an unknown field inside it
// survives too. So does an element of a slice (or array) of structs, under
// one rule: an element keeps the unknown fields of the old element whose
// known fields are exactly its own (the first such not yet taken, wherever it
// sat), and an element with no such twin, one this build added or changed,
// is written as v holds it. Matching by index alone would hand one element's
// fields to another the moment a slice was reordered or had an element
// removed, and a field a newer jit ties to an element (a nonce beside sealed
// bytes) must never end up next to different data; matching by content
// cannot do that, and losing the unknown fields of an element this build
// changed is what a changed element should lose. A map is v's alone, and so
// is an element whose type has its own MarshalJSON (it keeps its raw
// itself). Unknown fields follow the known ones, sorted by name.
func Marshal(v any, raw json.RawMessage) ([]byte, error) {
	known, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return merge(known, raw, reflect.TypeOf(v))
}

var marshalerType = reflect.TypeOf((*json.Marshaler)(nil)).Elem()

func merge(known []byte, raw json.RawMessage, t reflect.Type) ([]byte, error) {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if len(raw) == 0 || t == nil || t.Kind() != reflect.Struct {
		return known, nil
	}
	var old map[string]json.RawMessage
	if json.Unmarshal(raw, &old) != nil || old == nil {
		return known, nil // raw is not an object: nothing to keep
	}
	keys, vals, err := members(known)
	if err != nil || keys == nil {
		return known, err // v wrote something other than an object
	}
	fields := fieldsOf(t)
	for i, k := range keys {
		f, ok := fields.lookup(k)
		if !ok || (!f.nested && f.elem == nil) {
			continue
		}
		prev, ok := takeFold(old, k, false)
		if !ok {
			continue
		}
		if f.nested {
			vals[i], err = merge(vals[i], prev, f.typ)
		} else {
			vals[i], err = mergeElems(vals[i], prev, f.elem)
		}
		if err != nil {
			return nil, err
		}
	}
	for name := range fields {
		takeFold(old, name, true)
	}
	extra := make([]string, 0, len(old))
	for k := range old {
		extra = append(extra, k)
	}
	sort.Strings(extra)
	extraVals := make([]json.RawMessage, len(extra))
	for i, k := range extra {
		extraVals[i] = old[k]
	}
	return join(keys, vals, extra, extraVals)
}

// field is one member a struct type names.
type field struct {
	typ reflect.Type
	// nested: a struct (or pointer to one) with no marshaler of its own, so
	// its unknown fields are merged too.
	nested bool
	// elem: for a slice or array of such structs (or pointers to them), the
	// element type, so each element's unknown fields are merged too
	// (mergeElems).
	elem reflect.Type
}

// mergeable reports whether t (a pointer dereferenced) is a struct whose
// unknown fields jsonkeep merges: one with no marshaler of its own.
func mergeable(t reflect.Type) (reflect.Type, bool) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	ok := t.Kind() == reflect.Struct &&
		!t.Implements(marshalerType) && !reflect.PointerTo(t).Implements(marshalerType)
	return t, ok
}

// mergeElems merges a slice's elements: each element of known takes the
// unknown fields of the first element of raw not yet taken whose known
// fields, read as et and written again, are byte for byte its own. An
// element with no such twin keeps none (Marshal says why). Anything that is
// not two arrays is known, as it is.
func mergeElems(known []byte, raw json.RawMessage, et reflect.Type) ([]byte, error) {
	var kn, old []json.RawMessage
	if json.Unmarshal(known, &kn) != nil || kn == nil || json.Unmarshal(raw, &old) != nil {
		return known, nil
	}
	// canon[j] is what this build writes for old[j]'s known fields; nil for
	// one that does not read as et, which then matches nothing.
	canon := make([][]byte, len(old))
	for j, o := range old {
		p := reflect.New(et)
		if json.Unmarshal(o, p.Interface()) == nil {
			canon[j], _ = json.Marshal(p.Elem().Interface())
		}
	}
	taken := make([]bool, len(old))
	var err error
	for i := range kn {
		for j := range old {
			if taken[j] || canon[j] == nil || !bytes.Equal(canon[j], kn[i]) {
				continue
			}
			taken[j] = true
			if kn[i], err = merge(kn[i], old[j], et); err != nil {
				return nil, err
			}
			break
		}
	}
	var b bytes.Buffer
	b.WriteByte('[')
	for i, e := range kn {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(e)
	}
	b.WriteByte(']')
	return b.Bytes(), nil
}

// Unknown names every member of raw, the object a v was read from, that v's
// type does not name: at the top, inside a known struct field, and inside
// each element of a known slice of structs, as a dotted path ("secrets[0].x"),
// sorted. Names are matched without regard to case, as encoding/json reads
// them. A record with any is one this build does not fully understand, and a
// caller that would rewrite what the record's other fields mean (re-seal it)
// must leave it alone. raw that is not an object names nothing.
func Unknown(v any, raw json.RawMessage) []string {
	out := unknown(reflect.TypeOf(v), raw, "")
	sort.Strings(out)
	return out
}

func unknown(t reflect.Type, raw json.RawMessage, prefix string) []string {
	if t == nil || len(raw) == 0 {
		return nil
	}
	t, ok := mergeable(t)
	if !ok {
		return nil
	}
	var old map[string]json.RawMessage
	if json.Unmarshal(raw, &old) != nil {
		return nil
	}
	fields := fieldsOf(t)
	var out []string
	for k, val := range old {
		f, ok := fields.lookup(k)
		switch {
		case !ok:
			out = append(out, prefix+k)
		case f.nested:
			out = append(out, unknown(f.typ, val, prefix+k+".")...)
		case f.elem != nil:
			var elems []json.RawMessage
			if json.Unmarshal(val, &elems) == nil {
				for i, e := range elems {
					out = append(out, unknown(f.elem, e, fmt.Sprintf("%s%s[%d].", prefix, k, i))...)
				}
			}
		}
	}
	return out
}

type fieldSet map[string]field

func (fs fieldSet) lookup(name string) (field, bool) {
	if f, ok := fs[name]; ok {
		return f, true
	}
	for k, f := range fs {
		if strings.EqualFold(k, name) {
			return f, true
		}
	}
	return field{}, false
}

// fieldsOf is every JSON member name t's fields take, embedded structs'
// promoted fields included.
func fieldsOf(t reflect.Type) fieldSet {
	out := fieldSet{}
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		tag := sf.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		ft := sf.Type
		for ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if sf.Anonymous && name == "" && ft.Kind() == reflect.Struct {
			for k, f := range fieldsOf(ft) {
				out[k] = f
			}
			continue
		}
		if !sf.IsExported() {
			continue
		}
		if name == "" {
			name = sf.Name
		}
		f := field{typ: ft}
		_, f.nested = mergeable(ft)
		if ft.Kind() == reflect.Slice || ft.Kind() == reflect.Array {
			if et, ok := mergeable(ft.Elem()); ok {
				f.elem = et
			}
		}
		out[name] = f
	}
	return out
}

// takeFold removes from m every key equal to name without regard to case
// (all of them when all, else the exact one or the first found), returning
// one removed value.
func takeFold(m map[string]json.RawMessage, name string, all bool) (json.RawMessage, bool) {
	if v, ok := m[name]; ok {
		delete(m, name)
		if !all {
			return v, true
		}
	}
	var got json.RawMessage
	found := false
	for k, v := range m {
		if strings.EqualFold(k, name) {
			delete(m, k)
			got, found = v, true
			if !all {
				break
			}
		}
	}
	return got, found
}

// members splits a JSON object into its keys and values, in order. A
// document that is not an object gives nil keys.
func members(obj []byte) ([]string, []json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(obj))
	tok, err := dec.Token()
	if err != nil {
		return nil, nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, nil, nil
	}
	keys := []string{}
	var vals []json.RawMessage
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, nil, err
		}
		k, _ := tok.(string)
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, nil, err
		}
		keys, vals = append(keys, k), append(vals, v)
	}
	return keys, vals, nil
}

func join(keys []string, vals []json.RawMessage, extra []string, extraVals []json.RawMessage) ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	write := func(k string, v json.RawMessage) error {
		if b.Len() > 1 {
			b.WriteByte(',')
		}
		kb, err := json.Marshal(k)
		if err != nil {
			return err
		}
		b.Write(kb)
		b.WriteByte(':')
		b.Write(v)
		return nil
	}
	for i := range keys {
		if err := write(keys[i], vals[i]); err != nil {
			return nil, err
		}
	}
	for i := range extra {
		if err := write(extra[i], extraVals[i]); err != nil {
			return nil, err
		}
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}
