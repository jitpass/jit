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
// survives too; a slice or a map is v's alone (an element that must keep its
// own unknown fields keeps its raw itself). Unknown fields follow the known
// ones, sorted by name.
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
		if !ok || !f.nested {
			continue
		}
		if prev, ok := takeFold(old, k, false); ok {
			if vals[i], err = merge(vals[i], prev, f.typ); err != nil {
				return nil, err
			}
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
		nested := ft.Kind() == reflect.Struct &&
			!ft.Implements(marshalerType) && !reflect.PointerTo(ft).Implements(marshalerType)
		out[name] = field{typ: ft, nested: nested}
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
