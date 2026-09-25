// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package jsonkeep

import (
	"encoding/json"
	"testing"
	"time"
)

type inner struct {
	A string `json:"a"`
}

type rec struct {
	Name    string    `json:"name"`
	Note    string    `json:"note,omitempty"`
	Inner   inner     `json:"inner"`
	List    []inner   `json:"list"`
	When    time.Time `json:"when"`
	Skipped string    `json:"-"`
	Plain   int
	hidden  int
}

func TestMarshalKeepsUnknownFields(t *testing.T) {
	raw := json.RawMessage(`{"name":"old","note":"was set","NAME":"dup","inner":{"a":"x","deep":1},
		"list":[{"a":"1","lost":true}],"when":"2020-01-01T00:00:00Z","Skipped":"s","plain":7,
		"hidden":2,"zeta":{"k":[1,2]},"alpha":"kept"}`)
	r := rec{Name: "new", Inner: inner{A: "y"}, List: []inner{{A: "2"}}, Plain: 3, hidden: 9}
	got, err := Marshal(r, raw)
	if err != nil {
		t.Fatal(err)
	}
	// Known fields are v's (note cleared stays cleared; NAME and plain match
	// without case), inner keeps its unknown "deep", the list is v's alone,
	// and the unknown fields (Skipped: json:"-" is not a name; hidden is
	// unexported) follow, sorted.
	want := `{"name":"new","inner":{"a":"y","deep":1},"list":[{"a":"2"}],"when":"0001-01-01T00:00:00Z","Plain":3,` +
		`"Skipped":"s","alpha":"kept","hidden":2,"zeta":{"k":[1,2]}}`
	if string(got) != want {
		t.Errorf("Marshal:\n got %s\nwant %s", got, want)
	}
}

func TestMarshalWithoutRawIsJSONMarshal(t *testing.T) {
	r := rec{Name: "n"}
	want, _ := json.Marshal(r)
	for _, raw := range []json.RawMessage{nil, json.RawMessage(`[1]`), json.RawMessage(`"s"`)} {
		got, err := Marshal(r, raw)
		if err != nil || string(got) != string(want) {
			t.Errorf("Marshal(r, %s) = %s, %v; want %s", raw, got, err, want)
		}
	}
}
