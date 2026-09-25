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
	// without case), inner keeps its unknown "deep", the list's one element
	// changed (a "1" became "2"), so it is v's alone and "lost" is lost, and
	// the unknown fields (Skipped: json:"-" is not a name; hidden is
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

// An element of a slice keeps its own unknown fields when this build left
// it as it was, wherever it now sits; one it changed or added keeps none,
// and never takes another element's.
func TestMarshalKeepsUnknownFieldsOfUnchangedElements(t *testing.T) {
	raw := json.RawMessage(`{"name":"n","list":[{"a":"1","one":1},{"a":"2","two":2},{"a":"3","three":3},{"a":"1","again":1}]}`)
	// "2" dropped, "3" moved first, "1" twice as before, "x" new; "3"'s
	// field must not follow the index to whatever sits where "3" was.
	r := rec{Name: "n", List: []inner{{A: "3"}, {A: "1"}, {A: "x"}, {A: "1"}}}
	got, err := Marshal(r, raw)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"name":"n","inner":{"a":""},"list":[{"a":"3","three":3},{"a":"1","one":1},{"a":"x"},{"a":"1","again":1}],` +
		`"when":"0001-01-01T00:00:00Z","Plain":0}`
	if string(got) != want {
		t.Errorf("Marshal:\n got %s\nwant %s", got, want)
	}
}

func TestUnknownNamesEveryFieldThisBuildDoesNotKnow(t *testing.T) {
	raw := json.RawMessage(`{"NAME":"n","inner":{"a":"x","deep":1},"list":[{"a":"1"},{"a":"2","lost":true}],"Skipped":"s","zeta":1}`)
	got := Unknown(rec{}, raw)
	want := []string{"Skipped", "inner.deep", "list[1].lost", "zeta"}
	if len(got) != len(want) {
		t.Fatalf("Unknown = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Unknown = %v, want %v", got, want)
		}
	}
	for _, r := range []json.RawMessage{nil, json.RawMessage(`[1]`), json.RawMessage(`{"name":"n","list":[{"a":"1"}]}`)} {
		if u := Unknown(rec{}, r); len(u) != 0 {
			t.Errorf("Unknown(%s) = %v, want none", r, u)
		}
	}
}
