// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package job

import (
	"bytes"
	"encoding/json"
	"testing"
)

// A record Load skips comes back from Decode as the file held it, and
// Encode writes it back; one named like a loaded job is dropped at load and
// never written beside it, and a job passed to Encode under a kept name
// wins over the kept record.
func TestDecodeAndEncodeKeepSkippedRecords(t *testing.T) {
	const skipped = `{"name":"later","dir":"/tmp","argv":["x"],"exe":"/bin/x","ask":"on-weekdays","key_id":"j-0000000c","new_field":[1,2]}`
	const shadow = `{"name":"notion","dir":"","ask":"never"}`
	valid := `{"name":"notion","dir":"/tmp","argv":["x"],"exe":"/bin/x","ask":"never"}`
	jobs, kept, err := Decode([]byte(`{"version":1,"jobs":[` + valid + `,` + skipped + `,` + shadow + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs["notion"] == nil || jobs["notion"].Exe != "/bin/x" {
		t.Fatalf("loaded %v, want the valid notion alone", jobs)
	}
	if len(kept) != 1 || kept[0].Name != "later" || string(kept[0].Raw) != skipped {
		t.Fatalf("kept %+v, want the later record verbatim and not the shadow", kept)
	}
	data, err := Encode(jobs, kept)
	if err != nil {
		t.Fatal(err)
	}
	var back struct{ Jobs []json.RawMessage }
	if err := json.Unmarshal(data, &back); err != nil || len(back.Jobs) != 2 {
		t.Fatalf("encoded %d records (%v), want 2", len(back.Jobs), err)
	}
	var compact bytes.Buffer
	_ = json.Compact(&compact, back.Jobs[0])
	if compact.String() != skipped {
		t.Fatalf("the kept record came back as %s, want %s", compact.String(), skipped)
	}

	jobs["later"] = &Job{Name: "later", Dir: "/tmp", Argv: []string{"y"}, Exe: "/bin/y", Ask: AskEachTime}
	data, err = Encode(jobs, kept)
	if err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(data, []byte(`"name": "later"`)); n != 1 || bytes.Contains(data, []byte("on-weekdays")) {
		t.Fatalf("a job under a kept name did not replace it:\n%s", data)
	}
}

// A job read from the file keeps every field this build does not know, at
// the top and inside a secret, through two saves, while the fields it knows
// are written as the job holds them now (finding 2).
func TestEncodeKeepsFieldsThisBuildDoesNotKnow(t *testing.T) {
	const rec = `{"name":"notion","dir":"/tmp","argv":["x"],"exe":"/bin/x","ask":"never","runs":1,` +
		`"from_a_newer_jit":{"k":[1,2]},"secrets":[{"var":"T","path":"n/t","device_wrapped_sha256":"d","secret_extra":"s"}],` +
		`"fingerprint":{"files":null,"fp_extra":true}}`
	data := []byte(`{"version":1,"jobs":[` + rec + `]}`)
	for save := 1; save <= 2; save++ {
		jobs, kept, err := Decode(data)
		if err != nil || len(jobs) != 1 {
			t.Fatalf("save %d: decoded %d jobs, %v", save, len(jobs), err)
		}
		jobs["notion"].Runs++
		if data, err = Encode(jobs, kept); err != nil {
			t.Fatal(err)
		}
		var f struct{ Jobs []map[string]any }
		if err := json.Unmarshal(data, &f); err != nil || len(f.Jobs) != 1 {
			t.Fatalf("save %d: %v\n%s", save, err, data)
		}
		got := f.Jobs[0]
		if got["runs"] != float64(1+save) {
			t.Errorf("save %d: runs = %v, want the job's own count", save, got["runs"])
		}
		if x, ok := got["from_a_newer_jit"].(map[string]any); !ok || len(x["k"].([]any)) != 2 {
			t.Errorf("save %d: the unknown top-level field did not survive:\n%s", save, data)
		}
		secs, _ := got["secrets"].([]any)
		if len(secs) != 1 || secs[0].(map[string]any)["secret_extra"] != "s" {
			t.Errorf("save %d: the unknown field in a secret did not survive:\n%s", save, data)
		}
		if fp, _ := got["fingerprint"].(map[string]any); fp["fp_extra"] != true {
			t.Errorf("save %d: the unknown field in the fingerprint did not survive:\n%s", save, data)
		}
	}
}
