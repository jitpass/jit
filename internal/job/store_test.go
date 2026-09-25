// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package job

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// A record Load skips comes back from LoadKeeping as the file held it, and
// Encode writes it back; one named like a loaded job is dropped at load and
// never written beside it, and a job passed to Encode under a kept name
// wins over the kept record.
func TestLoadKeepingAndEncodeKeepSkippedRecords(t *testing.T) {
	const skipped = `{"name":"later","dir":"/tmp","argv":["x"],"exe":"/bin/x","ask":"on-weekdays","key_id":"j-0000000c","new_field":[1,2]}`
	const shadow = `{"name":"notion","dir":"","ask":"never"}`
	valid := `{"name":"notion","dir":"/tmp","argv":["x"],"exe":"/bin/x","ask":"never"}`
	path := filepath.Join(t.TempDir(), "jobs.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"jobs":[`+valid+`,`+skipped+`,`+shadow+`]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	jobs, kept, err := LoadKeeping(path)
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
