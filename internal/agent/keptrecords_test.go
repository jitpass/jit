// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package agent

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/jitpass/jit/internal/job"
)

// records reads a state file's record array (key "grants" or "jobs") as
// generic JSON, one value per record.
func records(t *testing.T, path, key string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f map[string]json.RawMessage
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	if err := json.Unmarshal(f[key], &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func generic(t *testing.T, raw string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// withField counts the records whose field equals value, and returns the
// last one.
func withField(recs []map[string]any, field, value string) (int, map[string]any) {
	n, last := 0, map[string]any(nil)
	for _, r := range recs {
		if r[field] == value {
			n, last = n+1, r
		}
	}
	return n, last
}

// A ledger grant SetGrantLedger drops (here, no anchor, and a field this
// build does not know) is written back unchanged by every save, never
// served or listed; its key id stays named in the file, so the start-up
// cleanup keeps its key at every later start too, not only the first.
// A dropped record with the id of a loaded grant is not kept: the loaded
// one wins, and the file never holds both.
func TestLedgerKeepsGrantsItCouldNotLoad(t *testing.T) {
	const dropped = `{"id":"g-0000000a","created_unix":2,"anchor":{"exec_path":"","name":""},"program":{"name":"node"},"profiles":[],"secrets":[{"path":"a/c","device_wrapped_sha256":"d","grant_wrapped":"00","wrap":"aead-v1"}],"from_a_newer_jit":{"x":1}}`
	const shadow = `{"id":"g-00000001","created_unix":3,"anchor":{"exec_path":"","name":""},"program":{"name":"shadow"},"profiles":[],"secrets":[]}`
	s, store, ledger, jobs := orphanWorld(t)
	raw, _ := os.ReadFile(ledger)
	var f rawLedgerFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	f.Grants = append(f.Grants, json.RawMessage(dropped), json.RawMessage(shadow))
	raw, _ = json.Marshal(f)
	if err := os.WriteFile(ledger, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateWrap("g-0000000a", GrantWrapKeychain); err != nil {
		t.Fatal(err)
	}

	for start := 1; start <= 2; start++ {
		s = &Server{GrantKeys: store}
		load(t, s, ledger, jobs)
		if len(s.standing) != 1 || s.standing["g-00000001"] == nil {
			t.Fatalf("start %d: loaded %d grants, want only g-00000001", start, len(s.standing))
		}
		for _, st := range s.standingStatuses() {
			if st.ID != "g-00000001" {
				t.Errorf("start %d: the list shows %s, a record this build could not load", start, st.ID)
			}
		}
		if err := s.saveLedger(); err != nil {
			t.Fatal(err)
		}
		recs := records(t, ledger, "grants")
		n, got := withField(recs, "id", "g-0000000a")
		if n != 1 || !reflect.DeepEqual(got, generic(t, dropped)) {
			t.Fatalf("start %d: the dropped grant was not written back unchanged: %d copies, %v", start, n, got)
		}
		if n, got := withField(recs, "id", "g-00000001"); n != 1 || got["program"].(map[string]any)["name"] != "node" {
			t.Fatalf("start %d: g-00000001 is in the ledger %d times (last %v); want the loaded one alone", start, n, got)
		}
		if deleted, errs := s.DeleteOrphanGrantKeys(); len(errs) != 0 || !store.has(GrantWrapKeychain, "g-0000000a") {
			t.Fatalf("start %d: the dropped grant's key was deleted (deleted %v, errs %v)", start, deleted, errs)
		}
	}

	// A grant made later under a kept record's id wins, for good.
	s.grantMu.Lock()
	s.standing["g-0000000a"] = &standingGrant{id: "g-0000000a", anchorPath: "/Applications/Claude.app", name: "fresh", secrets: map[string]standingSecret{}}
	s.grantMu.Unlock()
	if err := s.saveLedger(); err != nil {
		t.Fatal(err)
	}
	s.grantMu.Lock()
	delete(s.standing, "g-0000000a")
	s.grantMu.Unlock()
	if err := s.saveLedger(); err != nil {
		t.Fatal(err)
	}
	if n, _ := withField(records(t, ledger, "grants"), "id", "g-0000000a"); n != 0 {
		t.Fatalf("the kept record came back after the grant that replaced it was revoked (%d copies)", n)
	}
}

// The same for jobs.json: a job job.Load skips (a name this build rejects,
// an ask value from a newer jit) is written back unchanged by every save,
// never listed or run, and its key survives every start. A skipped record
// named like a loaded job is not kept.
func TestJobListKeepsJobsItCouldNotLoad(t *testing.T) {
	const badName = `{"name":"Bad Name!","dir":"/tmp","argv":["x"],"exe":"/bin/x","ask":"never","key_id":"j-0000000b","secrets":[],"from_a_newer_jit":true}`
	const later = `{"name":"later","dir":"/tmp","argv":["x"],"exe":"/bin/x","ask":"on-weekdays","key_id":"j-0000000c","secrets":[]}`
	const shadow = `{"name":"notion","dir":"","argv":[],"exe":"","ask":"never","key_id":"j-0000000d"}`
	s, store, ledger, jobs := orphanWorld(t)
	raw, _ := os.ReadFile(jobs)
	var f struct {
		Version int               `json:"version"`
		Jobs    []json.RawMessage `json:"jobs"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	f.Jobs = append(f.Jobs, json.RawMessage(badName), json.RawMessage(later), json.RawMessage(shadow))
	raw, _ = json.Marshal(f)
	if err := os.WriteFile(jobs, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"j-0000000b", "j-0000000c"} {
		if _, err := store.CreateWrap(id, GrantWrapKeychain); err != nil {
			t.Fatal(err)
		}
	}

	for start := 1; start <= 2; start++ {
		s = &Server{GrantKeys: store}
		load(t, s, ledger, jobs)
		list := s.listJobs(false)
		if len(list) != 1 || list[0].Name != "notion" {
			t.Fatalf("start %d: the list shows %v, want notion alone", start, list)
		}
		if resp := s.removeJob("later", nil); resp.OK {
			t.Fatalf("start %d: a job this build could not load was removable, so usable", start)
		}
		s.jobMu.Lock()
		err := s.saveJobsLocked()
		s.jobMu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		recs := records(t, jobs, "jobs")
		for _, want := range []string{badName, later} {
			w := generic(t, want)
			n, got := withField(recs, "name", w["name"].(string))
			if n != 1 || !reflect.DeepEqual(got, w) {
				t.Fatalf("start %d: %q was not written back unchanged: %d copies, %v", start, w["name"], n, got)
			}
		}
		if n, got := withField(recs, "name", "notion"); n != 1 || got["key_id"] != "j-00000002" {
			t.Fatalf("start %d: notion is in the list %d times (last %v); want the loaded one alone", start, n, got)
		}
		if deleted, errs := s.DeleteOrphanGrantKeys(); len(errs) != 0 || !store.has(GrantWrapKeychain, "j-0000000b") || !store.has(GrantWrapKeychain, "j-0000000c") {
			t.Fatalf("start %d: a skipped job's key was deleted (deleted %v, errs %v)", start, deleted, errs)
		}
	}

	// A job approved later under a kept record's name wins, for good.
	s.jobMu.Lock()
	s.jobs["later"] = &job.Job{Name: "later", Dir: "/tmp", Argv: []string{"y"}, Exe: "/bin/y", Ask: job.AskEachTime}
	err := s.saveJobsLocked()
	s.jobMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if n, got := withField(records(t, jobs, "jobs"), "name", "later"); n != 1 || got["ask"] != "each-time" {
		t.Fatalf("later is in the list %d times (last %v); want the approved one alone", n, got)
	}
	if resp := s.removeJob("later", nil); !resp.OK {
		t.Fatal(resp.Error)
	}
	if n, _ := withField(records(t, jobs, "jobs"), "name", "later"); n != 0 {
		t.Fatalf("the kept record came back after the job that replaced it was removed (%d copies)", n)
	}
}
