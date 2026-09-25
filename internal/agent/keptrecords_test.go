// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package agent

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/atomicfile"
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

	// A grant under a kept record's id (injected here: ids are random,
	// and Create refuses an id that still has a key) hides the kept record
	// only while it lives, and a save that fails meanwhile changes nothing
	// in memory, so the rollback leaves the kept record to the next
	// successful save.
	s.grantMu.Lock()
	s.standing["g-0000000a"] = &standingGrant{id: "g-0000000a", anchorPath: "/Applications/Claude.app", name: "fresh", secrets: map[string]standingSecret{}}
	s.grantMu.Unlock()
	s.stateWriter = func(string, []byte) error { return errors.New("disk full") }
	if err := s.saveLedger(); err == nil {
		t.Fatal("the failing write did not fail the save")
	}
	s.stateWriter = nil
	s.grantMu.Lock()
	delete(s.standing, "g-0000000a") // the caller's rollback
	s.grantMu.Unlock()
	if err := s.saveLedger(); err != nil {
		t.Fatal(err)
	}
	if n, got := withField(records(t, ledger, "grants"), "id", "g-0000000a"); n != 1 || !reflect.DeepEqual(got, generic(t, dropped)) {
		t.Fatalf("a failed save lost the kept record: %d copies, %v", n, got)
	}
}

// The same for jobs.json: a job job.Decode skips (a name this build rejects,
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

	// A job under a kept record's name (injected here: approval refuses
	// one, TestApprovalRefusesTheNameOfAJobItCannotRead) hides the kept
	// record only while it lives, and a save that fails meanwhile
	// changes nothing in memory, so the rollback leaves the kept record to
	// the next successful save.
	s.jobMu.Lock()
	s.jobs["later"] = &job.Job{Name: "later", Dir: "/tmp", Argv: []string{"y"}, Exe: "/bin/y", Ask: job.AskEachTime}
	s.stateWriter = func(string, []byte) error { return errors.New("disk full") }
	if err := s.saveJobsLocked(); err == nil {
		t.Fatal("the failing write did not fail the save")
	}
	s.stateWriter = nil
	delete(s.jobs, "later") // the caller's rollback
	err := s.saveJobsLocked()
	s.jobMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if n, got := withField(records(t, jobs, "jobs"), "name", "later"); n != 1 || !reflect.DeepEqual(got, generic(t, later)) {
		t.Fatalf("a failed save lost the kept record: %d copies, %v", n, got)
	}
}

// saveJobFile writes jobs as jobs.json holds them, for a test's setup.
func saveJobFile(path string, jobs map[string]*job.Job) error {
	data, err := job.Encode(jobs, nil)
	if err != nil {
		return err
	}
	return atomicfile.WriteFile(path, data)
}

// Approving a job under the name of a record this build cannot
// read would replace it unseen and leave its key named by nothing. Both
// approval and its preview refuse, naming the conflict, before any prompt,
// and the record stays in the file.
func TestApprovalRefusesTheNameOfAJobItCannotRead(t *testing.T) {
	r := newJobRig(t)
	const kept = `{"name":"notion-guests","dir":"/tmp","argv":["x"],"exe":"/bin/x","ask":"on-weekdays","key_id":"j-0000000c","secrets":[]}`
	if err := os.WriteFile(r.storeAt, []byte(`{"version":1,"jobs":[`+kept+`]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.s.SetJobStore(r.storeAt); err != nil {
		t.Fatal(err)
	}
	spec := r.spec()
	spec.Replace = true
	_, err := r.c.JobAllow("notion-guests", spec)
	if err == nil || !strings.Contains(err.Error(), "a job named notion-guests exists that this version of jit can't read") {
		t.Fatalf("JobAllow over an unreadable job: %v; want the conflict named", err)
	}
	if p, err := r.c.JobPreview("notion-guests", spec); err != nil || !strings.Contains(p.Refusal, "can't read") {
		t.Fatalf("JobPreview over an unreadable job: refusal %q, %v; want the conflict named", p.Refusal, err)
	}
	if r.prompts() != 0 {
		t.Errorf("the refused approval prompted %d times", r.prompts())
	}
	if n, got := withField(records(t, r.storeAt, "jobs"), "name", "notion-guests"); n != 1 || !reflect.DeepEqual(got, generic(t, kept)) {
		t.Fatalf("the unreadable job did not survive: %d copies, %v", n, got)
	}
	if _, err := r.c.JobAllow("notion-guests-2", r.spec()); err != nil {
		t.Fatalf("another name was refused too: %v", err)
	}
}

// Every save writes back what this build does not know. The
// ledger holds a grant with a field of its own, a field inside its anchor,
// a known entry with a field of its own, and an entry whose sealed bytes
// are not hex; jobs.json a job with a field of its own. Through two starts
// and saves, and a key move in between, all of it survives, and the bad
// entry is kept verbatim. The grant keeps its keychain key after the move,
// since nothing here knows which kind the bad entry needs.
func TestSavesKeepWhatThisBuildDoesNotKnow(t *testing.T) {
	store := newMemMover()
	dir := t.TempDir()
	ledger, jobs := filepath.Join(dir, "grants.json"), filepath.Join(dir, "jobs.json")
	key, err := store.CreateWrap("g-00000001", GrantWrapKeychain)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := key.Seal(make([]byte, 32), "env")
	if err != nil {
		t.Fatal(err)
	}
	const bad = `{"path":"a/x","device_wrapped_sha256":"d9","grant_wrapped":"zz","wrap":"aead-v1","bad_extra":2}`
	grant := `{"id":"g-00000001","created_unix":1,"anchor":{"exec_path":"/Applications/Claude.app","name":"Claude","anchor_extra":"a"},` +
		`"program":{"name":"node"},"profiles":[],"grant_extra":{"n":1},"secrets":[` +
		`{"path":"a/b","class":"env","device_wrapped_sha256":"d1","grant_wrapped":"` + hex.EncodeToString(sealed) + `","wrap":"aead-v1","secret_extra":"s"},` +
		bad + `]}`
	if err := os.WriteFile(ledger, []byte(`{"version":1,"grants":[`+grant+`]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	const jobRec = `{"name":"notion","dir":"/tmp","argv":["x"],"exe":"/bin/x","ask":"each-time","job_extra":[1]}`
	if err := os.WriteFile(jobs, []byte(`{"version":1,"jobs":[`+jobRec+`]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	check := func(when string) {
		t.Helper()
		recs := records(t, ledger, "grants")
		if len(recs) != 1 {
			t.Fatalf("%s: %d grants in the ledger, want 1", when, len(recs))
		}
		g := recs[0]
		if x, _ := g["grant_extra"].(map[string]any); x["n"] != float64(1) {
			t.Errorf("%s: the grant's unknown field is gone: %v", when, g)
		}
		if a, _ := g["anchor"].(map[string]any); a["anchor_extra"] != "a" || a["name"] != "Claude" {
			t.Errorf("%s: the anchor's unknown field is gone: %v", when, g["anchor"])
		}
		secs, _ := g["secrets"].([]any)
		var known, badSeen map[string]any
		for _, e := range secs {
			m := e.(map[string]any)
			switch m["path"] {
			case "a/b":
				known = m
			case "a/x":
				badSeen = m
			}
		}
		if known == nil || known["secret_extra"] != "s" {
			t.Errorf("%s: the entry's unknown field is gone: %v", when, secs)
		}
		if badSeen == nil || !mapsEqual(badSeen, generic(t, bad)) {
			t.Errorf("%s: the entry with bad sealed bytes did not come back verbatim: %v", when, badSeen)
		}
		jrecs := records(t, jobs, "jobs")
		if len(jrecs) != 1 || jrecs[0]["job_extra"] == nil {
			t.Errorf("%s: the job's unknown field is gone: %v", when, jrecs)
		}
	}

	for start := 1; start <= 2; start++ {
		s := &Server{GrantKeys: store}
		load(t, s, ledger, jobs)
		if got := len(s.standing["g-00000001"].secrets); got != 1 {
			t.Fatalf("start %d: serving %d entries, want the good one alone", start, got)
		}
		if start == 2 {
			store.mu.Lock()
			store.target = GrantWrapEnclave
			store.mu.Unlock()
			if moved, errs := s.MoveGrantKeys(); moved != 1 || len(errs) != 0 {
				t.Fatalf("move: moved %d, errs %v", moved, errs)
			}
			check("after the move")
			if !store.has(GrantWrapKeychain, "g-00000001") {
				t.Error("the move deleted the keychain key an unread entry may need")
			}
		}
		if err := s.saveLedger(); err != nil {
			t.Fatal(err)
		}
		s.jobMu.Lock()
		err := s.saveJobsLocked()
		s.jobMu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		check("after save " + string(rune('0'+start)))
	}
}

func mapsEqual(a, b map[string]any) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
