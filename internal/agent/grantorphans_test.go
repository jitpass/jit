// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jitpass/jit/internal/job"
)

func (m *memMover) ListGrantKeyIDs() ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	seen := map[string]bool{}
	var out []string
	for _, store := range []map[string][]byte{m.kc, m.se} {
		for id := range store {
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	return out, nil
}

// orphanWorld is a service with one standing grant (g-00000001), one
// never-ask job (j-00000002) and keys for both, plus whatever else a test
// plants.
func orphanWorld(t *testing.T) (*Server, *memMover, string, string) {
	t.Helper()
	store := newMemMover()
	dir := t.TempDir()
	ledger, jobs := filepath.Join(dir, "grants.json"), filepath.Join(dir, "jobs.json")
	for _, id := range []string{"g-00000001", "j-00000002"} {
		if _, err := store.CreateWrap(id, GrantWrapKeychain); err != nil {
			t.Fatal(err)
		}
	}
	g := ledgerGrant{ID: "g-00000001", CreatedUnix: 1, Profiles: []GrantProfile{},
		Secrets: []ledgerSecret{{Path: "a/b", DeviceDigest: "d", GrantWrapped: "00", Wrap: GrantWrapKeychain}}}
	g.Anchor.ExecPath, g.Anchor.Name, g.Program.Name = "/Applications/Claude.app", "Claude", "node"
	data, _ := json.Marshal(ledgerFile{Version: ledgerVersion, Grants: []ledgerGrant{g}})
	if err := os.WriteFile(ledger, data, 0o600); err != nil {
		t.Fatal(err)
	}
	j := &job.Job{Name: "notion", Dir: "/tmp", Argv: []string{"x"}, Exe: "/bin/x", Ask: job.AskNever, KeyID: "j-00000002",
		Secrets: []job.Secret{{Var: "T", Path: "n/t", DeviceDigest: "d", KeyWrapped: "00", Wrap: GrantWrapKeychain}}}
	if err := saveJobFile(jobs, map[string]*job.Job{j.Name: j}); err != nil {
		t.Fatal(err)
	}
	s := &Server{GrantKeys: store}
	return s, store, ledger, jobs
}

func load(t *testing.T, s *Server, ledger, jobs string) {
	t.Helper()
	_, _ = s.SetGrantLedger(ledger)
	_, _ = s.SetJobStore(jobs)
}

func TestOrphanKeysAreDeletedAndOnlyThose(t *testing.T) {
	s, store, ledger, jobs := orphanWorld(t)
	for _, id := range []string{"g-deadbeef", "j-0badf00d"} {
		_, _ = store.CreateWrap(id, GrantWrapEnclave)
	}
	_, _ = store.CreateWrap("someone-else", GrantWrapKeychain) // not an id jit mints
	load(t, s, ledger, jobs)
	deleted, errs := s.DeleteOrphanGrantKeys()
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	if len(deleted) != 2 || deleted[0] != "g-deadbeef" || deleted[1] != "j-0badf00d" {
		t.Fatalf("deleted %v, want exactly the two unused minted ids", deleted)
	}
	for _, id := range []string{"g-00000001", "j-00000002"} {
		if !store.has(GrantWrapKeychain, id) {
			t.Errorf("deleted %s, which a grant or job still names", id)
		}
	}
	if !store.has(GrantWrapKeychain, "someone-else") {
		t.Error("deleted a key whose id jit never mints")
	}
}

// A ledger that failed to load looks like "no grants": deleting then would
// take every grant's key. Nothing may be deleted.
func TestOrphanCleanupSkipsWhenTheLedgerDidNotLoad(t *testing.T) {
	s, store, ledger, jobs := orphanWorld(t)
	if err := os.WriteFile(ledger, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	load(t, s, ledger, jobs)
	deleted, errs := s.DeleteOrphanGrantKeys()
	if len(deleted) != 0 || len(errs) != 1 || !errors.Is(errs[0], errCleanupSkipped) {
		t.Fatalf("deleted %v, errs %v; want nothing deleted and a skip", deleted, errs)
	}
	if !store.has(GrantWrapKeychain, "g-00000001") {
		t.Fatal("a grant's key was deleted while its ledger was unreadable")
	}
}

func TestOrphanCleanupSkipsWhenTheJobListDidNotLoad(t *testing.T) {
	s, store, ledger, jobs := orphanWorld(t)
	if err := os.WriteFile(jobs, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	load(t, s, ledger, jobs)
	deleted, errs := s.DeleteOrphanGrantKeys()
	if len(deleted) != 0 || len(errs) != 1 || !errors.Is(errs[0], errCleanupSkipped) {
		t.Fatalf("deleted %v, errs %v; want nothing deleted and a skip", deleted, errs)
	}
	if !store.has(GrantWrapKeychain, "j-00000002") {
		t.Fatal("a job's key was deleted while the job list was unreadable")
	}
}

// A record a loader skipped still names its key. The ledger's grant with no
// anchor (SetGrantLedger drops it), a job whose name this build rejects and
// one whose ask value it does not know (job.Load skips both, as from a newer
// jit): none is in memory, and every one's key must survive. Both files are
// saved before the cleanup runs, as a move does at a real start, by a save
// that drops them (as every save did before they were kept verbatim): the
// names read as the files stood at load must keep the keys on their own.
func TestOrphanCleanupKeepsKeysOfRecordsTheLoadersSkipped(t *testing.T) {
	s, store, ledger, jobs := orphanWorld(t)
	raw, _ := os.ReadFile(ledger)
	var lf ledgerFile
	if err := json.Unmarshal(raw, &lf); err != nil {
		t.Fatal(err)
	}
	dropped := ledgerGrant{ID: "g-0000000a", CreatedUnix: 2, Profiles: []GrantProfile{},
		Secrets: []ledgerSecret{{Path: "a/c", DeviceDigest: "d", GrantWrapped: "00", Wrap: GrantWrapKeychain}}}
	dropped.Program.Name = "node" // no anchor
	lf.Grants = append(lf.Grants, dropped)
	raw, _ = json.Marshal(lf)
	if err := os.WriteFile(ledger, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	all, err := job.Load(jobs)
	if err != nil {
		t.Fatal(err)
	}
	all["Bad Name!"] = &job.Job{Name: "Bad Name!", Dir: "/tmp", Argv: []string{"x"}, Exe: "/bin/x", Ask: job.AskNever, KeyID: "j-0000000b",
		Secrets: []job.Secret{{Var: "T", Path: "n/t", DeviceDigest: "d", KeyWrapped: "00", Wrap: GrantWrapKeychain}}}
	all["later"] = &job.Job{Name: "later", Dir: "/tmp", Argv: []string{"x"}, Exe: "/bin/x", Ask: job.Ask("on-weekdays"), KeyID: "j-0000000c",
		Secrets: []job.Secret{{Var: "T", Path: "n/t", DeviceDigest: "d", KeyWrapped: "00", Wrap: GrantWrapKeychain}}}
	if err := saveJobFile(jobs, all); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"g-0000000a", "j-0000000b", "j-0000000c"} {
		if _, err := store.CreateWrap(id, GrantWrapKeychain); err != nil {
			t.Fatal(err)
		}
	}
	load(t, s, ledger, jobs)
	s.jobMu.Lock()
	n := len(s.jobs)
	s.jobMu.Unlock()
	if len(s.standing) != 1 || n != 1 {
		t.Fatalf("setup: loaded %d grants and %d jobs, want the loaders to skip all but one of each", len(s.standing), n)
	}
	// A save before the cleanup (a move's, at a real start) now writes the
	// skipped records back (TestLedgerKeepsGrantsItCouldNotLoad and
	// TestJobListKeepsJobsItCouldNotLoad pin that). Model one that does
	// not, as every save did before: the names read at load must still
	// keep the keys on their own.
	s.grantMu.Lock()
	s.ledgerKept = nil
	s.grantMu.Unlock()
	s.jobMu.Lock()
	s.jobKept = nil
	s.jobMu.Unlock()
	if err := s.saveLedger(); err != nil {
		t.Fatal(err)
	}
	s.jobMu.Lock()
	err = s.saveJobsLocked()
	s.jobMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{ledger, jobs} {
		b, _ := os.ReadFile(f)
		if bytes.Contains(b, []byte("g-0000000a")) || bytes.Contains(b, []byte("j-0000000b")) || bytes.Contains(b, []byte("j-0000000c")) {
			t.Fatalf("setup: %s still names a skipped record after the save", f)
		}
	}
	deleted, errs := s.DeleteOrphanGrantKeys()
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	for _, id := range []string{"g-0000000a", "j-0000000b", "j-0000000c"} {
		if !store.has(GrantWrapKeychain, id) {
			t.Errorf("deleted %s, which the files name in a record the loaders skipped (deleted %v)", id, deleted)
		}
	}
}

// The names are read raw at load; a job list that loaded but could not be
// read raw leaves no names, and the cleanup does nothing.
func TestOrphanCleanupSkipsWithoutRawNames(t *testing.T) {
	s, store, ledger, jobs := orphanWorld(t)
	_, _ = store.CreateWrap("g-deadbeef", GrantWrapKeychain)
	load(t, s, ledger, jobs)
	s.jobMu.Lock()
	s.jobNames = nil
	s.jobMu.Unlock()
	deleted, errs := s.DeleteOrphanGrantKeys()
	if len(deleted) != 0 || len(errs) != 1 || !errors.Is(errs[0], errCleanupSkipped) {
		t.Fatalf("deleted %v, errs %v; want nothing deleted and a skip", deleted, errs)
	}
}
