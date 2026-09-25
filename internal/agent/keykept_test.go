// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/job"
)

// noEnclave is the CLI's store as a jit without the Secure Enclave
// entitlement sees it: enclave keys exist (a jit that could reach them made
// them) but can be neither listed nor deleted from here. Delete clears the
// keychain half and says the enclave was unreachable, as the CLI's does.
type noEnclave struct{ *memMover }

func (n noEnclave) Delete(id string) error {
	return errors.Join(ErrGrantKeyUnreachable, n.DeleteWrap(id, GrantWrapKeychain))
}

func (n noEnclave) ListGrantKeyIDs() ([]string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []string
	for id := range n.kc {
		out = append(out, id)
	}
	return out, nil
}

// keptWorld writes a ledger holding one grant, g-00000001, and a job list
// holding one never-ask job, j-00000002, both sealed for keys of kind wrap,
// and makes those keys.
func keptWorld(t *testing.T, store *memMover, wrap string) (ledger, jobs string) {
	t.Helper()
	dir := t.TempDir()
	ledger, jobs = filepath.Join(dir, "grants.json"), filepath.Join(dir, "jobs.json")
	for _, id := range []string{"g-00000001", "j-00000002"} {
		if _, err := store.CreateWrap(id, wrap); err != nil {
			t.Fatal(err)
		}
	}
	g := ledgerGrant{ID: "g-00000001", CreatedUnix: 1, Profiles: []GrantProfile{},
		Secrets: []ledgerSecret{{Path: "a/b", Class: "env", DeviceDigest: "d", GrantWrapped: "00", Wrap: wrap}}}
	g.Anchor.ExecPath, g.Anchor.Name, g.Program.Name = "/Applications/Claude.app", "Claude", "node"
	data, _ := json.Marshal(ledgerFile{Version: ledgerVersion, Grants: []ledgerGrant{g}})
	if err := os.WriteFile(ledger, data, 0o600); err != nil {
		t.Fatal(err)
	}
	j := &job.Job{Name: "notion", Dir: "/tmp", Argv: []string{"x"}, Exe: "/bin/x", Ask: job.AskNever, KeyID: "j-00000002",
		Secrets: []job.Secret{{Var: "T", Path: "n/t", Class: "env", DeviceDigest: "d", KeyWrapped: "00", Wrap: wrap}}}
	if err := saveJobFile(jobs, map[string]*job.Job{j.Name: j}); err != nil {
		t.Fatal(err)
	}
	return ledger, jobs
}

func lastCause(t *testing.T, s *Server) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.events) == 0 {
		t.Fatal("no event was recorded")
	}
	return s.events[len(s.events)-1].Cause
}

// Finding 5: a jit that cannot reach the Secure Enclave revokes a grant and
// removes a job sealed for enclave keys. Both still end, nothing claims the
// key was deleted (the response and the audit trail say it was kept), and
// the next start of a service that can reach the enclave deletes both keys,
// because nothing names them any more.
func TestRevokeAndRemoveSayAnUnreachableKeyWasKept(t *testing.T) {
	store := newMemMover()
	ledger, jobs := keptWorld(t, store, GrantWrapEnclave)
	s := &Server{GrantKeys: noEnclave{store}}
	load(t, s, ledger, jobs)

	resp := s.revokeGrant("g-00000001", nil)
	if !resp.OK {
		t.Fatalf("the revoke failed: %s", resp.Error)
	}
	if resp.KeyNote != keyKeptNote {
		t.Errorf("revoke's key note = %q, want %q", resp.KeyNote, keyKeptNote)
	}
	if c := lastCause(t, s); !strings.Contains(c, keyKeptNote) {
		t.Errorf("revoke's audit cause %q does not say the key was kept", c)
	}
	s.grantMu.Lock()
	_, still := s.standing["g-00000001"]
	s.grantMu.Unlock()
	if still {
		t.Error("the grant survived its revoke")
	}

	resp = s.removeJob("notion", nil)
	if !resp.OK {
		t.Fatalf("the remove failed: %s", resp.Error)
	}
	if resp.KeyNote != keyKeptNote {
		t.Errorf("remove's key note = %q, want %q", resp.KeyNote, keyKeptNote)
	}
	c := lastCause(t, s)
	if strings.Contains(c, "deleted") || !strings.Contains(c, keyKeptNote) {
		t.Errorf("remove's audit cause %q: want the kept-key note, and no claim of a delete", c)
	}

	for _, id := range []string{"g-00000001", "j-00000002"} {
		if !store.has(GrantWrapEnclave, id) {
			t.Fatalf("setup: the unreachable enclave key %s was deleted", id)
		}
	}

	// The next start, by a jit that can reach the enclave.
	s2 := &Server{GrantKeys: store}
	load(t, s2, ledger, jobs)
	deleted, errs := s2.DeleteOrphanGrantKeys()
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	for _, id := range []string{"g-00000001", "j-00000002"} {
		if store.has(GrantWrapEnclave, id) {
			t.Errorf("the next start kept %s's enclave key (deleted %v)", id, deleted)
		}
	}
}

// The other side: a grant and a job sealed for the keychain lose that key,
// and an unreachable enclave (which a jit without the entitlement always
// is) is not news. They say deleted, as before.
func TestRevokeAndRemoveOfKeychainRecordsSayNothingExtra(t *testing.T) {
	store := newMemMover()
	ledger, jobs := keptWorld(t, store, GrantWrapKeychain)
	s := &Server{GrantKeys: noEnclave{store}}
	load(t, s, ledger, jobs)
	if resp := s.revokeGrant("g-00000001", nil); !resp.OK || resp.KeyNote != "" {
		t.Errorf("revoke: ok %v, note %q; want ok and no note", resp.OK, resp.KeyNote)
	}
	if resp := s.removeJob("notion", nil); !resp.OK || resp.KeyNote != "" {
		t.Errorf("remove: ok %v, note %q; want ok and no note", resp.OK, resp.KeyNote)
	}
	if c := lastCause(t, s); c != "removed, its key deleted" {
		t.Errorf("remove's audit cause = %q", c)
	}
	for _, id := range []string{"g-00000001", "j-00000002"} {
		if store.has(GrantWrapKeychain, id) {
			t.Errorf("%s's keychain key survived", id)
		}
	}
}

// The start-up cleanup in a jit that cannot reach the enclave deletes the
// keychain orphans it can see, and does not count the unreachable half as a
// failure.
func TestOrphanCleanupWithAnUnreachableEnclave(t *testing.T) {
	s, store, ledger, jobs := orphanWorld(t)
	_, _ = store.CreateWrap("g-deadbeef", GrantWrapKeychain)
	s.GrantKeys = noEnclave{store}
	load(t, s, ledger, jobs)
	deleted, errs := s.DeleteOrphanGrantKeys()
	if len(errs) != 0 || len(deleted) != 1 || deleted[0] != "g-deadbeef" {
		t.Fatalf("deleted %v, errs %v; want g-deadbeef and no error", deleted, errs)
	}
}

func TestWithoutUnreachable(t *testing.T) {
	boom := errors.New("boom")
	for _, c := range []struct {
		in   error
		want error
	}{
		{nil, nil},
		{ErrGrantKeyUnreachable, nil},
		{errors.Join(ErrGrantKeyUnreachable, nil), nil},
		{errors.Join(ErrGrantKeyUnreachable, boom), boom},
		{boom, boom},
	} {
		got := withoutUnreachable(c.in)
		if (got == nil) != (c.want == nil) || (got != nil && !errors.Is(got, c.want)) || errors.Is(got, ErrGrantKeyUnreachable) {
			t.Errorf("withoutUnreachable(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

// A revoke whose key delete really failed (not an enclave out of
// reach) says so, in the response and in the trail, as a remove does; it
// used to drop the error and let the caller believe the key was gone.
func TestRevokeAndRemoveReportAFailedKeyDelete(t *testing.T) {
	store := newMemMover()
	ledger, jobs := keptWorld(t, store, GrantWrapKeychain)
	s := &Server{GrantKeys: store}
	load(t, s, ledger, jobs)
	store.mu.Lock()
	store.failDelete = errors.New("keychain says no")
	store.mu.Unlock()

	resp := s.revokeGrant("g-00000001", nil)
	if !resp.OK {
		t.Fatalf("the revoke failed: %s", resp.Error)
	}
	if !strings.Contains(resp.KeyNote, "keychain says no") {
		t.Errorf("revoke's key note = %q, want the delete's failure", resp.KeyNote)
	}
	if c := lastCause(t, s); !strings.Contains(c, "keychain says no") {
		t.Errorf("revoke's audit cause %q does not say the delete failed", c)
	}

	resp = s.removeJob("notion", nil)
	if !resp.OK {
		t.Fatalf("the remove failed: %s", resp.Error)
	}
	if !strings.Contains(resp.KeyNote, "keychain says no") {
		t.Errorf("remove's key note = %q, want the delete's failure", resp.KeyNote)
	}
	if c := lastCause(t, s); !strings.Contains(c, "keychain says no") {
		t.Errorf("remove's audit cause %q does not say the delete failed", c)
	}
}
