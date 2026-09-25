// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package agent

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/job"
)

// memMover is a GrantKeyStore that holds both kinds of key in memory, like
// the CLI's keychain + enclave store, and can be told to fail.
type memMover struct {
	mu         sync.Mutex
	kc, se     map[string][]byte
	target     string
	failCreate error
	failDelete error
	// failSeal makes every key CreateWrap hands out refuse to seal: a move
	// that got its new key and then could not re-seal with it.
	failSeal error
}

// sealFails is a key whose Seal always fails, reporting the wrap of the key
// it wraps.
type sealFails struct {
	GrantKey
	err error
}

func (k sealFails) Seal([]byte, string) ([]byte, error) { return nil, k.err }
func (k sealFails) Wrap() string                        { return keyWrap(k.GrantKey) }

func newMemMover() *memMover {
	return &memMover{kc: map[string][]byte{}, se: map[string][]byte{}, target: GrantWrapKeychain}
}

func (m *memMover) of(wrap string) map[string][]byte {
	if wrap == GrantWrapEnclave {
		return m.se
	}
	return m.kc
}

func handOut(wrap string, k []byte) GrantKey {
	key := memGrantKey{key: append([]byte(nil), k...)}
	if wrap == GrantWrapEnclave {
		return &memEnclaveKey{key}
	}
	return &key
}

func (m *memMover) TargetWrap() string { m.mu.Lock(); defer m.mu.Unlock(); return m.target }

func (m *memMover) CreateWrap(id, wrap string) (GrantKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failCreate != nil {
		return nil, m.failCreate
	}
	k, ok := m.of(wrap)[id]
	if !ok {
		k = make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			return nil, err
		}
		m.of(wrap)[id] = k
	}
	if m.failSeal != nil {
		return sealFails{handOut(wrap, k), m.failSeal}, nil
	}
	return handOut(wrap, k), nil
}

func (m *memMover) LoadWrap(id, wrap string) (GrantKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.of(wrap)[id]
	if !ok {
		return nil, os.ErrNotExist
	}
	return handOut(wrap, k), nil
}

func (m *memMover) DeleteWrap(id, wrap string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failDelete != nil {
		return m.failDelete
	}
	delete(m.of(wrap), id)
	return nil
}

// The GrantKeyStore half, as the CLI's store behaves.
func (m *memMover) Create(id string) (GrantKey, error) {
	m.mu.Lock()
	w := m.target
	if _, dup := m.of(w)[id]; dup {
		m.mu.Unlock()
		return nil, os.ErrExist
	}
	m.mu.Unlock()
	return m.CreateWrap(id, w)
}

func (m *memMover) Load(id string) (GrantKey, error) {
	if k, err := m.LoadWrap(id, GrantWrapEnclave); err == nil {
		return k, nil
	}
	return m.LoadWrap(id, GrantWrapKeychain)
}

func (m *memMover) Delete(id string) error {
	return errors.Join(m.DeleteWrap(id, GrantWrapEnclave), m.DeleteWrap(id, GrantWrapKeychain))
}

func (m *memMover) has(wrap, id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.of(wrap)[id]
	return ok
}

// moverServer is standingTestServer for any GrantKeyStore.
func moverServer(t *testing.T, calls *int32, store GrantKeyStore, ledger string) (*Server, string, func()) {
	t.Helper()
	return startTestServerWith(t, time.Minute, calls, func(s *Server) {
		s.GrantKeys = store
		if _, err := s.SetGrantLedger(ledger); err != nil {
			t.Fatalf("SetGrantLedger: %v", err)
		}
	})
}

func ledgerWraps(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f ledgerFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, g := range f.Grants {
		for _, s := range g.Secrets {
			out = append(out, s.Wrap)
		}
	}
	return out
}

// A standing grant made on a keychain vault moves into the enclave at the
// next start after the vault did: re-sealed, the ledger rewritten, the old
// key deleted, and it serves after another restart with no prompt.
func TestMoveGrantKeysMovesAStandingGrant(t *testing.T) {
	var calls int32
	store := newMemMover()
	ledger := filepath.Join(t.TempDir(), "grants.json")
	s, socketPath, cleanup := moverServer(t, &calls, store, ledger)
	dek := bytes.Repeat([]byte{0x0b}, 32)
	sec := sealGrantSecret(t, "jamf/api-pass", "mcp", dek)
	wireGrantResolver(s, sec)
	name, parent := ownNameAndParent(t)
	st := standingCreate(t, NewClient(socketPath), name, parent)
	cleanup()

	store.target = GrantWrapEnclave // the vault moved into the enclave
	s2, _, cleanup2 := moverServer(t, &calls, store, ledger)
	moved, errs := s2.MoveGrantKeys()
	cleanup2()
	if moved != 1 || len(errs) != 0 {
		t.Fatalf("moved %d, errs %v", moved, errs)
	}
	if w := ledgerWraps(t, ledger); len(w) != 1 || w[0] != GrantWrapEnclave {
		t.Fatalf("ledger wraps %v, want the enclave's", w)
	}
	if store.has(GrantWrapKeychain, st.ID) || !store.has(GrantWrapEnclave, st.ID) {
		t.Fatal("after the move the keychain key should be gone and the enclave key present")
	}

	_, socketPath3, cleanup3 := moverServer(t, &calls, store, ledger)
	defer cleanup3()
	before := atomic.LoadInt32(&calls)
	got, err := NewClient(socketPath3).UnwrapKeyLabeled(sec.Wrapped, "jamf/api-pass", "mcp")
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("serve after the move: %v", err)
	}
	if atomic.LoadInt32(&calls) != before {
		t.Error("the moved grant prompted to serve")
	}
}

// If the new key cannot be made, nothing changes: the grant keeps its old
// key and still serves.
func TestMoveGrantKeysLeavesAGrantAloneWhenItCannot(t *testing.T) {
	var calls int32
	store := newMemMover()
	ledger := filepath.Join(t.TempDir(), "grants.json")
	s, socketPath, cleanup := moverServer(t, &calls, store, ledger)
	sec := sealGrantSecret(t, "jamf/api-pass", "mcp", bytes.Repeat([]byte{0x0c}, 32))
	wireGrantResolver(s, sec)
	name, parent := ownNameAndParent(t)
	st := standingCreate(t, NewClient(socketPath), name, parent)
	cleanup()

	store.target, store.failCreate = GrantWrapEnclave, errors.New("enclave unavailable")
	s2, _, cleanup2 := moverServer(t, &calls, store, ledger)
	moved, errs := s2.MoveGrantKeys()
	cleanup2()
	if moved != 0 || len(errs) != 1 {
		t.Fatalf("moved %d, errs %v; want 0 and one error", moved, errs)
	}
	if w := ledgerWraps(t, ledger); w[0] != GrantWrapKeychain {
		t.Fatalf("the ledger changed: %v", w)
	}
	if !store.has(GrantWrapKeychain, st.ID) {
		t.Fatal("the grant's only key was deleted")
	}
}

// A crash between writing the ledger and deleting the old key leaves an old
// key nothing names; the next start deletes it.
func TestMoveGrantKeysCleansUpAfterACrashBeforeTheDelete(t *testing.T) {
	var calls int32
	store := newMemMover()
	ledger := filepath.Join(t.TempDir(), "grants.json")
	s, socketPath, cleanup := moverServer(t, &calls, store, ledger)
	sec := sealGrantSecret(t, "jamf/api-pass", "mcp", bytes.Repeat([]byte{0x0d}, 32))
	wireGrantResolver(s, sec)
	name, parent := ownNameAndParent(t)
	st := standingCreate(t, NewClient(socketPath), name, parent)
	cleanup()

	store.target, store.failDelete = GrantWrapEnclave, errors.New("killed")
	s2, _, cleanup2 := moverServer(t, &calls, store, ledger)
	s2.MoveGrantKeys()
	cleanup2()
	if !store.has(GrantWrapKeychain, st.ID) {
		t.Fatal("the delete that was made to fail happened anyway")
	}
	store.failDelete = nil
	s3, _, cleanup3 := moverServer(t, &calls, store, ledger)
	defer cleanup3()
	if moved, errs := s3.MoveGrantKeys(); moved != 0 || len(errs) != 0 {
		t.Fatalf("second start moved %d (errs %v); nothing was left to move", moved, errs)
	}
	if store.has(GrantWrapKeychain, st.ID) {
		t.Fatal("the leftover keychain key was not cleaned up")
	}
}

// A never-ask AI Job's key moves the same way, and the job still opens.
func TestMoveGrantKeysMovesANeverAskJob(t *testing.T) {
	store := newMemMover()
	kcKey, err := store.CreateWrap("j-1", GrantWrapKeychain)
	if err != nil {
		t.Fatal(err)
	}
	dek := bytes.Repeat([]byte{0x0e}, 32)
	sealed, err := kcKey.Seal(dek, "env")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "jobs.json")
	j := &job.Job{Name: "notion-guests", Dir: "/tmp", Argv: []string{"x"}, Exe: "/bin/x", Ask: job.AskNever, KeyID: "j-1",
		Secrets: []job.Secret{{Var: "TOKEN", Path: "notion/token", Class: "env", DeviceDigest: "dd", KeyWrapped: hex.EncodeToString(sealed), Wrap: GrantWrapKeychain}}}
	if err := job.Save(path, map[string]*job.Job{j.Name: j}); err != nil {
		t.Fatal(err)
	}
	s := &Server{GrantKeys: store}
	if _, err := s.SetJobStore(path); err != nil {
		t.Fatal(err)
	}
	store.target = GrantWrapEnclave
	if moved, errs := s.MoveGrantKeys(); moved != 1 || len(errs) != 0 {
		t.Fatalf("moved %d, errs %v", moved, errs)
	}
	reloaded, err := job.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if w := reloaded["notion-guests"].Secrets[0].Wrap; w != GrantWrapEnclave {
		t.Fatalf("jobs.json wrap %q, want the enclave's", w)
	}
	if store.has(GrantWrapKeychain, "j-1") {
		t.Fatal("the job's old keychain key survived")
	}
	deks := map[string][]byte{}
	if err := s.openJobKeys(reloaded["notion-guests"], deks); err != nil || !bytes.Equal(deks["dd"], dek) {
		t.Fatalf("the moved job does not open: %v", err)
	}
}

// A move that made (or found) the new key and then failed leaves the grant
// sealed for its old key, beside a key of the new kind. Serving must use the
// key the entries are sealed for, not whichever kind exists: the store's
// plain Load prefers the enclave's, which opens nothing here.
func TestAGrantAMoveFailedOnStillServes(t *testing.T) {
	var calls int32
	store := newMemMover()
	ledger := filepath.Join(t.TempDir(), "grants.json")
	s, socketPath, cleanup := moverServer(t, &calls, store, ledger)
	dek := bytes.Repeat([]byte{0x1a}, 32)
	sec := sealGrantSecret(t, "jamf/api-pass", "mcp", dek)
	wireGrantResolver(s, sec)
	name, parent := ownNameAndParent(t)
	st := standingCreate(t, NewClient(socketPath), name, parent)
	cleanup()

	// A crashed earlier move left an enclave key; this one fails to re-seal.
	if _, err := store.CreateWrap(st.ID, GrantWrapEnclave); err != nil {
		t.Fatal(err)
	}
	store.target, store.failSeal = GrantWrapEnclave, errors.New("sealing failed")
	s2, socketPath2, cleanup2 := moverServer(t, &calls, store, ledger)
	defer cleanup2()
	if moved, errs := s2.MoveGrantKeys(); moved != 0 || len(errs) != 1 {
		t.Fatalf("moved %d, errs %v; want 0 and one error", moved, errs)
	}
	if !store.has(GrantWrapEnclave, st.ID) || !store.has(GrantWrapKeychain, st.ID) {
		t.Fatal("setup: both kinds of key should exist after the failed move")
	}
	before := atomic.LoadInt32(&calls)
	got, err := NewClient(socketPath2).UnwrapKeyLabeled(sec.Wrapped, "jamf/api-pass", "mcp")
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("the grant stopped serving after a failed move: %v", err)
	}
	if atomic.LoadInt32(&calls) != before {
		t.Error("the grant prompted to serve: it was not served from its own key")
	}
}

// The same for a never-ask job, on both of its failure paths: the re-seal
// failing, and jobs.json failing to save after the re-seal worked.
func TestAJobAMoveFailedOnStillOpens(t *testing.T) {
	for _, tc := range []struct {
		name string
		fail func(t *testing.T, store *memMover, dir string)
	}{
		{"reseal fails", func(t *testing.T, store *memMover, dir string) {
			if _, err := store.CreateWrap("j-1", GrantWrapEnclave); err != nil {
				t.Fatal(err)
			}
			store.failSeal = errors.New("sealing failed")
		}},
		{"save fails", func(t *testing.T, store *memMover, dir string) {
			if err := os.Chmod(dir, 0o500); err != nil { // #nosec G302 -- a test's own temp dir, made unwritable on purpose
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) // #nosec G302 -- restoring the test's temp dir
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newMemMover()
			kcKey, err := store.CreateWrap("j-1", GrantWrapKeychain)
			if err != nil {
				t.Fatal(err)
			}
			dek := bytes.Repeat([]byte{0x1b}, 32)
			sealed, err := kcKey.Seal(dek, "env")
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			path := filepath.Join(dir, "jobs.json")
			j := &job.Job{Name: "notion-guests", Dir: "/tmp", Argv: []string{"x"}, Exe: "/bin/x", Ask: job.AskNever, KeyID: "j-1",
				Secrets: []job.Secret{{Var: "TOKEN", Path: "notion/token", Class: "env", DeviceDigest: "dd", KeyWrapped: hex.EncodeToString(sealed), Wrap: GrantWrapKeychain}}}
			if err := job.Save(path, map[string]*job.Job{j.Name: j}); err != nil {
				t.Fatal(err)
			}
			s := &Server{GrantKeys: store}
			if _, err := s.SetJobStore(path); err != nil {
				t.Fatal(err)
			}
			store.target = GrantWrapEnclave
			tc.fail(t, store, dir)
			if moved, errs := s.MoveGrantKeys(); moved != 0 || len(errs) != 1 {
				t.Fatalf("moved %d, errs %v; want 0 and one error", moved, errs)
			}
			if !store.has(GrantWrapEnclave, "j-1") {
				t.Fatal("setup: the failed move should have left an enclave key")
			}
			s.jobMu.Lock()
			cur := *s.jobs["notion-guests"]
			s.jobMu.Unlock()
			if cur.Secrets[0].Wrap != GrantWrapKeychain {
				t.Fatalf("the job's record changed to %q although the move failed", cur.Secrets[0].Wrap)
			}
			deks := map[string][]byte{}
			if err := s.openJobKeys(&cur, deks); err != nil || !bytes.Equal(deks["dd"], dek) {
				t.Fatalf("the job no longer opens after a failed move: %v", err)
			}
		})
	}
}

// A new key made for a move that then failed is deleted again: it sealed
// nothing that was kept.
func TestAFailedMoveDeletesTheKeyItMade(t *testing.T) {
	store := newMemMover()
	kcKey, err := store.CreateWrap("j-1", GrantWrapKeychain)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := kcKey.Seal(bytes.Repeat([]byte{0x1c}, 32), "env")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "jobs.json")
	j := &job.Job{Name: "notion-guests", Dir: "/tmp", Argv: []string{"x"}, Exe: "/bin/x", Ask: job.AskNever, KeyID: "j-1",
		Secrets: []job.Secret{{Var: "TOKEN", Path: "notion/token", Class: "env", DeviceDigest: "dd", KeyWrapped: hex.EncodeToString(sealed), Wrap: GrantWrapKeychain}}}
	if err := job.Save(path, map[string]*job.Job{j.Name: j}); err != nil {
		t.Fatal(err)
	}
	s := &Server{GrantKeys: store}
	if _, err := s.SetJobStore(path); err != nil {
		t.Fatal(err)
	}
	store.target, store.failSeal = GrantWrapEnclave, errors.New("sealing failed")
	if moved, errs := s.MoveGrantKeys(); moved != 0 || len(errs) != 1 {
		t.Fatalf("moved %d, errs %v; want 0 and one error", moved, errs)
	}
	if store.has(GrantWrapEnclave, "j-1") {
		t.Error("the failed move left behind the enclave key it made")
	}
	if !store.has(GrantWrapKeychain, "j-1") {
		t.Fatal("the failed move deleted the job's only key")
	}
}

// manyWorld is a service with n standing grants and n never-ask jobs, each
// sealed for its own keychain key, and a stateWriter that counts writes per
// file. It writes nothing through the counter while it builds.
func manyWorld(t *testing.T, n int) (s *Server, store *memMover, ledger, jobs string, writes map[string]int) {
	t.Helper()
	store = newMemMover()
	dir := t.TempDir()
	ledger, jobs = filepath.Join(dir, "grants.json"), filepath.Join(dir, "jobs.json")
	s = &Server{GrantKeys: store}
	if _, err := s.SetGrantLedger(ledger); err != nil {
		t.Fatal(err)
	}
	all := map[string]*job.Job{}
	for i := 0; i < n; i++ {
		gid, jid := "g-0000000"+string(rune('1'+i)), "j-0000000"+string(rune('1'+i))
		gk, _ := store.CreateWrap(gid, GrantWrapKeychain)
		jk, _ := store.CreateWrap(jid, GrantWrapKeychain)
		dek := bytes.Repeat([]byte{byte(i + 1)}, 32)
		gs, _ := gk.Seal(dek, "env")
		js, _ := jk.Seal(dek, "env")
		s.standing[gid] = &standingGrant{id: gid, created: time.Unix(int64(i+1), 0), anchorPath: "/Applications/Claude.app", name: "node",
			secrets: map[string]standingSecret{"d": {path: "a/b", class: "env", digest: "d", grantWrapped: gs, wrap: GrantWrapKeychain}}}
		name := "job-" + string(rune('a'+i))
		all[name] = &job.Job{Name: name, Dir: "/tmp", Argv: []string{"x"}, Exe: "/bin/x", Ask: job.AskNever, KeyID: jid,
			Secrets: []job.Secret{{Var: "T", Path: "n/t", Class: "env", DeviceDigest: "dd", KeyWrapped: hex.EncodeToString(js), Wrap: GrantWrapKeychain}}}
	}
	if err := s.saveLedger(); err != nil {
		t.Fatal(err)
	}
	if err := job.Save(jobs, all); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetJobStore(jobs); err != nil {
		t.Fatal(err)
	}
	writes = map[string]int{}
	s.stateWriter = func(path string, data []byte) error {
		writes[filepath.Base(path)]++
		return os.WriteFile(path, data, 0o600)
	}
	return s, store, ledger, jobs, writes
}

// Moving n grants and n jobs writes the ledger once and jobs.json once, not
// once per grant and once per job (each write is the whole file).
func TestMoveGrantKeysWritesEachFileOnce(t *testing.T) {
	s, store, _, _, writes := manyWorld(t, 5)
	store.target = GrantWrapEnclave
	if moved, errs := s.MoveGrantKeys(); moved != 10 || len(errs) != 0 {
		t.Fatalf("moved %d, errs %v; want all 10", moved, errs)
	}
	if writes["grants.json"] != 1 || writes["jobs.json"] != 1 {
		t.Fatalf("wrote the ledger %d times and jobs.json %d times; want once each", writes["grants.json"], writes["jobs.json"])
	}
}

// One grant that cannot move stays exactly as it was; the others move, in
// the same single write.
func TestMoveGrantKeysIsolatesAFailingGrant(t *testing.T) {
	s, store, ledger, _, writes := manyWorld(t, 3)
	// g-00000002's keychain key is gone: it cannot be re-sealed.
	_ = store.DeleteWrap("g-00000002", GrantWrapKeychain)
	store.target = GrantWrapEnclave
	moved, errs := s.MoveGrantKeys()
	if moved != 5 || len(errs) != 1 {
		t.Fatalf("moved %d, errs %v; want 5 and one error", moved, errs)
	}
	if writes["grants.json"] != 1 {
		t.Fatalf("wrote the ledger %d times, want once", writes["grants.json"])
	}
	raw, _ := os.ReadFile(ledger)
	var f ledgerFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	for _, g := range f.Grants {
		want := GrantWrapEnclave
		if g.ID == "g-00000002" {
			want = GrantWrapKeychain
		}
		if g.Secrets[0].Wrap != want {
			t.Errorf("%s is %s on disk, want %s", g.ID, g.Secrets[0].Wrap, want)
		}
	}
	if store.has(GrantWrapEnclave, "g-00000002") {
		t.Error("the failed grant kept a new key it made")
	}
}

// A ledger that will not save moves nothing: memory stays as the file is,
// and no old key is deleted.
func TestMoveGrantKeysKeepsEveryOldKeyWhenTheLedgerWillNotSave(t *testing.T) {
	s, store, _, _, _ := manyWorld(t, 3)
	s.stateWriter = func(path string, data []byte) error {
		if filepath.Base(path) == "grants.json" {
			return errors.New("disk full")
		}
		return os.WriteFile(path, data, 0o600)
	}
	store.target = GrantWrapEnclave
	moved, errs := s.MoveGrantKeys()
	if moved != 3 || len(errs) != 3 {
		t.Fatalf("moved %d, errs %v; want the 3 jobs moved and 3 grant errors", moved, errs)
	}
	for _, id := range []string{"g-00000001", "g-00000002", "g-00000003"} {
		if !store.has(GrantWrapKeychain, id) {
			t.Errorf("%s's old key was deleted although the ledger was not written", id)
		}
		if w := s.standing[id].secrets["d"].wrap; w != GrantWrapKeychain {
			t.Errorf("%s is %s in memory, but the file still says keychain", id, w)
		}
	}
}

// unreadWorld writes a ledger with one grant, g-00000001: a keychain entry
// sealed for real when known is set, and an entry in a wrap this build
// cannot read (a newer jit's), which C1 keeps verbatim.
func unreadWorld(t *testing.T, store *memMover, known bool) (*Server, string) {
	t.Helper()
	g := ledgerGrant{ID: "g-00000001", CreatedUnix: 1, Profiles: []GrantProfile{}}
	g.Anchor.ExecPath, g.Anchor.Name, g.Program.Name = "/Applications/Claude.app", "Claude", "node"
	if known {
		k, err := store.CreateWrap("g-00000001", GrantWrapKeychain)
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := k.Seal(bytes.Repeat([]byte{0x2a}, 32), "env")
		if err != nil {
			t.Fatal(err)
		}
		g.Secrets = append(g.Secrets, ledgerSecret{Path: "a/known", Class: "env", DeviceDigest: "d1", GrantWrapped: hex.EncodeToString(sealed), Wrap: GrantWrapKeychain})
	}
	g.Secrets = append(g.Secrets, ledgerSecret{Path: "a/future", Class: "env", DeviceDigest: "d2", GrantWrapped: "0badf00d", Wrap: "future-v9"})
	ledger := filepath.Join(t.TempDir(), "grants.json")
	data, _ := json.Marshal(ledgerFile{Version: ledgerVersion, Grants: []ledgerGrant{g}})
	if err := os.WriteFile(ledger, data, 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Server{GrantKeys: store}
	if _, err := s.SetGrantLedger(ledger); err != nil {
		t.Fatal(err)
	}
	return s, ledger
}

// A grant that moves its readable entries keeps its old key too while an
// unreadable entry remains: that entry may be sealed for it.
func TestMoveKeepsTheOldKeyWhileAnUnreadEntryRemains(t *testing.T) {
	store := newMemMover()
	s, ledger := unreadWorld(t, store, true)
	store.target = GrantWrapEnclave
	if moved, errs := s.MoveGrantKeys(); moved != 1 || len(errs) != 0 {
		t.Fatalf("moved %d, errs %v", moved, errs)
	}
	raw, _ := os.ReadFile(ledger)
	if !bytes.Contains(raw, []byte(`"future-v9"`)) {
		t.Fatal("the unread entry was dropped from the ledger")
	}
	if !store.has(GrantWrapKeychain, "g-00000001") {
		t.Fatal("the move deleted the keychain key an unread entry may be sealed for")
	}
}

// A grant whose unread entries are the only thing naming a key of the other
// kind: already "on the target" by its readable entries (it has none), it
// must still keep that key.
func TestMoveKeepsAKeyOnlyUnreadEntriesName(t *testing.T) {
	store := newMemMover()
	for _, w := range []string{GrantWrapKeychain, GrantWrapEnclave} {
		if _, err := store.CreateWrap("g-00000001", w); err != nil {
			t.Fatal(err)
		}
	}
	s, _ := unreadWorld(t, store, false)
	store.target = GrantWrapKeychain
	if _, errs := s.MoveGrantKeys(); len(errs) != 0 {
		t.Fatal(errs)
	}
	if !store.has(GrantWrapEnclave, "g-00000001") {
		t.Fatal("the enclave key only an unread entry names was deleted")
	}
}

// A job sealed, in part, in a wrap this build cannot read is left alone:
// no attempt to re-seal it (which could only fail, every start), and every
// kind of key kept.
func TestMoveLeavesAJobItCannotReadAlone(t *testing.T) {
	store := newMemMover()
	for _, w := range []string{GrantWrapKeychain, GrantWrapEnclave} {
		if _, err := store.CreateWrap("j-1", w); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "jobs.json")
	j := &job.Job{Name: "notion-guests", Dir: "/tmp", Argv: []string{"x"}, Exe: "/bin/x", Ask: job.AskNever, KeyID: "j-1",
		Secrets: []job.Secret{{Var: "TOKEN", Path: "notion/token", Class: "env", DeviceDigest: "dd", KeyWrapped: "0badf00d", Wrap: "future-v9"}}}
	if err := job.Save(path, map[string]*job.Job{j.Name: j}); err != nil {
		t.Fatal(err)
	}
	s := &Server{GrantKeys: store}
	if _, err := s.SetJobStore(path); err != nil {
		t.Fatal(err)
	}
	store.target = GrantWrapKeychain
	if moved, errs := s.MoveGrantKeys(); moved != 0 || len(errs) != 0 {
		t.Fatalf("moved %d, errs %v; want the job left alone", moved, errs)
	}
	if !store.has(GrantWrapEnclave, "j-1") || !store.has(GrantWrapKeychain, "j-1") {
		t.Fatal("a key of a job this build cannot read was deleted")
	}
}
