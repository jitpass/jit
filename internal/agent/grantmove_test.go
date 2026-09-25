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
}

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
	if k, ok := m.of(wrap)[id]; ok {
		return handOut(wrap, k), nil
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	m.of(wrap)[id] = k
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
