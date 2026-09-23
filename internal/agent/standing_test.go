// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package agent

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/lineage"
)

// memGrantKeys is an in-memory GrantKeyStore: what the keychain store does,
// minus the keychain, so the agent's standing-grant logic is tested without
// touching the machine's login keychain (the same reason keychainwrap's own
// tests never use the production service name).
type memGrantKeys struct {
	mu   sync.Mutex
	keys map[string][]byte
}

type memGrantKey struct{ key []byte }

func (m *memGrantKeys) Create(id string) (GrantKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.keys == nil {
		m.keys = map[string][]byte{}
	}
	if _, dup := m.keys[id]; dup {
		return nil, os.ErrExist
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	m.keys[id] = k
	return &memGrantKey{key: append([]byte(nil), k...)}, nil
}

func (m *memGrantKeys) Load(id string) (GrantKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.keys[id]
	if !ok {
		return nil, os.ErrNotExist
	}
	return &memGrantKey{key: append([]byte(nil), k...)}, nil
}

func (m *memGrantKeys) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.keys, id)
	return nil
}

func (m *memGrantKeys) has(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.keys[id]
	return ok
}

func (k *memGrantKey) Seal(dek []byte, class string) ([]byte, error) {
	return seal(k.key, dek, []byte(class))
}

func (k *memGrantKey) Open(wrapped []byte, class string) ([]byte, error) {
	return open(k.key, wrapped, []byte(class))
}

func (k *memGrantKey) Close() {}

// standingTestServer is startTestServer with a key store and a ledger under
// a temp dir, so a second server started on the same ledger and store is a
// faithful "service restart".
func standingTestServer(t *testing.T, calls *int32, store *memGrantKeys, ledger string) (*Server, string, func()) {
	t.Helper()
	return startTestServerWith(t, time.Minute, calls, func(s *Server) {
		s.GrantKeys = store
		if _, err := s.SetGrantLedger(ledger); err != nil {
			t.Fatalf("SetGrantLedger: %v", err)
		}
	})
}

// ownNameAndParent is the tree the tests anchor under: the test binary's
// own name as the program, its parent (go test) as the app.
func ownNameAndParent(t *testing.T) (name string, parent int32) {
	t.Helper()
	p, ok := lineage.Describe(int32(os.Getpid())) // #nosec G115 -- test pid
	if !ok || p.Name() == "" {
		t.Fatal("Describe(self) yields no name")
	}
	return p.Name(), int32(os.Getppid()) // #nosec G115 -- test ppid
}

func standingCreate(t *testing.T, c *Client, name string, parent int32) GrantStatus {
	t.Helper()
	st, err := c.GrantCreateWith(GrantCreateOpts{
		TargetPID: parent, Name: name, Standing: true,
		Profiles: []GrantProfile{{Name: "jamf", Root: "/tmp/proj"}},
	})
	if err != nil {
		t.Fatalf("GrantCreateWith(standing): %v", err)
	}
	return st
}

func TestStandingGrantServesWithoutPromptAcrossRestart(t *testing.T) {
	var calls int32
	store := &memGrantKeys{}
	ledger := filepath.Join(t.TempDir(), "grants.json")
	s, socketPath, cleanup := standingTestServer(t, &calls, store, ledger)

	dek := bytes.Repeat([]byte{0x07}, 32)
	sec := sealGrantSecret(t, "jamf/api-pass", "mcp", dek)
	wireGrantResolver(s, sec)
	name, parent := ownNameAndParent(t)

	c := NewClient(socketPath)
	st := standingCreate(t, c, name, parent)
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("standing create challenged %d times, want exactly 1", got)
	}
	if !st.Standing || st.ExpiresUnix != 0 || st.AnchorPath == "" {
		t.Fatalf("status = %+v, want Standing with no expiry and an anchor path", st)
	}
	if len(st.ProfileRoots) != 1 || st.ProfileRoots[0].Root != "/tmp/proj" {
		t.Errorf("ProfileRoots = %v, want the folder each profile was named with", st.ProfileRoots)
	}
	if !store.has(st.ID) {
		t.Fatal("no grant key was created in the store")
	}
	if unlocked, _ := s.status(); unlocked {
		t.Fatal("creating a standing grant opened a session; a disclosed challenge must not")
	}

	// Served with the agent locked and nobody prompted.
	got, err := c.UnwrapKeyLabeled(sec.Wrapped, "jamf/api-pass", "mcp")
	if err != nil {
		t.Fatalf("UnwrapKeyLabeled under standing grant: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Errorf("served %x, want %x", got, dek)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("serve challenged the human (%d fetches, want 1)", got)
	}

	// The ledger holds wrapped material and never a key or a plaintext DEK.
	raw, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatalf("ledger not written: %v", err)
	}
	if bytes.Contains(raw, dek) {
		t.Fatal("the ledger contains a plaintext DEK")
	}
	for _, k := range store.keys {
		if bytes.Contains(raw, k) || strings.Contains(string(raw), string(k)) {
			t.Fatal("the ledger contains a grant key")
		}
	}
	var f ledgerFile
	if err := json.Unmarshal(raw, &f); err != nil || len(f.Grants) != 1 || len(f.Grants[0].Secrets) != 1 {
		t.Fatalf("ledger = %s, want one grant with one secret (%v)", raw, err)
	}
	if f.Grants[0].Secrets[0].Wrap != standingWrapAEAD {
		t.Errorf("ledger wrap = %q, want %q", f.Grants[0].Secrets[0].Wrap, standingWrapAEAD)
	}

	// The feature: restart the service and serve again with no session and
	// no prompt. Same ledger, same key store, a brand-new Server.
	cleanup()
	s2, socketPath2, cleanup2 := standingTestServer(t, &calls, store, ledger)
	defer cleanup2()
	if err := s2.saveLedger(); err != nil {
		t.Fatalf("saveLedger after reload: %v", err)
	}
	c2 := NewClient(socketPath2)
	grants, err := c2.GrantList()
	if err != nil {
		t.Fatalf("GrantList after restart: %v", err)
	}
	if len(grants) != 1 || grants[0].ID != st.ID || !grants[0].Standing {
		t.Fatalf("after restart GrantList = %+v, want the standing grant back", grants)
	}
	if grants[0].Serves != 1 {
		t.Errorf("serve count did not survive the restart: %d, want 1", grants[0].Serves)
	}
	got, err = c2.UnwrapKeyLabeled(sec.Wrapped, "jamf/api-pass", "mcp")
	if err != nil {
		t.Fatalf("UnwrapKeyLabeled after restart: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Errorf("after restart served %x, want %x", got, dek)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("serve after restart challenged the human (%d fetches, want 1)", got)
	}
}

func TestStandingGrantRevokeDeletesTheKeyAndPromptsAgain(t *testing.T) {
	var calls int32
	store := &memGrantKeys{}
	ledger := filepath.Join(t.TempDir(), "grants.json")
	s, socketPath, cleanup := standingTestServer(t, &calls, store, ledger)
	defer cleanup()

	dek := bytes.Repeat([]byte{0x07}, 32)
	sec := sealGrantSecret(t, "jamf/api-pass", "mcp", dek)
	wireGrantResolver(s, sec)
	name, parent := ownNameAndParent(t)
	var events []SessionEvent
	var evMu sync.Mutex
	s.OnSessionEvent = func(e SessionEvent) { evMu.Lock(); events = append(events, e); evMu.Unlock() }

	c := NewClient(socketPath)
	st := standingCreate(t, c, name, parent)
	if err := c.GrantRevoke(st.ID); err != nil {
		t.Fatalf("GrantRevoke: %v", err)
	}
	if store.has(st.ID) {
		t.Fatal("revoke left the grant key in the store")
	}
	if grants, _ := c.GrantList(); len(grants) != 0 {
		t.Fatalf("GrantList after revoke = %+v, want none", grants)
	}
	raw, _ := os.ReadFile(ledger)
	var f ledgerFile
	if err := json.Unmarshal(raw, &f); err != nil || len(f.Grants) != 0 {
		t.Fatalf("ledger after revoke = %s, want no grants", raw)
	}
	// Negative control: the same unwrap now rides the ordinary path, which
	// challenges. Revoke itself never did.
	if _, err := c.UnwrapKeyLabeled(sec.Wrapped, "jamf/api-pass", "mcp"); err != nil {
		t.Fatalf("UnwrapKeyLabeled after revoke: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("after revoke: %d fetches, want 2 (create + the ordinary unlock)", got)
	}
	evMu.Lock()
	defer evMu.Unlock()
	var ended bool
	for _, e := range events {
		if e.Kind == KindGrantEnd && e.Op == st.ID && strings.Contains(e.Cause, grantEndRevoked) {
			ended = true
		}
	}
	if !ended {
		t.Errorf("no %s event for the revoke in %+v", KindGrantEnd, events)
	}
}

func TestStandingGrantRotatedSecretIsReportedAndNotServed(t *testing.T) {
	var calls int32
	store := &memGrantKeys{}
	ledger := filepath.Join(t.TempDir(), "grants.json")
	s, socketPath, cleanup := standingTestServer(t, &calls, store, ledger)
	defer cleanup()

	dek := bytes.Repeat([]byte{0x07}, 32)
	sec := sealGrantSecret(t, "jamf/api-pass", "mcp", dek)
	wireGrantResolver(s, sec)
	name, parent := ownNameAndParent(t)
	current := sec.Wrapped
	var curMu sync.Mutex
	s.OnWrappedDEK = func(path string) ([]byte, string, error) {
		curMu.Lock()
		defer curMu.Unlock()
		return current, "mcp", nil
	}

	c := NewClient(socketPath)
	st := standingCreate(t, c, name, parent)
	grants, err := c.GrantList()
	if err != nil {
		t.Fatalf("GrantList: %v", err)
	}
	if len(grants[0].Rotated) != 0 {
		t.Fatalf("fresh grant reports rotated %v, want none", grants[0].Rotated)
	}

	// The secret is rotated: a new DEK, new wrapped bytes on the envelope.
	rotated := sealGrantSecret(t, "jamf/api-pass", "mcp", bytes.Repeat([]byte{0x08}, 32))
	curMu.Lock()
	current = rotated.Wrapped
	curMu.Unlock()
	grants, err = c.GrantList()
	if err != nil {
		t.Fatalf("GrantList: %v", err)
	}
	if len(grants) != 1 || grants[0].ID != st.ID {
		t.Fatalf("GrantList = %+v", grants)
	}
	if len(grants[0].Rotated) != 1 || grants[0].Rotated[0] != "jamf/api-pass" {
		t.Errorf("Rotated = %v, want [jamf/api-pass]", grants[0].Rotated)
	}
	// The rotated bytes miss the grant and ride the ordinary path (prompt);
	// the grant itself is untouched and still serves the old bytes.
	if _, err := c.UnwrapKeyLabeled(rotated.Wrapped, "jamf/api-pass", "mcp"); err != nil {
		t.Fatalf("UnwrapKeyLabeled(rotated): %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("rotated secret: %d fetches, want 2 (the grant must not serve it)", got)
	}
}

func TestStandingGrantRefusesTheWrongApp(t *testing.T) {
	var calls int32
	store := &memGrantKeys{}
	ledger := filepath.Join(t.TempDir(), "grants.json")
	s, socketPath, cleanup := standingTestServer(t, &calls, store, ledger)
	defer cleanup()

	dek := bytes.Repeat([]byte{0x07}, 32)
	sec := sealGrantSecret(t, "jamf/api-pass", "mcp", dek)
	wireGrantResolver(s, sec)
	name, parent := ownNameAndParent(t)
	c := NewClient(socketPath)
	st := standingCreate(t, c, name, parent)

	// Point the loaded grant at an app this process does not run under.
	// Everything else about it is intact: right name, right secret, a key
	// in the store.
	s.grantMu.Lock()
	s.standing[st.ID].anchorPath = "/Applications/NotThisApp.app/Contents/MacOS/NotThisApp"
	s.grantMu.Unlock()
	if _, err := c.UnwrapKeyLabeled(sec.Wrapped, "jamf/api-pass", "mcp"); err != nil {
		t.Fatalf("UnwrapKeyLabeled: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("a grant anchored under another app served this tree (%d fetches, want 2)", got)
	}

	// And the right app, wrong program name: also a miss. The miss above
	// rode the ordinary path and opened a session, so drop it first, or the
	// second unwrap would be served by the session rather than the grant
	// and prove nothing.
	s.LockWithCause("test")
	s.grantMu.Lock()
	s.standing[st.ID].anchorPath = st.AnchorPath
	s.standing[st.ID].name = "not-" + name
	s.grantMu.Unlock()
	if _, err := c.UnwrapKeyLabeled(sec.Wrapped, "jamf/api-pass", "mcp"); err != nil {
		t.Fatalf("UnwrapKeyLabeled: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Errorf("a grant for another program served this one (%d fetches, want 3)", got)
	}
}

func TestStandingGrantValidatesBeforePrompting(t *testing.T) {
	var calls int32
	store := &memGrantKeys{}
	ledger := filepath.Join(t.TempDir(), "grants.json")
	s, socketPath, cleanup := standingTestServer(t, &calls, store, ledger)
	defer cleanup()
	wireGrantResolver(s, sealGrantSecret(t, "jamf/api-pass", "mcp", bytes.Repeat([]byte{0x07}, 32)))
	name, parent := ownNameAndParent(t)
	c := NewClient(socketPath)
	profiles := []GrantProfile{{Name: "jamf"}}

	cases := []struct {
		name string
		opts GrantCreateOpts
		want string
	}{
		{"one process cannot be standing", GrantCreateOpts{TargetPID: int32(os.Getpid()), Standing: true, Profiles: profiles}, "reboot"}, // #nosec G115 -- test pid
		{"standing and a ttl are exclusive", GrantCreateOpts{TargetPID: parent, Name: name, Standing: true, TTL: time.Hour, Profiles: profiles}, "exclusive"},
		{"no profiles", GrantCreateOpts{TargetPID: parent, Name: name, Standing: true}, "grant_profiles"},
	}
	for _, tc := range cases {
		_, err := c.GrantCreateWith(tc.opts)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want one mentioning %q", tc.name, err, tc.want)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Errorf("refused creates reached the prompt %d times, want 0", got)
	}

	// An agent with no key store cannot make one either, and says so.
	s.GrantKeys = nil
	if _, err := c.GrantCreateWith(GrantCreateOpts{TargetPID: parent, Name: name, Standing: true, Profiles: profiles}); err == nil || !strings.Contains(err.Error(), "key store") {
		t.Errorf("no key store: err = %v, want a key-store refusal", err)
	}
}

func TestStandingGrantCannotBeExtended(t *testing.T) {
	var calls int32
	store := &memGrantKeys{}
	ledger := filepath.Join(t.TempDir(), "grants.json")
	s, socketPath, cleanup := standingTestServer(t, &calls, store, ledger)
	defer cleanup()
	wireGrantResolver(s, sealGrantSecret(t, "jamf/api-pass", "mcp", bytes.Repeat([]byte{0x07}, 32)))
	name, parent := ownNameAndParent(t)
	c := NewClient(socketPath)
	st := standingCreate(t, c, name, parent)
	if _, err := c.GrantExtend(st.ID, time.Hour); err == nil || !strings.Contains(err.Error(), "standing") {
		t.Errorf("extend on a standing grant = %v, want a refusal naming it", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("extend on a standing grant reached the prompt (%d fetches, want 1)", got)
	}
}

func TestStandingGrantReasonWording(t *testing.T) {
	got := grantCreateReason("claude", "iTerm2", []string{"mcp-caido"}, 1, 0, "", true)
	want := "let claude under iTerm2 use 1 secret (mcp-caido) until you revoke it"
	if got != want {
		t.Errorf("standing reason = %q, want %q", got, want)
	}
	// The OS dialog has a hard length budget (maxReasonLen), and a tree
	// grant's profile list is the part that yields to it: the sheet shows
	// the full sentence, the prompt shows it within the budget, and the
	// scope clause is never the half that goes.
	two := grantCreateReason("claude", "iTerm2", []string{"mcp-caido", "mcp-urlscan"}, 2, 0, "", true)
	if !strings.HasPrefix(two, "let claude under iTerm2 use 2 secrets (mcp-caido, ") || !strings.HasSuffix(two, ") until you revoke it") {
		t.Errorf("two-profile standing reason = %q, want the first profile named and the scope kept", two)
	}
	long := grantCreateReason(strings.Repeat("x", 100), strings.Repeat("z", 100), []string{strings.Repeat("y", 100)}, 12, 0, "JitPassApp", true)
	if len([]rune(long)) > maxReasonLen {
		t.Errorf("reason is %d runes, must fit the %d-rune prompt budget", len([]rune(long)), maxReasonLen)
	}
	if !strings.Contains(long, "until you revoke it") {
		t.Errorf("truncated reason = %q, lost the scope statement", long)
	}
}

func TestGrantLedgerRefusesANewerVersionWithoutOverwriting(t *testing.T) {
	ledger := filepath.Join(t.TempDir(), "grants.json")
	before := []byte(`{"version": 99, "grants": []}`)
	if err := os.WriteFile(ledger, before, 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewServer(shortSocketPath(t), nil, time.Minute)
	if _, err := s.SetGrantLedger(ledger); err == nil {
		t.Fatal("a newer ledger version was accepted")
	}
	if err := s.saveLedger(); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(ledger)
	if !bytes.Equal(before, after) {
		t.Errorf("a ledger that failed to load was overwritten: %s", after)
	}
}

// A timed grant dies with the service, so the stop is its ending and the
// trail must record it: a grant that simply vanished from `jit grant list`
// after a restart left an audit unable to say when its unattended access
// ceased. A STANDING grant has no such ending — it outlives the process —
// and the same run proves it stays.
func TestServiceStopEndsTimedGrantsAndRecordsIt(t *testing.T) {
	var calls int32
	store := &memGrantKeys{}
	ledger := filepath.Join(t.TempDir(), "grants.json")
	s, socketPath, cleanup := standingTestServer(t, &calls, store, ledger)

	sec := sealGrantSecret(t, "jamf/api-pass", "mcp", bytes.Repeat([]byte{0x07}, 32))
	wireGrantResolver(s, sec)
	name, parent := ownNameAndParent(t)
	var mu sync.Mutex
	var sunk []SessionEvent
	s.OnSessionEvent = func(e SessionEvent) {
		mu.Lock()
		sunk = append(sunk, e)
		mu.Unlock()
	}

	c := NewClient(socketPath)
	standing := standingCreate(t, c, name, parent)
	timed, err := c.GrantCreate(int32(os.Getpid()), "", []string{"jamf"}, "", time.Hour) // #nosec G115 -- test pid
	if err != nil {
		t.Fatalf("GrantCreate (timed): %v", err)
	}

	cleanup() // the service stops

	mu.Lock()
	var ended []SessionEvent
	for _, e := range sunk {
		if e.Kind == KindGrantEnd {
			ended = append(ended, e)
		}
	}
	mu.Unlock()
	if len(ended) != 1 {
		t.Fatalf("got %d grant_end events, want exactly 1 (the timed grant's): %+v", len(ended), ended)
	}
	end := ended[0]
	if end.Op != timed.ID {
		t.Errorf("grant_end names %q, want the timed grant %q (a standing grant survives the stop)", end.Op, timed.ID)
	}
	if end.Op == standing.ID {
		t.Fatal("the standing grant was ended by the service stopping; it must outlive the process")
	}
	if !strings.Contains(end.Cause, grantEndServiceStop) {
		t.Errorf("cause = %q, want one naming %q", end.Cause, grantEndServiceStop)
	}
	if !containsString(end.Labels, "jamf/api-pass") {
		t.Errorf("labels = %v, want the covered vault path — an ending that does not say what it covered answers nothing", end.Labels)
	}

	// Negative control: the standing grant is still in the ledger with its
	// key, so a fresh service serves it again.
	if !store.has(standing.ID) {
		t.Error("the standing grant's key was deleted by the service stopping")
	}
	s2, socketPath2, cleanup2 := standingTestServer(t, &calls, store, ledger)
	defer cleanup2()
	wireGrantResolver(s2, sec)
	grants, err := NewClient(socketPath2).GrantList()
	if err != nil {
		t.Fatalf("GrantList after restart: %v", err)
	}
	if len(grants) != 1 || grants[0].ID != standing.ID {
		t.Fatalf("after the stop GrantList = %+v, want only the standing grant", grants)
	}
}
