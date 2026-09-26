// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package agent

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
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
	// enclave makes the keys it hands out report the Secure Enclave wrap,
	// as secureenclave.GrantKey does; otherwise they say nothing, like the
	// keychain's.
	enclave bool
	// loadErr, when set, is what Load answers for a key that IS there: a
	// store that couldn't say (an enclave this jit can't reach).
	loadErr error
}

type memGrantKey struct{ key []byte }

// memEnclaveKey is memGrantKey that reports the enclave wrap.
type memEnclaveKey struct{ memGrantKey }

func (memEnclaveKey) Wrap() string { return standingWrapEnclave }

func (m *memGrantKeys) handOut(k []byte) GrantKey {
	key := memGrantKey{key: append([]byte(nil), k...)}
	if m.enclave {
		return &memEnclaveKey{key}
	}
	return &key
}

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
	return m.handOut(k), nil
}

func (m *memGrantKeys) Load(id string) (GrantKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.keys[id]
	if ok && m.loadErr != nil {
		return nil, m.loadErr
	}
	if !ok {
		return nil, fmt.Errorf("%w: %w", ErrGrantKeyAbsent, os.ErrNotExist)
	}
	return m.handOut(k), nil
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
	// ExpiresUnix carries the far-future compat instant, never a real
	// deadline; TestStandingGrantReportsACompatExpiryOldClientsCanRender
	// owns that contract.
	if !st.Standing || st.ExpiresUnix != standingExpiryCompat.Unix() || st.AnchorPath == "" {
		t.Fatalf("status = %+v, want Standing with the compat expiry and an anchor path", st)
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
	if _, err := c.GrantRevoke(st.ID); err != nil {
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
	// The refusal must say WHAT is wrong in the user's own vocabulary. The
	// word "standing" is this package's noun and appears on no user surface:
	// the flag is --until-revoked, the list says "until revoked".
	_, err := c.GrantExtend(st.ID, time.Hour)
	if err == nil || !strings.Contains(err.Error(), "no deadline to extend") {
		t.Errorf("extend on a standing grant = %v, want a refusal saying it has no deadline", err)
	}
	if err != nil && strings.Contains(err.Error(), "standing") {
		t.Errorf("refusal = %q, leaks the internal noun 'standing' onto a user surface", err)
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

// A standing grant has no deadline, but a client older than the feature has
// no Standing field to read and renders whatever ExpiresUnix holds. Zero came
// out as the Unix epoch, so jit 2.2.6 showed a live grant as "expires Thu
// 02:00 (0m left)" — never-expires reading as long-expired, the worst
// direction for that error. The wire therefore carries a far-future
// compatibility instant, and every CURRENT reader must ignore it and branch
// on Standing instead. Both halves are pinned here: the value is sent, and
// it decides nothing.
func TestStandingGrantReportsACompatExpiryOldClientsCanRender(t *testing.T) {
	var calls int32
	store := &memGrantKeys{}
	ledger := filepath.Join(t.TempDir(), "grants.json")
	s, socketPath, cleanup := standingTestServer(t, &calls, store, ledger)
	defer cleanup()
	wireGrantResolver(s, sealGrantSecret(t, "jamf/api-pass", "mcp", bytes.Repeat([]byte{0x07}, 32)))
	name, parent := ownNameAndParent(t)
	c := NewClient(socketPath)
	st := standingCreate(t, c, name, parent)

	if st.ExpiresUnix <= time.Now().Add(50*365*24*time.Hour).Unix() {
		t.Errorf("ExpiresUnix = %d, want a far-future instant an old client renders as 'does not expire'", st.ExpiresUnix)
	}
	if !st.Standing {
		t.Fatal("Standing is false; every current reader branches on it and would fall back to the compat date")
	}
	// It is a wire projection only: the record itself has no deadline, which
	// is why nothing prunes or expires a standing grant.
	s.grantMu.Lock()
	_, timed := s.grants[st.ID]
	_, standing := s.standing[st.ID]
	s.grantMu.Unlock()
	if timed || !standing {
		t.Fatalf("grant %s landed in the wrong store (timed=%v standing=%v)", st.ID, timed, standing)
	}
	// The compat date must never make a standing grant expire: prune it hard
	// at an instant far past any real deadline and it must still serve.
	s.pruneGrants(time.Now().Add(100 * 365 * 24 * time.Hour))
	grants, err := c.GrantList()
	if err != nil {
		t.Fatalf("GrantList: %v", err)
	}
	if len(grants) != 1 || grants[0].ID != st.ID {
		t.Fatalf("a prune past the compat date ended the standing grant: %+v", grants)
	}
}

// Every serve saves the ledger, because it bumps the serve count, and every
// mount read and `jit run` is a serve. Two of them racing used to write the
// same temp path and rename it out from under each other, publishing a
// spliced file — measured at six concurrent callers producing invalid JSON
// in a quarter of a second. The cost of losing is total: the next start
// cannot parse it, disowns the file, and every standing grant disappears
// with its keychain key orphaned and nothing left that can name it.
//
// The grant set changes length under the writers on purpose: that is what
// makes the payload lengths differ, which is what splices.
func TestConcurrentLedgerSavesPublishValidJSON(t *testing.T) {
	store := &memGrantKeys{}
	ledger := filepath.Join(t.TempDir(), "grants.json")
	s := NewServer(shortSocketPath(t), nil, time.Minute)
	s.GrantKeys = store
	if _, err := s.SetGrantLedger(ledger); err != nil {
		t.Fatalf("SetGrantLedger: %v", err)
	}
	s.grantMu.Lock()
	for i := range 6 {
		id := fmt.Sprintf("g-%04d", i)
		s.standing[id] = &standingGrant{
			id: id, created: time.Now(), anchorPath: "/Applications/T.app/Contents/MacOS/T",
			anchorName: "T", name: "claude", profiles: []GrantProfile{{Name: "p", Root: "/tmp/r"}},
			secrets: map[string]standingSecret{
				"d" + id: {path: "p/" + id, class: "mcp", digest: "d" + id, grantWrapped: bytes.Repeat([]byte{byte(i)}, 60)},
			},
		}
	}
	s.grantMu.Unlock()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	// A churner, so the serialized payload really does change length.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for n := 0; ; n++ {
			select {
			case <-stop:
				return
			default:
			}
			s.grantMu.Lock()
			for _, g := range s.standing {
				g.serves++
				g.lastServe = time.Now()
			}
			s.grantMu.Unlock()
		}
	}()
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 60 {
				if err := s.saveLedger(); err != nil {
					t.Errorf("saveLedger: %v", err)
					return
				}
				// Every published file must parse, every time. A reader
				// starting mid-run is exactly what a service restart is.
				data, err := os.ReadFile(ledger)
				if err != nil {
					t.Errorf("reading the published ledger: %v", err)
					return
				}
				var f ledgerFile
				if err := json.Unmarshal(data, &f); err != nil {
					t.Errorf("published ledger is not valid JSON (%d bytes): %v", len(data), err)
					return
				}
				if len(f.Grants) != 6 {
					t.Errorf("published ledger holds %d grants, want 6", len(f.Grants))
					return
				}
			}
		}()
	}
	close(stop)
	wg.Wait()

	// And the file it leaves behind is the one a restart will read.
	fi, err := os.Stat(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("ledger mode = %v, want 0600", fi.Mode().Perm())
	}
	if _, err := os.Stat(ledger + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("a temp file survived the run; a stale one is what carries a wrong mode into the next write")
	}
	s2 := NewServer(shortSocketPath(t), nil, time.Minute)
	n, err := s2.SetGrantLedger(ledger)
	if err != nil || n != 6 {
		t.Fatalf("a fresh service loaded %d grants (%v), want 6", n, err)
	}
}

// A revoke must be durable against a serve that is already mid-save. The
// serve snapshots inside ledgerMu, so a revoke that got there first is the
// picture that gets written; otherwise the serve's older snapshot renames
// the revoked grant back onto disk, where it is unservable (its key is
// gone) and unrevokable (it is in neither store).
func TestARevokeIsNotResurrectedByAConcurrentServe(t *testing.T) {
	store := &memGrantKeys{}
	ledger := filepath.Join(t.TempDir(), "grants.json")
	s := NewServer(shortSocketPath(t), nil, time.Minute)
	s.GrantKeys = store
	if _, err := s.SetGrantLedger(ledger); err != nil {
		t.Fatalf("SetGrantLedger: %v", err)
	}
	for round := range 40 {
		id := fmt.Sprintf("g-r%02d", round)
		key, err := store.Create(id)
		if err != nil {
			t.Fatal(err)
		}
		s.grantMu.Lock()
		s.standing[id] = &standingGrant{
			id: id, created: time.Now(), anchorPath: "/Applications/T.app/Contents/MacOS/T",
			anchorName: "T", name: "claude", key: key,
			secrets: map[string]standingSecret{"d": {path: "p/one", class: "mcp", digest: "d", grantWrapped: []byte("x")}},
		}
		s.grantMu.Unlock()
		if err := s.saveLedger(); err != nil {
			t.Fatal(err)
		}

		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); s.revokeStanding(id, nil) }()
		go func() { defer wg.Done(); _ = s.saveLedger() }() // the serve's bookkeeping
		wg.Wait()

		data, err := os.ReadFile(ledger)
		if err != nil {
			t.Fatal(err)
		}
		var f ledgerFile
		if err := json.Unmarshal(data, &f); err != nil {
			t.Fatalf("round %d: ledger not valid JSON: %v", round, err)
		}
		for _, g := range f.Grants {
			if g.ID == id {
				t.Fatalf("round %d: revoked grant %s came back on disk; its key is already deleted, so it can never serve and revoke will not find it", round, id)
			}
		}
		if store.has(id) {
			t.Fatalf("round %d: revoke left the key behind", round)
		}
	}
}

// A grant with no deadline promises to survive a restart, and its prompt and
// the app's sheet both say so. Without a ledger it cannot: it would die at
// the next start with its keychain key orphaned and nothing left able to
// name it for revoke. Refuse before the prompt rather than mint the lie.
func TestAStandingGrantIsRefusedWithoutAUsableLedger(t *testing.T) {
	var calls int32
	store := &memGrantKeys{}
	ledger := filepath.Join(t.TempDir(), "grants.json")
	// A ledger written by a newer jit: SetGrantLedger refuses it and clears
	// the path, which is exactly the state this guards.
	if err := os.WriteFile(ledger, []byte(`{"version": 99, "grants": []}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, socketPath, cleanup := startTestServerWith(t, time.Minute, &calls, func(s *Server) {
		s.GrantKeys = store
		if _, err := s.SetGrantLedger(ledger); err == nil {
			t.Fatal("a newer ledger version was accepted")
		}
	})
	defer cleanup()
	wireGrantResolver(s, sealGrantSecret(t, "jamf/api-pass", "mcp", bytes.Repeat([]byte{0x07}, 32)))
	name, parent := ownNameAndParent(t)

	_, err := NewClient(socketPath).GrantCreateWith(GrantCreateOpts{
		TargetPID: parent, Name: name, Standing: true, Profiles: []GrantProfile{{Name: "jamf"}},
	})
	if err == nil || !strings.Contains(err.Error(), "survive a restart") {
		t.Errorf("standing create with no usable ledger = %v, want a refusal naming what it could not promise", err)
	}
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Errorf("the refused create reached the prompt %d times, want 0", got)
	}
	if len(store.keys) != 0 {
		t.Errorf("a refused create left %d keys behind", len(store.keys))
	}
	// A TIMED grant is unaffected: it never needed the ledger.
	if _, err := NewClient(socketPath).GrantCreate(int32(os.Getpid()), "", []string{"jamf"}, "", time.Hour); err != nil { // #nosec G115 -- test pid
		t.Errorf("a timed grant was refused for a ledger it does not use: %v", err)
	}
}

// The anchor is matched by executable path on every serve, so an anchor the
// kernel reports no path for can never match again. Such a grant would cost
// a Touch ID, list as live, serve nothing, and then vanish on the next load
// (which skips a pathless entry) with its key orphaned. A process whose
// binary was replaced underneath it cannot be arranged in a test, so the
// guard is the unit; createGrant calls it before the prompt.
func TestAStandingGrantIsRefusedWhenTheAnchorHasNoExecutablePath(t *testing.T) {
	if msg := standingAnchorError(Request{Standing: true}, ""); msg == "" {
		t.Fatal("a standing grant with no anchor executable path was allowed")
	} else {
		if !strings.Contains(msg, "executable path") {
			t.Errorf("refusal = %q, want it to name what is missing", msg)
		}
		if !strings.Contains(msg, "--for") {
			t.Errorf("refusal = %q, want it to name the shape that still works", msg)
		}
	}
	// Everything else passes through: a real anchor, and any timed grant.
	if msg := standingAnchorError(Request{Standing: true}, "/Applications/iTerm.app/Contents/MacOS/iTerm2"); msg != "" {
		t.Errorf("a real anchor was refused: %s", msg)
	}
	if msg := standingAnchorError(Request{}, ""); msg != "" {
		t.Errorf("a timed grant was refused for an anchor path it does not use: %s", msg)
	}
	// And the serve gate agrees: an empty anchor matches nothing, so a
	// grant holding one could only ever have been dead weight.
	if lineage.AncestryNamedUnderPath(int32(os.Getpid()), "", "anything") { // #nosec G115 -- test pid
		t.Error("AncestryNamedUnderPath matched an empty anchor path")
	}
}

// closeCounting is a GrantKeyMover whose keys count every use after Close:
// the Secure Enclave key's Close frees cgo memory, so such a use is a
// use-after-free there.
type closeCounting struct {
	*memMover
	afterClose atomic.Int32
}

type countedKey struct {
	GrantKey
	closed atomic.Bool
	owner  *closeCounting
}

func (k *countedKey) Wrap() string { return keyWrap(k.GrantKey) }
func (k *countedKey) Close()       { k.closed.Store(true) }
func (k *countedKey) Open(b []byte, class string) ([]byte, error) {
	if k.closed.Load() {
		k.owner.afterClose.Add(1)
	}
	time.Sleep(50 * time.Microsecond) // an enclave open takes a while
	if k.closed.Load() {
		k.owner.afterClose.Add(1)
	}
	return k.GrantKey.Open(b, class)
}

func (c *closeCounting) LoadWrap(id, wrap string) (GrantKey, error) {
	k, err := c.memMover.LoadWrap(id, wrap)
	if err != nil {
		return nil, err
	}
	return &countedKey{GrantKey: k, owner: c}, nil
}

// A grant holding entries of both kinds (a move that failed
// half way) served concurrently, one kind and then the other. Loading one
// kind used to close the cached key of the other while a serve that had
// just been handed it was still to open with it.
func TestConcurrentMixedKindServesNeverUseAClosedKey(t *testing.T) {
	store := &closeCounting{memMover: newMemMover()}
	name, parent := ownNameAndParent(t)
	anchor, ok := lineage.Describe(parent)
	if !ok || anchor.ExecPath == "" {
		t.Skip("the test's parent has no executable path to anchor under")
	}
	g := &standingGrant{id: "g-00000001", anchorPath: anchor.ExecPath, name: name, secrets: map[string]standingSecret{}}
	wrappedOf := map[string][]byte{}
	for _, w := range []string{GrantWrapKeychain, GrantWrapEnclave} {
		k, err := store.CreateWrap(g.id, w)
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := k.Seal(make([]byte, 32), "env")
		if err != nil {
			t.Fatal(err)
		}
		wrapped := []byte("wrapped-" + w)
		wrappedOf[w] = wrapped
		d := wrappedDigest(wrapped)
		g.secrets[d] = standingSecret{path: "p/" + w, class: "env", digest: d, grantWrapped: sealed, wrap: w}
	}
	s := &Server{GrantKeys: store, standing: map[string]*standingGrant{g.id: g}}
	c := &caller{pid: int32(os.Getpid())} // #nosec G115 -- test pid

	var wg sync.WaitGroup
	var misses atomic.Int32
	for i := 0; i < 8; i++ {
		wrapped := wrappedOf[GrantWrapKeychain]
		if i%2 == 1 {
			wrapped = wrappedOf[GrantWrapEnclave]
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 100; n++ {
				if _, _, ok := s.standingUnwrap(c, wrapped); !ok {
					misses.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if n := store.afterClose.Load(); n != 0 {
		t.Errorf("%d opens used a key another serve had closed", n)
	}
	if n := misses.Load(); n != 0 {
		t.Errorf("%d serves missed", n)
	}
}

// revokeRaceStore is a memMover whose Delete stops until released, so a
// revoke can be held after it has retired the grant and before the store
// forgets the key; every key it hands out records its Close.
type revokeRaceStore struct {
	*memMover
	entered, release chan struct{}
	enterOnce        sync.Once

	mu     sync.Mutex
	handed []*closeRecorded
}

type closeRecorded struct {
	GrantKey
	closed atomic.Bool
}

func (k *closeRecorded) Wrap() string { return keyWrap(k.GrantKey) }
func (k *closeRecorded) Close()       { k.closed.Store(true); k.GrantKey.Close() }

func (r *revokeRaceStore) LoadWrap(id, wrap string) (GrantKey, error) {
	k, err := r.memMover.LoadWrap(id, wrap)
	if err != nil {
		return nil, err
	}
	ck := &closeRecorded{GrantKey: k}
	r.mu.Lock()
	r.handed = append(r.handed, ck)
	r.mu.Unlock()
	return ck, nil
}

func (r *revokeRaceStore) Delete(id string) error {
	r.enterOnce.Do(func() { close(r.entered) })
	<-r.release
	return r.memMover.Delete(id)
}

// Third review of #168: a revoke that lands after a serve found the grant
// live, and before the serve opens, must stop the serve. The serve used to
// find no cached key (the revoke had closed it), load it again from a store
// the revoke had not yet deleted it from, serve the secret after the
// revoke, and leave the key cached on a grant no longer in s.standing, so
// that nothing would ever close it.
func TestARevokeBetweenTheCheckAndTheOpenStopsTheServe(t *testing.T) {
	store := &revokeRaceStore{memMover: newMemMover(), entered: make(chan struct{}), release: make(chan struct{})}
	name, parent := ownNameAndParent(t)
	anchor, ok := lineage.Describe(parent)
	if !ok || anchor.ExecPath == "" {
		t.Skip("the test's parent has no executable path to anchor under")
	}
	k, err := store.CreateWrap("g-00000001", GrantWrapKeychain)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := k.Seal(make([]byte, 32), "env")
	if err != nil {
		t.Fatal(err)
	}
	wrapped := []byte("wrapped")
	d := wrappedDigest(wrapped)
	g := &standingGrant{id: "g-00000001", anchorPath: anchor.ExecPath, name: name,
		secrets: map[string]standingSecret{d: {path: "p", class: "env", digest: d, grantWrapped: sealed, wrap: GrantWrapKeychain}}}
	s := &Server{GrantKeys: store, standing: map[string]*standingGrant{g.id: g}}
	c := &caller{pid: int32(os.Getpid())} // #nosec G115 -- test pid

	revoked := make(chan bool)
	s.standingChecked = func(string) {
		// The serve has found the grant live. The revoke now runs up to
		// its key delete, and holds there while the serve goes on.
		go func() {
			ok, _ := s.revokeStanding(g.id, nil)
			revoked <- ok
		}()
		<-store.entered
	}
	_, _, served := s.standingUnwrap(c, wrapped)
	close(store.release)
	if !<-revoked {
		t.Fatal("the revoke did not happen")
	}
	if served {
		t.Error("a secret was served after its grant was revoked")
	}
	g.keyMu.Lock()
	cached := g.key
	g.keyMu.Unlock()
	if cached != nil {
		t.Error("a key is left cached on the revoked grant")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for i, k := range store.handed {
		if !k.closed.Load() {
			t.Errorf("key %d handed out was never closed", i)
		}
	}
}
