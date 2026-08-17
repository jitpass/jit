// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package agent

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/lineage"
)

// grantTestMEK matches fakeFetcher's key so tests can pre-seal wrapped DEKs
// the way real envelopes carry them.
var grantTestMEK = bytes.Repeat([]byte{0x42}, 32)

// sealGrantSecret builds one resolver entry: a DEK sealed under the test MEK
// with the class as AAD, exactly what vault.WrappedDEK would hand the real
// resolver.
func sealGrantSecret(t *testing.T, path, class string, dek []byte) GrantSecret {
	t.Helper()
	wrapped, err := seal(grantTestMEK, dek, []byte(class))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return GrantSecret{Path: path, Wrapped: wrapped, Class: class}
}

// wireGrantResolver points OnResolveGrant at a fixed secret set and returns
// the entries, so a test controls exactly what the profiles resolve to.
func wireGrantResolver(s *Server, secrets ...GrantSecret) {
	s.OnResolveGrant = func(profiles []string, projectRoot string) ([]GrantSecret, error) {
		return secrets, nil
	}
}

func TestGrantServesAcrossLockWithoutPrompting(t *testing.T) {
	var calls int32
	s, socketPath, cleanup := startTestServer(t, time.Minute, &calls)
	defer cleanup()

	dek := bytes.Repeat([]byte{0x07}, 32)
	sec := sealGrantSecret(t, "jamf/api-pass", "mcp", dek)
	wireGrantResolver(s, sec)

	c := NewClient(socketPath)
	st, err := c.GrantCreate(int32(os.Getpid()), "", []string{"jamf"}, "", time.Hour) // #nosec G115 -- test pid
	if err != nil {
		t.Fatalf("GrantCreate: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("grant creation challenged %d times, want exactly 1 (one disclosed prompt)", got)
	}
	if len(st.Secrets) != 1 || st.Secrets[0] != "jamf/api-pass" {
		t.Errorf("GrantStatus.Secrets = %v, want [jamf/api-pass]", st.Secrets)
	}
	if !st.RootAlive {
		t.Error("GrantStatus.RootAlive = false for a live root")
	}

	// A disclosed challenge is a confirmation, not an unlock: no session may
	// exist after creation.
	if unlocked, _ := s.status(); unlocked {
		t.Fatal("grant creation opened a session; a disclosed challenge must not")
	}

	// The feature itself: the covered unwrap is served with the agent locked,
	// and no human is prompted.
	got, err := c.UnwrapKeyLabeled(sec.Wrapped, "jamf/api-pass", "mcp")
	if err != nil {
		t.Fatalf("UnwrapKeyLabeled under grant: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Errorf("grant served %x, want %x", got, dek)
	}
	if err := c.Lock(); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if _, err := c.UnwrapKeyLabeled(sec.Wrapped, "jamf/api-pass", "mcp"); err != nil {
		t.Fatalf("UnwrapKeyLabeled after explicit lock: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("grant-covered unwraps challenged the human (%d fetches, want 1): the unattended case is the feature", got)
	}

	// The serves are on the record.
	grants, err := c.GrantList()
	if err != nil {
		t.Fatalf("GrantList: %v", err)
	}
	if len(grants) != 1 || grants[0].Serves != 2 {
		t.Errorf("GrantList = %+v, want one grant with 2 serves", grants)
	}
}

// TestTreeGrantServesByNameUnderAnchor pins the tree-scoped shape: a grant
// anchored at the caller's parent with the caller's own name as the filter
// must serve — the caller here stands in for "a claude started at any point
// inside the window", since creation records no pid set to check against.
func TestTreeGrantServesByNameUnderAnchor(t *testing.T) {
	var calls int32
	s, socketPath, cleanup := startTestServer(t, time.Minute, &calls)
	defer cleanup()

	dek := bytes.Repeat([]byte{0x07}, 32)
	sec := sealGrantSecret(t, "jamf/api-pass", "mcp", dek)
	wireGrantResolver(s, sec)

	ownName := ""
	if p, ok := lineage.Describe(int32(os.Getpid())); ok { // #nosec G115 -- test pid
		ownName = p.Name()
	}
	if ownName == "" {
		t.Fatal("Describe(self) yields no name")
	}

	c := NewClient(socketPath)
	st, err := c.GrantCreate(int32(os.Getppid()), ownName, []string{"jamf"}, "", time.Hour) // #nosec G115 -- test ppid
	if err != nil {
		t.Fatalf("GrantCreate (tree): %v", err)
	}
	if st.Anchor == "" {
		t.Error("tree grant reports no Anchor; the list cannot say what it hangs under")
	}
	if st.Name != ownName {
		t.Errorf("tree grant Name = %q, want the filter %q", st.Name, ownName)
	}

	got, err := c.UnwrapKeyLabeled(sec.Wrapped, "jamf/api-pass", "mcp")
	if err != nil {
		t.Fatalf("UnwrapKeyLabeled under tree grant: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Errorf("tree grant served %x, want %x", got, dek)
	}
	if gotCalls := atomic.LoadInt32(&calls); gotCalls != 1 {
		t.Errorf("tree-grant serve challenged the human (%d fetches, want 1)", gotCalls)
	}
}

// TestTreeGrantNameMissFallsThrough: same anchor, a name the caller's chain
// does not carry — the grant must not serve, and the request rides the
// ordinary challenge path instead.
func TestTreeGrantNameMissFallsThrough(t *testing.T) {
	var calls int32
	s, socketPath, cleanup := startTestServer(t, time.Minute, &calls)
	defer cleanup()

	dek := bytes.Repeat([]byte{0x07}, 32)
	sec := sealGrantSecret(t, "jamf/api-pass", "mcp", dek)
	wireGrantResolver(s, sec)

	c := NewClient(socketPath)
	if _, err := c.GrantCreate(int32(os.Getppid()), "sleep", []string{"jamf"}, "", time.Hour); err != nil { // #nosec G115 -- test ppid
		t.Fatalf("GrantCreate (tree, granting ahead of any sleep): %v", err)
	}
	if _, err := c.UnwrapKeyLabeled(sec.Wrapped, "jamf/api-pass", "mcp"); err != nil {
		t.Fatalf("UnwrapKeyLabeled: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("caller not named sleep was served by the tree grant (%d fetches, want 2)", got)
	}
}

// TestTreeGrantAnchorMustBeCallersOwnAncestor: anchoring under a pid the
// creator does not descend from must fail before any prompt, and launchd is
// never a session root.
func TestTreeGrantAnchorMustBeCallersOwnAncestor(t *testing.T) {
	var calls int32
	s, socketPath, cleanup := startTestServer(t, time.Minute, &calls)
	defer cleanup()
	sec := sealGrantSecret(t, "jamf/api-pass", "mcp", bytes.Repeat([]byte{0x07}, 32))
	wireGrantResolver(s, sec)

	// A child is inside OUR tree, but we are not inside ITS tree.
	child := exec.Command("sleep", "60")
	if err := child.Start(); err != nil {
		t.Fatalf("starting child: %v", err)
	}
	defer func() {
		_ = child.Process.Kill()
		_, _ = child.Process.Wait()
	}()

	c := NewClient(socketPath)
	if _, err := c.GrantCreate(int32(child.Process.Pid), "sleep", []string{"jamf"}, "", time.Hour); err == nil || !strings.Contains(err.Error(), "ancestor") { // #nosec G115 -- test pid
		t.Errorf("tree grant anchored under a non-ancestor = %v, want an ancestry refusal", err)
	}
	if _, err := c.GrantCreate(1, "sleep", []string{"jamf"}, "", time.Hour); err == nil || !strings.Contains(err.Error(), "launchd") {
		t.Errorf("tree grant anchored under launchd = %v, want a launchd refusal", err)
	}
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Errorf("refused tree grants reached the prompt %d times, want 0", got)
	}
}

func TestGrantMissFallsThroughToOrdinaryUnlock(t *testing.T) {
	var calls int32
	s, socketPath, cleanup := startTestServer(t, time.Minute, &calls)
	defer cleanup()

	dek := bytes.Repeat([]byte{0x07}, 32)
	covered := sealGrantSecret(t, "jamf/api-pass", "mcp", dek)
	wireGrantResolver(s, covered)

	c := NewClient(socketPath)
	if _, err := c.GrantCreate(int32(os.Getpid()), "", []string{"jamf"}, "", time.Hour); err != nil { // #nosec G115 -- test pid
		t.Fatalf("GrantCreate: %v", err)
	}

	// An UNCOVERED secret must ride the ordinary session path: fresh
	// challenge, session opened.
	other, err := seal(grantTestMEK, bytes.Repeat([]byte{0x08}, 32), []byte("aws"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := c.UnwrapKeyLabeled(other, "aws/key", "aws"); err != nil {
		t.Fatalf("UnwrapKeyLabeled (uncovered): %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("uncovered unwrap fetched %d times total, want 2 (grant prompt + ordinary unlock)", got)
	}
}

func TestGrantDoesNotServeAForeignProcessTree(t *testing.T) {
	var calls int32
	s, socketPath, cleanup := startTestServer(t, time.Minute, &calls)
	defer cleanup()

	dek := bytes.Repeat([]byte{0x07}, 32)
	sec := sealGrantSecret(t, "jamf/api-pass", "mcp", dek)
	wireGrantResolver(s, sec)

	// Anchor the grant to a process the TEST connection does not descend
	// from: a child we spawn. The client (this test process) is the child's
	// PARENT, and descent runs child-up, so the caller is outside the tree.
	child := exec.Command("sleep", "60")
	if err := child.Start(); err != nil {
		t.Fatalf("starting child: %v", err)
	}
	defer func() {
		_ = child.Process.Kill()
		_, _ = child.Process.Wait()
	}()

	c := NewClient(socketPath)
	if _, err := c.GrantCreate(int32(child.Process.Pid), "", []string{"jamf"}, "", time.Hour); err != nil { // #nosec G115 -- test pid
		t.Fatalf("GrantCreate: %v", err)
	}

	// The covered bytes, from OUTSIDE the granted tree: must not be served
	// from the grant — the fetcher firing again is the proof it took the
	// ordinary challenge path instead.
	if _, err := c.UnwrapKeyLabeled(sec.Wrapped, "jamf/api-pass", "mcp"); err != nil {
		t.Fatalf("UnwrapKeyLabeled: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("foreign-tree unwrap fetched %d times total, want 2 (grant prompt + ordinary unlock, never the grant cache)", got)
	}

	grants, err := c.GrantList()
	if err != nil {
		t.Fatalf("GrantList: %v", err)
	}
	if len(grants) != 1 || grants[0].Serves != 0 {
		t.Errorf("GrantList = %+v, want the grant intact with 0 serves", grants)
	}
}

func TestGrantEndsWhenRootExits(t *testing.T) {
	s, socketPath, cleanup := startTestServer(t, time.Minute, nil)
	defer cleanup()

	sec := sealGrantSecret(t, "jamf/api-pass", "mcp", bytes.Repeat([]byte{0x07}, 32))
	wireGrantResolver(s, sec)

	child := exec.Command("sleep", "60")
	if err := child.Start(); err != nil {
		t.Fatalf("starting child: %v", err)
	}
	pid := int32(child.Process.Pid) // #nosec G115 -- test pid

	c := NewClient(socketPath)
	if _, err := c.GrantCreate(pid, "", []string{"jamf"}, "", time.Hour); err != nil {
		t.Fatalf("GrantCreate: %v", err)
	}
	_ = child.Process.Kill()
	_, _ = child.Process.Wait()

	grants, err := c.GrantList()
	if err != nil {
		t.Fatalf("GrantList: %v", err)
	}
	if len(grants) != 0 {
		t.Fatalf("GrantList after root exit = %+v, want the grant pruned", grants)
	}
	assertGrantEndEvent(t, s, grantEndExited)
}

func TestGrantExpiryEndsTheGrant(t *testing.T) {
	var calls int32
	s, socketPath, cleanup := startTestServer(t, time.Minute, &calls)
	defer cleanup()

	dek := bytes.Repeat([]byte{0x07}, 32)
	sec := sealGrantSecret(t, "jamf/api-pass", "mcp", dek)
	wireGrantResolver(s, sec)

	c := NewClient(socketPath)
	st, err := c.GrantCreate(int32(os.Getpid()), "", []string{"jamf"}, "", time.Hour) // #nosec G115 -- test pid
	if err != nil {
		t.Fatalf("GrantCreate: %v", err)
	}
	// The RPC floor is a minute; expire it by hand — the serve path re-checks
	// the record's own deadline, which is the contract (expiry is enforced at
	// serve time, never baked into key material).
	s.grantMu.Lock()
	s.grants[st.ID].expires = time.Now().Add(-time.Second)
	s.grantMu.Unlock()

	if _, err := c.UnwrapKeyLabeled(sec.Wrapped, "jamf/api-pass", "mcp"); err != nil {
		t.Fatalf("UnwrapKeyLabeled after expiry: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("expired grant answered without a fresh challenge (%d fetches, want 2)", got)
	}
	grants, err := c.GrantList()
	if err != nil {
		t.Fatalf("GrantList: %v", err)
	}
	if len(grants) != 0 {
		t.Fatalf("GrantList after expiry = %+v, want empty", grants)
	}
	assertGrantEndEvent(t, s, grantEndExpired)
}

func TestGrantRevokeIsImmediateAndUnauthenticated(t *testing.T) {
	var calls int32
	s, socketPath, cleanup := startTestServer(t, time.Minute, &calls)
	defer cleanup()

	dek := bytes.Repeat([]byte{0x07}, 32)
	sec := sealGrantSecret(t, "jamf/api-pass", "mcp", dek)
	wireGrantResolver(s, sec)

	c := NewClient(socketPath)
	st, err := c.GrantCreate(int32(os.Getpid()), "", []string{"jamf"}, "", time.Hour) // #nosec G115 -- test pid
	if err != nil {
		t.Fatalf("GrantCreate: %v", err)
	}
	if err := c.GrantRevoke(st.ID); err != nil {
		t.Fatalf("GrantRevoke: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("revoke fetched the MEK (%d fetches, want 1): the kill switch must never require auth", got)
	}
	if _, err := c.UnwrapKeyLabeled(sec.Wrapped, "jamf/api-pass", "mcp"); err != nil {
		t.Fatalf("UnwrapKeyLabeled after revoke: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("revoked grant still answered without a challenge (%d fetches, want 2)", got)
	}
	assertGrantEndEvent(t, s, grantEndRevoked)

	if err := c.GrantRevoke(st.ID); err == nil || !strings.Contains(err.Error(), "no grant") {
		t.Errorf("revoking twice = %v, want a no-such-grant error", err)
	}
}

func TestGrantExtendReprompts(t *testing.T) {
	var calls int32
	s, socketPath, cleanup := startTestServer(t, time.Minute, &calls)
	defer cleanup()

	sec := sealGrantSecret(t, "jamf/api-pass", "mcp", bytes.Repeat([]byte{0x07}, 32))
	wireGrantResolver(s, sec)

	c := NewClient(socketPath)
	st, err := c.GrantCreate(int32(os.Getpid()), "", []string{"jamf"}, "", time.Hour) // #nosec G115 -- test pid
	if err != nil {
		t.Fatalf("GrantCreate: %v", err)
	}
	ext, err := c.GrantExtend(st.ID, 2*time.Hour)
	if err != nil {
		t.Fatalf("GrantExtend: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("extend fetched %d times total, want 2: more time is a new decision and must re-prompt", got)
	}
	if ext.ExpiresUnix <= st.ExpiresUnix {
		t.Errorf("extend moved expiry %d -> %d, want later", st.ExpiresUnix, ext.ExpiresUnix)
	}
}

func TestGrantCreateFailsClosedOnClassMismatch(t *testing.T) {
	s, socketPath, cleanup := startTestServer(t, time.Minute, nil)
	defer cleanup()

	// The wrapped bytes are sealed under "aws"; the resolver claims "docker".
	// The AAD check must fail the WHOLE create — the prompt described a set
	// the grant could not truthfully cover.
	wrapped, err := seal(grantTestMEK, bytes.Repeat([]byte{0x07}, 32), []byte("aws"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	good := sealGrantSecret(t, "jamf/api-pass", "mcp", bytes.Repeat([]byte{0x09}, 32))
	wireGrantResolver(s, good, GrantSecret{Path: "aws/key", Wrapped: wrapped, Class: "docker"})

	c := NewClient(socketPath)
	_, err = c.GrantCreate(int32(os.Getpid()), "", []string{"jamf", "aws"}, "", time.Hour) // #nosec G115 -- test pid
	if err == nil || !strings.Contains(err.Error(), "no grant created") {
		t.Fatalf("GrantCreate with a lying class = %v, want a no-grant-created failure", err)
	}
	grants, lerr := c.GrantList()
	if lerr != nil {
		t.Fatalf("GrantList: %v", lerr)
	}
	if len(grants) != 0 {
		t.Errorf("GrantList = %+v, want empty: a partial grant is a prompt that lied by omission", grants)
	}
}

func TestGrantCreateValidatesBeforePrompting(t *testing.T) {
	var calls int32
	s, socketPath, cleanup := startTestServer(t, time.Minute, &calls)
	defer cleanup()
	wireGrantResolver(s) // resolves to nothing
	_ = socketPath

	cases := []struct {
		name string
		req  Request
	}{
		{"no target", Request{Op: OpGrantCreate, GrantProfiles: []string{"jamf"}, TTLSeconds: 3600}},
		{"no profiles", Request{Op: OpGrantCreate, TargetPID: int32(os.Getpid()), TTLSeconds: 3600}},                                            // #nosec G115 -- test pid
		{"ttl too long", Request{Op: OpGrantCreate, TargetPID: int32(os.Getpid()), GrantProfiles: []string{"jamf"}, TTLSeconds: 8 * 24 * 3600}}, // #nosec G115 -- test pid
		{"ttl too short", Request{Op: OpGrantCreate, TargetPID: int32(os.Getpid()), GrantProfiles: []string{"jamf"}, TTLSeconds: 30}},           // #nosec G115 -- test pid
		{"dead target", Request{Op: OpGrantCreate, TargetPID: 999999999, GrantProfiles: []string{"jamf"}, TTLSeconds: 3600}},                    //
		{"empty resolution", Request{Op: OpGrantCreate, TargetPID: int32(os.Getpid()), GrantProfiles: []string{"jamf"}, TTLSeconds: 3600}},      // #nosec G115 -- test pid
	}
	for _, tc := range cases {
		resp := s.handle(tc.req, &caller{pid: int32(os.Getpid())}) // #nosec G115 -- test pid
		if resp.OK {
			t.Errorf("%s: handle succeeded, want failure", tc.name)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Errorf("invalid grant requests reached the prompt %d times, want 0: validation runs before any Touch ID", got)
	}
}

func TestGrantCreateReasonWording(t *testing.T) {
	got := grantCreateReason("claude", "", []string{"jamf", "aws-ci"}, 3, 8*time.Hour)
	want := "let claude use 3 secrets (jamf, aws-ci) unattended for 8h"
	if got != want {
		t.Errorf("grantCreateReason = %q, want %q", got, want)
	}
	// The tree-scoped shape must name both halves of the perimeter: the
	// filter name AND the anchor the human is hanging it under.
	tree := grantCreateReason("claude", "iTerm2", []string{"jamf"}, 1, time.Hour)
	if want := "let claude under iTerm2 use 1 secret (jamf) unattended for 1h"; tree != want {
		t.Errorf("tree grantCreateReason = %q, want %q", tree, want)
	}
	if r := grantCreateReason("", "", []string{"p"}, 1, time.Minute); !strings.Contains(r, "this process") {
		t.Errorf("nameless reason = %q, want a 'this process' fallback", r)
	}
	long := grantCreateReason(strings.Repeat("x", 100), strings.Repeat("z", 100), []string{strings.Repeat("y", 100)}, 12, 3*24*time.Hour)
	if len([]rune(long)) > maxReasonLen {
		t.Errorf("reason is %d runes, must fit the %d-rune prompt budget", len([]rune(long)), maxReasonLen)
	}
	if !strings.Contains(long, "unattended for 3d") {
		t.Errorf("truncated reason = %q, lost the scope statement — the half that changes the decision", long)
	}
}

func TestFormatGrantTTL(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{45 * time.Minute, "45m"},
		{8 * time.Hour, "8h"},
		{90 * time.Minute, "1h30m"},
		{24 * time.Hour, "1d"},
		{3 * 24 * time.Hour, "3d"},
	}
	for _, tc := range cases {
		if got := formatGrantTTL(tc.d); got != tc.want {
			t.Errorf("formatGrantTTL(%s) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

// TestGrantEventsReachTheDurableSink pins the audit contract: every stage of
// a grant's life must reach OnSessionEvent, because that callback IS the
// durable trail — the CLI wires it straight to agent-history.jsonl, which is
// the only thing `jit audit` reads. An event that stays in the in-memory ring
// but never fires the sink would render fine in tests that read history()
// and still be invisible to the one command users audit with.
func TestGrantEventsReachTheDurableSink(t *testing.T) {
	s, socketPath, cleanup := startTestServer(t, time.Minute, nil)
	defer cleanup()

	var mu sync.Mutex
	var sunk []SessionEvent
	s.OnSessionEvent = func(e SessionEvent) {
		mu.Lock()
		sunk = append(sunk, e)
		mu.Unlock()
	}

	dek := bytes.Repeat([]byte{0x07}, 32)
	sec := sealGrantSecret(t, "jamf/api-pass", "mcp", dek)
	wireGrantResolver(s, sec)

	c := NewClient(socketPath)
	st, err := c.GrantCreate(int32(os.Getpid()), "", []string{"jamf"}, "", time.Hour) // #nosec G115 -- test pid
	if err != nil {
		t.Fatalf("GrantCreate: %v", err)
	}
	if _, err := c.UnwrapKeyLabeled(sec.Wrapped, "jamf/api-pass", "mcp"); err != nil {
		t.Fatalf("UnwrapKeyLabeled: %v", err)
	}
	// A serve pends in the collapse window; a history read is one of the
	// moments that must flush it to the sink.
	_ = s.history()
	if err := c.GrantRevoke(st.ID); err != nil {
		t.Fatalf("GrantRevoke: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	find := func(want string, match func(SessionEvent) bool) {
		t.Helper()
		for _, e := range sunk {
			if match(e) {
				return
			}
		}
		var kinds []string
		for _, e := range sunk {
			kinds = append(kinds, fmt.Sprintf("%s/%s(%s)", e.Kind, e.Op, e.Cause))
		}
		t.Errorf("sink never received %s; got: %s", want, strings.Join(kinds, ", "))
	}
	find("the creation approval (KindApproved, op grant_create, unattended wording)", func(e SessionEvent) bool {
		return e.Kind == KindApproved && e.Op == OpGrantCreate && strings.Contains(e.Cause, "unattended for")
	})
	find("the grant serve (KindUse, op grant_use, path in labels)", func(e SessionEvent) bool {
		return e.Kind == KindUse && e.Op == OpGrantUse && containsString(e.Labels, "jamf/api-pass")
	})
	find("the ending (KindGrantEnd, revoked, paths in labels)", func(e SessionEvent) bool {
		return e.Kind == KindGrantEnd && strings.Contains(e.Cause, grantEndRevoked) && containsString(e.Labels, "jamf/api-pass")
	})
}

// assertGrantEndEvent asserts history carries a KindGrantEnd whose cause
// names how the grant ended.
func assertGrantEndEvent(t *testing.T, s *Server, cause string) {
	t.Helper()
	for _, e := range s.history() {
		if e.Kind == KindGrantEnd && strings.Contains(e.Cause, cause) {
			if len(e.Labels) == 0 {
				t.Errorf("grant_end event carries no secret paths: %+v", e)
			}
			return
		}
	}
	t.Errorf("no grant_end event with cause %q in history: %s", cause, historyKinds(s))
}

func historyKinds(s *Server) string {
	var kinds []string
	for _, e := range s.history() {
		kinds = append(kinds, fmt.Sprintf("%s(%s)", e.Kind, e.Cause))
	}
	return strings.Join(kinds, ", ")
}

// TestGrantExtendRefusesADeadRoot: creation verifies the root's fork-time
// stamp on both sides of its challenge, and every serve re-checks it — extend
// did neither. A human could be asked to widen the window of a grant whose
// root had already exited, approve it, and get back a status hard-coding
// RootAlive true; the next prune would end it moments later. The prompt bought
// nothing and the answer described a grant that was already over.
func TestGrantExtendRefusesADeadRoot(t *testing.T) {
	var calls int32
	s, socketPath, cleanup := startTestServer(t, time.Minute, &calls)
	defer cleanup()

	sec := sealGrantSecret(t, "jamf/api-pass", "mcp", bytes.Repeat([]byte{0x07}, 32))
	wireGrantResolver(s, sec)

	// A real short-lived child: its pid is genuine at creation and genuinely
	// gone afterwards, so this exercises the actual lineage check.
	cmd := exec.Command("/bin/sh", "-c", "sleep 30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the grant root: %v", err)
	}
	rootPID := int32(cmd.Process.Pid) // #nosec G115 -- a pid from the OS

	c := NewClient(socketPath)
	st, err := c.GrantCreate(rootPID, "", []string{"jamf"}, "", time.Hour)
	if err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("GrantCreate: %v", err)
	}

	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()

	before := atomic.LoadInt32(&calls)
	_, err = c.GrantExtend(st.ID, 2*time.Hour)
	if err == nil {
		t.Fatal("extending a grant whose root has exited must fail, not report RootAlive true")
	}
	if !strings.Contains(err.Error(), "exited") {
		t.Errorf("the error must say the process is gone, got %q", err)
	}
	if got := atomic.LoadInt32(&calls); got != before {
		t.Errorf("the dead root was checked AFTER prompting (%d -> %d): a Touch ID that can buy nothing must not be asked for", before, got)
	}
}

// Every arming used to leave its predecessor running, up to a week out,
// holding the id and its closure — so a grant extended through a working week
// accumulated a pile of live timers. Each was harmless (they re-check the
// deadline before acting) but the pile was unbounded.
func TestGrantExpiryTimersDoNotAccumulate(t *testing.T) {
	var calls int32
	s, socketPath, cleanup := startTestServer(t, time.Minute, &calls)
	defer cleanup()

	sec := sealGrantSecret(t, "jamf/api-pass", "mcp", bytes.Repeat([]byte{0x07}, 32))
	wireGrantResolver(s, sec)

	c := NewClient(socketPath)
	st, err := c.GrantCreate(int32(os.Getpid()), "", []string{"jamf"}, "", time.Hour) // #nosec G115 -- test pid
	if err != nil {
		t.Fatalf("GrantCreate: %v", err)
	}
	for i := 0; i < 10; i++ {
		if _, err := c.GrantExtend(st.ID, time.Duration(i+2)*time.Hour); err != nil {
			t.Fatalf("GrantExtend %d: %v", i, err)
		}
	}

	s.grantMu.Lock()
	timers := len(s.grantTimers)
	s.grantMu.Unlock()
	if timers != 1 {
		t.Errorf("one grant extended 10 times holds %d timers, want 1", timers)
	}

	// Ending the grant leaves none behind.
	if err := c.GrantRevoke(st.ID); err != nil {
		t.Fatalf("GrantRevoke: %v", err)
	}
	s.grantMu.Lock()
	timers = len(s.grantTimers)
	s.grantMu.Unlock()
	if timers != 0 {
		t.Errorf("a revoked grant left %d timers armed, want 0", timers)
	}
}
