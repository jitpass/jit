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
	"sync/atomic"
	"testing"
	"time"
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
	st, err := c.GrantCreate(int32(os.Getpid()), []string{"jamf"}, "", time.Hour) // #nosec G115 -- test pid
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

func TestGrantMissFallsThroughToOrdinaryUnlock(t *testing.T) {
	var calls int32
	s, socketPath, cleanup := startTestServer(t, time.Minute, &calls)
	defer cleanup()

	dek := bytes.Repeat([]byte{0x07}, 32)
	covered := sealGrantSecret(t, "jamf/api-pass", "mcp", dek)
	wireGrantResolver(s, covered)

	c := NewClient(socketPath)
	if _, err := c.GrantCreate(int32(os.Getpid()), []string{"jamf"}, "", time.Hour); err != nil { // #nosec G115 -- test pid
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
	if _, err := c.GrantCreate(int32(child.Process.Pid), []string{"jamf"}, "", time.Hour); err != nil { // #nosec G115 -- test pid
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
	if _, err := c.GrantCreate(pid, []string{"jamf"}, "", time.Hour); err != nil {
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
	st, err := c.GrantCreate(int32(os.Getpid()), []string{"jamf"}, "", time.Hour) // #nosec G115 -- test pid
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
	st, err := c.GrantCreate(int32(os.Getpid()), []string{"jamf"}, "", time.Hour) // #nosec G115 -- test pid
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
	st, err := c.GrantCreate(int32(os.Getpid()), []string{"jamf"}, "", time.Hour) // #nosec G115 -- test pid
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
	_, err = c.GrantCreate(int32(os.Getpid()), []string{"jamf", "aws"}, "", time.Hour) // #nosec G115 -- test pid
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
	got := grantCreateReason("claude", []string{"jamf", "aws-ci"}, 3, 8*time.Hour)
	want := "let claude use 3 secrets (jamf, aws-ci) unattended for 8h"
	if got != want {
		t.Errorf("grantCreateReason = %q, want %q", got, want)
	}
	if r := grantCreateReason("", []string{"p"}, 1, time.Minute); !strings.Contains(r, "this process") {
		t.Errorf("nameless reason = %q, want a 'this process' fallback", r)
	}
	long := grantCreateReason(strings.Repeat("x", 100), []string{strings.Repeat("y", 100)}, 12, 3*24*time.Hour)
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
