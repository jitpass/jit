// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/consent"
	"github.com/jitpass/jit/internal/lineage"
)

// fnFetcher is a MEKFetcher whose behavior a test controls per prompt reason,
// so a consent challenge ("… wants your … credential") can be declined while
// an ordinary unlock still succeeds.
type fnFetcher struct {
	fn func(reason string) ([]byte, error)
}

func (f fnFetcher) FetchMEK(reason string) ([]byte, error) { return f.fn(reason) }

var errConsentDeclined = errors.New("fixture: consent declined")

// startConsentServer is a real Server with consent enabled and a fetcher that
// declines any DISCLOSED challenge while denyConsent is set — a consent
// prompt, a --with grant, or a --trust registration — while still letting an
// ordinary unlock through. Keyed on the reason not being a plain unlock,
// rather than on one prompt's wording, so a new kind of disclosed gate is
// covered by default instead of silently sailing past the fixture.
//
// It also injects the caller's launcher: consent now keys its session cache on
// the tool that reached for the credential (consentCaller), which is an
// ancestor of the socket peer — but a test process cannot choose its own
// parents, so the real ancestry is whatever ran `go test`, and unstable. The
// returned *atomic.Pointer[string] is that launcher's exec path (default
// "/usr/local/bin/aws"); a test sets it to model a different tool, and "" to
// model an unresolvable launcher (a human at a bare shell). The real peer pid is
// preserved so the trust-descent path, which walks the ACTUAL process tree,
// still works.
func startConsentServer(t *testing.T, denyConsent *atomic.Bool) (*Server, string, *atomic.Pointer[string]) {
	t.Helper()
	key := bytes.Repeat([]byte{0x42}, 32)
	newFetcher := func() MEKFetcher {
		return fnFetcher{fn: func(reason string) ([]byte, error) {
			if denyConsent.Load() && !strings.HasPrefix(reason, "unlock the vault") {
				return nil, errConsentDeclined
			}
			k := make([]byte, len(key))
			copy(k, key)
			return k, nil
		}}
	}
	s := NewServer(shortSocketPath(t), newFetcher, time.Minute)
	s.Consent = consent.New(time.Minute)
	// Several of these tests flip a decline to an approval and retry
	// immediately, which the disclosed-prompt backoff would (correctly)
	// pause. That backoff has its own tests; here it would only buy sleep.
	s.discloseBackoff = nil

	var launcher atomic.Pointer[string]
	aws := "/usr/local/bin/aws"
	launcher.Store(&aws)
	s.identify = func(conn net.Conn) *caller {
		c := callerFromConn(conn)
		if c == nil {
			return nil
		}
		// Replace only the ancestry (keeping the real pid + self): an empty
		// stored path models an all-relay chain with no explanatory launcher.
		if p := launcher.Load(); p != nil && *p != "" {
			c.ancestors = []lineage.Process{{PID: 424242, ExecPath: *p}}
		} else {
			c.ancestors = nil
		}
		return c
	}

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx); close(done) }()
	t.Cleanup(func() { cancel(); _ = s.Close(); <-done })
	return s, s.socketPath, &launcher
}

// A consent prompt names the credential from req.Class — a field the caller
// sends, which nothing verifies until open() checks it against the AEAD much
// later. That made the prompt free to summon: any process that could reach the
// socket could claim a class it has no wrap for and put a Touch ID dialog on
// the screen, with no vault data of any kind.
func TestGarbageUnwrapNeverReachesTheUser(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	var disclosed atomic.Int32
	newFetcher := func() MEKFetcher {
		return fnFetcher{fn: func(reason string) ([]byte, error) {
			if !strings.HasPrefix(reason, "unlock the vault") {
				disclosed.Add(1)
			}
			k := make([]byte, len(key))
			copy(k, key)
			return k, nil
		}}
	}
	s := NewServer(shortSocketPath(t), newFetcher, time.Minute)
	s.Consent = consent.New(time.Minute)
	s.identify = func(conn net.Conn) *caller {
		c := callerFromConn(conn)
		if c == nil {
			return nil
		}
		c.ancestors = []lineage.Process{{PID: 424242, ExecPath: "/usr/local/bin/aws"}}
		return c
	}
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx); close(done) }()
	t.Cleanup(func() { cancel(); _ = s.Close(); <-done })

	c := NewClient(s.socketPath)
	dek := bytes.Repeat([]byte{0x07}, 32)

	// An ungated wrap opens the session without any disclosed prompt.
	if _, err := c.WrapKeyLabeled(dek, "app/.env/API_KEY", "dotenv"); err != nil {
		t.Fatalf("WrapKeyLabeled(dotenv): %v", err)
	}
	if n := disclosed.Load(); n != 0 {
		t.Fatalf("session setup produced %d disclosed prompt(s), want 0", n)
	}

	// The attack: a gated class the caller has no wrap for.
	for i := 0; i < 25; i++ {
		if _, err := c.UnwrapKeyLabeled([]byte("not a wrap at all"), "aws/default/key", "aws"); err == nil {
			t.Fatalf("request %d: unwrapping garbage must fail", i)
		}
	}
	if n := disclosed.Load(); n != 0 {
		t.Errorf("25 garbage requests produced %d prompt(s), want 0 — a caller with no vault data must not be able to summon one", n)
	}

	// Control: a caller that genuinely holds an aws wrap is still asked, so the
	// check rejects impostors rather than the gate itself.
	wrappedAWS, err := c.WrapKeyLabeled(dek, "aws/default/key", "aws")
	if err != nil {
		t.Fatalf("WrapKeyLabeled(aws): %v", err)
	}
	if _, err := c.UnwrapKeyLabeled(wrappedAWS, "aws/default/key", "aws"); err != nil {
		t.Fatalf("a genuine aws unwrap must still work: %v", err)
	}
	if n := disclosed.Load(); n != 1 {
		t.Errorf("a real aws unwrap produced %d prompt(s), want exactly 1", n)
	}
}

// `jit unlock` clears consent pauses because a human at the keyboard saying
// "now" is exactly what a refusal withheld. But OpUnlock against an
// already-open session challenges NOBODY and still returns OK — so clearing on
// success alone would hand every process on the machine a free reset, and the
// flood the backoff exists to stop would come back with one extra syscall per
// round. Only a FRESH challenge may clear it.
func TestUnlockOnLiveSessionDoesNotClearTheBackoff(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	var prompts atomic.Int32
	var denyConsent atomic.Bool
	newFetcher := func() MEKFetcher {
		return fnFetcher{fn: func(reason string) ([]byte, error) {
			if !strings.HasPrefix(reason, "unlock the vault") {
				prompts.Add(1)
				if denyConsent.Load() {
					return nil, errConsentDeclined
				}
			}
			k := make([]byte, len(key))
			copy(k, key)
			return k, nil
		}}
	}
	s := NewServer(shortSocketPath(t), newFetcher, time.Minute)
	s.Consent = consent.New(time.Minute)
	s.identify = func(conn net.Conn) *caller {
		c := callerFromConn(conn)
		if c == nil {
			return nil
		}
		c.ancestors = []lineage.Process{{PID: 424242, ExecPath: "/usr/local/bin/aws"}}
		return c
	}
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx); close(done) }()
	t.Cleanup(func() { cancel(); _ = s.Close(); <-done })

	c := NewClient(s.socketPath)
	dek := bytes.Repeat([]byte{0x07}, 32)
	wrapped, err := c.WrapKeyLabeled(dek, "aws/default/key", "aws")
	if err != nil {
		t.Fatalf("WrapKeyLabeled: %v", err)
	}

	// Earn a pause: one refused consent prompt.
	denyConsent.Store(true)
	if _, err := c.UnwrapKeyLabeled(wrapped, "aws/default/key", "aws"); err == nil {
		t.Fatal("expected the refused consent to deny the unwrap")
	}
	if got := prompts.Load(); got != 1 {
		t.Fatalf("prompts=%d after the first refusal, want 1", got)
	}

	// The attack: unlock an already-unlocked agent, then ask again. Repeated,
	// because one free reset per round is all the flood ever needed.
	for i := 0; i < 10; i++ {
		if _, _, err := c.Unlock(); err != nil {
			t.Fatalf("Unlock (round %d): %v", i, err)
		}
		_, _ = c.UnwrapKeyLabeled(wrapped, "aws/default/key", "aws")
	}
	if got := prompts.Load(); got != 1 {
		t.Errorf("prompts=%d after 10 unlock+retry rounds, want 1: OpUnlock on a live session must not clear the pause", got)
	}

	// The override itself must still work. A real lock means the next unlock
	// is a fresh challenge — a human — and that clears the pause.
	if err := c.Lock(); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if _, _, err := c.Unlock(); err != nil {
		t.Fatalf("Unlock after Lock: %v", err)
	}
	denyConsent.Store(false)
	if _, err := c.UnwrapKeyLabeled(wrapped, "aws/default/key", "aws"); err != nil {
		t.Fatalf("after a fresh unlock the request should reach the user again: %v", err)
	}
	if got := prompts.Load(); got != 2 {
		t.Errorf("prompts=%d, want 2 — a fresh unlock clears the pause so the next ask reaches the user", got)
	}
}

// Rejecting the attack silently would make the successful defense invisible to
// the one person who'd want to know it happened — but the record has to be
// aggregated, or the rejection becomes an eviction primitive: the ring holds
// MaxSessionEvents oldest-first, so an event an unauthenticated caller can
// mint on demand would let a flood erase every real unlock and denial, and
// with them the record of the flood itself.
func TestRejectedClassIsRecordedButCollapsed(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	newFetcher := func() MEKFetcher { return &fakeFetcher{key: key} }
	s := NewServer(shortSocketPath(t), newFetcher, time.Minute)
	s.Consent = consent.New(time.Minute)
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx); close(done) }()
	t.Cleanup(func() { cancel(); _ = s.Close(); <-done })

	c := NewClient(s.socketPath)
	if _, err := c.WrapKeyLabeled(bytes.Repeat([]byte{0x07}, 32), "app/.env/K", "dotenv"); err != nil {
		t.Fatalf("WrapKeyLabeled: %v", err)
	}

	const attempts = 50
	for i := 0; i < attempts; i++ {
		if _, err := c.UnwrapKeyLabeled([]byte("not a wrap at all"), "aws/default/key", "aws"); err == nil {
			t.Fatalf("attempt %d: unwrapping garbage must fail", i)
		}
	}

	events := s.history()
	var mismatches int
	var count int64
	for _, e := range events {
		if e.Op == opClassMismatch {
			mismatches++
			count += e.Count
		}
	}
	if mismatches == 0 {
		t.Error("a rejected class binding left no trace in history; the defense is invisible")
	}
	if mismatches > 3 {
		t.Errorf("%d attempts produced %d separate events, want them collapsed — history must not be floodable", attempts, mismatches)
	}
	if count < attempts {
		t.Errorf("collapsed events account for %d attempts, want at least %d", count, attempts)
	}
	if len(events) >= MaxSessionEvents {
		t.Errorf("history reached %d events from %d junk requests: the ring is evictable by an unauthenticated caller", len(events), attempts)
	}
}

// Collapsing per CALLER is no defense when the caller is what varies:
// useKey.by is the peer's own argv, so one fork per event buys a fresh
// aggregate and a few hundred execs push every real unlock and denial out of
// the ring — the attack erasing the record of itself. Rejections therefore
// collapse on the op alone.
func TestRejectionsCollapseAcrossDifferentCallers(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	s := NewServer(shortSocketPath(t), func() MEKFetcher { return &fakeFetcher{key: key} }, time.Minute)

	// Each "caller" wears a different argv, which is all an attacker needs to
	// mint a distinct identity.
	for i := 0; i < 300; i++ {
		s.recordRejectedClass(&caller{
			pid:  int32(1000 + i),
			self: lineage.Process{PID: int32(1000 + i), ExecPath: fmt.Sprintf("/tmp/x%d/probe", i)},
		})
	}

	events := s.history()
	var mismatches int
	for _, e := range events {
		if e.Op == opClassMismatch {
			mismatches++
		}
	}
	if mismatches != 1 {
		t.Errorf("300 rejections from 300 distinct argvs produced %d events, want 1 — varying identity must not multiply the ring", mismatches)
	}
	if len(events) >= MaxSessionEvents {
		t.Errorf("history reached %d events, want far below %d: the ring must not be evictable by an unauthenticated caller", len(events), MaxSessionEvents)
	}
}

// A request that fails verification must not renew the session it failed
// against, or a caller could hold the MEK resident indefinitely with a stream
// of ciphertext it never had the key for.
func TestFailedVerificationDoesNotExtendTheSession(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	newFetcher := func() MEKFetcher { return &fakeFetcher{key: key} }
	s := NewServer(shortSocketPath(t), newFetcher, time.Minute)

	if _, err := s.WrapKeyLabeled(bytes.Repeat([]byte{0x07}, 32), "", "dotenv"); err != nil {
		t.Fatalf("WrapKeyLabeled: %v", err)
	}

	s.mu.Lock()
	before := s.expiry
	s.mu.Unlock()

	if err := s.verifyClassBinding([]byte("not a wrap at all"), "aws", nil); err == nil {
		t.Fatal("verifying garbage must fail")
	}

	s.mu.Lock()
	after := s.expiry
	s.mu.Unlock()
	if !after.Equal(before) {
		t.Errorf("expiry moved from %s to %s: a rejected request must not buy the session more time", before, after)
	}
}

func TestConsentGateAllowsDeniesAndCaches(t *testing.T) {
	var deny atomic.Bool
	s, socket, _ := startConsentServer(t, &deny)
	c := NewClient(socket)
	dek := bytes.Repeat([]byte{0x07}, 32)

	// Wrapping is not gated (it's a write). This also unlocks the session.
	wrappedAWS, err := c.WrapKeyLabeled(dek, "aws/default/key", "aws")
	if err != nil {
		t.Fatalf("WrapKeyLabeled(aws): %v", err)
	}

	// Approve path: session unlocked, consent challenge approved -> unwrap works.
	got, err := c.UnwrapKeyLabeled(wrappedAWS, "aws/default/key", "aws")
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("approved unwrap: got %x err %v, want the dek allowed", got, err)
	}

	// Cached: a second unwrap this session is not re-prompted, so even flipping
	// to deny now must still allow (the session decision holds).
	deny.Store(true)
	if _, err := c.UnwrapKeyLabeled(wrappedAWS, "aws/default/key", "aws"); err != nil {
		t.Errorf("a cached session allow must hold: %v", err)
	}

	// A project-class secret (dotenv) is never gated, deny flag notwithstanding.
	wrappedEnv, err := c.WrapKeyLabeled(dek, "app/.env/API_KEY", "dotenv")
	if err != nil {
		t.Fatalf("WrapKeyLabeled(dotenv): %v", err)
	}
	if _, err := c.UnwrapKeyLabeled(wrappedEnv, "app/.env/API_KEY", "dotenv"); err != nil {
		t.Errorf("dotenv must never be gated: %v", err)
	}

	// Deny path: re-locking clears the consent cache; with deny set, the fresh
	// consent challenge is declined and the unwrap must fail closed.
	s.LockWithCause("test re-lock")
	deny.Store(true)
	if _, err := c.UnwrapKeyLabeled(wrappedAWS, "aws/default/key", "aws"); err == nil {
		t.Error("a declined consent must deny the unwrap (fail closed)")
	}
}

// TestDeniedUnwrapIsNotRecordedAsUse pins the finding-6 fix: consent is gated
// before ensureUnlocked, so a denied unwrap never rides the unlocked session as
// a KindUse. History should show the denial, not a use of a credential that
// never flowed.
func TestDeniedUnwrapIsNotRecordedAsUse(t *testing.T) {
	var deny atomic.Bool
	_, socket, _ := startConsentServer(t, &deny)
	c := NewClient(socket)
	dek := bytes.Repeat([]byte{0x07}, 32)

	// Wrap unlocks the session (fresh challenge -> an unlock event, no use).
	wrapped, err := c.WrapKeyLabeled(dek, "aws/default/key", "aws")
	if err != nil {
		t.Fatalf("WrapKeyLabeled: %v", err)
	}

	// The session is now unlocked, so an unwrap would ride it as a use — but
	// consent is declined, so the unwrap must fail closed BEFORE recording one.
	deny.Store(true)
	if _, err := c.UnwrapKeyLabeled(wrapped, "aws/default/key", "aws"); err == nil {
		t.Fatal("a declined consent must deny the unwrap")
	}

	events, err := c.History()
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	for _, e := range events {
		if e.Kind == KindUse && e.Op == OpUnwrap {
			t.Errorf("a denied unwrap must not be recorded as a use: %+v", e)
		}
	}
}

// TestConsentTrustDescentSkipsPrompt pins phase 1c: a caller inside a
// --trust'd run's tree is auto-allowed with no prompt, and re-locking clears
// that trust.
func TestConsentTrustDescentSkipsPrompt(t *testing.T) {
	var deny atomic.Bool
	s, socket, _ := startConsentServer(t, &deny)
	c := NewClient(socket)
	dek := bytes.Repeat([]byte{0x07}, 32)

	wrapped, err := c.WrapKeyLabeled(dek, "aws/default/key", "aws")
	if err != nil {
		t.Fatalf("WrapKeyLabeled: %v", err)
	}

	// Register this process (the socket peer) as a trust root: the test IS the
	// caller, so its own unwrap descends from the trust trivially.
	if err := c.Trust(); err != nil {
		t.Fatalf("Trust: %v", err)
	}

	// With every consent prompt now denied, a trusted caller must STILL succeed
	// because it skips the prompt entirely.
	deny.Store(true)
	got, err := c.UnwrapKeyLabeled(wrapped, "aws/default/key", "aws")
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("a trusted caller must skip the prompt and unwrap: got %x err %v", got, err)
	}

	// Re-locking clears trust, so the same unwrap now prompts and is denied.
	s.LockWithCause("relock")
	if _, err := c.UnwrapKeyLabeled(wrapped, "aws/default/key", "aws"); err == nil {
		t.Error("re-lock must clear trust, so a denied consent blocks again")
	}
}

// TestConsentCallerKeysOnLauncher pins the keying fix directly: the consent
// cache key must be the tool that reached for the credential (the nearest
// explanatory ancestor), never the jit helper that carried the request (c.self,
// always the jit binary). An all-relay chain resolves no launcher, which must
// leave ExecPath empty so the engine refuses to cache — fail-safe.
func TestConsentCallerKeysOnLauncher(t *testing.T) {
	jit := lineage.Process{PID: 10, ExecPath: "/usr/local/bin/jit"}

	// aws launched the helper: key on aws, not jit.
	c := &caller{
		pid:  10,
		self: jit,
		ancestors: []lineage.Process{
			{PID: 20, ExecPath: "/usr/local/bin/aws"},
			{PID: 30, ExecPath: "/bin/zsh"},
		},
	}
	if got := consentCaller(c).ExecPath; got != "/usr/local/bin/aws" {
		t.Errorf("ExecPath = %q, want the launcher /usr/local/bin/aws (not the jit helper)", got)
	}

	// Relays all the way up (a human at a shell): no launcher, empty key.
	relayOnly := &caller{
		pid:       10,
		self:      jit,
		ancestors: []lineage.Process{{PID: 30, ExecPath: "/bin/zsh"}},
	}
	if got := consentCaller(relayOnly).ExecPath; got != "" {
		t.Errorf("ExecPath = %q, want empty (unresolvable launcher must not cache)", got)
	}

	// A nil caller stays inert (an in-process call that never touched the socket).
	if got := consentCaller(nil).ExecPath; got != "" {
		t.Errorf("nil caller ExecPath = %q, want empty", got)
	}
}

// TestConsentIsPerLauncherNotPerClass is the end-to-end proof of the fix: two
// different tools reaching for the SAME credential class do not share one
// approval. Approving aws for the aws CLI must not silently cover a python
// script's aws in the same session — the exact over-sharing the old per-class
// key allowed.
func TestConsentIsPerLauncherNotPerClass(t *testing.T) {
	var deny atomic.Bool
	_, socket, launcher := startConsentServer(t, &deny)
	c := NewClient(socket)
	dek := bytes.Repeat([]byte{0x07}, 32)

	wrapped, err := c.WrapKeyLabeled(dek, "aws/default/key", "aws")
	if err != nil {
		t.Fatalf("WrapKeyLabeled: %v", err)
	}

	// aws (the CLI) asks and is approved -> cached under (aws, aws-path).
	if _, err := c.UnwrapKeyLabeled(wrapped, "aws/default/key", "aws"); err != nil {
		t.Fatalf("aws launcher should be approved: %v", err)
	}

	// A DIFFERENT tool (python) now reaches for the same aws credential. With
	// every prompt denied, it must be blocked: its key differs, so it does NOT
	// ride the aws CLI's approval.
	python := "/usr/local/bin/python3"
	launcher.Store(&python)
	deny.Store(true)
	if _, err := c.UnwrapKeyLabeled(wrapped, "aws/default/key", "aws"); err == nil {
		t.Error("a different launcher must re-prompt (and be denied), not ride aws's approval")
	}

	// Back to the aws CLI: its session approval still holds despite deny, proving
	// the first decision was scoped to that launcher and never cleared.
	aws := "/usr/local/bin/aws"
	launcher.Store(&aws)
	if _, err := c.UnwrapKeyLabeled(wrapped, "aws/default/key", "aws"); err != nil {
		t.Errorf("the original aws launcher's session approval must still hold: %v", err)
	}
}

// TestTrustRequiresAChallenge pins the fix for an outright consent bypass.
// OpTrust registers the caller's process tree as a consent trust root, which
// auto-allows every gated credential its descendants touch for the rest of the
// session — and it used to require nothing at all. Any process that could
// reach the socket could send one `trust` RPC and switch off the gate that
// exists precisely for untrusted code running as you. `jit run --trust` is a
// flag a human types; the prompt is what makes the RPC mean that.
func TestTrustRequiresAChallenge(t *testing.T) {
	var deny atomic.Bool
	deny.Store(true) // decline every disclosed challenge, including trust's
	_, socket, _ := startConsentServer(t, &deny)
	c := NewClient(socket)
	dek := bytes.Repeat([]byte{0x07}, 32)

	wrapped, err := c.WrapKeyLabeled(dek, "aws/default/key", "aws")
	if err != nil {
		t.Fatalf("WrapKeyLabeled: %v", err)
	}
	if _, err := c.UnwrapKeyLabeled(wrapped, "aws/default/key", "aws"); err == nil {
		t.Fatal("precondition: a declined consent must deny the unwrap")
	}

	if err := c.Trust(); err == nil {
		t.Error("a declined trust challenge must fail the RPC")
	}
	if _, err := c.UnwrapKeyLabeled(wrapped, "aws/default/key", "aws"); err == nil {
		t.Error("BYPASS: an unapproved trust root disabled the consent gate")
	}

	// And with the challenge approved, trust does what it always did.
	deny.Store(false)
	if err := c.Trust(); err != nil {
		t.Fatalf("approved Trust: %v", err)
	}
	deny.Store(true) // no further prompt may be needed now
	if _, err := c.UnwrapKeyLabeled(wrapped, "aws/default/key", "aws"); err != nil {
		t.Errorf("an approved trust root must serve without further prompts: %v", err)
	}
}

// The trust prompt must say what trusting actually means. "and everything it
// launches" is the entire scope of the flag, and the only part of the sentence
// that would change anyone's answer, so it may never be what gets truncated.
func TestTrustReasonStatesTheScope(t *testing.T) {
	long := &caller{pid: 4242, self: lineage.Process{
		PID:  4242,
		Argv: []string{"/opt/some/deeply/nested/path/a-very-long-program-name-indeed"},
	}}
	for _, c := range []*caller{nil, long, {pid: 7}} {
		reason := trustReason(c)
		if !strings.Contains(reason, "everything it launches") && !strings.Contains(reason, "without further prompts") {
			t.Errorf("trustReason(%v) = %q, want the scope stated", c, reason)
		}
		if len([]rune(reason)) > maxReasonLen {
			t.Errorf("trustReason = %q (%d runes), want <= %d", reason, len([]rune(reason)), maxReasonLen)
		}
	}
}

// A consent prompt leads with the ask ("use your <class> credential"), must
// not let a program's own filename disguise where it came from, and must not
// be long enough for macOS to clip the dialog.
func TestConsentReasonDisambiguatesAndStaysBounded(t *testing.T) {
	standard := consentReason(consent.Request{
		Credential: "gcp",
		Caller:     consent.Caller{PID: 1, ExecPath: "/usr/local/bin/gcloud"},
	})
	if !strings.HasPrefix(standard, "use your gcp credential for gcloud") {
		t.Errorf("standard tool dir reason = %q, want the ask first, then the bare tool name", standard)
	}

	// Legitimate install trees put the binary in a versioned or vendored
	// subdirectory — spelling those paths out is the wall of text that made
	// the prompt unreadable, so they render by name alone too.
	for _, tc := range []struct{ path, name string }{
		{"/opt/homebrew/Caskroom/claude-code/2.1.212/claude", "claude"},
		{"/Library/Developer/CommandLineTools/usr/libexec/git-core/git-remote-http", "git-remote-http"},
		{"/usr/libexec/git-core/git-remote-http", "git-remote-http"},
	} {
		got := consentReason(consent.Request{
			Credential: "git",
			Caller:     consent.Caller{PID: 1, ExecPath: tc.path},
		})
		if want := "use your git credential for " + tc.name; got != want {
			t.Errorf("reason for %s = %q, want %q", tc.path, got, want)
		}
	}

	impostor := consentReason(consent.Request{
		Credential: "gcp",
		Caller:     consent.Caller{PID: 1, ExecPath: "/tmp/evil/gcloud"},
	})
	if !strings.Contains(impostor, "/tmp/evil") {
		t.Errorf("reason = %q, want a non-standard location shown, not rendered as a bare %q", impostor, "gcloud")
	}

	huge := consentReason(consent.Request{
		Credential: "gcp",
		Caller: consent.Caller{
			PID:      1,
			ExecPath: "/tmp/" + strings.Repeat("a", 400) + "/gcloud",
			Lineage:  strings.Repeat("b", 400),
		},
	})
	if len([]rune(huge)) > maxReasonLen {
		t.Errorf("reason is %d runes, want <= %d", len([]rune(huge)), maxReasonLen)
	}
	if !strings.HasPrefix(huge, "use your gcp credential") {
		t.Errorf("reason = %q, want the credential name intact at the start", huge)
	}
	if !strings.Contains(huge, "gcloud") {
		t.Errorf("reason = %q, want the program name kept when a long path is trimmed", huge)
	}
}

// A repeated request has to look different from a first one — that difference
// is the only thing distinguishing "I asked for this" from "something is
// asking in a loop" — and saying so must never cost the credential's name its
// place in the dialog.
func TestConsentReasonReportsRepeatedRefusals(t *testing.T) {
	req := consent.Request{
		Credential: "gcp",
		Caller:     consent.Caller{PID: 1, ExecPath: "/usr/local/bin/gcloud"},
	}
	if got := consentReason(req); strings.Contains(got, "refused") {
		t.Errorf("first ask = %q, want no refusal count", got)
	}

	req.PriorRefusals = 1
	if got := consentReason(req); !strings.Contains(got, "refused once") {
		t.Errorf("second ask = %q, want it to report the earlier refusal", got)
	}

	req.PriorRefusals = 7
	seventh := consentReason(req)
	if !strings.Contains(seventh, "refused 7 times") {
		t.Errorf("eighth ask = %q, want the refusal count", seventh)
	}
	if !strings.Contains(seventh, "gcp credential") {
		t.Errorf("reason = %q, want the credential still named", seventh)
	}

	req.Caller.ExecPath = "/tmp/" + strings.Repeat("a", 400) + "/gcloud"
	req.Caller.Lineage = "launched by " + strings.Repeat("b", 400)
	if got := consentReason(req); len([]rune(got)) > maxReasonLen {
		t.Errorf("reason is %d runes, want <= %d", len([]rune(got)), maxReasonLen)
	}
}

// The FIFO path's identity is a process scan, not a kernel-vouched peer, and
// the prompt says so. That qualifier used to be appended AFTER the whole line
// was truncated from the tail — so as soon as a refusal count made the line
// long enough, the count was sliced mid-word and the user read a dangling
// "(…". Every decision-carrying part has to survive together, at every count.
func TestBestEffortReasonKeepsEveryDecisionPart(t *testing.T) {
	for _, n := range []int{0, 1, 3, 12, 400} {
		req := consent.Request{
			Credential:    "gcp",
			PriorRefusals: n,
			Caller: consent.Caller{
				PID:      1,
				ExecPath: "/usr/local/bin/gcloud",
				Lineage:  "npm install",
				Strength: consent.BestEffort,
			},
		}
		got := consentReason(req)

		if len([]rune(got)) > maxReasonLen {
			t.Errorf("n=%d: reason is %d runes, want <= %d: %q", n, len([]rune(got)), maxReasonLen, got)
		}
		if !strings.Contains(got, "identified by scan") {
			t.Errorf("n=%d: reason = %q, want the best-effort qualifier intact", n, got)
		}
		// The launcher survives a first ask — it used to be dropped from every
		// FIFO prompt, which is why the qualifier was shortened. Once there is
		// a refusal count to report it yields to that, which is the right
		// order: how many times you've already said no outranks who launched
		// the caller.
		if n == 0 && !strings.Contains(got, "npm install") {
			t.Errorf("n=0: reason = %q, want the launcher kept — the scan path is where that context matters most", got)
		}
		if !strings.Contains(got, "gcp credential") {
			t.Errorf("n=%d: reason = %q, want the credential named", n, got)
		}
		if strings.Contains(got, "(…") {
			t.Errorf("n=%d: reason = %q, want no half-truncated parenthetical", n, got)
		}
		if n > 0 && !strings.Contains(got, "refused") {
			t.Errorf("n=%d: reason = %q, want the refusal count kept", n, got)
		}
	}
}

// The unidentified fallback ("a process (pid N)") is the case that reaches the
// highest refusal counts, since every anonymous caller shares one throttle key
// — and it was the one path exempt from the length budget. macOS clips an
// over-long reason itself, which would cut off the very qualifier the tail
// ordering exists to protect.
func TestUnidentifiedBestEffortReasonStaysInBudget(t *testing.T) {
	for _, class := range []string{"gcp", "terraform"} {
		for _, n := range []int{0, 1, 3, 12, 400} {
			got := consentReason(consent.Request{
				Credential:    class,
				PriorRefusals: n,
				Caller: consent.Caller{
					PID:      987654,
					ExecPath: "", // unresolvable: the fallback path
					Lineage:  strings.Repeat("b", 200),
					Strength: consent.BestEffort,
				},
			})
			if len([]rune(got)) > maxReasonLen {
				t.Errorf("class=%s n=%d: reason is %d runes, want <= %d: %q", class, n, len([]rune(got)), maxReasonLen, got)
			}
			if !strings.Contains(got, class+" credential") {
				t.Errorf("class=%s n=%d: reason = %q, want the credential named", class, n, got)
			}
		}
	}
}

// A refused consent challenge must leave the credential REACHABLE: it earns a
// pause, never a standing Deny. The whole guarantee is one argument —
// gateConsent's prompter returns consent.Once on a failed challenge — and it
// lived in production code no test named, so changing it to consent.Session
// broke nothing and locked the credential out for the rest of the session.
//
// The discriminator needs no clock. With Once, the second attempt misses the
// decision cache and meets the post-refusal throttle, so a *consent.Throttled
// surfaces. With Session it would hit a cached Deny and never reach the
// throttle at all — a plain "not granted" error. Asserting on Throttled is
// therefore asserting on the scope.
func TestRefusedConsentPausesRatherThanStandingDeny(t *testing.T) {
	var deny atomic.Bool
	deny.Store(true)
	s, _, _ := startConsentServer(t, &deny)

	// "aws" rather than vault.ClassAWS: consent mirrors the class strings by
	// value on purpose (it does not import vault), and neither does this test.
	const class = "aws"
	c := &caller{
		pid:       424242,
		self:      lineage.Process{PID: 424242, ExecPath: "/usr/local/bin/aws"},
		ancestors: []lineage.Process{{PID: 424243, ExecPath: "/usr/local/bin/aws"}},
	}

	if err := s.gateConsent(class, c); err == nil {
		t.Fatal("a declined challenge granted access")
	}
	err := s.gateConsent(class, c)
	if err == nil {
		t.Fatal("second attempt granted access after a refusal")
	}
	var throttled *consent.Throttled
	if !errors.As(err, &throttled) {
		t.Errorf("after a refusal the next attempt must be PAUSED, not answered from a cached Deny; got %v", err)
	}
}
