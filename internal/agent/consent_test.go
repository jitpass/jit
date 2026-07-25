// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package agent

import (
	"bytes"
	"context"
	"errors"
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

// A consent prompt must not let a program's own filename disguise where it
// came from, and must not be long enough to push the credential's name out of
// the dialog.
func TestConsentReasonDisambiguatesAndStaysBounded(t *testing.T) {
	standard := consentReason(consent.Caller{PID: 1, ExecPath: "/usr/local/bin/gcloud"}, "gcp")
	if !strings.HasPrefix(standard, "gcloud wants your gcp") {
		t.Errorf("standard tool dir reason = %q, want the bare tool name", standard)
	}

	impostor := consentReason(consent.Caller{PID: 1, ExecPath: "/tmp/evil/gcloud"}, "gcp")
	if !strings.Contains(impostor, "/tmp/evil") {
		t.Errorf("reason = %q, want a non-standard location shown, not rendered as a bare %q", impostor, "gcloud")
	}

	huge := consentReason(consent.Caller{
		PID:      1,
		ExecPath: "/tmp/" + strings.Repeat("a", 400) + "/gcloud",
		Lineage:  "launched by " + strings.Repeat("b", 400),
	}, "gcp")
	if len([]rune(huge)) > maxReasonLen {
		t.Errorf("reason is %d runes, want <= %d", len([]rune(huge)), maxReasonLen)
	}
	if !strings.HasSuffix(huge, "wants your gcp credential") {
		t.Errorf("reason = %q, want the credential name intact at the end", huge)
	}
	if !strings.Contains(huge, "gcloud") {
		t.Errorf("reason = %q, want the program name kept when a long path is trimmed", huge)
	}
}
