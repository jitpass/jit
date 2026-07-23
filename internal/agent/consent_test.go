// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package agent

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/consent"
)

// fnFetcher is a MEKFetcher whose behavior a test controls per prompt reason,
// so a consent challenge ("… wants your … credential") can be declined while
// an ordinary unlock still succeeds.
type fnFetcher struct{ fn func(reason string) ([]byte, error) }

func (f fnFetcher) FetchMEK(reason string) ([]byte, error) { return f.fn(reason) }

var errConsentDeclined = errors.New("fixture: consent declined")

// startConsentServer is a real Server with consent enabled and a fetcher that
// declines any consent-reason challenge while denyConsent is set.
func startConsentServer(t *testing.T, denyConsent *atomic.Bool) (*Server, string) {
	t.Helper()
	key := bytes.Repeat([]byte{0x42}, 32)
	newFetcher := func() MEKFetcher {
		return fnFetcher{fn: func(reason string) ([]byte, error) {
			if denyConsent.Load() && strings.Contains(reason, "wants your") {
				return nil, errConsentDeclined
			}
			k := make([]byte, len(key))
			copy(k, key)
			return k, nil
		}}
	}
	s := NewServer(shortSocketPath(t), newFetcher, time.Minute)
	s.Consent = consent.New(time.Minute)
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx); close(done) }()
	t.Cleanup(func() { cancel(); _ = s.Close(); <-done })
	return s, s.socketPath
}

func TestConsentGateAllowsDeniesAndCaches(t *testing.T) {
	var deny atomic.Bool
	s, socket := startConsentServer(t, &deny)
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

// TestConsentTrustDescentSkipsPrompt pins phase 1c: a caller inside a
// --trust'd run's tree is auto-allowed with no prompt, and re-locking clears
// that trust.
func TestConsentTrustDescentSkipsPrompt(t *testing.T) {
	var deny atomic.Bool
	s, socket := startConsentServer(t, &deny)
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
