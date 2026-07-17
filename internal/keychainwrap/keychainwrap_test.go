// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package keychainwrap

import (
	"bytes"
	"errors"
	"testing"
)

// noChallenge lets automated tests exercise the real keychain read/write
// and AES wrap/unwrap logic without an interactive Touch ID/passcode
// approval — nothing in a CI or headless run can click that dialog. The
// challenge call itself (kw_challenge) is verified separately by manual,
// interactive testing — same discipline as spike/secure-enclave's own
// "confirmed by direct observation" note.
func noChallenge(string) error { return nil }

func failChallenge(string) error { return errors.New("simulated auth failure") }

// testWrapper returns a Wrapper scoped to a dedicated, non-production
// keychain service name. Never reuse prodService/prodAccount in a test —
// see the real incident documented on the Wrapper type: a test run on a
// machine with a real vault already set up triggered a live macOS
// permission prompt for the actual production MEK, one click away from
// deleting the key protecting every secret already stored in that vault.
func testWrapper(challenge func(string) error) *Wrapper {
	return &Wrapper{service: "com.jitpass.vault.mek.TEST-ONLY", account: "test", challenge: challenge}
}

func cleanupTestMEK(t *testing.T, w *Wrapper) {
	t.Helper()
	_ = w.deleteMEK()
	t.Cleanup(func() { _ = w.deleteMEK() })
}

func TestEnsureMEKIdempotent(t *testing.T) {
	w := testWrapper(noChallenge)
	cleanupTestMEK(t, w)

	if err := w.EnsureMEK(); err != nil {
		t.Fatalf("EnsureMEK (first call): %v", err)
	}
	if err := w.EnsureMEK(); err != nil {
		t.Fatalf("EnsureMEK (second call, should be a no-op): %v", err)
	}
}

func TestWrapUnwrapRoundTrip(t *testing.T) {
	w := testWrapper(noChallenge)
	cleanupTestMEK(t, w)
	if err := w.EnsureMEK(); err != nil {
		t.Fatalf("EnsureMEK: %v", err)
	}

	dek := bytes.Repeat([]byte{0x07}, 32)
	wrapped, err := w.WrapKey(dek)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	if bytes.Equal(wrapped, dek) {
		t.Error("WrapKey returned the DEK unmodified, not actually wrapped")
	}

	got, err := w.UnwrapKey(wrapped)
	if err != nil {
		t.Fatalf("UnwrapKey: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Errorf("UnwrapKey = %x, want %x", got, dek)
	}
}

func TestWrapFailsWithoutEnsureMEK(t *testing.T) {
	w := testWrapper(noChallenge)
	cleanupTestMEK(t, w) // no EnsureMEK call after this, item stays absent

	if _, err := w.WrapKey(bytes.Repeat([]byte{0x01}, 32)); err == nil {
		t.Error("WrapKey succeeded with no MEK ever created, want an error")
	}
}

func TestChallengeFailureBlocksAccess(t *testing.T) {
	setupWrapper := testWrapper(noChallenge)
	cleanupTestMEK(t, setupWrapper)
	if err := setupWrapper.EnsureMEK(); err != nil {
		t.Fatalf("EnsureMEK: %v", err)
	}

	w := testWrapper(failChallenge)
	if _, err := w.WrapKey(bytes.Repeat([]byte{0x01}, 32)); err == nil {
		t.Error("WrapKey succeeded despite a failed local-auth challenge, want an error")
	}
	if _, err := w.UnwrapKey(bytes.Repeat([]byte{0x01}, 48)); err == nil {
		t.Error("UnwrapKey succeeded despite a failed local-auth challenge, want an error")
	}
}

func TestWrapperCachesMEKAcrossMultipleCalls(t *testing.T) {
	setupWrapper := testWrapper(noChallenge)
	cleanupTestMEK(t, setupWrapper)
	if err := setupWrapper.EnsureMEK(); err != nil {
		t.Fatalf("EnsureMEK: %v", err)
	}

	var challengeCalls int
	countingChallenge := func(string) error {
		challengeCalls++
		return nil
	}
	w := testWrapper(countingChallenge)

	for i := 0; i < 3; i++ {
		dek := bytes.Repeat([]byte{byte(i)}, 32)
		wrapped, err := w.WrapKey(dek)
		if err != nil {
			t.Fatalf("WrapKey (call %d): %v", i, err)
		}
		got, err := w.UnwrapKey(wrapped)
		if err != nil {
			t.Fatalf("UnwrapKey (call %d): %v", i, err)
		}
		if !bytes.Equal(got, dek) {
			t.Errorf("UnwrapKey (call %d) = %x, want %x", i, got, dek)
		}
	}

	if challengeCalls != 1 {
		t.Errorf("challenge called %d times across 3 WrapKey + 3 UnwrapKey calls, want exactly 1 (cached)", challengeCalls)
	}
}

func TestWrapperFetchMEKReturnsIndependentCopies(t *testing.T) {
	setupWrapper := testWrapper(noChallenge)
	cleanupTestMEK(t, setupWrapper)
	if err := setupWrapper.EnsureMEK(); err != nil {
		t.Fatalf("EnsureMEK: %v", err)
	}

	w := testWrapper(noChallenge)
	first, err := w.fetchMEK("test")
	if err != nil {
		t.Fatalf("fetchMEK (1st): %v", err)
	}
	wipe(first) // simulates a caller's defer wipe(mek) after use

	second, err := w.fetchMEK("test")
	if err != nil {
		t.Fatalf("fetchMEK (2nd): %v", err)
	}
	if bytes.Equal(second, make([]byte, len(second))) {
		t.Error("second fetchMEK call returned all-zero bytes, the cache was corrupted by wiping the first call's copy")
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	plaintext := []byte("data encryption key material")

	sealed, err := seal(key, plaintext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := open(key, sealed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("open(seal(x)) = %q, want %q", got, plaintext)
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	wrongKey := bytes.Repeat([]byte{0x99}, 32)
	sealed, err := seal(key, []byte("secret"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := open(wrongKey, sealed); err == nil {
		t.Error("open with the wrong key succeeded, want an error")
	}
}

// TestRequireUserPresenceChallenges is GAPS.md #60's regression test: an
// explicit user-presence call must actually run the challenge (a
// deletion-only `jit migrate remove` used to skip it entirely, since
// Vault.Remove never touches the KeyWrapper), and must prime the cache so
// a later unwrap in the same invocation doesn't prompt a second time.
func TestRequireUserPresenceChallenges(t *testing.T) {
	calls := 0
	counting := func(string) error { calls++; return nil }
	w := testWrapper(counting)
	cleanupTestMEK(t, w)
	if err := w.EnsureMEK(); err != nil {
		t.Fatalf("EnsureMEK: %v", err)
	}

	if err := w.RequireUserPresence("test"); err != nil {
		t.Fatalf("RequireUserPresence: %v", err)
	}
	if calls != 1 {
		t.Fatalf("challenge ran %d time(s), want exactly 1", calls)
	}

	// Same invocation, later key use: the primed cache must not re-prompt.
	wrapped, err := w.WrapKey([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	if _, err := w.UnwrapKey(wrapped); err != nil {
		t.Fatalf("UnwrapKey: %v", err)
	}
	if calls != 1 {
		t.Errorf("challenge ran %d time(s) after wrap/unwrap, want still 1 (RequireUserPresence primes the cache)", calls)
	}
}

// A failed challenge must propagate — deletion may not proceed without it.
func TestRequireUserPresenceFailedChallenge(t *testing.T) {
	w := testWrapper(failChallenge)
	cleanupTestMEK(t, w)
	if err := w.EnsureMEK(); err != nil {
		t.Fatalf("EnsureMEK: %v", err)
	}
	if err := w.RequireUserPresence("test"); err == nil {
		t.Fatal("RequireUserPresence succeeded despite a failed challenge")
	}
}
