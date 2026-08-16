// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package keychainwrap

import (
	"bytes"
	"errors"
	"strings"
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

	// The KEY has to be unchanged, not merely the error nil. This test checked
	// only `err != nil` twice and read the key never — so replacing
	// kw_ensure_mek's `existsStatus == errSecSuccess` early return with the
	// delete-then-add shape setMEK uses would report success from both calls
	// while silently re-minting the MEK, at which point every wrapped DEK in
	// the vault is permanently undecryptable. That is the whole consequence of
	// this function, and nothing observed it.
	//
	// Read back through FRESH wrappers: fetchMEK memoizes in w.mek, so two
	// fetches on one wrapper would compare a cached value against itself and
	// pass vacuously. Same reasoning PromoteStagedRekeyMEK's verification uses.
	before, err := testWrapper(noChallenge).fetchMEK("")
	if err != nil {
		t.Fatalf("fetching the MEK: %v", err)
	}
	if err := w.EnsureMEK(); err != nil {
		t.Fatalf("EnsureMEK (second call, should be a no-op): %v", err)
	}
	after, err := testWrapper(noChallenge).fetchMEK("")
	if err != nil {
		t.Fatalf("fetching the MEK again: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("a second EnsureMEK re-minted the master key — every DEK already wrapped under the old one is now undecryptable")
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

// Close is what stops a Wrapper leaving a plaintext master key behind inside a
// long-lived host. internal/agent builds one per unlock and per disclosed
// prompt and discards it, in a process that runs for weeks; before Close, each
// of those left a pinned, unzeroed MEK that outlived the session's own lock,
// screen-lock and sleep wipes.
func TestCloseWipesTheCachedMEK(t *testing.T) {
	setupWrapper := testWrapper(noChallenge)
	cleanupTestMEK(t, setupWrapper)
	if err := setupWrapper.EnsureMEK(); err != nil {
		t.Fatalf("EnsureMEK: %v", err)
	}

	w := testWrapper(noChallenge)
	if _, err := w.fetchMEK("test"); err != nil {
		t.Fatalf("fetchMEK: %v", err)
	}

	w.mu.Lock()
	cached := w.mek
	w.mu.Unlock()
	if cached == nil {
		t.Fatal("expected the Wrapper to be holding a cached MEK before Close")
	}
	if bytes.Equal(cached, make([]byte, len(cached))) {
		t.Fatal("cached MEK is already all-zero before Close; the test proves nothing")
	}

	w.Close()

	// The backing array, not the field: the point is that the bytes are gone
	// from memory, not merely unreferenced and awaiting a GC that may never
	// come during a weeks-long process.
	if !bytes.Equal(cached, make([]byte, len(cached))) {
		t.Errorf("after Close the cached MEK still holds %d non-zero byte(s)", countNonZero(cached))
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.mek != nil {
		t.Error("after Close the Wrapper still references a MEK")
	}
}

// Close must be safe on a Wrapper that never fetched, and safe to call twice —
// the agent closes unconditionally, including on the path where the challenge
// failed and nothing was ever cached.
func TestCloseIsIdempotentAndSafeWhenUnused(t *testing.T) {
	w := testWrapper(failChallenge)
	w.Close()
	w.Close()

	if _, err := w.fetchMEK("test"); err == nil {
		t.Error("expected the failing challenge to still be enforced after Close")
	}
	w.Close()
}

// A closed Wrapper re-challenges rather than silently serving a stale key:
// Close ends the cache, and ending a cache of a credential means the next
// caller has to earn it again.
func TestFetchAfterCloseChallengesAgain(t *testing.T) {
	setupWrapper := testWrapper(noChallenge)
	cleanupTestMEK(t, setupWrapper)
	if err := setupWrapper.EnsureMEK(); err != nil {
		t.Fatalf("EnsureMEK: %v", err)
	}

	var challenges int
	w := testWrapper(func(string) error { challenges++; return nil })

	if _, err := w.fetchMEK("test"); err != nil {
		t.Fatalf("fetchMEK (1st): %v", err)
	}
	if _, err := w.fetchMEK("test"); err != nil {
		t.Fatalf("fetchMEK (2nd): %v", err)
	}
	if challenges != 1 {
		t.Fatalf("challenges=%d before Close, want 1 (cached)", challenges)
	}

	w.Close()

	got, err := w.fetchMEK("test")
	if err != nil {
		t.Fatalf("fetchMEK after Close: %v", err)
	}
	if challenges != 2 {
		t.Errorf("challenges=%d after Close, want 2 — a closed Wrapper must re-challenge", challenges)
	}
	if bytes.Equal(got, make([]byte, len(got))) {
		t.Error("fetchMEK after Close returned all-zero bytes")
	}
}

func countNonZero(b []byte) int {
	n := 0
	for _, c := range b {
		if c != 0 {
			n++
		}
	}
	return n
}

func TestSealOpenRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	plaintext := []byte("data encryption key material")

	sealed, err := seal(key, plaintext, []byte("aws"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := open(key, sealed, []byte("aws"))
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
	sealed, err := seal(key, []byte("secret"), nil)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := open(wrongKey, sealed, nil); err == nil {
		t.Error("open with the wrong key succeeded, want an error")
	}
}

// TestOpenRejectsWrongClass pins the class-binding: a DEK sealed under one
// class must not open when a different class is presented as AAD — this is
// what makes the class authoritative for the consent gate.
func TestOpenRejectsWrongClass(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	sealed, err := seal(key, []byte("secret"), []byte("aws"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := open(key, sealed, []byte("dotenv")); err == nil {
		t.Error("open with the wrong class succeeded, want an error (class must be AAD-bound)")
	}
	if got, err := open(key, sealed, []byte("aws")); err != nil || !bytes.Equal(got, []byte("secret")) {
		t.Errorf("open with the right class failed: got %q err %v", got, err)
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

// A keychain item that is not a 32-byte key must be rejected AT THE FETCH,
// where "the master key item is malformed" can still be stated plainly. Left
// to travel on, a short item surfaces from aes.NewCipher as "invalid key
// size" several layers below the fact that explains it — and a user who has
// just approved a Touch ID prompt reads any error about their vault as "my
// secrets are gone". Reachable in practice through a half-written migration
// or a hand-edited Keychain Access entry.
func TestFetchMEKRejectsAMalformedKeychainItem(t *testing.T) {
	w := testWrapper(noChallenge)
	cleanupTestMEK(t, w)

	if err := w.setMEK(make([]byte, 16)); err != nil { // AES-128 length, not this vault's AES-256
		t.Fatalf("setMEK: %v", err)
	}

	_, err := w.fetchMEK("test")
	if err == nil {
		t.Fatal("fetchMEK accepted a 16-byte master key item; a wrong-length item must never reach the cipher")
	}
	if !strings.Contains(err.Error(), "malformed") {
		t.Errorf("error = %q, want it to name the item as malformed rather than surfacing a cipher-level message", err)
	}
	if w.mek != nil {
		t.Error("a rejected item must not be cached on the Wrapper")
	}
}
