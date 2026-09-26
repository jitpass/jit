// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package keychainwrap

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// The agent's standing-grant logic is covered against an in-memory store.
// This is the one piece that touches the real login keychain, and until now
// nothing exercised it at all: every negative control in the design's build
// order ran against memory.
//
// NEVER use grantService here. A test that shared this package's production
// identifier once put a live keychain-access dialog on a real user's screen,
// one click from deleting the key protecting their whole vault; that is why
// GrantKeys.service exists.
func testGrantKeys(t *testing.T) GrantKeys {
	t.Helper()
	var suffix [6]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal(err)
	}
	return GrantKeys{service: "com.jitpass.grant.key.TEST-ONLY." + hex.EncodeToString(suffix[:])}
}

// testGrantID keeps each case on its own keychain item, and removes it
// however the case ends.
func testGrantID(t *testing.T, keys GrantKeys, id string) string {
	t.Helper()
	t.Cleanup(func() {
		if err := keys.Delete(id); err != nil {
			t.Errorf("cleanup: deleting %s: %v", id, err)
		}
	})
	return id
}

func TestGrantKeyRoundTripsADEK(t *testing.T) {
	keys := testGrantKeys(t)
	id := testGrantID(t, keys, "g-roundtrip")

	key, err := keys.Create(id)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer key.Close()

	dek := bytes.Repeat([]byte{0x07}, 32)
	wrapped, err := key.Seal(dek, "mcp")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(wrapped, dek) {
		t.Fatal("the wrapped copy contains the plaintext DEK")
	}

	// A SEPARATE Load, because that is what a service restart does: the
	// cached key is gone and the item on disk is all there is.
	loaded, err := keys.Load(id)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer loaded.Close()
	got, err := loaded.Open(wrapped, "mcp")
	if err != nil {
		t.Fatalf("Open after a fresh Load: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Errorf("Open returned %x, want %x", got, dek)
	}

	// The class is AAD, exactly as the MEK wrap binds it: a copy opened
	// under the wrong class must fail rather than return bytes.
	if _, err := loaded.Open(wrapped, "aws"); err == nil {
		t.Error("Open with the wrong class succeeded; the class must be bound into the wrap")
	}
}

func TestGrantKeysAreNotSharedBetweenGrants(t *testing.T) {
	keys := testGrantKeys(t)
	a := testGrantID(t, keys, "g-aaaa")
	b := testGrantID(t, keys, "g-bbbb")

	ka, err := keys.Create(a)
	if err != nil {
		t.Fatalf("Create(a): %v", err)
	}
	defer ka.Close()
	kb, err := keys.Create(b)
	if err != nil {
		t.Fatalf("Create(b): %v", err)
	}
	defer kb.Close()

	dek := bytes.Repeat([]byte{0x11}, 32)
	wrapped, err := ka.Seal(dek, "mcp")
	if err != nil {
		t.Fatal(err)
	}
	// If the two grants shared a key, revoking one would not make the
	// other's ledger copies unreadable, which is the whole guarantee.
	if _, err := kb.Open(wrapped, "mcp"); err == nil {
		t.Error("one grant's key opened another's wrapped DEK; each grant must hold its own")
	}
}

func TestGrantKeyCreateRefusesAnIDThatAlreadyHasOne(t *testing.T) {
	keys := testGrantKeys(t)
	id := testGrantID(t, keys, "g-dup")
	first, err := keys.Create(id)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer first.Close()
	if _, err := keys.Create(id); err == nil {
		t.Error("Create on an id that already has a key succeeded; reusing one would let a revoked grant's copies open again")
	}
}

// Revoke deletes the key, and that is what makes the ledger's wrapped copies
// unrecoverable. Delete must also be idempotent, because revoke, a failed
// create's cleanup and a re-revoke all reach it.
func TestGrantKeyDeleteIsFinalAndIdempotent(t *testing.T) {
	keys := testGrantKeys(t)
	id := "g-delete"
	key, err := keys.Create(id)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := key.Seal(bytes.Repeat([]byte{0x22}, 32), "mcp"); err != nil {
		t.Fatal(err)
	}
	key.Close()

	if err := keys.Delete(id); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := keys.Delete(id); err != nil {
		t.Errorf("Delete on a key already gone = %v, want success: the state the caller wants is 'no key'", err)
	}

	// The copies the ledger holds are now garbage, and the error names the
	// grant rather than telling the user to run `jit vault init`.
	_, err = keys.Load(id)
	if err == nil {
		t.Fatal("Load succeeded after Delete")
	}
	if !strings.Contains(err.Error(), id) {
		t.Errorf("Load error = %q, want it to name the grant", err)
	}
	if strings.Contains(err.Error(), "jit vault init") {
		t.Errorf("Load error = %q, sends the user at the vault for a grant's missing key", err)
	}
	if !errors.Is(err, ErrNoGrantKey) {
		t.Errorf("Load after Delete = %v, want ErrNoGrantKey", err)
	}
}

// Load's "gone" is proof, not a guess: only the keychain saying the item is
// not there is ErrNoGrantKey (the agent stops a never-ask job for good on
// it). A lookup only: this test makes no item.
func TestGrantKeyLoadOfAMissingKeyIsNoGrantKey(t *testing.T) {
	keys := testGrantKeys(t)
	_, err := keys.Load("g-never-made")
	if !errors.Is(err, ErrNoGrantKey) {
		t.Fatalf("Load of a key never made = %v, want ErrNoGrantKey", err)
	}
	if want := "no key for grant g-never-made in the keychain (was it revoked?)"; err.Error() != want {
		t.Errorf("the sentence changed: %q, want %q", err, want)
	}
	if _, err := keys.Load(""); err == nil || errors.Is(err, ErrNoGrantKey) {
		t.Errorf("Load(\"\") = %v: must fail, and not as a key proven gone", err)
	}
}

func TestGrantKeyRefusesAnEmptyID(t *testing.T) {
	keys := testGrantKeys(t)
	if _, err := keys.Create(""); err == nil {
		t.Error("Create(\"\") succeeded")
	}
	if _, err := keys.Load(""); err == nil {
		t.Error("Load(\"\") succeeded")
	}
	if err := keys.Delete(""); err == nil {
		t.Error("Delete(\"\") succeeded")
	}
}

// The production identifier must never be what a test touches, and the zero
// value must still be the production one for the CLI that wires it.
func TestGrantKeysServiceName(t *testing.T) {
	if got := (GrantKeys{}).serviceName(); got != grantService {
		t.Errorf("zero value targets %q, want the production service %q", got, grantService)
	}
	if got := testGrantKeys(t).serviceName(); got == grantService {
		t.Fatal("the test store targets the production keychain service")
	}
	if !strings.Contains(testGrantKeys(t).serviceName(), "TEST-ONLY") {
		t.Error("a test store's service name must say so out loud")
	}
}

// Plan C4: List names every grant key under the service, from metadata only.
func TestGrantKeysList(t *testing.T) {
	g := testGrantKeys(t)
	if ids, err := g.List(); err != nil || len(ids) != 0 {
		t.Fatalf("empty store: %v, %v", ids, err)
	}
	for _, id := range []string{"g-00000001", "j-00000002"} {
		t.Cleanup(func() { _ = g.Delete(id) })
		if _, err := g.Create(id); err != nil {
			t.Fatal(err)
		}
	}
	ids, err := g.List()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, id := range ids {
		got[id] = true
	}
	if len(ids) != 2 || !got["g-00000001"] || !got["j-00000002"] {
		t.Fatalf("List = %v", ids)
	}
}

// Open tells a copy that doesn't open under the key (ErrWrongKey) from a
// keychain that won't hand the key over: only a read that would have had to
// ask is ErrCantReadNow (the one refusal a never-ask job skips a run for);
// errSecAuthFailed and anything else are the keychain's answers, cause
// kept. The keychain's refusal is faked (GrantKey.read): the item itself is
// real and TEST-ONLY, so Create, Load, Seal and the first Opens take the
// production read (quietFetchNoSwitch).
func TestGrantKeyOpenTellsAWrongKeyFromAKeychainThatWontRead(t *testing.T) {
	keys := testGrantKeys(t)
	id := testGrantID(t, keys, "g-open")
	key, err := keys.Create(id)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	sealed, err := key.Seal(bytes.Repeat([]byte{0x07}, 32), "mcp")
	if err != nil {
		t.Fatal(err)
	}
	if dek, err := key.Open(sealed, "mcp"); err != nil || !bytes.Equal(dek, bytes.Repeat([]byte{0x07}, 32)) {
		t.Fatalf("the production read: %v", err)
	}
	if _, err := key.Open(sealed, "aws"); !errors.Is(err, ErrWrongKey) || errors.Is(err, ErrCantReadNow) {
		t.Errorf("another class: %v, want ErrWrongKey", err)
	}
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 1
	if _, err := key.Open(tampered, "mcp"); !errors.Is(err, ErrWrongKey) {
		t.Errorf("tampered: %v, want ErrWrongKey", err)
	}

	for status, cantRead := range map[int32]bool{
		errSecInteractionNotAllowed: true,
		errSecAuthFailed:            false, // the per-signature ACL's refusal (keychain.m); a lock looks the same
		-25291:                      false, // errSecNotAvailable
	} {
		loaded, err := keys.Load(id)
		if err != nil {
			t.Fatal(err)
		}
		loaded.read = func() ([]byte, error) {
			return nil, &QuietReadError{Status: status, Msg: fmt.Sprintf("reading failed, OSStatus=%d", status)}
		}
		_, err = loaded.Open(sealed, "mcp")
		if errors.Is(err, ErrCantReadNow) != cantRead || errors.Is(err, ErrWrongKey) {
			t.Errorf("OSStatus=%d: Open = %v; ErrCantReadNow should be %v, and never ErrWrongKey", status, err, cantRead)
		}
		if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("OSStatus=%d", status)) {
			t.Errorf("OSStatus=%d: the cause was lost: %v", status, err)
		}
	}
}

// A key whose item went after Load is the grant's own "no key", read
// quietly: the service's read (quietFetchNoSwitch) of a missing item.
func TestGrantKeyOpenOfAKeyGoneSinceLoad(t *testing.T) {
	keys := testGrantKeys(t)
	id := testGrantID(t, keys, "g-gone")
	key, err := keys.Create(id)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := key.Seal(bytes.Repeat([]byte{0x07}, 32), "mcp")
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := keys.Load(id)
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.Delete(id); err != nil {
		t.Fatal(err)
	}
	_, err = loaded.Open(sealed, "mcp")
	if !errors.Is(err, ErrNoGrantKey) || errors.Is(err, ErrCantReadNow) || errors.Is(err, ErrWrongKey) {
		t.Fatalf("Open with the item gone = %v, want ErrNoGrantKey", err)
	}
}

// The store other packages' tests use finds every key and reads it through
// its read: Load never asks the keychain, and Open's answers are the
// production Open's over what read gives.
func TestGrantKeysReadingAnswersThroughOpen(t *testing.T) {
	key := bytes.Repeat([]byte{0x05}, mekSize)
	g := NewTestingGrantKeysReading("com.jitpass.grant.key.TEST-ONLY.reading", func() ([]byte, error) {
		return append([]byte(nil), key...), nil
	})
	k, err := g.Load("never-made")
	if err != nil {
		t.Fatalf("Load = %v, want a key without the keychain", err)
	}
	sealed, err := seal(key, []byte("dek"), []byte("mcp"))
	if err != nil {
		t.Fatal(err)
	}
	if dek, err := k.Open(sealed, "mcp"); err != nil || string(dek) != "dek" {
		t.Fatalf("Open = %q, %v", dek, err)
	}
	if _, err := k.Open(sealed, "aws"); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("Open of another class = %v, want ErrWrongKey", err)
	}
	defer func() {
		if recover() == nil {
			t.Error("a service without TEST-ONLY was accepted")
		}
	}()
	NewTestingGrantKeysReading(grantService, nil)
}

func TestNewTestingGrantKeysRefusesProductionNames(t *testing.T) {
	for _, service := range []string{grantService, "com.jitpass.grant.key.other"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("NewTestingGrantKeys(%q) did not panic", service)
				}
			}()
			NewTestingGrantKeys(service)
		}()
	}
}

// Only a quiet read that would have had to ask is ErrCantReadNow; its text
// is the bridge's own sentence either way.
func TestQuietReadErrorCantReadNowIsOnlyAReadThatWouldAsk(t *testing.T) {
	for status, want := range map[int32]bool{
		errSecInteractionNotAllowed: true,
		errSecAuthFailed:            false,
		errSecItemNotFound:          false,
		-34018:                      false,
	} {
		e := &QuietReadError{Status: status, Msg: "the bridge's sentence"}
		if errors.Is(e, ErrCantReadNow) != want || e.Error() != "the bridge's sentence" {
			t.Errorf("OSStatus=%d: ErrCantReadNow %v (want %v), text %q", status, errors.Is(e, ErrCantReadNow), want, e)
		}
	}
}
