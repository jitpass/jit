// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package keychainwrap

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
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
