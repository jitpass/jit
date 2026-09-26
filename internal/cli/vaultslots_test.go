// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/keystore"
	"github.com/jitpass/jit/internal/secureenclave"
	"github.com/jitpass/jit/internal/vault"
)

// memoryStore is an enclave vault's Store whose Presence is the real
// secureenclave.Wrapper's over in-memory slots (secureenclave.MemoryTesting),
// mapped as keystore maps it: the whole chain status and doctor read, with
// no enclave and no keychain behind it. Its keys can't be fetched, made or
// deleted (recordingStore panics or records).
type memoryStore struct {
	recordingStore
	mem *secureenclave.MemoryTesting
}

func (s memoryStore) Presence() keystore.Presence {
	return keystore.EnclavePresence(s.mem.Wrapper().Presence())
}

// withMemoryEnclave makes the fixture vault an enclave vault over in-memory
// slots, and keeps status off the production keychain's copy check.
func withMemoryEnclave(t *testing.T, root string) *secureenclave.MemoryTesting {
	t.Helper()
	mem := secureenclave.NewMemoryTesting(root)
	orig, origCopy := openKeyStore, keychainCopyPresence
	openKeyStore = func(string) keystore.Store {
		return memoryStore{recordingStore{kind: keystore.KindSecureEnclave, deleted: &[]keystore.Kind{}}, mem}
	}
	keychainCopyPresence = func() keystore.Presence { return keystore.Absent }
	t.Cleanup(func() { openKeyStore, keychainCopyPresence = orig, origCopy })
	return mem
}

func testVaultMEK(t *testing.T) []byte {
	t.Helper()
	return bytes.Repeat([]byte{0x5a}, 32)
}

// A vault a later jit rotated into slot B is a healthy enclave vault to
// status and doctor: set up, in the Secure Enclave, and no lost key.
func TestStatusAndDoctorOnASlotBVault(t *testing.T) {
	home := withFixtureHome(t)
	plantVaultSecret(t, home, "aws/s3-access-key")
	root := fixtureRoot(home)
	mem := withMemoryEnclave(t, root)
	if err := mem.SealInSlotB(testVaultMEK(t)); err != nil {
		t.Fatal(err)
	}
	if mem.Has("a") {
		t.Fatal("fixture: slot A has a key; the vault must be slot B's alone")
	}

	if p := openKeyStore(root).Presence(); p != keystore.Present {
		t.Fatalf("presence %v, want Present", p)
	}
	got, err := gatherVaultStatus(fixtureVault(home), root)
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyStore != string(keystore.KindSecureEnclave) || got.Initialized != "yes" {
		t.Fatalf("status: key_store %q, initialized %q; want secure-enclave, yes", got.KeyStore, got.Initialized)
	}
	for _, f := range gatherVaultIntegrityFindings(root, fixtureVault(home)) {
		if f.Kind == kindVaultKey || f.Kind == kindVaultRestore {
			t.Fatalf("doctor on a healthy slot B vault: %s: %s", f.Kind, f.Detail)
		}
	}
}

// A slot this jit does not know (a later jit's third) is a set-up vault
// whose key may be fine: never lost, never offered a first-run setup.
func TestAVaultSealedByANewerJitIsNeverLost(t *testing.T) {
	home := withFixtureHome(t)
	plantVaultSecret(t, home, "aws/s3-access-key")
	root := fixtureRoot(home)
	withMemoryEnclave(t, root)
	sealed := `{"version": 1, "wrap": "se-p256-ecies-v1", "kek_tag": "com.jitpass.vault.kek.TEST-ONLY.memory.c", "blob": "00"}`
	if err := os.WriteFile(filepath.Join(root, vault.SealedKeyFile), []byte(sealed), 0o600); err != nil {
		t.Fatal(err)
	}

	if p := openKeyStore(root).Presence(); p != keystore.NeedsNewerJit {
		t.Fatalf("presence %v, want NeedsNewerJit", p)
	}
	got, err := gatherVaultStatus(fixtureVault(home), root)
	if err != nil {
		t.Fatal(err)
	}
	if got.Initialized != "yes" {
		t.Fatalf("status: initialized %q, want yes", got.Initialized)
	}
	for _, f := range gatherVaultIntegrityFindings(root, fixtureVault(home)) {
		if f.Kind == kindVaultKey {
			t.Fatalf("doctor called a newer jit's vault lost: %s", f.Detail)
		}
	}
	if !prodFirstRunDeps(rootCmd).vaultReady() {
		t.Fatal("first run would offer setup over a newer jit's vault")
	}
}

// The move back to the keychain from a vault in slot B: it opens from slot
// B, and afterwards neither slot holds a key.
func TestMoveBackToTheKeychainFromSlotB(t *testing.T) {
	w := newMoveWorld(t)
	mem := secureenclave.NewMemoryTesting(w.root)
	if err := mem.SealInSlotB(w.mek); err != nil {
		t.Fatal(err)
	}
	m := w.mover()
	// newKeyMoverWith's own two enclave operations, over the memory slots.
	m.seOpen = func(reason string) ([]byte, error) {
		w.prompts = append(w.prompts, "enclave: "+reason)
		se := mem.Wrapper()
		defer se.Close()
		return se.FetchMEK(reason)
	}
	m.seDelete = func() error { return mem.Wrapper().Delete() }

	if err := m.toKeychain(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(w.kc, w.mek) {
		t.Fatal("the keychain does not hold the MEK")
	}
	if exists(w.real()) || mem.Has("a") || mem.Has("b") {
		t.Fatalf("enclave leftovers: sealed file %v, slot A %v, slot B %v", exists(w.real()), mem.Has("a"), mem.Has("b"))
	}
	w.assertSettled()
	if len(w.prompts) != 1 || !strings.HasPrefix(w.prompts[0], "enclave:") {
		t.Errorf("prompts = %q, want only the enclave's", w.prompts)
	}
}
