// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// fakeKeyWrapper is a deterministic, fixed-key stand-in for a real
// KeyWrapper (internal/keychainwrap in production) — lets vault.go's
// envelope/storage logic be tested without touching the real OS keychain
// or requiring an interactive Touch ID/passcode approval.
type fakeKeyWrapper struct {
	key []byte
}

func newFakeKeyWrapper() *fakeKeyWrapper {
	return &fakeKeyWrapper{key: bytes.Repeat([]byte{0x42}, dekSize)}
}

func (f *fakeKeyWrapper) WrapKey(dek []byte) ([]byte, error)       { return seal(f.key, dek) }
func (f *fakeKeyWrapper) UnwrapKey(wrapped []byte) ([]byte, error) { return open(f.key, wrapped) }

func newTestVault(t *testing.T) *Vault {
	t.Helper()
	return &Vault{
		Root:        t.TempDir(),
		KeyWrapper:  newFakeKeyWrapper(),
		RecipientID: "test-device",
	}
}

func TestVaultSetGetRoundTrip(t *testing.T) {
	v := newTestVault(t)
	want := []byte("sk_test_51Mz...")

	if err := v.Set("stripe/dev-key", want); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := v.Get("stripe/dev-key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("Get = %q, want %q", got, want)
	}
}

func TestVaultGetNotFound(t *testing.T) {
	v := newTestVault(t)
	if _, err := v.Get("nope/nothing-here"); err != ErrNotFound {
		t.Errorf("Get on missing secret = %v, want ErrNotFound", err)
	}
}

func TestVaultOverwrite(t *testing.T) {
	v := newTestVault(t)
	if err := v.Set("stripe/dev-key", []byte("first")); err != nil {
		t.Fatalf("Set 1: %v", err)
	}
	if err := v.Set("stripe/dev-key", []byte("second")); err != nil {
		t.Fatalf("Set 2: %v", err)
	}
	got, err := v.Get("stripe/dev-key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "second" {
		t.Errorf("Get after overwrite = %q, want %q", got, "second")
	}
}

func TestVaultList(t *testing.T) {
	v := newTestVault(t)
	paths := []string{"stripe/dev-key", "stripe/webhook-secret", "aws/s3-access-key"}
	for _, p := range paths {
		if err := v.Set(p, []byte("value")); err != nil {
			t.Fatalf("Set(%q): %v", p, err)
		}
	}

	got, err := v.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []string{"aws/s3-access-key", "stripe/dev-key", "stripe/webhook-secret"}
	if len(got) != len(want) {
		t.Fatalf("List = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("List[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestVaultListEmptyVault(t *testing.T) {
	v := newTestVault(t)
	got, err := v.List()
	if err != nil {
		t.Fatalf("List on a vault that's never had Set called: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("List = %v, want empty", got)
	}
}

func TestVaultRemove(t *testing.T) {
	v := newTestVault(t)
	if err := v.Set("stripe/dev-key", []byte("value")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := v.Remove("stripe/dev-key"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := v.Get("stripe/dev-key"); err != ErrNotFound {
		t.Errorf("Get after Remove = %v, want ErrNotFound", err)
	}
	if err := v.Remove("stripe/dev-key"); err != ErrNotFound {
		t.Errorf("Remove on already-removed secret = %v, want ErrNotFound", err)
	}
}

func TestVaultPathTraversalRejected(t *testing.T) {
	v := newTestVault(t)
	bad := []string{
		"../../etc/passwd",
		"/etc/passwd",
		"a/../../b",
		"",
		"a b",
		"a/../b",
	}
	for _, p := range bad {
		if err := v.Set(p, []byte("x")); err == nil {
			t.Errorf("Set(%q) succeeded, want a rejection", p)
		}
	}

	// Confirm nothing escaped the vault directory.
	outside := filepath.Join(filepath.Dir(v.Root), "passwd")
	if _, err := os.Stat(outside); err == nil {
		t.Errorf("a file was created outside the vault root at %s", outside)
	}
}

func TestVaultTamperedCiphertextRejected(t *testing.T) {
	v := newTestVault(t)
	if err := v.Set("stripe/dev-key", []byte("sk_test_51Mz...")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	path := filepath.Join(v.vaultDir(), "stripe", "dev-key.enc")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading raw envelope: %v", err)
	}
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	payload, err := hex.DecodeString(env.Payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	payload[len(payload)-1] ^= 0xFF // flip a byte in the GCM tag/ciphertext
	env.Payload = hex.EncodeToString(payload)
	tampered, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal tampered envelope: %v", err)
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatalf("writing tampered envelope: %v", err)
	}

	if _, err := v.Get("stripe/dev-key"); err == nil {
		t.Error("Get on a tampered envelope succeeded, want an authentication error")
	}
}

func TestVaultWrongKeyRejected(t *testing.T) {
	root := t.TempDir()
	vA := &Vault{Root: root, KeyWrapper: newFakeKeyWrapper(), RecipientID: "device-a"}
	if err := vA.Set("stripe/dev-key", []byte("secret")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	wrongWrapper := &fakeKeyWrapper{key: bytes.Repeat([]byte{0x99}, dekSize)}
	vB := &Vault{Root: root, KeyWrapper: wrongWrapper, RecipientID: "device-a"}
	if _, err := vB.Get("stripe/dev-key"); err == nil {
		t.Error("Get with the wrong unwrap key succeeded, want an error")
	}
}

// TestVaultDifferentRecipientAndKeyRejected: a genuinely different machine
// (different KeyWrapper key, not just a different recipient label) must
// still fail. This test used to assert the label mismatch ALONE was
// rejected — that behavior turned out to be the bug, not the guarantee: a
// hostname-keyed label drifts with a Mac rename/DHCP name while the key
// material doesn't move an inch, locking a device out of its own vault
// (see EnsureDeviceID and Get's single-recipient fallback). The KeyWrapper
// is, and always was, what actually gates decryption.
func TestVaultDifferentRecipientAndKeyRejected(t *testing.T) {
	root := t.TempDir()
	vA := &Vault{Root: root, KeyWrapper: newFakeKeyWrapper(), RecipientID: "device-a"}
	if err := vA.Set("stripe/dev-key", []byte("secret")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	wrongWrapper := &fakeKeyWrapper{key: bytes.Repeat([]byte{0x99}, dekSize)}
	vB := &Vault{Root: root, KeyWrapper: wrongWrapper, RecipientID: "device-b"}
	if _, err := vB.Get("stripe/dev-key"); err == nil {
		t.Error("Get from a machine with a different key succeeded, want an error — the single-recipient fallback must never bypass the KeyWrapper itself")
	}
}

func TestVaultSetIsAtomicNoLeftoverTempFiles(t *testing.T) {
	v := newTestVault(t)
	if err := v.Set("stripe/dev-key", []byte("value")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(v.vaultDir(), "stripe"))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "dev-key.enc" {
		t.Errorf("directory contents = %v, want exactly [dev-key.enc]", entries)
	}
}
