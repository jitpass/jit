// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureDeviceIDStableAcrossCalls(t *testing.T) {
	root := t.TempDir()

	first, err := EnsureDeviceID(root)
	if err != nil {
		t.Fatalf("EnsureDeviceID (first call): %v", err)
	}
	if !strings.HasPrefix(first, "device-") || len(first) <= len("device-") {
		t.Errorf("EnsureDeviceID = %q, want a non-empty \"device-\"-prefixed identifier", first)
	}

	second, err := EnsureDeviceID(root)
	if err != nil {
		t.Fatalf("EnsureDeviceID (second call): %v", err)
	}
	if second != first {
		t.Errorf("EnsureDeviceID changed across calls: %q then %q — the whole point is an identifier that never drifts", first, second)
	}
}

func TestEnsureDeviceIDDistinctPerRoot(t *testing.T) {
	a, err := EnsureDeviceID(t.TempDir())
	if err != nil {
		t.Fatalf("EnsureDeviceID (root a): %v", err)
	}
	b, err := EnsureDeviceID(t.TempDir())
	if err != nil {
		t.Fatalf("EnsureDeviceID (root b): %v", err)
	}
	if a == b {
		t.Errorf("two fresh roots produced the same device ID %q — must be random per generation, never a shared constant", a)
	}
}

func TestEnsureDeviceIDFilePermissions(t *testing.T) {
	root := t.TempDir()
	if _, err := EnsureDeviceID(root); err != nil {
		t.Fatalf("EnsureDeviceID: %v", err)
	}
	info, err := os.Stat(filepath.Join(root, deviceIDFile))
	if err != nil {
		t.Fatalf("stat device ID file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("device ID file permissions = %o, want 600", perm)
	}
}

func TestEnsureDeviceIDRegeneratesEmptyFile(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, deviceIDFile), []byte("\n"), 0o600); err != nil {
		t.Fatalf("planting empty device ID file: %v", err)
	}
	id, err := EnsureDeviceID(root)
	if err != nil {
		t.Fatalf("EnsureDeviceID: %v", err)
	}
	if id == "" {
		t.Error("EnsureDeviceID returned \"\" for an empty file — an empty identifier must never become every envelope's recipient key")
	}
}

// TestGetFallsBackToSingleRecipient covers the migration path away from
// hostname-keyed envelopes: a vault whose envelopes were written under a
// different RecipientID (an old hostname, before EnsureDeviceID existed —
// or simply after a Mac rename) must still decrypt, since every envelope
// Set has ever written has exactly one recipient and the KeyWrapper itself
// is what actually gates decryption.
func TestGetFallsBackToSingleRecipient(t *testing.T) {
	root := t.TempDir()
	kw := newFakeKeyWrapper()

	writer := &Vault{Root: root, KeyWrapper: kw, RecipientID: "old-hostname.local"}
	want := []byte("survives-a-rename")
	if err := writer.Set("stripe/dev-key", want); err != nil {
		t.Fatalf("Set: %v", err)
	}

	reader := &Vault{Root: root, KeyWrapper: kw, RecipientID: "device-abc123"}
	got, err := reader.Get("stripe/dev-key")
	if err != nil {
		t.Fatalf("Get under a different RecipientID: %v — a hostname change must not lock the vault", err)
	}
	if string(got) != string(want) {
		t.Errorf("Get = %q, want %q", got, want)
	}
}

// TestGetMultiRecipientMismatchStillFails locks in the fallback's limit:
// with MORE than one recipient there's a genuine choice to make, and
// guessing would be wrong — only the exact-match path may proceed.
func TestGetMultiRecipientMismatchStillFails(t *testing.T) {
	root := t.TempDir()
	kw := newFakeKeyWrapper()
	v := &Vault{Root: root, KeyWrapper: kw, RecipientID: "device-abc123"}

	dek, err := generateDEK()
	if err != nil {
		t.Fatalf("generateDEK: %v", err)
	}
	sealed, err := seal(dek, []byte("value"), nil)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	wrapped, err := kw.WrapKey(dek)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	env := envelope{
		Version: envelopeVersion,
		Recipients: map[string]string{
			"machine-a": hex.EncodeToString(wrapped),
			"machine-b": hex.EncodeToString(wrapped),
		},
		Payload: hex.EncodeToString(sealed),
	}
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	dest := filepath.Join(root, "vault", "multi", "key.enc")
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(dest, data, 0o600); err != nil {
		t.Fatalf("writing envelope: %v", err)
	}

	if _, err := v.Get("multi/key"); err == nil {
		t.Error("Get succeeded against a multi-recipient envelope with no matching recipient — the single-recipient fallback must never guess between several")
	}
}
