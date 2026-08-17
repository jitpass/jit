// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package vault

import (
	"bytes"
	"testing"
)

func TestExportImportRoundTrip(t *testing.T) {
	v := newTestVault(t)
	secrets := map[string]string{
		"stripe/dev-key":        "sk_test_51Mz...",
		"aws/s3-access-key":     "AKIAFIXTURE",
		"stripe/webhook-secret": "whsec_fixture",
	}
	for path, value := range secrets {
		if err := v.Set(path, []byte(value)); err != nil {
			t.Fatalf("Set(%q): %v", path, err)
		}
	}

	passphrase := []byte("correct horse battery staple")
	env, err := v.Export(passphrase)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	// Restoring into a brand-new, empty vault (a different machine, in
	// spirit) — Import must not depend on anything Export's own vault
	// still has in memory or on disk.
	v2 := newTestVault(t)
	n, err := v2.Import(env, passphrase)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if n != len(secrets) {
		t.Errorf("Import restored %d secret(s), want %d", n, len(secrets))
	}

	for path, want := range secrets {
		got, err := v2.Get(path)
		if err != nil {
			t.Fatalf("Get(%q) after import: %v", path, err)
		}
		if string(got) != want {
			t.Errorf("Get(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestExportEmptyVault(t *testing.T) {
	v := newTestVault(t)
	env, err := v.Export([]byte("passphrase"))
	if err != nil {
		t.Fatalf("Export on an empty vault: %v", err)
	}

	v2 := newTestVault(t)
	n, err := v2.Import(env, []byte("passphrase"))
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if n != 0 {
		t.Errorf("Import restored %d secret(s) from an empty export, want 0", n)
	}
}

func TestImportWrongPassphraseRejected(t *testing.T) {
	v := newTestVault(t)
	if err := v.Set("stripe/dev-key", []byte("secret")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	env, err := v.Export([]byte("right passphrase"))
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	v2 := newTestVault(t)
	if _, err := v2.Import(env, []byte("wrong passphrase")); err == nil {
		t.Error("Import with the wrong passphrase succeeded, want a decryption error")
	}
}

func TestImportTamperedPayloadRejected(t *testing.T) {
	v := newTestVault(t)
	if err := v.Set("stripe/dev-key", []byte("secret")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	passphrase := []byte("passphrase")
	env, err := v.Export(passphrase)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	tampered := []byte(env.Payload)
	tampered[len(tampered)-1] ^= 0xFF
	env.Payload = string(tampered)

	v2 := newTestVault(t)
	if _, err := v2.Import(env, passphrase); err == nil {
		t.Error("Import on a tampered export succeeded, want an error")
	}
}

func TestImportUnsupportedVersionRejected(t *testing.T) {
	v := newTestVault(t)
	env, err := v.Export([]byte("passphrase"))
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	env.Version = exportVersion + 1

	v2 := newTestVault(t)
	if _, err := v2.Import(env, []byte("passphrase")); err == nil {
		t.Error("Import on an unsupported version succeeded, want an error")
	}
}

func TestImportOverwritesExistingSecret(t *testing.T) {
	v := newTestVault(t)
	if err := v.Set("stripe/dev-key", []byte("old-value")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	passphrase := []byte("passphrase")
	if err := v.Set("stripe/dev-key", []byte("new-value")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	env, err := v.Export(passphrase)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	v2 := newTestVault(t)
	if err := v2.Set("stripe/dev-key", []byte("stale-local-value")); err != nil {
		t.Fatalf("Set on destination vault: %v", err)
	}
	if _, err := v2.Import(env, passphrase); err != nil {
		t.Fatalf("Import: %v", err)
	}
	got, err := v2.Get("stripe/dev-key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "new-value" {
		t.Errorf("Get after import = %q, want %q (import must overwrite, not merge-skip)", got, "new-value")
	}
}

// TestExportTwiceProducesDifferentCiphertext confirms Export generates a
// fresh salt every call — two exports of the same vault under the same
// passphrase must never look identical on disk (a fixed salt would leak
// that two backup files protect the same secrets, and would let an
// attacker precompute one KDF run against many stolen exports).
func TestExportTwiceProducesDifferentCiphertext(t *testing.T) {
	v := newTestVault(t)
	if err := v.Set("stripe/dev-key", []byte("secret")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	env1, err := v.Export([]byte("passphrase"))
	if err != nil {
		t.Fatalf("Export 1: %v", err)
	}
	env2, err := v.Export([]byte("passphrase"))
	if err != nil {
		t.Fatalf("Export 2: %v", err)
	}
	if env1.Salt == env2.Salt {
		t.Error("two exports produced the same salt")
	}
	if env1.Payload == env2.Payload {
		t.Error("two exports produced the same payload")
	}
}

func TestVerifyExportPassphrase(t *testing.T) {
	v := newTestVault(t)
	if err := v.Set("stripe/dev-key", []byte("secret")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	env, err := v.Export([]byte("right passphrase"))
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	if err := VerifyExportPassphrase(env, []byte("right passphrase")); err != nil {
		t.Errorf("VerifyExportPassphrase with the right passphrase: %v", err)
	}
	if err := VerifyExportPassphrase(env, []byte("wrong passphrase")); err == nil {
		t.Error("VerifyExportPassphrase with the wrong passphrase succeeded, want an error")
	}
}

func TestWipeEntriesZeroesEveryEntry(t *testing.T) {
	m := map[string]exportEntry{
		"a": {Value: bytes.Repeat([]byte{0xAA}, 8)},
		"b": {Value: bytes.Repeat([]byte{0xBB}, 8), Storage: StorageOpRef},
	}
	// Hold the slices BEFORE the call. Re-reading through m would prove
	// nothing about the property: wipeEntries has to scrub in place, because
	// what it protects is exported plaintext still resident in the backing
	// array (export.go defer-calls it over the decrypted maps in Export,
	// Import and VerifyExportPassphrase). An implementation doing
	// `m[k] = exportEntry{Value: make([]byte, len(v))}` hands a range loop
	// over m fresh zeroed slices and passes while every secret stays live in
	// memory; a delete-based one makes the loop body never execute at all.
	// Both used to pass here.
	a, b := m["a"].Value, m["b"].Value
	wipeEntries(m)
	for name, held := range map[string][]byte{"a": a, "b": b} {
		for i, byteVal := range held {
			if byteVal != 0 {
				t.Errorf("m[%q][%d] = %#x, want 0 — the plaintext is still in the backing array", name, i, byteVal)
			}
		}
	}
}
