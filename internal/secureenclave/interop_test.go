// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package secureenclave

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"testing"
)

// The format every MEK-wraps-a-DEK step in jit shares (keychainwrap/crypto.go,
// agent/crypto.go): AES-256-GCM, 12-byte random nonce prefixed, Class as AAD.
// Written out here independently, so a change to this package's crypto.go
// that would stop a DEK crossing backends fails this test.
func referenceSeal(t *testing.T, key, pt, aad []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	return gcm.Seal(nonce, nonce, pt, aad)
}

func referenceOpen(t *testing.T, key, sealed, aad []byte) []byte {
	t.Helper()
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	pt, err := gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], aad)
	if err != nil {
		t.Fatal(err)
	}
	return pt
}

func TestWrapFormatMatchesTheOtherBackends(t *testing.T) {
	w, _, mek := installed(t)
	dek := testMEK(t)
	for _, class := range []string{"", "env", "aws"} {
		// This backend wraps, the shared format opens.
		wrapped, err := w.WrapKeyLabeled(dek, "", class)
		if err != nil {
			t.Fatal(err)
		}
		if got := referenceOpen(t, mek, wrapped, []byte(class)); !bytes.Equal(got, dek) {
			t.Fatalf("class %q: reference open differs", class)
		}
		// The shared format wraps, this backend opens.
		ref := referenceSeal(t, mek, dek, []byte(class))
		got, err := w.UnwrapKeyLabeled(ref, "", class)
		if err != nil || !bytes.Equal(got, dek) {
			t.Fatalf("class %q: this backend could not open a reference wrap: %v", class, err)
		}
	}
}
