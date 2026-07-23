// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// seal/open implement this package's own MEK-wraps-a-DEK step, duplicated
// (not shared) from internal/keychainwrap's identical pair — same
// reasoning as that package's own comment: a KeyWrapper-shaped component
// owns its own wrapping details rather than sharing code across the
// package boundary for three small functions.
// aad, when non-empty, is bound into the wrap as AES-GCM additional
// authenticated data: the secret's provenance Class. An open must present the
// same aad or the auth tag fails, which is what makes the class authoritative
// for the consent gate. An empty aad ([]byte("") or nil) is the legacy shape
// (v1/v2 secrets with no provenance), byte-compatible with the pre-AAD wraps.
func seal(key, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("constructing cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("constructing GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

func open(key, sealed, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("constructing cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("constructing GCM: %w", err)
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, fmt.Errorf("wrapped key too short to contain a nonce")
	}
	nonce, ciphertext := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("unwrap failed (wrong MEK, wrong class, or corrupted data): %w", err)
	}
	return plaintext, nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
