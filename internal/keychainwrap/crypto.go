// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package keychainwrap

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// seal/open implement this package's own DEK-wrapping step (MEK protects
// the DEK, one level up from vault's own DEK-protects-the-payload step) —
// intentionally not shared code with internal/vault beyond the algorithm
// choice, since KeyWrapper implementations own their own wrapping details.
// aad, when non-empty, binds the secret's provenance Class into the wrap as
// AES-GCM additional authenticated data. It MUST match internal/agent's seal
// byte-for-byte in effect: a DEK wrapped by keychainwrap directly (no agent)
// may later be unwrapped through the agent, and vice versa, so both have to
// agree on the AAD. Empty aad is the legacy shape, byte-compatible with the
// pre-AAD wraps.
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
