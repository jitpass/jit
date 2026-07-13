// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

const dekSize = 32 // AES-256

// generateDEK returns a fresh, random 32-byte Data Encryption Key.
func generateDEK() ([]byte, error) {
	dek := make([]byte, dekSize)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("generating DEK: %w", err)
	}
	return dek, nil
}

// seal AES-256-GCM encrypts plaintext under key, returning nonce||ciphertext.
func seal(key, plaintext []byte) ([]byte, error) {
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
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// open reverses seal: key must be the same key, sealed must be nonce||ciphertext.
func open(key, sealed []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("constructing cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("constructing GCM: %w", err)
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, fmt.Errorf("sealed data too short to contain a nonce")
	}
	nonce, ciphertext := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong key or corrupted/tampered data): %w", err)
	}
	return plaintext, nil
}

// wipe zeroes b in place — best-effort hygiene for key/plaintext material
// once it's no longer needed. Not a guarantee against a GC-moved copy or a
// swapped page; real in-memory hardening (mlock, memguard) is out of scope
// for this first cut of the vault — see spike/memguard/ for the validated
// mechanism this can grow into once jit-agent (task #9) exists.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
