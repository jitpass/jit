// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package vault

// envelope is the on-disk JSON shape for a single .enc file, matching
// RFC.md Pillar II's schema exactly: a per-secret Data Encryption Key
// (DEK), itself wrapped once per recipient (Phase 1 has exactly one: this
// device), protects the actual payload.
type envelope struct {
	Version int `json:"version"`
	// Recipients maps a recipient ID (this device's hostname in Phase 1;
	// Phase 2 adds real multi-recipient sharing, RFC.md §5.2) to that
	// recipient's hex-encoded wrapped DEK.
	Recipients map[string]string `json:"recipients"`
	// Payload is the hex-encoded (nonce || ciphertext) of the secret value,
	// AES-256-GCM sealed under the DEK.
	Payload string `json:"payload"`
}

const envelopeVersion = 1
