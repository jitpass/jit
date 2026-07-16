// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package vault

import "fmt"

// envelope is the on-disk JSON shape for a single .enc file, matching
// RFC.md Pillar II's schema exactly: a per-secret Data Encryption Key
// (DEK), itself wrapped once per recipient (Phase 1 has exactly one: this
// device), protects the actual payload.
type envelope struct {
	Version int `json:"version"`
	// CreatedUnix is when a secret was first stored at this path and
	// UpdatedUnix when it was last overwritten (version 2+, so both are
	// omitempty for version-1 files). Set preserves CreatedUnix across
	// overwrites, which is what lets "this key hasn't been rotated since
	// January" be answered at all. Plaintext on disk — timestamps aren't
	// secret — but NOT tamperable: both are bound into the payload's AAD
	// (envelopeAAD), so editing them makes decryption fail rather than
	// silently backdating a stale credential.
	CreatedUnix int64 `json:"created_unix,omitempty"`
	UpdatedUnix int64 `json:"updated_unix,omitempty"`
	// Recipients maps a recipient ID (this device's hostname in Phase 1;
	// Phase 2 adds real multi-recipient sharing, RFC.md §5.2) to that
	// recipient's hex-encoded wrapped DEK.
	Recipients map[string]string `json:"recipients"`
	// Payload is the hex-encoded (nonce || ciphertext) of the secret value,
	// AES-256-GCM sealed under the DEK — with envelopeAAD as the additional
	// authenticated data for version 2+, nothing for version 1.
	Payload string `json:"payload"`
}

const (
	// envelopeVersionAADLess is the original schema: no metadata, payload
	// sealed with no additional authenticated data. Never written anymore,
	// readable forever — vaults full of v1 files must keep decrypting
	// without a migration step.
	envelopeVersionAADLess = 1
	// envelopeVersion is what Set writes today.
	envelopeVersion = 2
)

// envelopeAAD is the additional authenticated data a version-2+ payload is
// sealed under: the secret's own vault path plus the envelope's version and
// timestamps. Binding the path is what makes a swapped .enc file fail
// closed — before this, copying stripe/live-key.enc over stripe/dev-key.enc
// decrypted cleanly and handed the live key to whatever asked for the dev
// one, with nothing anywhere able to notice. Binding the metadata keeps the
// plaintext-on-disk timestamps honest (see envelope.CreatedUnix).
//
// The path needs no escaping in this colon-joined string: sanitizeSecretPath
// admits only [A-Za-z0-9_.-] and '/', so a colon can never appear in it and
// the encoding is unambiguous.
func envelopeAAD(path string, version int, createdUnix, updatedUnix int64) []byte {
	return fmt.Appendf(nil, "jit-envelope:%d:%s:%d:%d", version, path, createdUnix, updatedUnix)
}
