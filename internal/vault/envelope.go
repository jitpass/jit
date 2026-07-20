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

// wrappedDEKFor selects the hex-encoded wrapped DEK this device should use to
// open the envelope — the single recipient-resolution rule Get and Verify
// MUST agree on (a doctor that validated a recipient Get never reads would
// false-flag a shareable envelope as corrupt, or pass one this device can't
// actually open). It is deliberately the only place that rule lives.
//
// Exact match first. Failing that, a single-recipient envelope is still worth
// returning: every envelope this vault has ever written has exactly one
// recipient (Set always writes one), so a mismatch there almost always means
// the machine's IDENTIFIER changed, not the machine — envelopes written before
// EnsureDeviceID existed are keyed by os.Hostname(), which drifts with a Mac
// rename or even a DHCP-supplied name. If the wrapped DEK genuinely came from
// a different machine, UnwrapKey fails at the KeyWrapper layer anyway (the MEK
// won't match), so returning it costs nothing and never decrypts anything this
// device couldn't already decrypt. A multi-recipient envelope with no match,
// by contrast, is genuinely not for this device and is reported as such.
func (env envelope) wrappedDEKFor(recipientID, path string) (string, error) {
	if w, ok := env.Recipients[recipientID]; ok {
		return w, nil
	}
	switch len(env.Recipients) {
	case 0:
		return "", fmt.Errorf("corrupt envelope %s: no recipients, its wrapped key is gone", path)
	case 1:
		for _, w := range env.Recipients {
			return w, nil
		}
	}
	return "", fmt.Errorf("no key for this device (%s) in %s, it was likely encrypted on a different machine", recipientID, path)
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
