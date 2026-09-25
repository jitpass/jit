// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// Package vault implements atomic, file-per-secret storage (RFC.md Pillar I)
// and envelope encryption (RFC.md Pillar II): each secret gets its own
// random AES-256-GCM Data Encryption Key, itself wrapped by whatever
// KeyWrapper the caller provides. This package has no opinion on how the
// wrapping key is protected — internal/keychainwrap and
// internal/secureenclave implement KeyWrapper, and internal/keystore
// chooses one per vault.
package vault
