// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

// Package vault implements atomic, file-per-secret storage (RFC.md Pillar I)
// and envelope encryption (RFC.md Pillar II): each secret gets its own
// random AES-256-GCM Data Encryption Key, itself wrapped by whatever
// KeyWrapper the caller provides. This package has no opinion on how the
// wrapping key is protected — see internal/keychainwrap for Phase 1's
// interim implementation and its real guarantee level (RFC.md B9). See
// task #6.
package vault
