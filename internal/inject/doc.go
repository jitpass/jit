// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

// Package inject resolves a profile (internal/profile) against the vault
// (internal/vault) into plaintext environment variable values, shared by
// jit run (RFC.md Pillar III Tier 1, process-overwrite injection) and
// jit export (materializing a profile into the current shell session).
// See task #9.
package inject
