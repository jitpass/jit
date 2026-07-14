// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package vault

// KeyWrapper wraps and unwraps a Data Encryption Key (DEK) using whatever
// Master Encryption Key a concrete implementation manages access to, and
// enforces whatever local-auth gating policy it implements. See RFC.md
// Pillar II. internal/keychainwrap is Phase 1's interim implementation —
// see its package doc and RFC.md B9 for the real guarantee it provides
// (prompted local authentication, not OS-enforced access control).
type KeyWrapper interface {
	WrapKey(dek []byte) (wrapped []byte, err error)
	UnwrapKey(wrapped []byte) (dek []byte, err error)
}
