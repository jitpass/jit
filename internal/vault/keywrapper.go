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

// LabeledKeyWrapper is an optional extension a KeyWrapper may also
// implement: the same two operations plus a human-readable label naming
// WHAT the DEK protects (the secret's vault path, e.g. "stripe/live-key").
// Vault.Get/Set pass the label when the wrapper supports it, falling back
// to the plain methods otherwise — see wrapKey/unwrapKey.
//
// It exists for the agent-backed wrapper: the agent's audit history can
// name who asked for an unwrap (kernel-derived) but not what secret it
// was for, because the wire carries only opaque key bytes. The label is
// that missing fact — strictly audit-side, self-reported by the caller,
// and never allowed to gate anything (internal/agent records and displays
// it as caller-reported).
//
// class is different: it is the secret's provenance Class (one of the
// vault.Class* values) and it is bound into the DEK-wrap as AEAD additional
// authenticated data. Unlike label, class is therefore AUTHORITATIVE — an
// unwrap that names the wrong class (or omits it) fails the auth tag, so a
// caller cannot lie about what kind of credential it is unwrapping to dodge
// a class-based policy, nor unwrap while lying. Binding class here is what
// lets the agent gate consent on it (per-process credential consent). Both
// wrappers (agent and keychainwrap) MUST bind it identically: a DEK wrapped
// by one and unwrapped by the other has to agree on the AAD.
type LabeledKeyWrapper interface {
	KeyWrapper
	WrapKeyLabeled(dek []byte, label, class string) (wrapped []byte, err error)
	UnwrapKeyLabeled(wrapped []byte, label, class string) (dek []byte, err error)
}
