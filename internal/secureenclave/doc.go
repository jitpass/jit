// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

// Package secureenclave is the hand-written CGo bridge to Security.framework
// and LocalAuthentication.framework: Secure Enclave key generation, Touch ID
// gating, and ECDH (RFC.md Pillar II, TECH_STACK.md §2.3). The mechanism is
// confirmed working end-to-end in spike/secure-enclave/ — this package is where
// that would get promoted into real code.
//
// Deferred (adoption-gated), and NOT merely on a signing identity: re-tested
// 2026-07-11 with a real Apple Development identity, the persistent-key path
// still fails -34018 because SE keychain persistence needs a provisioning-
// profile-authorized entitlement that can only live in an .app bundle, never a
// bare `go install`/Homebrew-formula CLI binary. The intended landing is a
// notarized .app-wrapped jit-agent holding the SE key; until then
// internal/keychainwrap is the shipped interim. See spike/secure-enclave/
// FINDINGS.md's 2026-07-11 update. Keep this package small and isolated.
package secureenclave
