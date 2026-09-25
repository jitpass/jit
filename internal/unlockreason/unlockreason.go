// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// Package unlockreason holds the words macOS shows in the vault's unlock
// dialog for a plain store or read, after the app's name: "JitPass is trying
// to unlock the vault to read a secret." Every process that asks uses these
// constants (internal/keychainwrap, internal/secureenclave and
// internal/agent), so a prompt reads the same whichever one asked.
//
// A leaf of its own, with no imports, because no other package fits every
// user: internal/agent never imports internal/vault (agent/doc.go), and the
// two wrappers are darwin-only CGo, which the agent's portable half must not
// depend on for a string.
package unlockreason

const (
	// Store is the reason for unlocking the vault to store a secret.
	Store = "unlock the vault to store a secret"
	// Read is the reason for unlocking the vault to read a secret.
	Read = "unlock the vault to read a secret"
)
