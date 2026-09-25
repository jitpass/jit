// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

// Package keystore is the one place jit decides where a vault's master key
// (MEK) is kept, and the one place anything outside internal/keychainwrap
// reaches for it. Every command, the service's unlock, doctor and status get
// a Store from Open and never build a key backend themselves.
//
// Today Open returns the login keychain (internal/keychainwrap) for every
// vault, so this package changes nothing a user can see; it exists so that
// the Secure Enclave backend (internal/secureenclave) can be chosen per vault
// in one place (design/secure-enclave-plan.md, step B3) instead of at eleven.
// TestNothingElseBuildsAKeychainWrapper holds that line.
//
// Two things stay outside the Store on purpose:
//
//   - keychainwrap.Challenge, the bare "prove a person is here" prompt. It
//     reads no key, so it is not a question of where a key lives.
//   - Rekey, which rotates the keychain item's bytes through staged items
//     (`jit vault rekey`). It is keychain-specific until step B4 gives every
//     backend its own staging, so it gets the keychain directly (Keychain).
package keystore

import (
	"github.com/jitpass/jit/internal/keychainwrap"
	"github.com/jitpass/jit/internal/vault"
)

// Kind names where a vault's MEK is kept. It is what `jit doctor` and
// `jit status` will report once there is more than one (step B3).
type Kind string

const (
	// KindKeychain: a plain item in the login keychain, behind jit's own
	// Touch ID check (internal/keychainwrap).
	KindKeychain Kind = "keychain"
)

// Presence is what can be said about the MEK without a prompt.
type Presence int

const (
	// Indeterminate: presence could not be established without interaction.
	// The zero value, so an unset result is never mistaken for Absent.
	Indeterminate Presence = iota
	// Present: the key is there.
	Present
	// Absent: the key is genuinely gone. With secrets in the vault, the
	// total-loss state `jit doctor` exists to catch.
	Absent
)

// Fetcher is what the service builds per unlock: FetchMEK copies the key
// out (prompting), Close wipes the fetcher's own copy. It is
// agent.ClosableFetcher's method set; internal/cli asserts that at compile
// time where it wires the service.
type Fetcher interface {
	FetchMEK(reason string) ([]byte, error)
	Close()
}

// Wrapper is what a command opening the vault directly uses: a
// vault.KeyWrapper that can also ask for presence on demand, which the
// fresh-auth commands require (requireFreshUserPresence in internal/cli).
type Wrapper interface {
	vault.KeyWrapper
	RequireUserPresence(reason string) error
}

// Store is one vault's master key.
type Store interface {
	Kind() Kind
	// Presence never prompts; safe on a non-interactive run.
	Presence() Presence
	// NewFetcher returns a FRESH fetcher. Its cache lives as long as it
	// does, so reusing one would skip every challenge after the first.
	NewFetcher() Fetcher
	// NewWrapper returns a FRESH wrapper, for the same reason: one per
	// command, so a command asks once and the next command asks again.
	NewWrapper() Wrapper
	// Init creates the key if there is none. Idempotent (`jit vault init`).
	Init() error
	// Delete destroys the key. Every secret it protected is gone with it.
	Delete() error
}

// Open returns the Store for the vault at root. Until step B3 it is the
// keychain for every vault; root is taken now so that no caller changes
// when the choice starts depending on the vault.
func Open(root string) Store {
	_ = root
	return keychainStore{}
}

// Keychain returns the keychain backend's own Wrapper for `jit vault rekey`
// and the staged-key cleanup in `jit uninstall`, the two paths that work on
// the keychain's items directly until step B4. Nothing else should call it.
func Keychain() *keychainwrap.Wrapper {
	return keychainwrap.New()
}

type keychainStore struct{}

func (keychainStore) Kind() Kind { return KindKeychain }

func (keychainStore) Presence() Presence {
	switch keychainwrap.New().MEKPresence() {
	case keychainwrap.MEKPresent:
		return Present
	case keychainwrap.MEKAbsent:
		return Absent
	}
	return Indeterminate
}

func (keychainStore) NewFetcher() Fetcher { return keychainwrap.New() }

func (keychainStore) NewWrapper() Wrapper { return keychainwrap.New() }

func (keychainStore) Init() error { return keychainwrap.New().EnsureMEK() }

func (keychainStore) Delete() error { return keychainwrap.New().DeleteMEK() }
