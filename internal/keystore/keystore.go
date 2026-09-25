// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

// Package keystore is the one place jit decides where a vault's master key
// (MEK) is kept, and the one place anything outside internal/keychainwrap
// reaches for it. Every command, the service's unlock, doctor and status get
// a Store from Open and never build a key backend themselves.
//
// Open chooses per vault: a vault whose root holds vault.SealedKeyFile keeps
// its MEK sealed to a Secure Enclave key (internal/secureenclave); every
// other vault keeps it in the login keychain (internal/keychainwrap). No
// vault has a sealed file until `jit vault rekey --wrapper secure-enclave`
// (design/secure-enclave-plan.md, step B4) writes one, so today every vault
// still opens the keychain. TestNothingElseBuildsAKeychainWrapper keeps this
// the one place the choice is made.
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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/jitpass/jit/internal/keychainwrap"
	"github.com/jitpass/jit/internal/secureenclave"
	"github.com/jitpass/jit/internal/vault"
)

// Kind names where a vault's MEK is kept. It is what `jit doctor` and
// `jit status` will report once there is more than one (step B3).
type Kind string

const (
	// KindKeychain: a plain item in the login keychain, behind jit's own
	// Touch ID check (internal/keychainwrap).
	KindKeychain Kind = "keychain"
	// KindSecureEnclave: sealed to a key in this Mac's Secure Enclave
	// (internal/secureenclave); the enclave asks, not jit.
	KindSecureEnclave Kind = "secure-enclave"
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
	// KeyLost: the vault says its key is in the Secure Enclave, and this
	// Mac's enclave has no such key (the vault was copied here, or the
	// enclave was reset). As final as Absent: only a recovery file helps.
	KeyLost
	// Unavailable: the key is in the Secure Enclave and this process cannot
	// reach it (a jit outside JitPass.app). The key may be fine.
	Unavailable
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
	_, err := os.Lstat(filepath.Join(root, vault.SealedKeyFile))
	if err != nil && errors.Is(err, fs.ErrNotExist) {
		return keychainStore{}
	}
	// The file exists, or it could not be checked: either way this vault
	// may be an enclave vault, and treating it as a keychain one would
	// quietly use the wrong key (or, on delete, orphan the right one). The
	// enclave store fails loudly instead.
	return enclaveStore{root: root}
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

func (keychainStore) Init() error { return initKeychain() }

// initKeychain creates the keychain key; a var so no test reaches the
// production keychain item (keychainwrap's TEST-ONLY rule).
var initKeychain = func() error { return keychainwrap.New().EnsureMEK() }

func (keychainStore) Delete() error { return keychainwrap.New().DeleteMEK() }

// enclaveWrapper is what enclaveStore needs from internal/secureenclave's
// Wrapper; a package var builds it so tests never reach the real enclave.
type enclaveWrapper interface {
	Wrapper
	Fetcher
	Presence() secureenclave.Presence
	Delete() error
}

var newEnclaveWrapper = func(root string) enclaveWrapper { return secureenclave.New(root) }

type enclaveStore struct{ root string }

func (enclaveStore) Kind() Kind { return KindSecureEnclave }

func (s enclaveStore) Presence() Presence {
	switch newEnclaveWrapper(s.root).Presence() {
	case secureenclave.Present:
		return Present
	case secureenclave.Absent:
		// Open saw a sealed file; its absence now is a race or a failed
		// check, never proof that no key exists, which is what callers
		// read Absent as.
		return Indeterminate
	case secureenclave.KeyLost:
		return KeyLost
	case secureenclave.Unavailable:
		return Unavailable
	}
	return Indeterminate
}

func (s enclaveStore) NewFetcher() Fetcher { return newEnclaveWrapper(s.root) }

func (s enclaveStore) NewWrapper() Wrapper { return newEnclaveWrapper(s.root) }

// LostSealedFile is where Init sets a sealed key file aside when this Mac's
// enclave has no key for it: kept, not deleted, because it is the one record
// of which key the old secrets were sealed under.
const LostSealedFile = vault.SealedKeyFile + ".lost"

// Init has nothing to create for an enclave vault whose key is there: it was
// made when the vault moved into the enclave. When the key is LOST it starts
// over the way a keychain vault whose key is gone does: the sealed file is
// set aside and a new keychain key is made, so `jit vault import` can
// restore a recovery file. The old secrets stay unreadable, as they already
// were; nothing else would ever open them again.
func (s enclaveStore) Init() error {
	switch s.Presence() {
	case Present:
		return nil
	case KeyLost:
		if err := os.Rename(filepath.Join(s.root, vault.SealedKeyFile), filepath.Join(s.root, LostSealedFile)); err != nil {
			return fmt.Errorf("setting the lost vault key's file aside: %w", err)
		}
		return keychainStore{}.Init()
	case Unavailable:
		return secureenclave.ErrUnavailable
	}
	return errors.New("could not check this vault's Secure Enclave key")
}

func (s enclaveStore) Delete() error { return newEnclaveWrapper(s.root).Delete() }
