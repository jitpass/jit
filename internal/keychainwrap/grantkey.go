// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package keychainwrap

import (
	"errors"
	"fmt"
)

// A standing grant's own key (design/standing-grants.md): one plain keychain
// generic-password item per grant, under grantService with the grant id as
// the account, the same posture as the MEK item and for the same reason
// (see the package comment: an OS-enforced ACL needs a provisioning profile
// this binary cannot carry). What differs from the MEK is the challenge:
// there is none. A grant key is used with no prompt, which is the whole
// feature, and the human's decision was the disclosed Touch ID that made
// the grant. Its protection equals the MEK's and it opens strictly fewer
// secrets.
//
// When the Secure Enclave path exists, both items move there one flag
// apart: the MEK with the biometry access-control flag, the grant key
// without. This type is built behind the same Wrapper so that swap is a
// change of constructor, not of the agent.

const grantService = "com.jitpass.grant.key"

// GrantKeys is the keychain-backed store the agent's standing grants use.
// The zero value is ready.
type GrantKeys struct{}

// GrantKey is one grant's key: a Wrapper whose challenge always passes and
// whose "missing" error names the grant rather than the vault.
type GrantKey struct {
	w *Wrapper
}

func grantWrapper(id string) (*Wrapper, error) {
	if id == "" {
		return nil, errors.New("grant key: empty grant id")
	}
	return &Wrapper{
		service:   grantService,
		account:   id,
		challenge: func(string) error { return nil },
		missing:   fmt.Errorf("no key for grant %s in the keychain (was it revoked?)", id),
	}, nil
}

// Create mints a fresh random key for id. It refuses an id that already
// has one: a grant id is minted once, and reusing a key across grants
// would let a revoked grant's ledger copies open again.
func (GrantKeys) Create(id string) (*GrantKey, error) {
	w, err := grantWrapper(id)
	if err != nil {
		return nil, err
	}
	if w.MEKPresence() == MEKPresent {
		return nil, fmt.Errorf("grant key: a key for %s already exists", id)
	}
	if err := w.EnsureMEK(); err != nil {
		return nil, fmt.Errorf("grant key: %w", err)
	}
	return &GrantKey{w: w}, nil
}

// Load returns the key for an existing grant. It never prompts; a missing
// item is an error naming the grant.
func (GrantKeys) Load(id string) (*GrantKey, error) {
	w, err := grantWrapper(id)
	if err != nil {
		return nil, err
	}
	if w.MEKPresence() == MEKAbsent {
		return nil, w.missing
	}
	return &GrantKey{w: w}, nil
}

// Delete destroys the key. Idempotent: a key already gone is success,
// since the state the caller wants is "no key".
func (GrantKeys) Delete(id string) error {
	w, err := grantWrapper(id)
	if err != nil {
		return err
	}
	if w.MEKPresence() == MEKAbsent {
		return nil
	}
	return w.deleteMEK()
}

// Seal wraps a DEK under the grant key with the secret's class as AAD,
// byte-compatible with the MEK wrap (same seal, same AAD rule).
func (k *GrantKey) Seal(dek []byte, class string) ([]byte, error) {
	return k.w.WrapKeyLabeled(dek, "", class)
}

// Open unwraps a copy Seal made.
func (k *GrantKey) Open(wrapped []byte, class string) ([]byte, error) {
	return k.w.UnwrapKeyLabeled(wrapped, "", class)
}

// Close wipes the cached key bytes; the keychain item stays.
func (k *GrantKey) Close() {
	k.w.Close()
}
