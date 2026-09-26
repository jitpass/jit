// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/keychainwrap"
	"github.com/jitpass/jit/internal/secureenclave"
)

// testGrantKeyStore is the production grantKeyStore over a TEST-ONLY
// keychain service (real items, never the production service) and an
// enclave store whose lookups answer present (a plain `go test` can't reach
// the enclave), each Open answering openErr.
func testGrantKeyStore(t *testing.T, present func(tag string) (bool, error), openErr error) grantKeyStore {
	t.Helper()
	var suffix [6]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal(err)
	}
	kc := keychainwrap.NewTestingGrantKeys("com.jitpass.grant.key.TEST-ONLY.cli." + hex.EncodeToString(suffix[:]))
	return grantKeyStore{
		root:    t.TempDir(),
		keys:    keychainGrantKeys{keys: kc},
		enclave: enclaveGrantKeys{keys: secureenclave.NewTestingGrantKeysLookup("com.jitpass.grant.TEST-ONLY.cli.", present, openErr)},
	}
}

// Through the production adapters, not absentAs alone: a key its store
// proves gone comes out of keychainGrantKeys.Load, enclaveGrantKeys.Load,
// grantKeyStore.LoadWrap (both kinds) and grantKeyStore.Load as
// agent.ErrGrantKeyAbsent; an enclave that can't be reached or used right
// now does not.
func TestGrantKeyAdaptersMarkAGoneKeyAbsent(t *testing.T) {
	absent := func(string) (bool, error) { return false, nil }
	g := testGrantKeyStore(t, absent, nil)
	for name, load := range map[string]func() (agent.GrantKey, error){
		"keychainGrantKeys.Load":     func() (agent.GrantKey, error) { return g.keys.Load("j-gone") },
		"enclaveGrantKeys.Load":      func() (agent.GrantKey, error) { return g.enclave.Load("j-gone") },
		"LoadWrap, the keychain's":   func() (agent.GrantKey, error) { return g.LoadWrap("j-gone", agent.GrantWrapKeychain) },
		"LoadWrap, the enclave's":    func() (agent.GrantKey, error) { return g.LoadWrap("j-gone", agent.GrantWrapEnclave) },
		"grantKeyStore.Load, either": func() (agent.GrantKey, error) { return g.Load("j-gone") },
	} {
		if _, err := load(); !errors.Is(err, agent.ErrGrantKeyAbsent) {
			t.Errorf("%s of a gone key = %v, want ErrGrantKeyAbsent", name, err)
		}
	}
	for _, cause := range []error{secureenclave.ErrUnavailable, secureenclave.ErrLocked} {
		g := testGrantKeyStore(t, func(string) (bool, error) { return false, cause }, nil)
		_, err := g.LoadWrap("j-x", agent.GrantWrapEnclave)
		if err == nil || errors.Is(err, agent.ErrGrantKeyAbsent) || !errors.Is(err, cause) {
			t.Errorf("the enclave answering %v: LoadWrap = %v, want it unmarked", cause, err)
		}
	}
}

// And Open: only a copy that doesn't open under the key is
// agent.ErrGrantKeyWrongKey (the sticky stop); a key that can't be used
// right now passes through unmarked, cause kept. The kinds' wraps survive
// the adapter, so the agent still tells them apart. The enclave runs
// through the production adapter (enclaveGrantKeys.Load, LoadWrap); the
// keychain's Load needs an item, and this suite writes none (its HOME is a
// temp dir, under which a keychain write blocks), so its markedKey is
// driven with keychainwrap's own errors, and keychainwrap's
// TestGrantKeyOpenTellsAWrongKeyFromAKeychainThatWontRead pins that a real
// item's Open gives them.
func TestGrantKeyAdaptersMarkOnlyAWrongKeyOnOpen(t *testing.T) {
	// The enclave: the lookup-only store, its Open answering as told.
	for _, tc := range []struct {
		openErr error
		wrong   bool
	}{
		{secureenclave.ErrLocked, false},
		{secureenclave.ErrUnavailable, false},
		{errors.New("opening with the Secure Enclave key: OSStatus=-25291"), false},
		{fmt.Errorf("opening with the Secure Enclave key: %w", secureenclave.ErrWrongKey), true},
	} {
		g := testGrantKeyStore(t, func(string) (bool, error) { return true, nil }, tc.openErr)
		for name, load := range map[string]func() (agent.GrantKey, error){
			"enclaveGrantKeys.Load":   func() (agent.GrantKey, error) { return g.enclave.Load("j-open") },
			"LoadWrap, the enclave's": func() (agent.GrantKey, error) { return g.LoadWrap("j-open", agent.GrantWrapEnclave) },
		} {
			se, err := load()
			if err != nil {
				t.Fatal(err)
			}
			if keyWrapOf(se) != agent.GrantWrapEnclave {
				t.Errorf("%s: the key's wrap = %q", name, keyWrapOf(se))
			}
			_, err = se.Open([]byte{1}, "mcp")
			if errors.Is(err, agent.ErrGrantKeyWrongKey) != tc.wrong || !errors.Is(err, tc.openErr) {
				t.Errorf("%s, Open answering %v: %v; marked should be %v, cause kept", name, tc.openErr, err, tc.wrong)
			}
		}
	}

	// The keychain's errors, through the same markedKey keychainGrantKeys
	// wraps its keys in.
	for _, tc := range []struct {
		openErr error
		wrong   bool
	}{
		{fmt.Errorf("grant key: %w", keychainwrap.ErrCantReadNow), false},
		{errors.New("grant key: reading the master key from the keychain failed, OSStatus=-25291"), false},
		{fmt.Errorf("%w: cipher: message authentication failed", keychainwrap.ErrWrongKey), true},
	} {
		k := markedKey{failingOpen{tc.openErr}, keychainwrap.ErrWrongKey}
		if keyWrapOf(k) != agent.GrantWrapKeychain {
			t.Errorf("the keychain key's wrap = %q", keyWrapOf(k))
		}
		_, err := k.Open([]byte{1}, "mcp")
		if errors.Is(err, agent.ErrGrantKeyWrongKey) != tc.wrong || !errors.Is(err, tc.openErr) {
			t.Errorf("keychain Open answering %v: %v; marked should be %v, cause kept", tc.openErr, err, tc.wrong)
		}
	}
}

// failingOpen is a grant key whose Open fails with err.
type failingOpen struct{ err error }

func (failingOpen) Seal([]byte, string) ([]byte, error)   { return nil, errors.New("unused") }
func (f failingOpen) Open([]byte, string) ([]byte, error) { return nil, f.err }
func (failingOpen) Close()                                {}

// keyWrapOf is the agent's keyWrap: the key's Wrap, else the keychain's.
func keyWrapOf(k agent.GrantKey) string {
	if w, ok := k.(interface{ Wrap() string }); ok {
		return w.Wrap()
	}
	return agent.GrantWrapKeychain
}
