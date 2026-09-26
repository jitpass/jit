// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
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

// Through the production adapters: a key its store proves gone comes out
// of keychainGrantKeys.Load, enclaveGrantKeys.Load, grantKeyStore.LoadWrap
// (both kinds) and grantKeyStore.Load as agent.ErrGrantKeyAbsent; an
// enclave that can't be used right now as agent.ErrGrantKeyNotNow; any
// other lookup failure unmarked, which stops a never-ask job.
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
	for cause, notNow := range map[error]bool{
		secureenclave.ErrUnavailable: true,
		secureenclave.ErrLocked:      true,
		errors.New("checking for the Secure Enclave key failed (OSStatus=-50)"): false,
	} {
		g := testGrantKeyStore(t, func(string) (bool, error) { return false, cause }, nil)
		_, err := g.LoadWrap("j-x", agent.GrantWrapEnclave)
		if err == nil || errors.Is(err, agent.ErrGrantKeyAbsent) || !errors.Is(err, cause) || errors.Is(err, agent.ErrGrantKeyNotNow) != notNow {
			t.Errorf("the enclave answering %v: LoadWrap = %v; ErrGrantKeyNotNow should be %v, cause kept", cause, err, notNow)
		}
	}
}

// And Open, through each kind's production Load (keychainGrantKeys.Load,
// enclaveGrantKeys.Load, LoadWrap): only a copy that doesn't open under the
// key is agent.ErrGrantKeyWrongKey; only a key that can't be used right now
// is agent.ErrGrantKeyNotNow (the keychain refusing a read that would have
// had to ask, the enclave locked or unentitled); everything else passes
// through unmarked, cause kept, and stops the job. The kinds' wraps survive
// the adapter, so the agent still tells them apart. The keychain's key is
// keychainwrap's own GrantKey, whose read is faked
// (NewTestingGrantKeysReading: this suite's HOME can hold no item), so what
// is marked is what keychainwrap's Open really returns for each read.
func TestGrantKeyAdaptersMarkOpenErrorsByWhatTheyProve(t *testing.T) {
	const (
		wrong = iota
		notNow
		answer
	)
	marks := func(err error) int {
		switch {
		case errors.Is(err, agent.ErrGrantKeyWrongKey) && !errors.Is(err, agent.ErrGrantKeyNotNow):
			return wrong
		case errors.Is(err, agent.ErrGrantKeyNotNow) && !errors.Is(err, agent.ErrGrantKeyWrongKey):
			return notNow
		case err != nil && !errors.Is(err, agent.ErrGrantKeyNotNow) && !errors.Is(err, agent.ErrGrantKeyWrongKey):
			return answer
		}
		return -1
	}

	// The enclave: the lookup-only store, its Open answering as told.
	for _, tc := range []struct {
		openErr error
		want    int
	}{
		{secureenclave.ErrLocked, notNow},
		{secureenclave.ErrUnavailable, notNow},
		{errors.New("opening with the Secure Enclave key: OSStatus=-25291"), answer},
		{errors.New("opening with the Secure Enclave key: The operation couldn't be completed. (CryptoTokenKit error -3.)"), answer},
		{errors.New("finding the Secure Enclave key (OSStatus=-50)"), answer},
		{fmt.Errorf("opening with the Secure Enclave key: %w", secureenclave.ErrWrongKey), wrong},
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
			if marks(err) != tc.want || !errors.Is(err, tc.openErr) {
				t.Errorf("%s, Open answering %v: %v; marked %d, want %d, cause kept", name, tc.openErr, err, marks(err), tc.want)
			}
		}
	}

	// The keychain: keychainwrap's GrantKey over a faked read.
	key := bytes.Repeat([]byte{0x05}, 32)
	sealed := sealUnder(t, key, "mcp")
	for _, tc := range []struct {
		name string
		read func() ([]byte, error)
		want int
	}{
		{"a read that would have had to ask", func() ([]byte, error) {
			return nil, &keychainwrap.QuietReadError{Status: -25308, Msg: "reading the key in the keychain without asking failed, OSStatus=-25308"}
		}, notNow},
		{"errSecAuthFailed", func() ([]byte, error) {
			return nil, &keychainwrap.QuietReadError{Status: -25293, Msg: "reading the key in the keychain without asking failed, OSStatus=-25293"}
		}, answer},
		{"another OSStatus", func() ([]byte, error) {
			return nil, &keychainwrap.QuietReadError{Status: -25291, Msg: "reading the key in the keychain without asking failed, OSStatus=-25291"}
		}, answer},
		{"another key", func() ([]byte, error) { return bytes.Repeat([]byte{0x06}, 32), nil }, wrong},
	} {
		g := testGrantKeyStoreReading(t, tc.read)
		for name, load := range map[string]func() (agent.GrantKey, error){
			"keychainGrantKeys.Load":   func() (agent.GrantKey, error) { return g.keys.Load("j-open") },
			"LoadWrap, the keychain's": func() (agent.GrantKey, error) { return g.LoadWrap("j-open", agent.GrantWrapKeychain) },
		} {
			kc, err := load()
			if err != nil {
				t.Fatal(err)
			}
			if keyWrapOf(kc) != agent.GrantWrapKeychain {
				t.Errorf("%s: the keychain key's wrap = %q", name, keyWrapOf(kc))
			}
			_, err = kc.Open(sealed, "mcp")
			if marks(err) != tc.want {
				t.Errorf("%s, %s: %v; marked %d, want %d", name, tc.name, err, marks(err), tc.want)
			}
		}
	}
	// The control: the same key opens what it sealed, through the adapter.
	g := testGrantKeyStoreReading(t, func() ([]byte, error) { return append([]byte(nil), key...), nil })
	kc, err := g.keys.Load("j-open")
	if err != nil {
		t.Fatal(err)
	}
	if dek, err := kc.Open(sealed, "mcp"); err != nil || string(dek) != "the dek" {
		t.Fatalf("the faked read's own key: %q, %v", dek, err)
	}
}

// testGrantKeyStoreReading is testGrantKeyStore whose keychain half is
// keychainwrap's store over a faked read (NewTestingGrantKeysReading).
func testGrantKeyStoreReading(t *testing.T, read func() ([]byte, error)) grantKeyStore {
	t.Helper()
	g := testGrantKeyStore(t, func(string) (bool, error) { return false, nil }, nil)
	g.keys = keychainGrantKeys{keys: keychainwrap.NewTestingGrantKeysReading("com.jitpass.grant.key.TEST-ONLY.cli.reading", read)}
	return g
}

// sealUnder seals "the dek" for class under key, as keychainwrap's GrantKey
// Seal does, through that Seal itself over a faked read.
func sealUnder(t *testing.T, key []byte, class string) []byte {
	t.Helper()
	k, err := keychainwrap.NewTestingGrantKeysReading("com.jitpass.grant.key.TEST-ONLY.cli.seal", func() ([]byte, error) {
		return append([]byte(nil), key...), nil
	}).Load("j-seal")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := k.Seal([]byte("the dek"), class)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

// keyWrapOf is the agent's keyWrap: the key's Wrap, else the keychain's.
func keyWrapOf(k agent.GrantKey) string {
	if w, ok := k.(interface{ Wrap() string }); ok {
		return w.Wrap()
	}
	return agent.GrantWrapKeychain
}
