// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package keychainwrap

/*
#include "keychain.h"
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"
)

// A standing grant's own key (design/standing-grants.md): one plain keychain
// generic-password item per grant, under grantService with the grant id as
// the account, the same posture as the MEK item and for the same reason
// (see the package comment: an OS-enforced ACL needs a provisioning profile
// a bare binary cannot carry). What differs from the MEK is the challenge:
// there is none. A grant key is used with no prompt, which is the whole
// feature, and the human's decision was the disclosed Touch ID that made
// the grant. Its protection equals the MEK's and it opens strictly fewer
// secrets.
//
// On a vault whose key is in the Secure Enclave, grant and job keys live
// there too, one flag apart from the MEK: the MEK's enclave key asks for
// presence, a grant key's does not (secureenclave.GrantKeys, plan C2).
// These keychain grant keys remain for keychain vaults.

const grantService = "com.jitpass.grant.key"

// ErrNoGrantKey is Load's answer when the keychain says the grant's item is
// not there (errSecItemNotFound): the key is proven gone. Besides that,
// Load fails only on an empty id; a key that is there but can't be read
// fails later, in Open.
var ErrNoGrantKey = errors.New("no key for this grant in the keychain")

// missingGrantKey is ErrNoGrantKey (errors.Is) in a sentence naming the
// grant.
type missingGrantKey string

func (id missingGrantKey) Error() string {
	return fmt.Sprintf("no key for grant %s in the keychain (was it revoked?)", string(id))
}

func (missingGrantKey) Is(target error) bool { return target == ErrNoGrantKey }

// GrantKeys is the keychain-backed store the agent's standing grants use.
// The zero value is ready and targets the production service.
type GrantKeys struct {
	// service overrides the keychain service name. Empty means the real
	// one. A TEST MUST SET IT, for the reason this package's Wrapper
	// documents at length: a test that shared the production identifier
	// once put a live "wants to access your confidential information"
	// dialog on a real user's screen, one click from deleting the key
	// protecting their whole vault. Never let a test near grantService.
	service string
	// read, when set, makes every Load find a key without asking the
	// keychain, and stands in for that key's read (NewTestingGrantKeysReading).
	read func() ([]byte, error)
}

// NewTestingGrantKeysReading is NewTestingGrantKeys whose keys are never
// in the keychain: every Load finds one, and every read of it (Seal, Open)
// is read, in place of the keychain's. It is for another package's tests of
// what the keychain's answers become (internal/cli's grant key adapters),
// from a test HOME where no item can be written. It panics on a service
// without "TEST-ONLY", as NewTestingGrantKeys does.
func NewTestingGrantKeysReading(service string, read func() ([]byte, error)) GrantKeys {
	g := NewTestingGrantKeys(service)
	g.read = read
	return g
}

// NewTestingGrantKeys returns a store over TEST-ONLY keychain items, for
// another package's tests of the real keychain path (internal/cli's grant
// key adapters). It panics on a service without "TEST-ONLY", as NewTesting
// does.
func NewTestingGrantKeys(service string) GrantKeys {
	if !strings.Contains(service, "TEST-ONLY") || service == grantService {
		panic("keychainwrap.NewTestingGrantKeys: service " + service + " is not a TEST-ONLY identifier")
	}
	return GrantKeys{service: service}
}

func (g GrantKeys) serviceName() string {
	if g.service == "" {
		return grantService
	}
	return g.service
}

// GrantKey is one grant's key: a Wrapper whose challenge always passes and
// whose "missing" error names the grant rather than the vault.
type GrantKey struct {
	w *Wrapper
	// read, when set, stands in for the keychain read (key): a test's way
	// to have the keychain refuse to read an item that is there.
	read func() ([]byte, error)
}

func (g GrantKeys) wrapper(id string) (*Wrapper, error) {
	if id == "" {
		return nil, errors.New("grant key: empty grant id")
	}
	return &Wrapper{
		service:   g.serviceName(),
		account:   id,
		challenge: func(string) error { return nil },
		missing:   missingGrantKey(id),
	}, nil
}

// Create mints a fresh random key for id. It refuses an id that already
// has one: a grant id is minted once, and reusing a key across grants
// would let a revoked grant's ledger copies open again.
func (g GrantKeys) Create(id string) (*GrantKey, error) {
	w, err := g.wrapper(id)
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
func (g GrantKeys) Load(id string) (*GrantKey, error) {
	w, err := g.wrapper(id)
	if err != nil {
		return nil, err
	}
	if g.read != nil {
		return &GrantKey{w: w, read: g.read}, nil
	}
	if w.MEKPresence() == MEKAbsent {
		return nil, w.missing
	}
	return &GrantKey{w: w}, nil
}

// Delete destroys the key. Idempotent: a key already gone is success,
// since the state the caller wants is "no key".
//
// The long-running service calls this (a revoke, an expiry, the unused-key
// cleanup, a move of grant keys). A key another jit made at another path
// (a switch between the tarball or cask and the app: S3g, the creator's
// PATH decides) answers SecItemDelete with errSecInvalidOwnerEdit, and
// without a fallback a revoked grant's key would stay and the cleanup
// would fail on it at every start. So it takes the reference fallback, in
// its service form (serviceRefFallback): never the CLI form, which
// switches keychain UI off for the whole process (kwWithoutUI), under every
// other request in flight. The lookup still refuses UI per call, and the
// delete by reference needs none on these items (keychain.m,
// kwDeleteRefsIn; TestHardwareGrantKeyDeleteAnOldJitsItem*). It is not
// tried at all on a LOCKED default keychain (never measured with
// interaction on): the error says "your keychain is locked", which the
// revoke or remove passes on in its key note, and the start-up cleanup
// tries the key again the next time the service starts.
func (g GrantKeys) Delete(id string) error {
	w, err := g.wrapper(id)
	if err != nil {
		return err
	}
	ops := newItemOps(w)
	if ops.presence() == MEKAbsent {
		return nil
	}
	_, err = deleteItem(ops, deleteOpts{fallback: serviceRefFallback, verb: "delete failed"})
	return err
}

// List returns every grant id with a keychain key, from metadata only: it
// never reads a key and never prompts. For the orphan-key cleanup (plan C4).
func (g GrantKeys) List() ([]string, error) {
	cService := C.CString(g.serviceName())
	defer C.free(unsafe.Pointer(cService))
	var accounts **C.char
	var n C.int
	if err := goErr(C.kw_list_accounts(cService, &accounts, &n)); err != nil {
		return nil, err
	}
	if accounts == nil {
		return nil, nil
	}
	defer C.free(unsafe.Pointer(accounts))
	list := unsafe.Slice(accounts, int(n))
	ids := make([]string, 0, len(list))
	for _, a := range list {
		ids = append(ids, C.GoString(a))
		C.free(unsafe.Pointer(a))
	}
	return ids, nil
}

// Seal wraps a DEK under the grant key with the secret's class as AAD,
// byte-compatible with the MEK wrap (same seal, same AAD rule). It reads
// the key the quiet way (read), as Open does.
func (k *GrantKey) Seal(dek []byte, class string) ([]byte, error) {
	key, err := k.key()
	if err != nil {
		return nil, fmt.Errorf("grant key: %w", err)
	}
	defer wipe(key)
	return seal(key, dek, []byte(class))
}

// ErrWrongKey is Open saying the copy does not open under this key: the
// AES-GCM authentication failed (tampered or damaged bytes, another key, or
// another class). A key Open couldn't read is not this: it says nothing
// about the copy.
var ErrWrongKey = errors.New("the sealed copy does not open under this grant's key")

// Open unwraps a copy Seal made. Only the unwrap failing is ErrWrongKey;
// reading the key fails with the keychain's own error (key), which is
// ErrCantReadNow only for a read that would have had to ask.
func (k *GrantKey) Open(wrapped []byte, class string) ([]byte, error) {
	key, err := k.key()
	if err != nil {
		return nil, fmt.Errorf("grant key: %w", err)
	}
	defer wipe(key)
	dek, err := open(key, wrapped, []byte(class))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrWrongKey, err)
	}
	return dek, nil
}

// key reads the grant's key the quiet way: no challenge, and no keychain
// dialog either (the registry's KW_Q_FETCH_QUIET, kSecUseAuthenticationUIFail),
// in the service's form (quietFetchNoSwitch: the process's interaction
// switch left alone, a locked default keychain not read at all). Grant keys
// are read only by the long-running service, where a dialog would wait on
// nobody: a never-ask job runs while the owner is away, and one keychain
// dialog would hold its run, and every run after it, until someone clicked.
// A read that would need one fails with errSecInteractionNotAllowed instead
// (ErrCantReadNow: the caller skips that one run, and a skip that persists
// is surfaced, internal/agent's job escalation). A key gone since Load is
// the grant's own "no key" (ErrNoGrantKey). Every other failure (a
// malformed item, errSecAuthFailed) is the keychain's answer, kept whole.
func (k *GrantKey) key() ([]byte, error) {
	if k.read != nil {
		return k.read()
	}
	key, err := k.w.quietFetchNoSwitch()
	var q *QuietReadError
	if errors.As(err, &q) && q.Status == errSecItemNotFound && k.w.missing != nil {
		return nil, k.w.missing
	}
	return key, err
}

// Close wipes the cached key bytes; the keychain item stays.
func (k *GrantKey) Close() {
	k.w.Close()
}
