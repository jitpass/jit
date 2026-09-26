// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package secureenclave

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// A standing grant's or an AI Job's own key, in the Secure Enclave
// (design/secure-enclave-plan.md, step C2): one enclave key per grant, the
// same contract keychainwrap.GrantKeys keeps in the login keychain.
//
// Two differences from the vault's key, both measured:
//   - It never asks. The human's decision was the prompt that made the
//     grant or approved the job; a key that asked again would defeat both.
//   - It works while the Mac is locked (AfterFirstUnlockThisDeviceOnly).
//     A never-ask job runs while you are away, and spike S4 measured a
//     WhenUnlocked key failing about 9 s into a lock.
//
// Apple's ECIES has no additional-data input, so the secret's class, which
// the keychain wrap binds as AES-GCM AAD, is bound inside the sealed bytes
// instead: the plaintext is len(class) | class | DEK, and Open refuses a
// class that does not match. A caller lying about the class gets nothing,
// as with the AAD.

// GrantWrap names what a GrantKey seals, for the ledger's per-secret "wrap"
// (internal/agent's standingWrapAEAD is the keychain's "aead-v1").
const GrantWrap = "se-p256-v1"

const grantTagPrefix = "com.jitpass.grant."

// ErrNoGrantKey is Load's answer when the enclave was reached and holds no
// key for the grant: the key is proven gone. Every other Load failure (an
// enclave this jit can't reach, a lookup that failed) says nothing about
// the key, and a caller must not treat it as gone.
var ErrNoGrantKey = errors.New("no Secure Enclave key for this grant")

// missingGrantKey is ErrNoGrantKey (errors.Is) in a sentence naming the
// grant.
type missingGrantKey string

func (id missingGrantKey) Error() string {
	return fmt.Sprintf("no Secure Enclave key for grant %s (was it revoked?)", string(id))
}

func (missingGrantKey) Is(target error) bool { return target == ErrNoGrantKey }

// GrantKeys creates, loads and deletes grant keys in the enclave. The zero
// value targets production tags; tests set tagPrefix through
// NewTestingGrantKeys.
type GrantKeys struct {
	tagPrefix string
	// newKey builds the enclave handle for a tag; tests pass a fake.
	newKey func(tag string) enclave
	// list returns the ids under a prefix; tests pass a fake.
	list func(prefix string) ([]string, error)
}

// NewTestingGrantKeys returns a store whose tags carry prefix, which must
// contain "TEST-ONLY" (it panics otherwise, as NewTesting does).
func NewTestingGrantKeys(prefix string) GrantKeys {
	if !strings.Contains(prefix, "TEST-ONLY") {
		panic("secureenclave.NewTestingGrantKeys: prefix " + prefix + " is not a TEST-ONLY identifier")
	}
	return GrantKeys{tagPrefix: prefix}
}

// NewTestingGrantKeysLookup is NewTestingGrantKeys whose keys answer the
// lookup (Load, Present) through present, and every Open with openErr,
// instead of the enclave; nothing else about them works. It is for another
// package's tests of what those answers become (internal/cli's grant key
// adapters) from a plain `go test`, which cannot reach the enclave. It
// panics without "TEST-ONLY" in prefix, as NewTestingGrantKeys does.
func NewTestingGrantKeysLookup(prefix string, present func(tag string) (bool, error), openErr error) GrantKeys {
	g := NewTestingGrantKeys(prefix)
	g.newKey = func(tag string) enclave { return lookupOnly{tag: tag, lookup: present, openErr: openErr} }
	return g
}

// lookupOnly is NewTestingGrantKeysLookup's key.
type lookupOnly struct {
	tag     string
	lookup  func(tag string) (bool, error)
	openErr error
}

var errLookupOnly = errors.New("grant key: a lookup-only test key can't be used")

func (l lookupOnly) present() (bool, error)    { return l.lookup(l.tag) }
func (lookupOnly) create() error               { return errLookupOnly }
func (lookupOnly) remove() error               { return errLookupOnly }
func (lookupOnly) seal([]byte) ([]byte, error) { return nil, errLookupOnly }
func (l lookupOnly) open([]byte, string) ([]byte, error) {
	if l.openErr != nil {
		return nil, l.openErr
	}
	return nil, errLookupOnly
}

func (g GrantKeys) tag(id string) (string, error) {
	if id == "" {
		return "", errors.New("grant key: empty grant id")
	}
	prefix := g.tagPrefix
	if prefix == "" {
		prefix = grantTagPrefix
	}
	return prefix + id, nil
}

func (g GrantKeys) key(id string) (enclave, error) {
	tag, err := g.tag(id)
	if err != nil {
		return nil, err
	}
	if g.newKey != nil {
		return g.newKey(tag), nil
	}
	return hardware{tag: tag, group: AccessGroup, afterFirstUnlock: true}, nil
}

// Create mints a fresh enclave key for id and refuses an id that already has
// one: a reused key would let a revoked grant's sealed copies open again.
func (g GrantKeys) Create(id string) (*GrantKey, error) {
	k, err := g.key(id)
	if err != nil {
		return nil, err
	}
	present, err := k.present()
	if err != nil {
		return nil, fmt.Errorf("grant key: %w", err)
	}
	if present {
		return nil, fmt.Errorf("grant key: a key for %s already exists", id)
	}
	if err := k.create(); err != nil {
		return nil, fmt.Errorf("grant key: %w", err)
	}
	return &GrantKey{k: k}, nil
}

// Load returns the key for an existing grant, never prompting. A missing
// key is an error naming the grant.
func (g GrantKeys) Load(id string) (*GrantKey, error) {
	k, err := g.key(id)
	if err != nil {
		return nil, err
	}
	present, err := k.present()
	if err != nil {
		return nil, fmt.Errorf("grant key: %w", err)
	}
	if !present {
		return nil, missingGrantKey(id)
	}
	return &GrantKey{k: k}, nil
}

// Present reports whether id has an enclave key, without using it.
func (g GrantKeys) Present(id string) (bool, error) {
	k, err := g.key(id)
	if err != nil {
		return false, err
	}
	return k.present()
}

// List returns every grant id with an enclave key, from attributes only:
// never uses a key, never prompts. For the orphan-key cleanup (plan C4).
func (g GrantKeys) List() ([]string, error) {
	prefix := g.tagPrefix
	if prefix == "" {
		prefix = grantTagPrefix
	}
	if g.list != nil {
		return g.list(prefix)
	}
	return listTags(AccessGroup, prefix)
}

// Delete destroys the key; a key already gone is success. Every copy sealed
// to it becomes unreadable for good, which is what revoking means.
func (g GrantKeys) Delete(id string) error {
	k, err := g.key(id)
	if err != nil {
		return err
	}
	return k.remove()
}

// GrantKey is one grant's enclave key.
type GrantKey struct{ k enclave }

// Wrap names what Seal produces, for the ledger entry.
func (*GrantKey) Wrap() string { return GrantWrap }

// Seal binds class and seals class and DEK to the key's public half. It never
// prompts.
func (gk *GrantKey) Seal(dek []byte, class string) ([]byte, error) {
	if len(class) > 0xffff {
		return nil, errors.New("grant key: class too long")
	}
	framed := make([]byte, 2+len(class)+len(dek))
	binary.BigEndian.PutUint16(framed, uint16(len(class))) // #nosec G115 -- bounded just above
	copy(framed[2:], class)
	copy(framed[2+len(class):], dek)
	defer wipe(framed)
	return gk.k.seal(framed)
}

// Open unseals with the enclave (no dialog: this key has no presence flag)
// and returns the DEK only if the sealed class is exactly class. Bytes that
// don't open, or open to another class, are ErrWrongKey; an enclave that
// can't be used right now is the enclave's own error (ErrLocked,
// ErrUnavailable: NotNow), which says nothing about the bytes. Everything
// else (a damaged ephemeral key's CryptoTokenKit -3, a lookup's -50) is
// the bridge's error as it came, and not NotNow.
func (gk *GrantKey) Open(wrapped []byte, class string) ([]byte, error) {
	framed, err := gk.k.open(wrapped, "")
	if err != nil {
		return nil, err
	}
	defer wipe(framed)
	if len(framed) < 2 {
		return nil, fmt.Errorf("grant key: sealed copy is damaged: %w", ErrWrongKey)
	}
	n := int(binary.BigEndian.Uint16(framed))
	if len(framed) < 2+n {
		return nil, fmt.Errorf("grant key: sealed copy is damaged: %w", ErrWrongKey)
	}
	if string(framed[2:2+n]) != class {
		return nil, fmt.Errorf("grant key: unwrap failed (wrong class): %w", ErrWrongKey)
	}
	dek := make([]byte, len(framed)-2-n)
	copy(dek, framed[2+n:])
	return dek, nil
}

// Close is a no-op: the enclave keeps the key, and nothing is cached.
func (*GrantKey) Close() {}
