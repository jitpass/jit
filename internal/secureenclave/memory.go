// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package secureenclave

import (
	"crypto/rand"
	"sync"
)

// MemoryTesting holds the vault key's two slots in memory instead of the
// Secure Enclave, for tests in other packages (internal/cli) that need the
// real Wrapper, with its slot rules, Presence and Delete, without a signed
// binary. It never reaches the enclave, and its tags are TEST-ONLY. Its
// "sealing" is AES-GCM under a random key per slot: what matters in those
// tests is which slot holds a key, not the enclave's cryptography.
type MemoryTesting struct {
	root string

	mu   sync.Mutex
	keys map[string][]byte // tag to the stand-in private key
}

const memoryTag = "com.jitpass.vault.kek.TEST-ONLY.memory"

// NewMemoryTesting returns empty slots for the vault at root.
func NewMemoryTesting(root string) *MemoryTesting {
	return &MemoryTesting{root: root, keys: map[string][]byte{}}
}

// Wrapper returns a fresh Wrapper over these slots, as New does over the
// enclave's.
func (m *MemoryTesting) Wrapper() *Wrapper {
	return newWrapper(m.root, memoryTag, func(tag string) enclave { return memoryKey{m: m, tag: tag} })
}

// SealInSlotB makes slot B's key and writes the sealed file naming it,
// sealing mek: the state a jit that rotates the key leaves behind.
func (m *MemoryTesting) SealInSlotB(mek []byte) error {
	w := m.Wrapper()
	b := w.slots[1]
	if err := b.enc.create(); err != nil {
		return err
	}
	blob, err := b.enc.seal(mek)
	if err != nil {
		return err
	}
	return writeSealed(w.path, b.tag, blob)
}

// Has reports whether slot "a" or "b" holds a key.
func (m *MemoryTesting) Has(slotName string) bool {
	tag := memoryTag
	if slotName == "b" {
		tag += slotBSuffix
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.keys[tag] != nil
}

type memoryKey struct {
	m   *MemoryTesting
	tag string
}

func (k memoryKey) key() []byte {
	k.m.mu.Lock()
	defer k.m.mu.Unlock()
	return k.m.keys[k.tag]
}

func (k memoryKey) present() (bool, error) { return k.key() != nil, nil }

func (k memoryKey) create() error {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	k.m.mu.Lock()
	defer k.m.mu.Unlock()
	k.m.keys[k.tag] = key
	return nil
}

func (k memoryKey) remove() error {
	k.m.mu.Lock()
	defer k.m.mu.Unlock()
	delete(k.m.keys, k.tag)
	return nil
}

func (k memoryKey) seal(pt []byte) ([]byte, error) {
	key := k.key()
	if key == nil {
		return nil, ErrNoKey
	}
	return seal(key, pt, []byte(k.tag))
}

func (k memoryKey) open(ct []byte, _ string) ([]byte, error) {
	key := k.key()
	if key == nil {
		return nil, ErrNoKey
	}
	return open(key, ct, []byte(k.tag))
}
