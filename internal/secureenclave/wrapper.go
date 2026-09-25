// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package secureenclave

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/jitpass/jit/internal/vault"
)

const (
	// prodTag is the vault key's tag in the enclave. A TEST MUST NOT USE IT:
	// keychainwrap's package comment records the incident behind the rule (a
	// test that shared the production identifier was one click away from
	// deleting a real vault's key). Tests build their Wrapper with a
	// TEST-ONLY tag through newWrapper.
	prodTag = "com.jitpass.vault.kek"

	// AccessGroup is where every JitPass enclave key lives. It is named for
	// the vault, not a bundle ID, so moving the service between bundles never
	// orphans a key (design/secure-enclave.md). The provisioning profile
	// authorizes CZC6BH93GJ.* (checked 2026-09-25).
	AccessGroup = "CZC6BH93GJ.com.jitpass.vault"

	mekSize = 32 // AES-256, the same MEK keychainwrap holds
)

// Wrapper is the vault's MEK kept sealed to an enclave key: a
// vault.KeyWrapper, an agent.MEKFetcher and agent.ClosableFetcher, the same
// contract as keychainwrap.Wrapper. Only where the MEK rests differs; what
// it wraps and how is byte-identical (crypto.go), so envelopes, grants and
// jobs never learn which backend a vault uses.
//
// Like keychainwrap.Wrapper it caches the MEK after the first approved open,
// mlocked, and hands every caller its own copy. A long-lived host (the
// agent) builds one per unlock and must Close it.
type Wrapper struct {
	path string // the sealed file: <vault root>/vault-key.sealed
	tag  string
	enc  enclave

	mu  sync.Mutex
	mek []byte
}

var (
	_ vault.KeyWrapper        = (*Wrapper)(nil)
	_ vault.LabeledKeyWrapper = (*Wrapper)(nil)
)

// New returns the production Wrapper for the vault at root: the real enclave
// key, which asks for Touch ID or the login password on every open and is
// usable only while the Mac is unlocked (the service already drops its
// session on lock).
func New(root string) *Wrapper {
	return newWrapper(root, prodTag, hardware{tag: prodTag, group: AccessGroup, presence: true})
}

func newWrapper(root, tag string, enc enclave) *Wrapper {
	return &Wrapper{path: filepath.Join(root, SealedFile), tag: tag, enc: enc}
}

// Presence is what can be said about a vault's enclave key without a prompt.
type Presence int

const (
	// Indeterminate: something failed that says neither yes nor no. The
	// zero value, so an unset result is never mistaken for Absent.
	Indeterminate Presence = iota
	// Absent: no sealed file. This vault's key is not in the enclave.
	Absent
	// Present: the sealed file and the enclave key are both there.
	Present
	// KeyLost: the sealed file is there and the enclave has no key for it.
	// The vault cannot open on this Mac; only a recovery file brings the
	// secrets back. `jit doctor` reports it as loudly as a missing MEK.
	KeyLost
	// Unavailable: the sealed file is there and this process cannot reach
	// the enclave at all (a jit outside JitPass.app).
	Unavailable
)

// Presence checks the file and the key's existence. It never uses the key,
// so it never prompts, and is safe on a non-interactive run.
func (w *Wrapper) Presence() Presence {
	// Lstat, like keystore.Open: a symlink here (dangling or planted) is
	// neither a sealed key nor proof there is none.
	info, err := os.Lstat(w.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Absent
		}
		return Indeterminate
	}
	if !info.Mode().IsRegular() {
		return Indeterminate
	}
	ok, err := w.enc.present()
	switch {
	case err == nil && ok:
		return Present
	case err == nil:
		return KeyLost
	case errors.Is(err, ErrUnavailable):
		return Unavailable
	}
	return Indeterminate
}

// Install seals mek to the enclave key, creating the key when it does not
// exist, and writes the sealed file. It refuses when a sealed file is
// already there: replacing one is a rekey, which stages and verifies (plan
// B4), never an overwrite. Sealing uses only the public half, so Install
// never prompts (spike S1b). It does not verify by opening, which would; a
// caller that moves an existing MEK must read it back with FetchMEK.
func (w *Wrapper) Install(mek []byte) error {
	if len(mek) != mekSize {
		return fmt.Errorf("refusing to install a %d-byte master key, want %d", len(mek), mekSize)
	}
	if _, err := os.Stat(w.path); err == nil {
		return fmt.Errorf("%s already exists; replacing a sealed vault key is a rekey", w.path)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("checking %s: %w", w.path, err)
	}
	present, err := w.enc.present()
	if err != nil {
		return err
	}
	if !present {
		if err := w.enc.create(); err != nil {
			return err
		}
	}
	blob, err := w.enc.seal(mek)
	if err != nil {
		return err
	}
	return writeSealed(w.path, w.tag, blob)
}

// FetchMEK returns the MEK, opening the sealed file in the enclave first
// unless this Wrapper already holds it. The open is where the dialog appears
// ("JitPass is trying to <reason>."), so reason comes from the caller, the
// way keychainwrap.Wrapper.FetchMEK's does.
func (w *Wrapper) FetchMEK(reason string) ([]byte, error) {
	return w.fetchMEK(reason)
}

var errNoSealed = errors.New("this vault's key is not in the Secure Enclave (no sealed key file)")

func (w *Wrapper) fetchMEK(reason string) ([]byte, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.mek == nil {
		k, blob, err := readSealed(w.path)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, errNoSealed
			}
			return nil, err
		}
		// The tag is checked, never followed: the file is writable by any
		// program running as the user, and a tag it chose must not choose
		// which key this Wrapper opens.
		if k.Tag != w.tag {
			return nil, fmt.Errorf("%s was sealed by key %q, not %q", w.path, k.Tag, w.tag)
		}
		mek, err := w.enc.open(blob, reason)
		if err != nil {
			return nil, err
		}
		// Checked here, where "the sealed key is not a master key" can still
		// be said plainly; the same reasoning as keychainwrap's length check.
		if len(mek) != mekSize {
			wipe(mek)
			return nil, fmt.Errorf("%s opened to %d bytes, want %d", w.path, len(mek), mekSize)
		}
		w.mek = mek
		// Best-effort, as in keychainwrap: keep the page out of swap, never
		// fail an unlock over a resource limit.
		_ = unix.Mlock(w.mek)
	}
	out := make([]byte, len(w.mek))
	copy(out, w.mek)
	return out, nil
}

// Close wipes the cached MEK. Idempotent. After Close a fetch opens again,
// which is what bounds how long the key is available.
func (w *Wrapper) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.mek == nil {
		return
	}
	wipe(w.mek)
	_ = unix.Munlock(w.mek)
	w.mek = nil
}

// RequireUserPresence opens now, showing reason, and primes the cache; the
// same role and the same reason (a deletion-only fresh-auth command must
// still ask) as keychainwrap's. internal/cli asserts this method on a vault's
// KeyWrapper.
func (w *Wrapper) RequireUserPresence(reason string) error {
	mek, err := w.fetchMEK(reason)
	if err != nil {
		return err
	}
	wipe(mek)
	return nil
}

// Delete removes the sealed file and then the enclave key, so a crash between
// the two leaves a key with no file (harmless, reported by Presence as
// Absent) rather than a file with no key. Idempotent. Without a recovery
// file, the vault is gone for good.
func (w *Wrapper) Delete() error {
	w.Close()
	if err := os.Remove(w.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("removing %s: %w", w.path, err)
	}
	return w.enc.remove()
}

// WrapKey implements vault.KeyWrapper.
func (w *Wrapper) WrapKey(dek []byte) ([]byte, error) {
	return w.WrapKeyLabeled(dek, "", "")
}

// UnwrapKey implements vault.KeyWrapper.
func (w *Wrapper) UnwrapKey(wrapped []byte) ([]byte, error) {
	return w.UnwrapKeyLabeled(wrapped, "", "")
}

// WrapKeyLabeled implements vault.LabeledKeyWrapper: class is the AAD, bound
// exactly as keychainwrap and the agent bind it; label is ignored, as there.
func (w *Wrapper) WrapKeyLabeled(dek []byte, label, class string) ([]byte, error) {
	mek, err := w.fetchMEK("unlock jit vault to store a secret")
	if err != nil {
		return nil, err
	}
	defer wipe(mek)
	return seal(mek, dek, []byte(class))
}

// UnwrapKeyLabeled implements vault.LabeledKeyWrapper.
func (w *Wrapper) UnwrapKeyLabeled(wrapped []byte, label, class string) ([]byte, error) {
	mek, err := w.fetchMEK("unlock jit vault to read a secret")
	if err != nil {
		return nil, err
	}
	defer wipe(mek)
	return open(mek, wrapped, []byte(class))
}
