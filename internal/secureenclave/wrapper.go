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
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/jitpass/jit/internal/unlockreason"
	"github.com/jitpass/jit/internal/vault"
)

const (
	// prodTag is the vault key's tag in the enclave: slot A, the key of
	// every enclave vault until a rotation. A TEST MUST NOT USE IT, nor slot
	// B's tag: keychainwrap's package comment records the incident behind
	// the rule (a test that shared the production identifier was one click
	// away from deleting a real vault's key). Tests build their Wrapper with
	// a TEST-ONLY tag through newWrapper.
	prodTag = "com.jitpass.vault.kek"

	// TeamID is the Apple team that signs JitPass.app.
	TeamID = "CZC6BH93GJ"

	// slotBSuffix makes slot B's tag from slot A's: com.jitpass.vault.kek.b.
	// A rotation (a later jit) seals the new MEK to the slot the file does
	// not name, then deletes the other; the next goes back to A with a fresh
	// key (design/secure-enclave-rotation.md, D1). This jit only reads both.
	slotBSuffix = ".b"

	// AccessGroup is where every JitPass enclave key lives. It is named for
	// the vault, not a bundle ID, so moving the service between bundles never
	// orphans a key (design/secure-enclave.md). The provisioning profile
	// authorizes CZC6BH93GJ.* (checked 2026-09-25).
	AccessGroup = TeamID + ".com.jitpass.vault"

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
	path  string // the sealed file: <vault root>/vault-key.sealed
	slots [2]slot

	mu  sync.Mutex
	mek []byte
}

// slot is one of the vault key's two places in the enclave: A, where every
// vault's key is made (Install), or B. Both keys are made the same way
// (UserPresence), which is why the file may choose between them and nothing
// else.
type slot struct {
	tag string
	enc enclave
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
	return newWrapper(root, prodTag, vaultKey)
}

// vaultKey is the real enclave key at tag, made as the vault's key is.
func vaultKey(tag string) enclave {
	return hardware{tag: tag, group: AccessGroup, presence: true}
}

// newWrapper builds the Wrapper whose slot A is tag and slot B tag+".b",
// each key from key(tag).
func newWrapper(root, tag string, key func(tag string) enclave) *Wrapper {
	b := tag + slotBSuffix
	return &Wrapper{
		path:  filepath.Join(root, SealedFile),
		slots: [2]slot{{tag: tag, enc: key(tag)}, {tag: b, enc: key(b)}},
	}
}

// slotFor returns the key that the sealed file's tag names. It follows the
// tag only to one of this vault's two slots: a grant's key (which never
// asks) or any other key is refused, so the file can never choose a key
// that opens without a dialog. A tag in slot A's namespace that is neither
// slot is a slot a newer jit made: refused as that, never as a lost key.
func (w *Wrapper) slotFor(tag string) (enclave, error) {
	for _, s := range w.slots {
		if tag == s.tag {
			return s.enc, nil
		}
	}
	if strings.HasPrefix(tag, w.slots[0].tag+".") {
		return nil, ErrSealedByNewerJit
	}
	return nil, fmt.Errorf("%s was sealed by key %q, not %q or %q", w.path, tag, w.slots[0].tag, w.slots[1].tag)
}

// NewTesting and NewStagedTesting return the real enclave Wrapper under a
// TEST-ONLY tag, for tests in other packages that drive the hardware
// (internal/cli's move test, through scripts/se-test.sh). They panic on any
// tag without "TEST-ONLY", so no test can reach the vault's own key.
func NewTesting(root, tag string) *Wrapper {
	if !strings.Contains(tag, "TEST-ONLY") || tag == prodTag {
		panic("secureenclave.NewTesting: tag " + tag + " is not a TEST-ONLY identifier")
	}
	return newWrapper(root, tag, vaultKey)
}

// NewStagedTesting is NewTesting over the staged sealed file.
func NewStagedTesting(root, tag string) *Wrapper {
	w := NewTesting(root, tag)
	w.path += stagedSuffix
	return w
}

// stagedSuffix names the sealed file a move writes and verifies before it
// becomes the vault's (`jit vault rekey --wrapper secure-enclave`): until the
// rename, keystore.Open still sees a keychain vault.
const stagedSuffix = ".next"

// NewStaged returns the production Wrapper over the STAGED sealed file, the
// one a move seals to and then opens once to verify.
func NewStaged(root string) *Wrapper {
	w := New(root)
	w.path += stagedSuffix
	return w
}

// PromoteStaged renames the verified staged file over the vault's sealed
// key file, atomically: from this rename on, the vault is an enclave vault.
func PromoteStaged(root string) error {
	real := filepath.Join(root, SealedFile)
	if err := os.Rename(real+stagedSuffix, real); err != nil {
		return fmt.Errorf("promoting the staged sealed key: %w", err)
	}
	return nil
}

// RemoveStaged removes a staged file an interrupted move left, which was
// never verified. The enclave key stays: the real sealed file, if any,
// still needs it.
func RemoveStaged(root string) error {
	err := os.Remove(filepath.Join(root, SealedFile) + stagedSuffix)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("removing the staged sealed key: %w", err)
	}
	return nil
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
	// NeedsNewerJit: the sealed file is one only a newer jit reads (a slot,
	// version or sealing this jit does not know). The key may be fine; this
	// jit can't tell, and must never call it lost.
	NeedsNewerJit
)

// Presence checks the file, and the key in the slot the file names. It never
// uses the key, so it never prompts, and is safe on a non-interactive run.
// A file naming a slot whose key is gone is KeyLost even when the other slot
// has a key: that key sealed no file this vault uses (a planted old file
// reads the same way, and putting the right file back still works, since
// `jit vault init` sets the file aside rather than deleting it).
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
	k, _, err := readSealed(w.path)
	if err != nil {
		if errors.Is(err, errUpdateJit) {
			return NeedsNewerJit
		}
		return Indeterminate
	}
	enc, err := w.slotFor(k.Tag)
	if err != nil {
		if errors.Is(err, errUpdateJit) {
			return NeedsNewerJit
		}
		return Indeterminate
	}
	ok, err := enc.present()
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

// Install seals mek to slot A's key, creating the key when it does not
// exist, and writes the sealed file naming slot A (a move into the enclave
// always lands there). It refuses when a sealed file is already there:
// replacing one is a rekey, which stages and verifies (plan B4), never an
// overwrite. Sealing uses only the public half, so Install
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
	a := w.slots[0]
	present, err := a.enc.present()
	if err != nil {
		return err
	}
	if !present {
		if err := a.enc.create(); err != nil {
			return err
		}
	}
	blob, err := a.enc.seal(mek)
	if err != nil {
		return err
	}
	return writeSealed(w.path, a.tag, blob)
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
		// The tag is followed only to one of this vault's two slots: the
		// file is writable by any program running as the user, and a tag it
		// chose must not choose any other key.
		enc, err := w.slotFor(k.Tag)
		if err != nil {
			return nil, err
		}
		mek, err := enc.open(blob, reason)
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

// Delete removes the sealed file and then the enclave keys, so a crash
// between the two leaves a key with no file (harmless, reported by Presence
// as Absent) rather than a file with no key. Both slots' keys go, whichever
// the file named and without reading it (`jit vault delete` has removed the
// file already): a key a rotation staged in the other slot goes too. Each
// slot is tried even when the other fails; a failure both share (a jit
// outside JitPass.app) is said once. Idempotent. Without a recovery file,
// the vault is gone for good.
func (w *Wrapper) Delete() error {
	w.Close()
	if err := os.Remove(w.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("removing %s: %w", w.path, err)
	}
	var errs []error
	for _, s := range w.slots {
		err := s.enc.remove()
		if err != nil && (len(errs) == 0 || errs[0].Error() != err.Error()) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
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
	mek, err := w.fetchMEK(unlockreason.Store)
	if err != nil {
		return nil, err
	}
	defer wipe(mek)
	return seal(mek, dek, []byte(class))
}

// UnwrapKeyLabeled implements vault.LabeledKeyWrapper.
func (w *Wrapper) UnwrapKeyLabeled(wrapped []byte, label, class string) ([]byte, error) {
	mek, err := w.fetchMEK(unlockreason.Read)
	if err != nil {
		return nil, err
	}
	defer wipe(mek)
	return open(mek, wrapped, []byte(class))
}
