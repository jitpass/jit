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
	"time"

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
	// NeedsNewerJit: the key is in the Secure Enclave, sealed in a way only
	// a newer jit reads (secureenclave.ErrSealedByNewerJit). The key may be
	// fine; like Unavailable, the vault is set up and never offered a new
	// key.
	NeedsNewerJit
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
	// The result says what it did, for the command to report.
	Init() (InitResult, error)
	// Delete destroys the key. Every secret it protected is gone with it.
	Delete() error
}

// InitResult is what Store.Init did.
type InitResult int

const (
	// InitReady: the key was there, or was made for a new vault.
	InitReady InitResult = iota
	// InitNewKey: the vault's Secure Enclave key was lost and a new
	// keychain key was made. The old secrets stay on disk, sealed to the
	// lost key, until `jit vault import` brings them back (restore_pending).
	InitNewKey
	// InitRecovered: the vault's Secure Enclave key was lost, and the
	// keychain still held the vault's own key (a copy a move into the
	// enclave could not delete), measured by it opening every secret. The
	// vault opens from the keychain now, and nothing waits for a restore.
	InitRecovered
)

// ErrEnclaveKeyKept and ErrKeychainCopyKept say which key an enclave
// vault's Delete could not remove; both may be in one error (errors.Is).
var (
	ErrEnclaveKeyKept   = errors.New("couldn't delete the vault key in the Secure Enclave")
	ErrKeychainCopyKept = errors.New("couldn't delete the keychain copy of the vault key")
)

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

// OpenTesting is Open for another package's tests, with key standing in for
// the login keychain's vault key item, so a test drives a command's real
// path through the Store without reaching the production item. It panics
// for a vault in the Secure Enclave, which it cannot stand in for.
func OpenTesting(root string, key KeychainKey) Store {
	s := Open(root)
	if s.Kind() != KindKeychain {
		panic("keystore.OpenTesting: " + root + " is not a keychain vault")
	}
	return keychainStore{key: func() KeychainKey { return key }}
}

// Keychain returns the keychain backend's own Wrapper for `jit vault rekey`
// and the staged-key cleanup in `jit uninstall`, the two paths that work on
// the keychain's items directly until step B4. Nothing else should call it.
func Keychain() *keychainwrap.Wrapper {
	return keychainwrap.New()
}

// KeychainCopy reports, without a prompt, whether the login keychain holds
// the vault key item, whichever backend the vault uses. For an enclave vault
// that item is a copy a move into the Secure Enclave could not delete: never
// read (Open follows the sealed file), but still a readable key, so `jit
// status` and `jit doctor` report it (internal/cli, keychain_copy_left and
// vault_key_copy). Metadata only (keychainwrap.MEKPresence).
func KeychainCopy() Presence { return keychainStore{}.Presence() }

// KeychainItemName is the vault key item's name as Keychain Access lists it.
const KeychainItemName = keychainwrap.VaultKeyItem

// KeychainKey is what the keychain Store hands out: the vault key item's
// Wrapper, which is also each unlock's Fetcher (keychainwrap.Wrapper).
type KeychainKey interface {
	Wrapper
	Fetcher
}

// newKeychainKey builds the production item's Wrapper; a var so this
// package's tests never reach that item.
var newKeychainKey = func() KeychainKey { return keychainwrap.New() }

// keychainStore is a keychain vault's key. key, when set, stands in for the
// item (OpenTesting); the zero value is the production item.
type keychainStore struct {
	key func() KeychainKey
}

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

// NewFetcher and NewWrapper are fresh each call: every command through
// openVault, and each of the service's unlocks, which builds a fetcher per
// unlock.
func (s keychainStore) NewFetcher() Fetcher { return s.open() }

func (s keychainStore) NewWrapper() Wrapper { return s.open() }

func (s keychainStore) open() KeychainKey {
	if s.key != nil {
		return s.key()
	}
	return newKeychainKey()
}

func (keychainStore) Init() (InitResult, error) { return InitReady, initKeychain() }

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
	return EnclavePresence(newEnclaveWrapper(s.root).Presence())
}

// EnclavePresence is what an enclave vault's Store reports for what its
// secureenclave.Wrapper found.
func EnclavePresence(p secureenclave.Presence) Presence {
	switch p {
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
	case secureenclave.NeedsNewerJit:
		return NeedsNewerJit
	}
	return Indeterminate
}

func (s enclaveStore) NewFetcher() Fetcher { return newEnclaveWrapper(s.root) }

func (s enclaveStore) NewWrapper() Wrapper { return newEnclaveWrapper(s.root) }

// LostSealedFile is where Init sets a sealed key file aside when this Mac's
// enclave has no key for it: kept, not deleted, because it is the one record
// of which key the old secrets were sealed under. vault.SealedToLostKey
// reads it (with the snapshot Init writes beside it) to tell status and
// doctor which secrets a recovery file still has to bring back.
const LostSealedFile = vault.LostSealedKeyFile

// Init has nothing to create for an enclave vault whose key is there: it was
// made when the vault moved into the enclave. When the key is LOST it starts
// over the way a keychain vault whose key is gone does: the sealed file is
// set aside and a new keychain key is made, so `jit vault import` can
// restore a recovery file. The old secrets stay unreadable, as they already
// were, and stay on disk; vault.SetAsideLostSealedKey records which they are
// so `jit status` (restore_pending) and `jit doctor` (vault_restore) keep
// saying so until the import has brought them back.
//
// Except when the keychain already holds a key under the vault key's name.
// Making a "new" key would quietly adopt it (kw_ensure_mek keeps an item it
// finds), so Init never gets that far without deciding what the item is:
//
//   - It may be the vault's own key, left by a move into the enclave that
//     could not delete it: then it rescues every secret. It counts as that
//     only when it opens every live secret's key (leftoverOpens; the item is
//     read with no challenge and no dialog, so init still asks nothing).
//     The vault then opens from the keychain: the sealed file is set aside
//     under a name no lost-key rule reads, no lost-key record is written,
//     and Init reports InitRecovered.
//   - Anything else is refused with nothing changed. The refusal advises
//     removing the item only when the measure PROVED it opens none of this
//     vault's secrets: it was read, every live secret was tried against it
//     (none untested) and none opened. A locked keychain is "unlock it and
//     run init again"; a secret that couldn't be tried is "run init again
//     once jit can read it"; an item this copy of jit isn't allowed to read,
//     one it can't use, a vault with no secrets to try it on, or a key that
//     opens only some of them leaves removing it to the person, recovery
//     file first, saying what jit couldn't tell (and, for some, what it
//     would cost). Keeping the vault on a key jit can't vouch for,
//     silently, is the one outcome this must not have; advising the delete
//     of what may be the vault's only key is the other.
func (s enclaveStore) Init() (InitResult, error) {
	switch s.Presence() {
	case Present:
		return InitReady, nil
	case KeyLost:
		switch leftoverPresence() {
		case Absent:
			if err := vault.SetAsideLostSealedKey(s.root, time.Now()); err != nil {
				return InitReady, err
			}
			return InitNewKey, initKeychain()
		case Present:
			return s.initOverLeftover()
		}
		return InitReady, errors.New("the vault's Secure Enclave key is lost,\n" +
			"and jit couldn't check your keychain for a key under its name.\n" +
			"Nothing changed. If your keychain is locked, unlock it;\n" +
			"then run `jit vault init` again")
	case Unavailable:
		return InitReady, secureenclave.ErrUnavailable
	case NeedsNewerJit:
		return InitReady, secureenclave.ErrSealedByNewerJit
	}
	return InitReady, errors.New("could not check this vault's Secure Enclave key")
}

// initOverLeftover is Init's decision over a keychain item found when the
// enclave key is lost (see Init).
func (s enclaveStore) initOverLeftover() (InitResult, error) {
	m, err := leftoverOpens(s.root)
	var q *keychainwrap.QuietReadError
	switch {
	case errors.As(err, &q) && q.MayBeLocked():
		// A LOCKED login keychain answers presence (so this item counts as
		// there) and fails the read at once with errSecAuthFailed
		// (measured, TestHardwareLockedKeychainNeverAsks). That says
		// nothing about the item, which may be the vault's only key.
		return InitReady, fmt.Errorf("the vault's Secure Enclave key is lost, and jit couldn't read\n"+
			"the key in your keychain under the vault key's name right now\n"+
			"(OSStatus=%d): your keychain may be locked.\n"+
			"Nothing changed. Unlock it, then run `jit vault init` again", q.Status)
	case errors.As(err, &q) && q.NotAllowed():
		// errSecInteractionNotAllowed: this copy of jit isn't on the item's
		// access list (S3g: another signer or path made it). Not a lock,
		// and every run of this jit fails the same way, so the way on is
		// the person's own, recovery file first; and the item may be the
		// vault's only key, so jit never advises it.
		return InitReady, fmt.Errorf("the vault's Secure Enclave key is lost, and this copy of jit\n"+
			"isn't allowed to read the key in your keychain under the vault\n"+
			"key's name (OSStatus=%d); another copy of jit likely saved it.\n"+
			"Nothing changed.\n%s", q.Status, removeItYourself())
	case err != nil:
		// An item that isn't a master key, or can't be read for another
		// reason: it fails the same way every run, so not "try again", and
		// nothing about it was measured.
		return InitReady, fmt.Errorf("the vault's Secure Enclave key is lost, and jit can't use\n"+
			"the key in your keychain under the vault key's name\n"+
			"(%s). Nothing changed.\n%s", truncateStart(err.Error(), 48), removeItYourself())
	case m.Total > 0 && m.Opened == m.Total:
		from := filepath.Join(s.root, vault.SealedKeyFile)
		to := filepath.Join(s.root, RecoveredSealedFile+"-"+time.Now().UTC().Format("20060102T150405.000000000Z"))
		if err := os.Rename(from, to); err != nil {
			return InitReady, fmt.Errorf("setting the lost vault key's file aside: %w", err)
		}
		return InitRecovered, nil
	case m.Untested > 0:
		// A secret that couldn't be tried is one the key may open.
		files := "their files couldn't be read"
		if m.Untested == 1 {
			files = "its file couldn't be read"
		}
		return InitReady, fmt.Errorf("the vault's Secure Enclave key is lost, and jit couldn't test\n"+
			"%s against the key in your keychain: %s.\n"+
			"Nothing changed; jit won't use that key or remove it.\n"+
			"Once jit can read them, run `jit vault init` again", secretsWord(m.Untested), files)
	case m.Total == 0:
		return InitReady, fmt.Errorf("the vault's Secure Enclave key is lost.\n"+
			"A key in your keychain has the vault key's name, but with no\n"+
			"secrets to try it on, jit can't tell whose it is.\n"+
			"jit won't use it; nothing changed.\n%s", removeItYourself())
	case m.Opened == 0:
		// The one case that may advise removing it: read, tried against
		// every live secret, and it opened none.
		return InitReady, fmt.Errorf("the vault's Secure Enclave key is lost.\n"+
			"A key in your keychain has the vault key's name, but it opens\n"+
			"none of this vault's %s. jit won't use it; nothing changed.\n"+
			"Remove %q in Keychain Access,\n"+
			"then run `jit vault init` again", secretsWord(m.Total), KeychainItemName)
	}
	// Some, not all: the item is proven to open those, so the cost of
	// removing it is said plainly.
	lose := fmt.Sprintf("those %d unless your recovery file has them", m.Opened)
	if m.Opened == 1 {
		lose = "that one unless your recovery file has it"
	}
	return InitReady, fmt.Errorf("the vault's Secure Enclave key is lost.\n"+
		"A key in your keychain has the vault key's name, and it opens\n"+
		"%d of this vault's %s. Removing it loses\n"+
		"%s.\n"+
		"jit won't use it or remove it; nothing changed.\n"+
		"If your recovery file has your secrets, you can remove that key\n"+
		"yourself in Keychain Access (%q),\n"+
		"run `jit vault init` again, then import the file", m.Opened, secretsWord(m.Total), lose, KeychainItemName)
}

// removeItYourself is the way on from a refusal over an item jit couldn't
// measure: the person's choice, recovery file first, never jit's advice to
// delete what may be the vault's only key.
func removeItYourself() string {
	return fmt.Sprintf("If your recovery file has your secrets, you can remove that key\n"+
		"yourself in Keychain Access (%q),\n"+
		"run `jit vault init` again, then import the file;\n"+
		"jit can't tell whether that key is still needed", KeychainItemName)
}

// secretsWord is "1 secret" or "n secrets".
func secretsWord(n int) string {
	if n == 1 {
		return "1 secret"
	}
	return fmt.Sprintf("%d secrets", n)
}

// RecoveredSealedFile is where Init sets the sealed file aside once the
// keychain's own copy of the key has rescued the vault. Not
// LostSealedFile: nothing is sealed to a lost key any more, and every
// lost-key rule reads that name.
const RecoveredSealedFile = vault.SealedKeyFile + ".recovered"

// leftoverPresence is KeychainCopy, and leftoverOpens is the measure of a
// leftover key, as vars so no test reaches the production keychain item.
var (
	leftoverPresence = KeychainCopy
	leftoverOpens    = func(root string) (KeyMeasure, error) { return KeychainKeyOpens(root, keychainwrap.New()) }
)

// truncateStart shortens s to n runes from the front, marking the cut: the
// end of a keychain error is where its OSStatus is.
func truncateStart(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return "…" + string(r[len(r)-n+1:])
}

// KeyCounter is what KeychainKeyOpens needs of a keychain item
// (keychainwrap.Wrapper's CountOpens).
type KeyCounter interface {
	CountOpens([]keychainwrap.WrappedKey) (int, error)
}

// KeyMeasure is what measuring a keychain item against a vault's live
// secrets found.
type KeyMeasure struct {
	Opened   int // secrets whose data key the item opens
	Untested int // secrets whose envelope couldn't be read, so never tried
	Total    int // live secrets
}

// KeychainKeyOpens measures a keychain item against a vault's live
// secrets: how many it opens, and how many couldn't be tried (an envelope
// that couldn't be read). Init over a lost key takes it before deciding on
// an item it found, and `jit vault rekey --wrapper secure-enclave --force`
// before it deletes one. It reads the item quietly (keychainwrap.CountOpens:
// no challenge, no dialog), always, even with nothing to try it on, so a
// nil error means the item itself was read.
func KeychainKeyOpens(root string, kc KeyCounter) (KeyMeasure, error) {
	id, err := vault.EnsureDeviceID(root)
	if err != nil {
		return KeyMeasure{}, err
	}
	v := &vault.Vault{Root: root, RecipientID: id}
	paths, err := v.List()
	if err != nil {
		return KeyMeasure{}, err
	}
	m := KeyMeasure{Total: len(paths)}
	var keys []keychainwrap.WrappedKey
	for _, p := range paths {
		wrapped, class, err := v.WrappedDEK(p)
		if err != nil {
			m.Untested++
			continue
		}
		keys = append(keys, keychainwrap.WrappedKey{Wrapped: wrapped, Class: class})
	}
	m.Opened, err = kc.CountOpens(keys)
	return m, err
}

// Delete destroys the enclave key, and a keychain copy of the same key if a
// move into the enclave left one: after `jit vault delete`, a copy left
// behind would be picked up as the NEW vault's key by the next `jit vault
// init` (kw_ensure_mek keeps an item it finds), quietly reviving the old key.
// Each failure says which key it was (ErrEnclaveKeyKept,
// ErrKeychainCopyKept), because the caller's next step depends on it.
func (s enclaveStore) Delete() error {
	var errs []error
	if err := newEnclaveWrapper(s.root).Delete(); err != nil {
		errs = append(errs, fmt.Errorf("%w: %w", ErrEnclaveKeyKept, err))
	}
	if err := deleteKeychainCopy(); err != nil {
		errs = append(errs, fmt.Errorf("%w: %w", ErrKeychainCopyKept, err))
	}
	return errors.Join(errs...)
}

// deleteKeychainCopy removes the keychain item under the vault key's name; a
// missing item is done. A var so no test reaches the production keychain.
var deleteKeychainCopy = func() error { return keychainStore{}.Delete() }
