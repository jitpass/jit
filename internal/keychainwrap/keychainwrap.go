// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

// Package keychainwrap is the login-keychain implementation of
// vault.KeyWrapper: a Master Encryption Key stored as a plain macOS
// Keychain item, gated by an application-level LocalAuthentication
// challenge (Touch ID/passcode) before every use. It is every vault's
// backend unless the vault has moved into the Secure Enclave
// (internal/secureenclave; internal/keystore chooses per vault), and the
// only one a jit outside JitPass.app can use.
//
// This is deliberately NOT the "hardware-bound" guarantee RFC.md Pillar II
// describes — see spike/keychain-interim-key/FINDINGS.md. Any keychain
// item with real OS-enforced access control (SecAccessControl, whether
// backed by a Secure Enclave key or a plain software key) needs an
// entitlement only a provisioning profile embedded in an .app bundle can
// authorize, which a bare jit binary can never carry
// (spike/secure-enclave-mek/FINDINGS.md, S3a). Only a plain, non-ACL
// keychain item persists without it. To still provide a real
// local-auth gate, this package enforces it in application code via
// LAContext.evaluatePolicy (independent of Keychain ACL, confirmed working
// without special entitlements), rather than relying on the OS to refuse
// key release.
//
// The real guarantee: a genuine Touch ID/passcode prompt via a real OS
// API, on every wrap/unwrap. What it is NOT: cryptographically enforced —
// a determined attacker with existing code execution as this same local
// user could read the keychain item directly, bypassing this package's
// challenge call entirely. RFC.md B9 calls this distinction out explicitly
// as "OS local-authentication-bound" vs. a stronger, enforced guarantee.
//
// internal/secureenclave is the enforced implementation: the same MEK,
// sealed to a Secure Enclave key that only opens after the enclave's own
// prompt. It needs the jit inside JitPass.app's signed helper bundle, and a
// vault moves to it only by `jit vault rekey --wrapper secure-enclave`
// (design/secure-enclave-plan.md).
package keychainwrap

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework Security -framework LocalAuthentication
#include "keychain.h"
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/jitpass/jit/internal/unlockreason"
	"github.com/jitpass/jit/internal/vault"
)

const (
	prodService = "com.jitpass.vault.mek"
	prodAccount = "default" // Phase 1 is single-user per machine
	mekSize     = 32        // AES-256
)

// VaultKeyItem is the vault key item's name as Keychain Access lists it (its
// service), for messages that tell a person which item to delete by hand.
const VaultKeyItem = prodService

// Wrapper implements vault.KeyWrapper. Use New() to get one with the real
// Touch ID/passcode challenge and the real production keychain identifier;
// tests construct Wrapper{service: ..., account: ..., challenge: ...}
// directly with a fake challenge AND a dedicated, non-production service
// name.
//
// service/account are per-Wrapper fields, not shared package constants,
// specifically so tests can never accidentally target the real MEK a real
// `jit vault init` created on the machine running them. A real incident
// motivated this: this package's tests originally hardcoded the production
// service name, and macOS's per-code-signature keychain access control
// then popped a live "keychainwrap.test wants to use your confidential
// information stored in com.jitpass.vault.mek" permission prompt during a
// test run on a machine that already had a real vault — meaning a test's
// cleanup step was one click away from deleting the real MEK protecting
// every secret already stored in that vault. Never share this identifier
// between tests and production again.
//
// Caches the MEK in memory after the first successful challenge, for the
// lifetime of this Wrapper value — one CLI invocation resolving a whole
// profile (jit run/jit export) only prompts once, not once per secret.
// Every caller still gets its own copy (see fetchMEK) so a caller's
// defer wipe(mek) can't zero out the cache.
//
// A short-lived CLI process may simply drop the Wrapper: it either execs
// (replacing the whole address space) or exits shortly after, and Go
// provides no deterministic-destructor hook to wipe it earlier — the same
// caveat internal/vault's own wipe() documents. A LONG-LIVED host must call
// Close instead. internal/agent builds a fresh Wrapper per unlock and per
// disclosed prompt and then discards it, inside a process that runs for
// weeks; without Close, every one of those left a pinned, unzeroed MEK
// behind that outlived the session's own lock, screen-lock and sleep wipes,
// disappearing only whenever the GC happened to reuse the page.
type Wrapper struct {
	service   string
	account   string
	challenge func(reason string) error
	// missing is the error a definite absence answers with; nil means
	// errNoMEK (the vault's master key). A grant key (grantkey.go) names
	// its grant instead of telling the user to run `jit vault init`.
	missing error

	mu  sync.Mutex
	mek []byte
}

var _ vault.KeyWrapper = (*Wrapper)(nil)

// New returns a Wrapper backed by the real LocalAuthentication challenge
// and the real production keychain identifier.
func New() *Wrapper {
	return &Wrapper{service: prodService, account: prodAccount, challenge: realChallenge}
}

// NewTesting returns a Wrapper over a TEST-ONLY keychain item, for tests in
// other packages that must drive a real keychain (internal/cli's hardware
// move test). It panics on any service name without "TEST-ONLY": the rule
// this type's comment records, enforced where a caller could break it.
func NewTesting(service, account string, challenge func(reason string) error) *Wrapper {
	if !strings.Contains(service, "TEST-ONLY") || service == prodService {
		panic("keychainwrap.NewTesting: service " + service + " is not a TEST-ONLY identifier")
	}
	return &Wrapper{service: service, account: account, challenge: challenge}
}

// FetchMEK returns the raw MEK bytes, challenging first unless already
// cached by this Wrapper instance. Exposed for internal/agent, which
// manages its own TTL-based expiry on top of this rather than relying on
// a Wrapper's forever-cache — internal/agent constructs a fresh Wrapper
// per unlock specifically so an expired session really does re-challenge.
//
// reason comes from the caller because only the agent knows what the unlock
// is FOR. This used to be the fixed string "unlock jit agent", which macOS
// rendered as "jit is trying to unlock jit agent." — true, circular, and
// unable to answer the only question a surprise prompt raises. The agent now
// builds the reason from the kernel-derived identity of whoever asked (see
// internal/agent's challengeReason), so the dialog can say "...for profile
// "mcp-jamf", launched by claude" instead.
func (w *Wrapper) FetchMEK(reason string) ([]byte, error) {
	return w.fetchMEK(reason)
}

// EnsureMEK generates and stores the master encryption key if one doesn't
// already exist. Called by `jit vault init`; safe to call repeatedly.
func (w *Wrapper) EnsureMEK() error {
	cService := C.CString(w.service)
	defer C.free(unsafe.Pointer(cService))
	cAccount := C.CString(w.account)
	defer C.free(unsafe.Pointer(cAccount))

	return goErr(C.kw_ensure_mek(cService, cAccount, C.int(mekSize)))
}

// MEKPresence is the result of a no-prompt master-key existence check
// (Wrapper.MEKPresence). Unlike HasMEK it distinguishes a key that is
// genuinely gone from one whose presence could not be established without
// interaction, so a caller (jit doctor) can report the first and stay silent
// on the second rather than guessing.
type MEKPresence int

const (
	// MEKIndeterminate: presence couldn't be established without a prompt (a
	// keychain error, or interaction that kSecUseAuthenticationUIFail refused).
	// The zero value, so an unset result is never mistaken for "absent".
	MEKIndeterminate MEKPresence = iota
	// MEKPresent: the master-key item exists.
	MEKPresent
	// MEKAbsent: the item is genuinely gone (errSecItemNotFound) — with a
	// vault full of secrets, the total-loss state jit doctor exists to catch.
	MEKAbsent
)

// MEKPresence checks whether this wrapper's keychain item exists WITHOUT
// reading its bytes or prompting (see kw_mek_present), so it is safe to call
// on a non-interactive run where no one could dismiss a keychain dialog.
func (w *Wrapper) MEKPresence() MEKPresence {
	cService := C.CString(w.service)
	defer C.free(unsafe.Pointer(cService))
	cAccount := C.CString(w.account)
	defer C.free(unsafe.Pointer(cAccount))

	return presenceFromStatus(int32(C.kw_mek_present(cService, cAccount)))
}

// The OSStatus values this package decides on. Spelled out rather than taken
// from cgo so the pure-Go decisions (presenceFromStatus, deleteItem) can be
// tested with fakes.
const (
	errSecSuccess               int32 = 0
	errSecItemNotFound          int32 = -25300
	errSecInvalidOwnerEdit      int32 = -25244
	errSecInteractionNotAllowed int32 = -25308
	errSecAuthFailed            int32 = -25293
)

// presenceFromStatus reads kw_mek_present's status. Only errSecItemNotFound
// is a key that is gone. errSecInteractionNotAllowed is a keychain that
// would have had to ask, which the query refuses to do
// (kSecUseAuthenticationUIFail): not an answer, so indeterminate, like any
// other error. (A locked file keychain answers presence without asking:
// TestHardwareLockedKeychainNeverAsks.)
func presenceFromStatus(status int32) MEKPresence {
	switch status {
	case errSecSuccess:
		return MEKPresent
	case errSecItemNotFound:
		return MEKAbsent
	case errSecInteractionNotAllowed:
		return MEKIndeterminate
	}
	return MEKIndeterminate
}

// errNoMEK is the sentence kw_fetch_mek answers errSecItemNotFound with
// (keychain.m), word for word, so the message is the same whether the absence
// is caught before the challenge or, in a race, after it. The backticks are
// what the CLI's error printer renders cyan.
var errNoMEK = errors.New("no master key stored in the keychain, run `jit vault init` first")

// WrapKey implements vault.KeyWrapper.
func (w *Wrapper) WrapKey(dek []byte) ([]byte, error) {
	return w.WrapKeyLabeled(dek, "", "")
}

// UnwrapKey implements vault.KeyWrapper.
func (w *Wrapper) UnwrapKey(wrapped []byte) ([]byte, error) {
	return w.UnwrapKeyLabeled(wrapped, "", "")
}

// WrapKeyLabeled implements vault.LabeledKeyWrapper. keychainwrap has no audit
// trail so it ignores label, but it MUST bind class into the wrap identically
// to internal/agent (both wrappers protect the same vault; a DEK may cross
// between them), so class flows into the AAD.
func (w *Wrapper) WrapKeyLabeled(dek []byte, label, class string) ([]byte, error) {
	mek, err := w.fetchMEK(unlockreason.Store)
	if err != nil {
		return nil, err
	}
	defer wipe(mek)
	return seal(mek, dek, []byte(class))
}

// UnwrapKeyLabeled implements vault.LabeledKeyWrapper — see WrapKeyLabeled.
func (w *Wrapper) UnwrapKeyLabeled(wrapped []byte, label, class string) ([]byte, error) {
	mek, err := w.fetchMEK(unlockreason.Read)
	if err != nil {
		return nil, err
	}
	defer wipe(mek)
	return open(mek, wrapped, []byte(class))
}

func (w *Wrapper) fetchMEK(reason string) ([]byte, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.mek == nil {
		// No fingerprint for a key that is not there. On a Mac that never
		// ran `jit vault init` the challenge used to come first, so the user
		// authenticated and was then told there was nothing to open — from
		// the JitPass app's Protect button, with no terminal to explain it.
		// Only a definite MEKAbsent short-circuits: MEKIndeterminate goes on
		// to the challenge and the real fetch, whose own errors say more.
		if w.MEKPresence() == MEKAbsent {
			if w.missing != nil {
				return nil, w.missing
			}
			return nil, errNoMEK
		}
		if err := w.challenge(reason); err != nil {
			return nil, fmt.Errorf("local authentication failed: %w", err)
		}

		cService := C.CString(w.service)
		defer C.free(unsafe.Pointer(cService))
		cAccount := C.CString(w.account)
		defer C.free(unsafe.Pointer(cAccount))

		var keyPtr *C.uchar
		var keyLen C.int
		result := C.kw_fetch_mek(cService, cAccount, &keyPtr, &keyLen, 0)
		if err := goErr(result); err != nil {
			return nil, err
		}
		mek := C.GoBytes(unsafe.Pointer(keyPtr), keyLen)
		// Same wipe hygiene as the Go-side copies: don't leave a stray MEK
		// in freed C heap memory.
		wipe(unsafe.Slice((*byte)(unsafe.Pointer(keyPtr)), int(keyLen)))
		C.free(unsafe.Pointer(keyPtr))
		// Check the length HERE, where "the keychain item is not a
		// master key" can still be said plainly. A truncated or
		// foreign item (a hand-edited Keychain Access entry, a
		// half-written migration) otherwise travels on and surfaces
		// from aes.NewCipher as "invalid key size", several layers
		// below the fact that explains it — and a user who has just
		// been asked for Touch ID reads any error about their vault
		// as "my secrets are gone".
		if len(mek) != mekSize {
			wipe(mek)
			return nil, fmt.Errorf("master key item in keychain %q is malformed: got %d bytes, want %d", w.service, len(mek), mekSize)
		}
		w.mek = mek
		// Best-effort: keep the cached MEK's page out of swap for this
		// Wrapper's lifetime (same defense-in-depth internal/agent applies
		// to ITS cache). Ignored on failure — a resource-limit refusal
		// must never fail the unlock; macOS also encrypts swap by default.
		_ = unix.Mlock(w.mek)
	}

	// A fresh copy every call: callers defer wipe(mek) on what they get
	// back, which must never zero out the shared cache.
	out := make([]byte, len(w.mek))
	copy(out, w.mek)
	return out, nil
}

// ErrCantReadNow is a quiet read (no challenge, no dialog) the keychain
// refused because it would have had to ask: errSecInteractionNotAllowed
// (-25308), which a *QuietReadError with that status is (errors.Is). It says
// nothing about the item, and it is the one refusal of a grant key's read
// that skips a never-ask job's run rather than stopping the job (a skip
// that goes on is surfaced). errSecAuthFailed (-25293) is not it: keychain.m's
// fetch reads it as the per-code-signature ACL refusing this binary (the
// binary under a running process replaced), and a locked file keychain
// answers a quiet read with it too (TestHardwareLockedKeychainNeverAsks),
// so it can't be told from a refusal that lasts, and a caller that stops
// on an answer must stop on it.
var ErrCantReadNow = errors.New("the keychain can't be read right now without asking")

// Close wipes the cached MEK and releases the mlock pinning its page. It is
// idempotent, and safe to call on a Wrapper that never fetched anything.
//
// Copies already handed out by fetchMEK are untouched — they belong to their
// callers, who wipe them on their own schedule. Close only ends the Wrapper's
// own cache, so a Wrapper that outlives its usefulness inside a long-running
// process stops being a copy of the master key sitting in resident memory.
// After Close a further fetch re-challenges, which is the correct behavior for
// a value whose whole purpose is to bound how long the key is available.
func (w *Wrapper) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.mek == nil {
		return
	}
	wipe(w.mek)
	// Best-effort, mirroring the Mlock in fetchMEK: a failure here leaves a
	// zeroed page pinned, which is harmless — the secret is already gone.
	_ = unix.Munlock(w.mek)
	w.mek = nil
}

// RequireUserPresence runs the local-auth challenge (and MEK fetch)
// immediately, with reason shown in the Touch ID/passcode dialog —
// priming this Wrapper's cache, so wrap/unwrap later in the same
// invocation won't prompt a second time. Exists for commands whose
// mutation can be DELETION-ONLY (GAPS.md #60): Vault.Remove never touches
// the KeyWrapper, so a fresh-auth command that happens to have nothing to
// decrypt used to silently skip the challenge its own docs promised —
// found by a real user on `jit migrate remove`'s very first real run
// ("it didn't prompt for a fingerprint"): the files had already been
// restored by an earlier undo, making the whole run deletions.
func (w *Wrapper) RequireUserPresence(reason string) error {
	mek, err := w.fetchMEK(reason)
	if err != nil {
		return err
	}
	wipe(mek)
	return nil
}

// DeleteMEK permanently removes this wrapper's keychain-stored MEK — the
// key protecting every secret in a keychain vault. Its callers, each behind
// its own explicit confirmation, all CLI commands: `jit vault delete` and
// `jit uninstall --purge` (through keystore's Delete, with a fresh presence
// check, the second only after the vault directory itself is gone); and a
// move into the Secure Enclave, and the removal of a copy it left (`jit
// vault rekey --wrapper secure-enclave`, with or without --force), only once
// the enclave copy has opened. `jit vault init` never deletes it.
// Without the MEK, every envelope in the vault (and the encrypted
// `_backups/` entries) is permanently undecryptable; passphrase-encrypted
// `jit vault export` files are the only thing that survives it. Never
// call this from a test — a test's cleanup one identifier-collision away
// from the production MEK is a real incident this package already had
// (see testWrapper's TEST-ONLY service name).
func (w *Wrapper) DeleteMEK() error {
	return w.deleteMEK()
}

// deleteMEK removes the stored MEK for this Wrapper's service/account, and
// is what DeleteMEK and the staged-key deletes run: all CLI commands (`jit
// vault delete`, `jit uninstall --purge`, the vault key's move, rotation),
// so it may take the CLI's reference fallback. It's a method (not a free
// function keyed on the shared production constants) precisely so a test
// can only ever delete the identifier its own Wrapper was built with. The
// service's grant and job keys never come here (GrantKeys.Delete).
func (w *Wrapper) deleteMEK() error {
	_, err := deleteItem(newItemOps(w), deleteOpts{fallback: cliRefFallback, verb: "delete failed"})
	return err
}

// deleteMEKWithoutFallback is deleteMEK with only SecItemDelete, never the
// reference delete (kw_item_delete_by_ref). It exists for the hardware
// tests that show an older jit's item still needs the fallback, so the
// fallback is never kept after the reason for it is gone, or dropped while
// it still matters.
func (w *Wrapper) deleteMEKWithoutFallback() error {
	_, err := deleteItem(newItemOps(w), deleteOpts{verb: "delete failed"})
	return err
}

// DeleteMEKWithoutFallbackTesting is deleteMEKWithoutFallback for another
// package's hardware test (internal/cli's), which must show the same
// precondition before relying on the fallback. It panics on anything but a
// TEST-ONLY item.
func (w *Wrapper) DeleteMEKWithoutFallbackTesting() error {
	if !strings.Contains(w.service, "TEST-ONLY") || w.service == prodService {
		panic("keychainwrap: DeleteMEKWithoutFallbackTesting on " + w.service)
	}
	return w.deleteMEKWithoutFallback()
}

// DisallowKeychainUITesting switches this process's keychain interaction off
// for good, so no later keychain call can show a dialog: one that would
// have to ask fails with errSecInteractionNotAllowed instead. For the
// hardware tests only (scripts/se-test.sh sets JIT_SE_TEST=1), which must
// never raise a dialog on the Mac running them; it panics anywhere else.
func DisallowKeychainUITesting() {
	if os.Getenv("JIT_SE_TEST") != "1" {
		panic("keychainwrap: DisallowKeychainUITesting outside scripts/se-test.sh")
	}
	C.kw_set_user_interaction(0)
}

// itemOps are the keychain calls deleteItem and setMEK sequence, so their
// decisions can be tested against fakes (cOps is the real one).
type itemOps interface {
	presence() MEKPresence                      // kw_mek_present: every keychain on the search list
	secItemDelete() int32                       // SecItemDelete, no dialog
	deleteByRefNoUI() int32                     // kw_item_delete_by_ref: switches the PROCESS's keychain UI off
	deleteByRefAsIs() int32                     // kw_item_delete_by_ref_no_switch: leaves the switch alone
	defaultKeychainLock() (keychainLock, int32) // kw_default_keychain_lock_state: no UI
	presenceInDefault() MEKPresence
	add(mek []byte) error // kw_add_mek
}

// newItemOps is the itemOps every delete here runs over: a var so a test
// can put fakes under GrantKeys.Delete and setMEK.
var newItemOps = func(w *Wrapper) itemOps { return cOps{w} }

// refFallback is how deleteItem may delete through an item's reference.
type refFallback int

const (
	// noRefFallback: SecItemDelete only.
	noRefFallback refFallback = iota
	// cliRefFallback: kw_item_delete_by_ref, which switches keychain UI off
	// for the whole PROCESS while it runs (kwWithoutUI). Only a CLI command
	// asks for it (deleteMEK, setMEK): the vault key's move, rotation, `jit
	// vault delete`, `jit uninstall --purge`.
	cliRefFallback
	// serviceRefFallback: kw_item_delete_by_ref_no_switch, the same lookup
	// and delete with the process's switch left as it is: the service's
	// grant and job key deletes (GrantKeys.Delete), where flipping it would
	// reach every other request in flight. The delete needs no UI on these
	// items (keychain.m, kwDeleteRefsIn, has the measurements), and it is
	// never tried on a LOCKED default keychain, where that was not measured
	// with interaction on (deleteItem checks the lock first).
	serviceRefFallback
)

// keychainLock is the default keychain's lock state, as the service's
// reference delete checks it first.
type keychainLock int

const (
	lockUnknown  keychainLock = iota // SecKeychainGetStatus (or finding the keychain) failed
	lockUnlocked                     // unlocked
	lockLocked                       // locked
)

// lockFromState reads kw_default_keychain_lock_state: 1 unlocked, 0 locked,
// anything else the OSStatus that stopped the check.
func lockFromState(st int32) (keychainLock, int32) {
	switch st {
	case 1:
		return lockUnlocked, 0
	case 0:
		return lockLocked, 0
	}
	return lockUnknown, st
}

// deleteOpts is what a caller of deleteItem asks for.
type deleteOpts struct {
	// fallback says whether, and how, deleteItem deletes through the
	// item's reference on errSecInvalidOwnerEdit (S3g).
	fallback refFallback
	// addFollows: an add follows (setMEK), and fails with a duplicate if the
	// item is really still there, so a reference delete whose result can't
	// be confirmed is let through (reported as unconfirmed) rather than
	// stopping a replace whose old item is most likely gone.
	addFollows bool
	// verb starts the error ("delete failed", "replacing existing key
	// failed"), which carries the original OSStatus, as it always has.
	verb string
}

// deleteItem deletes an item and decides what the keychain's answers mean.
// A missing item is done. On exactly errSecInvalidOwnerEdit, with a
// fallback asked for, it deletes through the item's reference (S3g), and
// then checks the item is gone, in the
// default keychain only, the one the reference delete deletes in (an item
// of the same name in another keychain on the search list is not this one):
//
//   - a reference lookup that finds nothing is not "deleted". SecItemDelete
//     just saw an item; the lookup, which searches only the login keychain,
//     not finding it means it is somewhere else, and still there. The
//     original error is returned.
//   - a reference delete that reports success is checked, because the item
//     is what matters, not the status. Present is an error. Indeterminate
//     (the check itself would not answer) is an error for a plain delete,
//     saying the delete could not be confirmed; before an add (addFollows)
//     it is let through with unconfirmed set, since the add fails on a
//     duplicate if the item is really still there.
func deleteItem(ops itemOps, o deleteOpts) (unconfirmed bool, err error) {
	status := ops.secItemDelete()
	switch {
	case status == errSecSuccess || status == errSecItemNotFound:
		return false, nil
	case status != errSecInvalidOwnerEdit || o.fallback == noRefFallback:
		return false, fmt.Errorf("%s, OSStatus=%d", o.verb, status)
	}
	var ref int32
	if o.fallback == serviceRefFallback {
		// The service's form runs with keychain interaction as the service
		// has it (on), and a delete on a LOCKED keychain was never measured
		// with interaction on: it might ask to unlock. So it is not tried
		// on one. The grant or job record is already gone, so nothing uses
		// the key, and the start-up cleanup tries it again the next time
		// the service starts (the key note says so).
		switch lock, st := ops.defaultKeychainLock(); lock {
		case lockLocked:
			return false, fmt.Errorf("your keychain is locked: %s, OSStatus=%d", o.verb, status)
		case lockUnknown:
			return false, fmt.Errorf("couldn't check whether your keychain is locked (OSStatus=%d): %s, OSStatus=%d", st, o.verb, status)
		}
		ref = ops.deleteByRefAsIs()
	} else {
		ref = ops.deleteByRefNoUI()
	}
	if ref != errSecSuccess {
		return false, fmt.Errorf("%s, OSStatus=%d (deleting it through its reference: OSStatus=%d)", o.verb, status, ref)
	}
	switch ops.presenceInDefault() {
	case MEKAbsent:
		return false, nil
	case MEKPresent:
		return false, fmt.Errorf("%s, OSStatus=%d (the item is still there after deleting it through its reference)", o.verb, status)
	}
	if o.addFollows {
		return true, nil
	}
	return false, fmt.Errorf("%s, OSStatus=%d (deleted it through its reference, but couldn't confirm it is gone)", o.verb, status)
}

// cOps is itemOps over this wrapper's own item.
type cOps struct{ w *Wrapper }

func (o cOps) secItemDelete() int32 {
	cService, cAccount := o.w.cNames()
	defer C.free(unsafe.Pointer(cService))
	defer C.free(unsafe.Pointer(cAccount))
	return int32(C.kw_item_delete(cService, cAccount))
}

func (o cOps) deleteByRefNoUI() int32 {
	cService, cAccount := o.w.cNames()
	defer C.free(unsafe.Pointer(cService))
	defer C.free(unsafe.Pointer(cAccount))
	return int32(C.kw_item_delete_by_ref(cService, cAccount))
}

func (o cOps) deleteByRefAsIs() int32 {
	cService, cAccount := o.w.cNames()
	defer C.free(unsafe.Pointer(cService))
	defer C.free(unsafe.Pointer(cAccount))
	return int32(C.kw_item_delete_by_ref_no_switch(cService, cAccount))
}

func (o cOps) defaultKeychainLock() (keychainLock, int32) {
	return lockFromState(int32(C.kw_default_keychain_lock_state()))
}

func (o cOps) presence() MEKPresence { return o.w.MEKPresence() }

func (o cOps) presenceInDefault() MEKPresence {
	cService, cAccount := o.w.cNames()
	defer C.free(unsafe.Pointer(cService))
	defer C.free(unsafe.Pointer(cAccount))
	return presenceFromStatus(int32(C.kw_mek_present_default(cService, cAccount)))
}

func (o cOps) add(mek []byte) error {
	cService, cAccount := o.w.cNames()
	defer C.free(unsafe.Pointer(cService))
	defer C.free(unsafe.Pointer(cAccount))
	var p *C.uchar
	if len(mek) > 0 {
		p = (*C.uchar)(unsafe.Pointer(&mek[0]))
	}
	return goErr(C.kw_add_mek(cService, cAccount, p, C.int(len(mek))))
}

// cNames returns the wrapper's service and account as C strings; the caller
// frees both.
func (w *Wrapper) cNames() (*C.char, *C.char) {
	return C.CString(w.service), C.CString(w.account)
}

// uiScopeProbe and queryTraits expose keychain.m's test probes (see
// kw_ui_scope_probe and kw_query_traits in keychain.h) to this package's
// tests, which cannot use cgo.
func uiScopeProbe(start bool) (during, after bool) {
	var s, d, a C.int
	if start {
		s = 1
	}
	C.kw_ui_scope_probe(s, &d, &a)
	return d != 0, a != 0
}

func queryTraits(which int) int { return int(C.kw_query_traits(C.int(which))) }

func queryCount() int { return int(C.kw_query_count()) }

func queryName(which int) string { return C.GoString(C.kw_query_name(C.int(which))) }

func uiOverlapProbe(usec int) bool { return C.kw_ui_overlap_probe(C.int(usec)) != 0 }

func uiAllowed() bool { return C.kw_get_user_interaction() != 0 }

func setUIAllowed(allowed bool) {
	var a C.int
	if allowed {
		a = 1
	}
	C.kw_set_user_interaction(a)
}

// addInKeychain and probeInKeychain are kw_add_in_keychain and
// kw_probe_in_keychain, for the hardware test's temporary keychain.
func addInKeychain(path, service, account string) int32 {
	cp, cs, ca := C.CString(path), C.CString(service), C.CString(account)
	defer C.free(unsafe.Pointer(cp))
	defer C.free(unsafe.Pointer(cs))
	defer C.free(unsafe.Pointer(ca))
	return int32(C.kw_add_in_keychain(cp, cs, ca))
}

// The registry numbers probeInKeychain takes (keychain.h).
const (
	probePresence  = int(C.KW_Q_PRESENCE)
	probeQuietRead = int(C.KW_Q_FETCH_QUIET)
	probeDelete    = int(C.KW_Q_DELETE)
	// probeDeleteByRef is the delete by reference (kwDeleteRefsIn), not a
	// query of its own: KW_Q_REF's lookup, then SecKeychainItemDelete.
	probeDeleteByRef = int(C.KW_Q_REF)
	// probeLockState is the service's lock check before its reference
	// delete (kwKeychainLockState) on that keychain: 1 unlocked, 0 locked.
	probeLockState = int(C.KW_PROBE_LOCK_STATE)
)

func probeInKeychain(path, service, account string, which int, withoutUI bool) int32 {
	cp, cs, ca := C.CString(path), C.CString(service), C.CString(account)
	defer C.free(unsafe.Pointer(cp))
	defer C.free(unsafe.Pointer(cs))
	defer C.free(unsafe.Pointer(ca))
	var w C.int
	if withoutUI {
		w = 1
	}
	return int32(C.kw_probe_in_keychain(cp, cs, ca, C.int(which), w))
}

func realChallenge(reason string) error {
	cReason := C.CString(reason)
	defer C.free(unsafe.Pointer(cReason))
	return goErr(C.kw_challenge(cReason))
}

// BiometryAvailable reports whether Touch ID can currently satisfy a challenge
// on this Mac (hardware present, a fingerprint enrolled, not locked out). It
// performs no prompt. It exists only to sharpen the audit log's best-effort
// "how were you asked" phrasing — "Touch ID or device passcode" when true,
// "device passcode" when false — and is never an authorization signal:
// challenges always fall back to the passcode regardless of what this returns.
func BiometryAvailable() bool {
	return C.kw_biometry_available() != 0
}

func goErr(r C.KWResult) error {
	if r.success != 0 {
		return nil
	}
	msg := "unknown error"
	if r.error_message != nil {
		msg = C.GoString(r.error_message)
		C.free(unsafe.Pointer(r.error_message))
	}
	return fmt.Errorf("%s", msg)
}
