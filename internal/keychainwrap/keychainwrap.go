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
)

// presenceFromStatus reads kw_mek_present's status. Only errSecItemNotFound
// is a key that is gone. errSecInteractionNotAllowed is a keychain that
// would have had to ask (a locked one, say), which the query refuses to do
// (kSecUseAuthenticationUIFail): not an answer, so indeterminate, like any
// other error.
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

// The dialog reasons for a direct wrap and unwrap. macOS shows them after
// the app's name: "JitPass is trying to unlock the vault to read a secret."
// The same words internal/agent uses, so a prompt reads the same whichever
// process asked.
const (
	reasonStore = "unlock the vault to store a secret"
	reasonRead  = "unlock the vault to read a secret"
)

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
	mek, err := w.fetchMEK(reasonStore)
	if err != nil {
		return nil, err
	}
	defer wipe(mek)
	return seal(mek, dek, []byte(class))
}

// UnwrapKeyLabeled implements vault.LabeledKeyWrapper — see WrapKeyLabeled.
func (w *Wrapper) UnwrapKeyLabeled(wrapped []byte, label, class string) ([]byte, error) {
	mek, err := w.fetchMEK(reasonRead)
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
// key protecting every secret in the vault. Two callers exist, on purpose
// and no more: `jit vault delete` and `jit uninstall --purge`, each behind
// its own explicit confirmation and a fresh presence check, and the second
// only after the vault directory itself is gone.
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
// is what DeleteMEK and every other delete here run. It's a method (not a
// free function keyed on the shared production constants) precisely so a
// test can only ever delete the identifier its own Wrapper was built with.
func (w *Wrapper) deleteMEK() error {
	return deleteItem(w.cOps(), true, "delete failed")
}

// deleteMEKWithoutFallback is deleteMEK with only SecItemDelete, never the
// reference delete (kw_item_delete_by_ref). It exists for the hardware
// tests that show an older jit's item still needs the fallback, so the
// fallback is never kept after the reason for it is gone, or dropped while
// it still matters.
func (w *Wrapper) deleteMEKWithoutFallback() error {
	return deleteItem(w.cOps(), false, "delete failed")
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

// itemOps are the three keychain calls deleteItem sequences, so its
// decisions can be tested against fakes (cOps is the real one).
type itemOps interface {
	secItemDelete() int32 // SecItemDelete, no dialog
	deleteByRef() int32   // kw_item_delete_by_ref
	presence() MEKPresence
}

// deleteItem deletes an item and decides what the keychain's answers mean.
// A missing item is done. On exactly errSecInvalidOwnerEdit, with fallback
// set, it deletes through the item's reference (kw_item_delete_by_ref, S3g),
// and then only a presence check that finds the item GONE counts as success:
//
//   - a reference lookup that finds nothing is not "deleted". SecItemDelete
//     just saw an item; the lookup, which searches only the login keychain,
//     not finding it means it is somewhere else, and still there. The
//     original error is returned.
//   - a reference delete that reports success is checked, because the item
//     is what matters, not the status.
//
// verb starts the error ("delete failed", "replacing existing key failed"),
// which carries the original OSStatus, as it always has.
func deleteItem(ops itemOps, fallback bool, verb string) error {
	status := ops.secItemDelete()
	switch {
	case status == errSecSuccess || status == errSecItemNotFound:
		return nil
	case status != errSecInvalidOwnerEdit || !fallback:
		return fmt.Errorf("%s, OSStatus=%d", verb, status)
	}
	if ref := ops.deleteByRef(); ref != errSecSuccess {
		return fmt.Errorf("%s, OSStatus=%d (deleting it through its reference: OSStatus=%d)", verb, status, ref)
	}
	if p := ops.presence(); p != MEKAbsent {
		return fmt.Errorf("%s, OSStatus=%d (the item is still there after deleting it through its reference)", verb, status)
	}
	return nil
}

// cOps is itemOps over this wrapper's own item.
type cOps struct{ w *Wrapper }

func (w *Wrapper) cOps() cOps { return cOps{w} }

func (o cOps) secItemDelete() int32 {
	cService, cAccount := o.w.cNames()
	defer C.free(unsafe.Pointer(cService))
	defer C.free(unsafe.Pointer(cAccount))
	return int32(C.kw_item_delete(cService, cAccount))
}

func (o cOps) deleteByRef() int32 {
	cService, cAccount := o.w.cNames()
	defer C.free(unsafe.Pointer(cService))
	defer C.free(unsafe.Pointer(cAccount))
	return int32(C.kw_item_delete_by_ref(cService, cAccount))
}

func (o cOps) presence() MEKPresence { return o.w.MEKPresence() }

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
