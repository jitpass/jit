// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

// Package keychainwrap is Phase 1's interim implementation of
// vault.KeyWrapper: a Master Encryption Key stored as a plain macOS
// Keychain item, gated by an application-level LocalAuthentication
// challenge (Touch ID/passcode) before every use.
//
// This is deliberately NOT the "hardware-bound" guarantee RFC.md Pillar II
// describes — see spike/keychain-interim-key/FINDINGS.md. Any keychain
// item with real OS-enforced access control (SecAccessControl, whether
// backed by a Secure Enclave key or a plain software key) requires a code
// signature this project doesn't have yet (a real Developer ID identity,
// currently blocked on an unresolved Apple account issue). Only a plain,
// non-ACL keychain item persists without it. To still provide a real
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
// internal/secureenclave is where the real Secure-Enclave-token-bound
// implementation of vault.KeyWrapper lands once a signing identity exists
// — same interface, swapped in behind it, no changes needed elsewhere.
package keychainwrap

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework Security -framework LocalAuthentication
#include "keychain.h"
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
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

	mu  sync.Mutex
	mek []byte
}

var _ vault.KeyWrapper = (*Wrapper)(nil)

// New returns a Wrapper backed by the real LocalAuthentication challenge
// and the real production keychain identifier.
func New() *Wrapper {
	return &Wrapper{service: prodService, account: prodAccount, challenge: realChallenge}
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

	switch int(C.kw_mek_present(cService, cAccount)) {
	case 1:
		return MEKPresent
	case 0:
		return MEKAbsent
	default:
		return MEKIndeterminate
	}
}

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
	mek, err := w.fetchMEK("unlock jit vault to store a secret")
	if err != nil {
		return nil, err
	}
	defer wipe(mek)
	return seal(mek, dek, []byte(class))
}

// UnwrapKeyLabeled implements vault.LabeledKeyWrapper — see WrapKeyLabeled.
func (w *Wrapper) UnwrapKeyLabeled(wrapped []byte, label, class string) ([]byte, error) {
	mek, err := w.fetchMEK("unlock jit vault to read a secret")
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
		if err := w.challenge(reason); err != nil {
			return nil, fmt.Errorf("local authentication failed: %w", err)
		}

		cService := C.CString(w.service)
		defer C.free(unsafe.Pointer(cService))
		cAccount := C.CString(w.account)
		defer C.free(unsafe.Pointer(cAccount))

		var keyPtr *C.uchar
		var keyLen C.int
		result := C.kw_fetch_mek(cService, cAccount, &keyPtr, &keyLen)
		if err := goErr(result); err != nil {
			return nil, err
		}
		mek := C.GoBytes(unsafe.Pointer(keyPtr), keyLen)
		// Same wipe hygiene as the Go-side copies: don't leave a stray MEK
		// in freed C heap memory.
		wipe(unsafe.Slice((*byte)(unsafe.Pointer(keyPtr)), int(keyLen)))
		C.free(unsafe.Pointer(keyPtr))
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
// key protecting every secret in the vault. Exactly one caller exists on
// purpose: `jit vault delete`, behind its own explicit confirmation.
// Without the MEK, every envelope in the vault (and the encrypted
// `_backups/` entries) is permanently undecryptable; passphrase-encrypted
// `jit vault export` files are the only thing that survives it. Never
// call this from a test — a test's cleanup one identifier-collision away
// from the production MEK is a real incident this package already had
// (see testWrapper's TEST-ONLY service name).
func (w *Wrapper) DeleteMEK() error {
	return w.deleteMEK()
}

// deleteMEK removes the stored MEK for this Wrapper's service/account.
// Test-only cleanup helper — normal CLI operation never deletes the MEK
// (that would orphan every existing secret), and it's a method (not a
// free function keyed on the shared production constants) precisely so a
// test can only ever delete the identifier its own Wrapper was built with.
func (w *Wrapper) deleteMEK() error {
	cService := C.CString(w.service)
	defer C.free(unsafe.Pointer(cService))
	cAccount := C.CString(w.account)
	defer C.free(unsafe.Pointer(cAccount))
	return goErr(C.kw_delete_mek(cService, cAccount))
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
