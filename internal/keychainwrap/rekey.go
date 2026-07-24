// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package keychainwrap

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework Security -framework LocalAuthentication
#include "keychain.h"
#include <stdlib.h>
*/
import "C"

import (
	"bytes"
	"fmt"
	"unsafe"
)

// MEK rotation support for `jit vault rekey`. The MEK is a plain keychain
// item any same-user process could have read at any point in its life
// (this package's own doc comment concedes exactly that), which makes
// rotation MORE important here, not less — and there was previously no
// way to do it at all.
//
// The protocol is two-phase so that no crash, at any instant, strands a
// vault that can't be recovered by re-running `jit vault rekey`:
//
//  1. Stage: a fresh MEK is generated under a second keychain account
//     (stagedAccount). Both keys now exist.
//  2. The caller rewraps every envelope's DEK old→staged
//     (vault.RewrapAll), then Promote: the staged bytes replace the
//     primary item and the staged item is deleted.
//
// Crash before promote: primary still opens everything not yet rewrapped,
// staged opens the rest — RewrapAll skips already-current envelopes, so
// re-running finishes the job. Crash during promote (worst case: primary
// deleted, not yet re-added): every envelope was already rewrapped —
// promote only runs after a complete pass — so a re-run finds the staged
// key still present, verifies, and promotes again. The CLI layer keeps a
// marker file so other vault commands refuse to write mid-rekey.

// stagedAccount names the keychain account holding a rekey's
// not-yet-promoted MEK, derived from (never colliding with) the primary
// account. Tests get the same isolation they have for the primary: a
// test Wrapper's staged account is scoped under its TEST-ONLY service.
func stagedAccount(account string) string { return account + ".rekey-next" }

// EnsureStagedRekeyMEK generates and stores the staged next-MEK if one
// doesn't already exist — idempotent, so a resumed rekey reuses the key
// the interrupted run already rewrapped half the vault under, rather
// than generating a third.
func (w *Wrapper) EnsureStagedRekeyMEK() error {
	cService := C.CString(w.service)
	defer C.free(unsafe.Pointer(cService))
	cAccount := C.CString(stagedAccount(w.account))
	defer C.free(unsafe.Pointer(cAccount))
	return goErr(C.kw_ensure_mek(cService, cAccount, C.int(mekSize)))
}

// StagedRekeyWrapper returns a Wrapper over the staged MEK with a NO-OP
// challenge: the rekey command has already put one real challenge in
// front of the whole operation, and a second prompt per rewrapped
// envelope (or even one more for the staged key) would train exactly the
// approve-out-of-habit reflex the prompts exist to break. Only meaningful
// between EnsureStagedRekeyMEK and PromoteStagedRekeyMEK.
func (w *Wrapper) StagedRekeyWrapper() *Wrapper {
	return &Wrapper{service: w.service, account: stagedAccount(w.account), challenge: func(string) error { return nil }}
}

// HasMEK reports whether this wrapper's keychain item exists, without a
// challenge and without leaving anything cached. Any read failure counts
// as "no" — the rekey flow treats a missing primary as the
// crashed-during-promote state, whose recovery path (everything must
// already unwrap under the staged key) fails safe if that guess is wrong.
func (w *Wrapper) HasMEK() bool {
	cService := C.CString(w.service)
	defer C.free(unsafe.Pointer(cService))
	cAccount := C.CString(w.account)
	defer C.free(unsafe.Pointer(cAccount))

	var keyPtr *C.uchar
	var keyLen C.int
	if err := goErr(C.kw_fetch_mek(cService, cAccount, &keyPtr, &keyLen)); err != nil {
		return false
	}
	wipe(unsafe.Slice((*byte)(unsafe.Pointer(keyPtr)), int(keyLen)))
	C.free(unsafe.Pointer(keyPtr))
	return true
}

// PromoteStagedRekeyMEK installs the staged MEK as the primary — the
// point of no return, run only after every envelope has been rewrapped —
// then verifies the primary item now reads back byte-identical before
// deleting the staged copy. The verification order matters: the staged
// item is the only other copy of the key the whole vault now depends on,
// so it must outlive any doubt about the promote.
func (w *Wrapper) PromoteStagedRekeyMEK() error {
	staged := w.StagedRekeyWrapper()
	mek, err := staged.fetchMEK("")
	if err != nil {
		return fmt.Errorf("reading staged rekey key: %w", err)
	}
	defer wipe(mek)

	if err := w.setMEK(mek); err != nil {
		return fmt.Errorf("installing new master key: %w", err)
	}

	// Fresh wrapper: w may have the OLD primary cached; the point is to
	// read what the keychain holds NOW.
	check := &Wrapper{service: w.service, account: w.account, challenge: func(string) error { return nil }}
	got, err := check.fetchMEK("")
	if err != nil {
		return fmt.Errorf("verifying new master key: %w", err)
	}
	defer wipe(got)
	if !bytes.Equal(got, mek) {
		return fmt.Errorf("verifying new master key: keychain read back a different key, staged key kept, rekey NOT complete")
	}

	return staged.deleteMEK()
}

// DeleteStagedRekeyMEK removes a staged key outright — cleanup for `jit
// vault delete` (which destroys the vault the staged key was meant for)
// and for tests.
func (w *Wrapper) DeleteStagedRekeyMEK() error {
	return w.StagedRekeyWrapper().deleteMEK()
}

// Challenge runs the bare LocalAuthentication prompt with no keychain
// fetch attached — for the one rekey resume state (primary key already
// consumed by an interrupted promote) where the human gesture is still
// owed but there is no primary MEK to fetch behind it.
func Challenge(reason string) error {
	return realChallenge(reason)
}

// setMEK stores the given bytes as this wrapper's keychain item,
// replacing any existing one. Private: only the promote step above has
// any business writing chosen key bytes.
func (w *Wrapper) setMEK(mek []byte) error {
	cService := C.CString(w.service)
	defer C.free(unsafe.Pointer(cService))
	cAccount := C.CString(w.account)
	defer C.free(unsafe.Pointer(cAccount))
	var p *C.uchar
	if len(mek) > 0 {
		p = (*C.uchar)(unsafe.Pointer(&mek[0]))
	}
	return goErr(C.kw_set_mek(cService, cAccount, p, C.int(len(mek))))
}
