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
	"errors"
	"fmt"
	"unsafe"
)

// WrappedKey is one secret's data key as its envelope holds it: wrapped by a
// master key, with the class bound into the wrap (vault.Vault.WrappedDEK).
type WrappedKey struct {
	Wrapped []byte
	Class   string
}

// CountOpens reports how many of keys this wrapper's keychain item unwraps.
// It is internal/keystore's measure of a key left in the keychain when a
// vault's Secure Enclave key is lost: is it the vault's own key, which would
// open every secret, or some other key? No byte of the item leaves this
// function, and nothing unwrapped is kept.
//
// The item is read quietly (kw_fetch_mek with quiet set): no challenge, and
// no keychain dialog either, so it asks nothing of the person running `jit
// vault init`, which prompts for nothing today. A read that would need a
// dialog fails instead, and so does CountOpens: the caller must then not
// treat the item as either answer.
func (w *Wrapper) CountOpens(keys []WrappedKey) (int, error) {
	mek, err := w.quietFetch()
	if err != nil {
		return 0, err
	}
	defer wipe(mek)
	opened := 0
	for _, k := range keys {
		dek, err := open(mek, k.Wrapped, []byte(k.Class))
		if err != nil {
			continue
		}
		wipe(dek)
		opened++
	}
	return opened, nil
}

// QuietReadError is a quiet read (no challenge, no dialog) the keychain
// refused, with its OSStatus, so a caller can tell "can't read it right
// now" from an answer about the item.
type QuietReadError struct {
	Status int32
	Msg    string
}

func (e *QuietReadError) Error() string { return e.Msg }

// MayBeLocked reports the refusal a LOCKED file keychain gives a data read:
// errSecAuthFailed (-25293), at once and with no dialog (measured,
// TestHardwareLockedKeychainNeverAsks). It says nothing about the item;
// unlocking the keychain and trying again is the way on.
func (e *QuietReadError) MayBeLocked() bool { return e.Status == errSecAuthFailed }

// NotAllowed reports errSecInteractionNotAllowed (-25308): the read would
// have had to ask, because this copy of jit isn't on the item's access list
// (another signer or another path made it: S3g). It is not a lock (a locked
// keychain answers -25293), and a quiet read from this copy of jit fails
// the same way every time, so a jit command that rests on one (init over a
// lost key, the move's comparisons, --force's measure) is no way out. It
// says nothing about whether the item is still needed.
func (e *QuietReadError) NotAllowed() bool { return e.Status == errSecInteractionNotAllowed }

// CheckQuietRead reads the item the quiet way (no challenge, no dialog) and
// keeps nothing: nil when this copy of jit can read it without asking, else
// quietFetch's error (a *QuietReadError for a refused read). The move asks
// it after a keychain copy would not go, so the way out it prints is one
// that can work.
func (w *Wrapper) CheckQuietRead() error {
	mek, err := w.quietFetch()
	if err != nil {
		return err
	}
	wipe(mek)
	return nil
}

// ErrNotAMasterKey is a quiet read that found an item of the wrong length:
// it can't be a vault's master key, and it fails the same way every run.
var ErrNotAMasterKey = errors.New("is not a master key")

// quietFetch reads the item with no challenge and no dialog, and checks it
// is a master key's length. A refused read is a *QuietReadError.
func (w *Wrapper) quietFetch() ([]byte, error) {
	cService, cAccount := w.cNames()
	defer C.free(unsafe.Pointer(cService))
	defer C.free(unsafe.Pointer(cAccount))
	var keyPtr *C.uchar
	var keyLen C.int
	r := C.kw_fetch_mek(cService, cAccount, &keyPtr, &keyLen, 1)
	status := int32(r.status)
	if err := goErr(r); err != nil {
		return nil, &QuietReadError{Status: status, Msg: err.Error()}
	}
	mek := C.GoBytes(unsafe.Pointer(keyPtr), keyLen)
	wipe(unsafe.Slice((*byte)(unsafe.Pointer(keyPtr)), int(keyLen)))
	C.free(unsafe.Pointer(keyPtr))
	if len(mek) != mekSize {
		wipe(mek)
		return nil, fmt.Errorf("the keychain item %q %w: %d bytes, want %d", w.service, ErrNotAMasterKey, len(mek), mekSize)
	}
	return mek, nil
}
