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

// quietFetch reads the item with no challenge and no dialog, and checks it
// is a master key's length.
func (w *Wrapper) quietFetch() ([]byte, error) {
	cService, cAccount := w.cNames()
	defer C.free(unsafe.Pointer(cService))
	defer C.free(unsafe.Pointer(cAccount))
	var keyPtr *C.uchar
	var keyLen C.int
	if err := goErr(C.kw_fetch_mek(cService, cAccount, &keyPtr, &keyLen, 1)); err != nil {
		return nil, err
	}
	mek := C.GoBytes(unsafe.Pointer(keyPtr), keyLen)
	wipe(unsafe.Slice((*byte)(unsafe.Pointer(keyPtr)), int(keyLen)))
	C.free(unsafe.Pointer(keyPtr))
	if len(mek) != mekSize {
		wipe(mek)
		return nil, fmt.Errorf("the keychain item %q is not a master key: %d bytes, want %d", w.service, len(mek), mekSize)
	}
	return mek, nil
}
