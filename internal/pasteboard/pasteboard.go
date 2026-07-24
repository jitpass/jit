// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

// Package pasteboard is the narrow CGo bridge to NSPasteboard that `jit
// vault get --copy`'s clipboard hygiene needs — the same "small, isolated,
// one place to review" posture as internal/keychainwrap's bridge.
//
// It exists because a bare pbcopy leaves a copied secret on the pasteboard
// forever, where every clipboard manager on the machine indexes it into a
// searchable history — precisely the "swept into indexes, stays long after
// the moment of use" exposure jit exists to close. Two mitigations, both
// here:
//
//   - WriteConcealed declares org.nspasteboard.ConcealedType alongside the
//     text, the convention (nspasteboard.org) clipboard managers honor by
//     not recording the entry at all.
//   - ClearIfUnchanged lets a later process wipe the pasteboard only if
//     nothing else has been copied since — identified by NSPasteboard's
//     changeCount, never by re-reading or carrying the secret's value.
package pasteboard

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework AppKit
#include "pasteboard.h"
*/
import "C"

import (
	"errors"
	"unsafe"
)

// ErrNotUTF8 means the value can't be represented as an NSString — the
// caller should fall back to pbcopy (raw bytes, no concealment).
var ErrNotUTF8 = errors.New("value is not valid UTF-8")

// WriteConcealed puts value on the general pasteboard, marked concealed,
// and returns the pasteboard changeCount identifying this write — the
// handle ClearIfUnchanged later keys on.
func WriteConcealed(value []byte) (changeCount int64, err error) {
	var p *C.char
	if len(value) > 0 {
		p = (*C.char)(unsafe.Pointer(&value[0]))
	}
	n := C.pb_write_concealed(p, C.int(len(value)))
	if n < 0 {
		return 0, ErrNotUTF8
	}
	return int64(n), nil
}

// ChangeCount returns the general pasteboard's current changeCount — for
// a caller that filled the pasteboard some other way (pbcopy) and still
// wants ClearIfUnchanged's contract.
func ChangeCount() int64 {
	return int64(C.pb_change_count())
}

// ClearIfUnchanged clears the pasteboard if its changeCount still equals
// changeCount, reporting whether it did. False means someone copied
// something newer, which must be left alone — clearing the user's OWN
// later copy would turn hygiene into data loss.
func ClearIfUnchanged(changeCount int64) bool {
	return C.pb_clear_if_unchanged(C.long(changeCount)) == 1
}
