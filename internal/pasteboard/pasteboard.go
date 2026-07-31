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
#include <stdlib.h>
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
	return writeConcealed("", value)
}

// ChangeCount returns the general pasteboard's current changeCount — for
// a caller that filled the pasteboard some other way (pbcopy) and still
// wants ClearIfUnchanged's contract.
func ChangeCount() int64 {
	return changeCount("")
}

// ClearIfUnchanged clears the pasteboard if its changeCount still equals
// changeCount, reporting whether it did. False means someone copied
// something newer, which must be left alone — clearing the user's OWN
// later copy would turn hygiene into data loss.
func ClearIfUnchanged(count int64) bool {
	return clearIfUnchanged("", count)
}

// The three below are the exported functions with the pasteboard named
// instead of assumed — the seam the package test drives the real
// write/count/clear behavior through against a private scratch board.
//
// It exists for the same reason internal/screenlock's watch() takes its
// notification name: a test against the GENERAL pasteboard would clear
// whatever the person running the suite had just copied, and
// clearIfUnchanged would then be destroying their data rather than jit's
// secret. Named pasteboards have identical changeCount semantics and no
// connection to the clipboard. An empty name means the general pasteboard,
// so production behavior is unchanged and untouched by any of this.

func writeConcealed(name string, value []byte) (int64, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	var p *C.char
	if len(value) > 0 {
		p = (*C.char)(unsafe.Pointer(&value[0]))
	}
	n := C.pb_write_concealed(cname, p, C.int(len(value)))
	if n < 0 {
		return 0, ErrNotUTF8
	}
	return int64(n), nil
}

func changeCount(name string) int64 {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	return int64(C.pb_change_count(cname))
}

func clearIfUnchanged(name string, count int64) bool {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	return C.pb_clear_if_unchanged(cname, C.long(count)) == 1
}

// concealedType is the marker whose PRESENCE tells a clipboard manager not to
// record this entry (nspasteboard.org). It duplicates the literal
// pb_write_concealed declares, deliberately: the test asserts this spelling is
// on the board, so the two drifting apart is a failure rather than a silently
// ineffective marker.
const concealedType = "org.nspasteboard.ConcealedType"

// hasType reports whether the named pasteboard declares t. TEST-ONLY — see
// pb_has_type in pasteboard.h. Reports type presence only, never contents.
func hasType(name, t string) bool {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	ctype := C.CString(t)
	defer C.free(unsafe.Pointer(ctype))
	return C.pb_has_type(cname, ctype) == 1
}
