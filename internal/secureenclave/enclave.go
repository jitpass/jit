// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package secureenclave

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework Security -framework LocalAuthentication
#include "enclave.h"
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"
)

// The statuses this package tells apart. They arrive as OSStatus, or as a
// CFError code in the LocalAuthentication domain for the LAError ones.
const (
	statusItemNotFound          = -25300 // errSecItemNotFound
	statusMissingEntitlement    = -34018 // errSecMissingEntitlement
	statusInteractionNotAllowed = -25308 // errSecInteractionNotAllowed: locked, or no UI allowed
	statusParam                 = -50    // errSecParam: what a sealed blob that won't decrypt gets (measured)
	statusUserCanceled          = -128   // errSecUserCanceled
	statusLAUserCancel          = -2     // LAErrorUserCancel
	statusLASystemCancel        = -4     // LAErrorSystemCancel
	statusLAAppCancel           = -9     // LAErrorAppCancel
)

var (
	// ErrUnavailable: this process cannot reach the vault's access group.
	// That is every jit outside JitPass.app's helper bundle (a tarball, `go
	// install`, a test binary not signed by scripts/se-test.sh): the
	// entitlement needs a provisioning profile only a bundle can carry
	// (spike/secure-enclave-mek/FINDINGS.md, S3a).
	ErrUnavailable = errors.New("this copy of jit can't use the Secure Enclave; use the jit inside JitPass.app")

	// ErrNoKey: the access group is reachable and holds no key under the
	// tag. With a sealed key file present, that is the lost-key state: the
	// vault was copied from another Mac, or this one's enclave was reset.
	ErrNoKey = errors.New("the Secure Enclave on this Mac has no vault key")

	// ErrCanceled: the person dismissed the dialog, or macOS did.
	ErrCanceled = errors.New("canceled")

	// ErrLocked: the key cannot be used right now because the Mac is locked
	// (or no dialog may be shown). Spike S4 measured it about 9 s after a
	// lock for a WhenUnlocked key.
	ErrLocked = errors.New("the Mac is locked")

	// ErrWrongKey: the key was used and the sealed bytes do not open under
	// it (the AES-GCM step of ECIES failed: tampered or damaged bytes, or
	// bytes sealed to another key), or what opened is not what was sealed
	// for this use (GrantKey's class). Nothing about reaching the key.
	ErrWrongKey = errors.New("the sealed bytes don't open under this key")
)

// NotNow reports whether err is the enclave saying its key can't be used
// right now, for a reason that says nothing about the key or the sealed
// bytes and may pass by itself: ErrLocked (the Mac is locked, or no dialog
// may be shown) or ErrUnavailable (this copy of jit isn't entitled: a
// service run by a jit outside JitPass.app, until the app's jit runs it).
// Nothing else is: a wrong key, damaged or truncated bytes, a lookup's
// other statuses and CryptoTokenKit's errors are answers, and a caller
// that stops on an answer (a never-ask job) must stop on them.
func NotNow(err error) bool {
	return errors.Is(err, ErrLocked) || errors.Is(err, ErrUnavailable)
}

// classify turns a status into one of the errors above where one applies,
// keeping the bridge's own sentence for everything else.
func classify(status int, msg string) error {
	switch status {
	case statusMissingEntitlement:
		return ErrUnavailable
	case statusItemNotFound:
		return ErrNoKey
	case statusUserCanceled, statusLAUserCancel, statusLASystemCancel, statusLAAppCancel:
		return fmt.Errorf("local authentication failed: %w", ErrCanceled)
	case statusInteractionNotAllowed:
		return ErrLocked
	}
	return errors.New(msg)
}

// enclave is the one key's operations. The real one is the Secure Enclave
// through enclave.m; tests use a fake with the same contract, because a key
// in the enclave needs a signed, provisioned binary a plain `go test` is not.
type enclave interface {
	present() (bool, error)
	create() error
	remove() error
	seal(plaintext []byte) ([]byte, error)
	open(sealed []byte, reason string) ([]byte, error)
}

// maxBytes bounds what seal and open take. The vault's MEK is 32 bytes and
// sealed it is 113 (spike S1); nothing near this limit is ever a key, and
// the bound is what makes the length's conversion to a C int safe.
const maxBytes = 64 << 10

// hardware is the real enclave key at (tag, group).
type hardware struct {
	tag, group string
	// presence: every open asks for Touch ID or the password (the vault
	// key). afterFirstUnlock: usable while the screen is locked (a key that
	// never asks, for grants and jobs; spike S4).
	presence, afterFirstUnlock bool
}

func boolInt(b bool) C.int {
	if b {
		return 1
	}
	return 0
}

func goResult(r C.SEResult) error {
	if r.success != 0 {
		return nil
	}
	msg := "unknown Secure Enclave error"
	if r.error_message != nil {
		msg = C.GoString(r.error_message)
		C.free(unsafe.Pointer(r.error_message))
	}
	return classify(int(r.status), msg)
}

func (h hardware) cstrings() (tag, group *C.char, free func()) {
	tag, group = C.CString(h.tag), C.CString(h.group)
	return tag, group, func() {
		C.free(unsafe.Pointer(tag))
		C.free(unsafe.Pointer(group))
	}
}

func (h hardware) present() (bool, error) {
	tag, group, free := h.cstrings()
	defer free()
	var status C.int
	switch C.se_present(tag, group, &status) {
	case 1:
		return true, nil
	case 0:
		return false, nil
	}
	return false, classify(int(status), fmt.Sprintf("checking for the Secure Enclave key failed (OSStatus=%d)", int(status)))
}

func (h hardware) create() error {
	tag, group, free := h.cstrings()
	defer free()
	return goResult(C.se_create(tag, group, boolInt(h.presence), boolInt(h.afterFirstUnlock)))
}

func (h hardware) remove() error {
	tag, group, free := h.cstrings()
	defer free()
	return goResult(C.se_delete(tag, group))
}

// takeBytes copies a malloc'd C buffer into Go memory, then zeroes and frees
// the C copy: it may be the master key.
func takeBytes(p *C.uchar, n C.int) []byte {
	out := C.GoBytes(unsafe.Pointer(p), n)
	wipe(unsafe.Slice((*byte)(unsafe.Pointer(p)), int(n)))
	C.free(unsafe.Pointer(p))
	return out
}

func (h hardware) seal(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 || len(plaintext) > maxBytes {
		return nil, fmt.Errorf("refusing to seal %d bytes", len(plaintext))
	}
	tag, group, free := h.cstrings()
	defer free()
	var out *C.uchar
	var n C.int
	n0 := C.int(len(plaintext)) // #nosec G115 -- bounded by maxBytes above
	if err := goResult(C.se_seal(tag, group, (*C.uchar)(unsafe.Pointer(&plaintext[0])), n0, &out, &n)); err != nil {
		return nil, err
	}
	return takeBytes(out, n), nil
}

func (h hardware) open(sealed []byte, reason string) ([]byte, error) {
	if len(sealed) == 0 || len(sealed) > maxBytes {
		return nil, fmt.Errorf("refusing to open %d bytes", len(sealed))
	}
	tag, group, free := h.cstrings()
	defer free()
	cReason := C.CString(reason)
	defer C.free(unsafe.Pointer(cReason))
	var out *C.uchar
	var n, decrypting C.int
	n0 := C.int(len(sealed)) // #nosec G115 -- bounded by maxBytes above
	r := C.se_open(tag, group, (*C.uchar)(unsafe.Pointer(&sealed[0])), n0, cReason, &out, &n, &decrypting)
	// A blob that won't decrypt is errSecParam from SecKeyCreateDecryptedData
	// ("ECIES: Failed to aes-gcm decrypt data", TestHardwareKeyNeverAsking).
	// Only the decryption's -50 says that: the same status from finding the
	// key (se_open's lookup, decrypting 0) is about the query, never the
	// bytes, so it is told apart here by the failing step, not in classify.
	status := int(r.status)
	if err := goResult(r); err != nil {
		return nil, openFailure(status, decrypting != 0, err)
	}
	return takeBytes(out, n), nil
}

// openFailure is se_open's failure as open returns it: ErrWrongKey only for
// the decryption's errSecParam; any other status, and a lookup's -50, keep
// goResult's error as it is.
func openFailure(status int, decrypting bool, err error) error {
	if decrypting && status == statusParam {
		return fmt.Errorf("%w: %w", ErrWrongKey, err)
	}
	return err
}

// listTags returns, with prefix removed, the tag of every enclave key in
// group that starts with prefix.
func listTags(group, prefix string) ([]string, error) {
	cGroup, cPrefix := C.CString(group), C.CString(prefix)
	defer C.free(unsafe.Pointer(cGroup))
	defer C.free(unsafe.Pointer(cPrefix))
	var tags **C.char
	var n C.int
	if err := goResult(C.se_list_tags(cGroup, cPrefix, &tags, &n)); err != nil {
		return nil, err
	}
	if tags == nil {
		return nil, nil
	}
	defer C.free(unsafe.Pointer(tags))
	list := unsafe.Slice(tags, int(n))
	out := make([]string, 0, len(list))
	for _, t := range list {
		out = append(out, strings.TrimPrefix(C.GoString(t), prefix))
		C.free(unsafe.Pointer(t))
	}
	return out, nil
}
