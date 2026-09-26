// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package secureenclave

/*
#include "enclave.h"
#include <stdlib.h>
*/
import "C"

import (
	"strings"
	"unsafe"
)

// entitlements is what this process's own signature grants, as far as the
// enclave's keys care.
type entitlements struct {
	// hasGroup: keychain-access-groups names AccessGroup.
	hasGroup bool
	// appID is com.apple.application-identifier, "" when there is none.
	appID string
}

// readEntitlements reads this process's signature; tests replace it.
var readEntitlements = hardwareEntitlements

func hardwareEntitlements() (entitlements, error) {
	group := C.CString(AccessGroup)
	defer C.free(unsafe.Pointer(group))
	var has C.int
	var appID *C.char
	if err := goResult(C.se_entitlements(group, &has, &appID)); err != nil {
		return entitlements{}, err
	}
	e := entitlements{hasGroup: has != 0}
	if appID != nil {
		e.appID = C.GoString(appID)
		C.free(unsafe.Pointer(appID))
	}
	return e, nil
}

// Entitled reports whether THIS binary may use the enclave's keys: its
// signature carries keychain-access-groups naming AccessGroup, and an
// application identifier of the same team. That is JitPass.app's helper
// (and a test binary scripts/se-test.sh signs); a jit outside the app (a
// tarball, `go install`) carries neither.
//
// It is a property of the binary, not a keychain query, so it never
// prompts and answers the same while the Mac is locked, in a session with
// no UI, and whatever state the keychain is in: a command deciding whether
// this copy of jit could ever run the service decides from this, never
// from a lookup that can fail for a reason that has nothing to do with it.
// A restricted entitlement is honoured only when a provisioning profile
// authorizes it, and macOS kills a binary that claims one without at
// launch (spike S3a), so a running process that carries it has it.
//
// The error is non-nil only when the signature could not be read at all.
func Entitled() (bool, error) {
	e, err := readEntitlements()
	if err != nil {
		return false, err
	}
	return e.hasGroup && strings.HasPrefix(e.appID, TeamID+"."), nil
}
