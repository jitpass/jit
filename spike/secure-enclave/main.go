// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

// Command secure-enclave-spike is a throwaway technical spike (ROADMAP.md's
// "Spike: Secure Enclave key generation + Touch ID + ECDH") that answers one
// question: can jit, from Go via CGo, (1) generate a P-256 key pair inside the
// Secure Enclave, (2) gate it behind Touch ID / passcode, and (3) perform an
// ECDH key exchange with it? This is the foundation RFC.md Pillar II assumes.
//
// Not production code — throwaway or to be promoted into internal/vault later
// depending on the outcome.
package main

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework Security -framework LocalAuthentication
#include "secureenclave.h"
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"os"
	"unsafe"
)

const keyTag = "com.jitpass.spike.mek"

func goResult(r C.SEResult) (bool, string) {
	ok := r.success != 0
	msg := ""
	if r.error_message != nil {
		msg = C.GoString(r.error_message)
		C.free(unsafe.Pointer(r.error_message))
	}
	return ok, msg
}

func main() {
	fmt.Println("=== jit Secure Enclave spike ===")

	tag := C.CString(keyTag)
	defer C.free(unsafe.Pointer(tag))

	// Clean slate: delete any leftover key from a previous run.
	if ok, msg := goResult(C.se_delete_key(tag)); !ok {
		fmt.Printf("[warn] cleanup before run failed: %s\n", msg)
	}

	fmt.Println("\n[1/3] Checking biometry availability (LocalAuthentication)...")
	if ok, msg := goResult(C.se_check_biometry_available()); ok {
		fmt.Println("      OK: biometric auth is available on this device.")
	} else {
		fmt.Printf("      NOTE: biometric auth not available (%s) — passcode fallback should still gate the key.\n", msg)
	}

	fmt.Println("\n[2/3] Generating a PERSISTENT P-256 key pair inside the Secure Enclave")
	fmt.Println("      (kSecAttrIsPermanent: YES, written to the keychain)...")
	persistOK, persistMsg := goResult(C.se_generate_key(tag))
	if !persistOK {
		fmt.Printf("      FAILED: %s\n", persistMsg)
		fmt.Println("      NOTE: -34018 (errSecMissingEntitlement) means this binary's code signature")
		fmt.Println("      doesn't carry the entitlement macOS requires to WRITE a Secure-Enclave key")
		fmt.Println("      to the keychain. Ad-hoc signing (codesign -s -) is not sufficient for this —")
		fmt.Println("      matches TECH_STACK.md §5's requirement for real Developer ID signing.")
		fmt.Println("      Falling through to an ephemeral (non-persisted) test to isolate whether the")
		fmt.Println("      core SE + Touch ID + ECDH mechanism works at all, independent of persistence.")
	} else {
		fmt.Println("      OK: Secure Enclave key generated and persisted to keychain.")
	}

	fmt.Println("\n[3/3] Performing ECDH against a Secure Enclave key.")
	fmt.Println("      *** This should trigger a Touch ID / passcode prompt now. ***")

	var sharedSecret *C.uchar
	var sharedLen C.int
	var ok bool
	var msg string
	if persistOK {
		ok, msg = goResult(C.se_ecdh(tag, &sharedSecret, &sharedLen))
	} else {
		ok, msg = goResult(C.se_ephemeral_generate_and_ecdh(&sharedSecret, &sharedLen))
	}
	if !ok {
		fmt.Printf("      FAILED: %s\n", msg)
		fmt.Println("\nSPIKE RESULT: FAIL.")
		fmt.Println("If the error mentions user interaction / UI not allowed, this process likely")
		fmt.Println("has no window-server session (e.g. run via an automated tool) — rerun this")
		fmt.Println("binary directly from a real Terminal.app/iTerm2 window instead.")
		os.Exit(1)
	}
	secret := C.GoBytes(unsafe.Pointer(sharedSecret), sharedLen)
	C.free(unsafe.Pointer(sharedSecret))
	fmt.Printf("      OK: ECDH succeeded, shared secret = %d bytes.\n", len(secret))

	if persistOK {
		fmt.Println("\nSPIKE RESULT: FULL PASS — persistent Secure Enclave key gen + Touch ID gating + ECDH all work from Go via CGo.")
	} else {
		fmt.Println("\nSPIKE RESULT: PARTIAL PASS — the core mechanism (SE + Touch ID + ECDH) works from Go via CGo,")
		fmt.Println("but keychain PERSISTENCE of the key needs a properly entitled code signature, not ad-hoc signing.")
	}
}