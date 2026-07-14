// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

// Command keychain-interim-key-spike answers one question before building
// internal/vault's interim key-wrapping backend on top of it: does a PLAIN
// (non-Secure-Enclave) persistent keychain EC key — same architecture as
// spike/secure-enclave, minus kSecAttrTokenID: kSecAttrTokenIDSecureEnclave —
// avoid the -34018 errSecMissingEntitlement that blocked SE-token persistence
// under ad-hoc signing? Subcommands let separate process invocations exercise
// real persistence (generate in one process, ECDH in another), not just
// same-process reuse.
package main

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework Security -framework LocalAuthentication
#include "keychain.h"
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"os"
	"unsafe"
)

const keyTag = "com.jitpass.spike.interim-mek"

func goResult(r C.KCResult) (bool, string) {
	ok := r.success != 0
	msg := ""
	if r.error_message != nil {
		msg = C.GoString(r.error_message)
		C.free(unsafe.Pointer(r.error_message))
	}
	return ok, msg
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: keychain-interim-key-spike <generate|exists|ecdh|delete>")
		os.Exit(2)
	}

	tag := C.CString(keyTag)
	defer C.free(unsafe.Pointer(tag))

	switch os.Args[1] {
	case "generate":
		fmt.Println("Generating a PERSISTENT plain (non-SE) P-256 keychain key...")
		ok, msg := goResult(C.kc_generate_persistent_key(tag))
		if !ok {
			fmt.Printf("FAILED: %s\n", msg)
			os.Exit(1)
		}
		fmt.Println("OK: key generated and persisted to keychain (no Secure Enclave token).")

	case "exists":
		var exists C.int
		ok, msg := goResult(C.kc_key_exists(tag, &exists))
		if !ok {
			fmt.Printf("FAILED: %s\n", msg)
			os.Exit(1)
		}
		if exists != 0 {
			fmt.Println("Key exists in keychain.")
		} else {
			fmt.Println("Key NOT found in keychain.")
			os.Exit(1)
		}

	case "ecdh":
		fmt.Println("Looking up the persisted key FRESH in this process and performing ECDH...")
		fmt.Println("*** This should trigger a Touch ID / passcode prompt now. ***")
		var sharedSecret *C.uchar
		var sharedLen C.int
		ok, msg := goResult(C.kc_ecdh_with_stored_key(tag, &sharedSecret, &sharedLen))
		if !ok {
			fmt.Printf("FAILED: %s\n", msg)
			os.Exit(1)
		}
		secret := C.GoBytes(unsafe.Pointer(sharedSecret), sharedLen)
		C.free(unsafe.Pointer(sharedSecret))
		fmt.Printf("OK: ECDH succeeded in a fresh process against the persisted key, shared secret = %d bytes.\n", len(secret))

	case "delete":
		ok, msg := goResult(C.kc_delete_key(tag))
		if !ok {
			fmt.Printf("FAILED: %s\n", msg)
			os.Exit(1)
		}
		fmt.Println("OK: key deleted (cleanup).")

	default:
		fmt.Printf("unknown subcommand %q\n", os.Args[1])
		os.Exit(2)
	}
}