// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

// Command exec-after-cgo-spike confirms that syscall.Exec (Tier 1 process
// replacement, RFC.md Pillar III) is reliable immediately after this same
// process has used CGo + Objective-C runtime + LocalAuthentication/Security
// framework calls. CGo/ObjC runtimes sometimes spawn background threads
// (dispatch queues, XPC connections) that have a known history of causing
// flaky execve behavior in some configurations — this is the entire
// mechanism Tier 1 depends on, so it needs to be rock solid.
//
// Modes:
//   -phase check   : touches LocalAuthentication (canEvaluatePolicy, no prompt)
//                    then execs immediately. Cheap, no user interaction —
//                    run this in a loop for iteration coverage.
//   -phase ecdh     : does the full real-world flow — ephemeral Secure Enclave
//                    key gen + Touch-ID-gated ECDH — then execs immediately.
//                    Needs one Touch ID approval; this is what Tier 1 actually
//                    does in production, so it's the most important single run.
//
// Not production code — throwaway or informs internal/exec later.
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
	"syscall"
	"unsafe"
)

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
	phase := ""
	iteration := ""
	for i, a := range os.Args {
		if a == "-phase" && i+1 < len(os.Args) {
			phase = os.Args[i+1]
		}
		if a == "-iteration" && i+1 < len(os.Args) {
			iteration = os.Args[i+1]
		}
	}

	switch phase {
	case "check":
		ok, msg := goResult(C.se_check_biometry_available())
		fmt.Printf("[iter %s] biometry check: ok=%v msg=%q — now calling syscall.Exec...\n", iteration, ok, msg)
	case "ecdh":
		var sharedSecret *C.uchar
		var sharedLen C.int
		fmt.Println("*** This should trigger a Touch ID / passcode prompt now. ***")
		ok, msg := goResult(C.se_ephemeral_generate_and_ecdh(&sharedSecret, &sharedLen))
		if ok {
			C.free(unsafe.Pointer(sharedSecret))
		}
		fmt.Printf("ECDH: ok=%v msg=%q secretLen=%d — now calling syscall.Exec...\n", ok, msg, sharedLen)
	default:
		fmt.Fprintln(os.Stderr, "usage: -phase check|ecdh [-iteration N]")
		os.Exit(2)
	}

	// The moment of truth: replace this process image entirely, right after
	// CGo/ObjC/Security-framework activity. If this hangs, crashes, or the
	// exec'd command never prints, that's a real flakiness finding.
	target := "/bin/echo"
	args := []string{"/bin/echo", "EXEC_SUCCEEDED:" + phase + ":" + iteration}
	env := os.Environ()

	err := syscall.Exec(target, args, env)
	// If Exec succeeds it never returns — reaching here means it failed.
	fmt.Fprintf(os.Stderr, "syscall.Exec FAILED to replace process image: %v\n", err)
	os.Exit(1)
}