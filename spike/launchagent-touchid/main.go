// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

// Command launchagent-touchid-spike answers one question before building
// a persistent jit-agent: can a process started by launchd as a per-user
// LaunchAgent (not from an interactive terminal) still successfully
// trigger a real LAContext Touch ID/passcode dialog? Earlier in this
// project, processes launched via an automated tool call (no
// window-server session) could NOT show one — this spike checks whether
// a proper LaunchAgent has that same limitation or not, since the whole
// persistent-agent design depends on the answer.
//
// Writes its result to a log file (not stdout — launchd-managed agents
// don't have an attached terminal to print to) so the outcome can be
// inspected after the fact.
package main

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework LocalAuthentication
#include <stdlib.h>

typedef struct {
    int success;
    char *error_message;
} LATestResult;

LATestResult la_challenge(const char *reason);
*/
import "C"

import (
	"fmt"
	"os"
	"time"
	"unsafe"
)

const logPath = "/tmp/jit-launchagent-touchid-spike.log"

func main() {
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return
	}
	defer f.Close()

	fmt.Fprintf(f, "[%s] launchagent-touchid-spike started, pid=%d\n", time.Now().Format(time.RFC3339), os.Getpid())

	reason := C.CString("jit launchagent-touchid-spike: approve to prove a LaunchAgent can show this")
	defer C.free(unsafe.Pointer(reason))

	result := C.la_challenge(reason)
	if result.success != 0 {
		fmt.Fprintf(f, "[%s] RESULT: SUCCESS — challenge approved, LaunchAgent CAN show Touch ID/passcode dialogs\n", time.Now().Format(time.RFC3339))
		return
	}

	msg := "unknown error"
	if result.error_message != nil {
		msg = C.GoString(result.error_message)
		C.free(unsafe.Pointer(result.error_message))
	}
	fmt.Fprintf(f, "[%s] RESULT: FAILED — %s\n", time.Now().Format(time.RFC3339), msg)
}