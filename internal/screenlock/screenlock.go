// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package screenlock

/*
#cgo LDFLAGS: -framework CoreFoundation -framework IOKit
#include <stdlib.h>
#include "screenlock.h"
*/
import "C"

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"unsafe"
)

// CauseScreenLocked and CauseSystemSleep are the human-readable causes
// handed to Watch's onEvent — phrased to slot directly into the agent's
// lock provenance ("locked 2m ago — screen locked"), the same sentence
// position "15m idle timeout" and "explicit lock" already occupy.
const (
	CauseScreenLocked = "screen locked"
	CauseSystemSleep  = "system sleeping"
)

// screenIsLocked is the distributed notification loginwindow posts the
// moment the screen locks — the same signal password managers key their
// own auto-lock off. There is deliberately no screenIsUnlocked observer:
// unlocking the SCREEN proves presence, not intent to open the VAULT, and
// silently re-unlocking the session on it would be an unprompted unlock.
const screenIsLocked = "com.apple.screenIsLocked"

var (
	mu      sync.Mutex
	started bool
	causes  map[string]string  // notification name -> cause handed to onEvent
	handler func(cause string) // called by goScreenLockEvent
)

// Watch registers for the screen locking and the system going to sleep,
// calling onEvent (synchronously from the main run loop — keep it quick; a
// system sleep is literally waiting on it) with CauseScreenLocked or
// CauseSystemSleep per event. Registration works from any thread, but
// nothing is DELIVERED until RunMain is parked on the main thread — see
// its doc comment for the OS constraint that makes the two halves
// inseparable. Once per process: a second call errors rather than
// double-registering process-global observers.
func Watch(onEvent func(cause string)) error {
	return watch(map[string]string{screenIsLocked: CauseScreenLocked}, true, onEvent)
}

// watch is Watch with the notification names injectable and the power
// watch optional — the seam the package test drives the full register/
// deliver/callback path through, with a jit-namespaced test name instead
// of an OS-owned one (posting a fake "com.apple.screenIsLocked" would tell
// every password manager on the machine the screen just locked).
func watch(names map[string]string, power bool, onEvent func(cause string)) error {
	mu.Lock()
	defer mu.Unlock()
	if started {
		return errors.New("already watching in this process")
	}
	started = true
	causes = names
	handler = onEvent

	for name := range names {
		cname := C.CString(name)
		C.sl_observe_distributed(cname)
		C.free(unsafe.Pointer(cname))
	}
	if power {
		C.sl_watch_power()
	}
	return nil
}

// RunMain parks the calling goroutine — which MUST be on the process's
// main OS thread — in the main run loop until ctx is cancelled, delivering
// everything Watch registered. Errors immediately (rather than running a
// loop nothing will ever deliver to) when called off the main thread.
//
// Why the main thread specifically: the distributed notification center
// delivers to the MAIN run loop, full stop — not to the run loop of the
// registering thread. Empirically pinned during development: an observer
// registered on a secondary thread running its own CFRunLoop never
// received a post, and the identical registration received it the moment
// the main thread ran ITS loop instead. cmd/jit locks its main goroutine
// to the main thread at init precisely so `jit agent run` can hand that
// thread here.
func RunMain(ctx context.Context) error {
	if C.sl_is_main_thread() == 0 {
		return errors.New("RunMain must run on the process's main thread — distributed notifications are only ever delivered to the main run loop")
	}
	// Already on the main thread; pin the goroutine to it for the loop's
	// whole life so the scheduler can't migrate us mid-run.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	stopDone := make(chan struct{})
	loopDone := make(chan struct{})
	go func() {
		defer close(stopDone)
		select {
		case <-ctx.Done():
			C.sl_stop_main()
		case <-loopDone:
		}
	}()
	C.sl_run_main()
	close(loopDone)
	<-stopDone
	return nil
}

// post delivers a distributed notification. TEST-ONLY — see
// sl_post_distributed's header comment; it exists here because _test.go
// files cannot import "C".
func post(name string) {
	cname := C.CString(name)
	C.sl_post_distributed(cname)
	C.free(unsafe.Pointer(cname))
}

//export goScreenLockEvent
func goScreenLockEvent(cname *C.char) {
	name := C.GoString(cname)
	mu.Lock()
	h := handler
	cause, known := causes[name]
	mu.Unlock()
	if h == nil {
		return
	}
	if name == C.GoString(C.sl_power_sleep_name) {
		h(CauseSystemSleep)
		return
	}
	if known {
		h(cause)
	}
	// Unknown names are dropped silently: observers are only ever
	// registered for our own, but the distributed center is a shared bus
	// and defensiveness here is free.
}
