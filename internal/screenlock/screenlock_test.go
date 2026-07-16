// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package screenlock

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"
)

func init() {
	// Keep the main goroutine on the main OS thread so TestMain can hand
	// it to RunMain — the same arrangement cmd/jit makes for the agent.
	runtime.LockOSThread()
}

// TestMain inverts the usual arrangement: the tests run on a side
// goroutine while the MAIN thread parks in RunMain — because that's the
// only thread the distributed center will ever deliver to (see the
// package doc comment), delivery-path tests can't run any other way.
func TestMain(m *testing.M) {
	go func() {
		os.Exit(m.Run())
	}()
	if err := RunMain(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "RunMain: %v\n", err)
		os.Exit(1)
	}
	os.Exit(1) // unreachable: the ctx above never cancels; m.Run's os.Exit ends the process
}

// TestWatchDeliversDistributedNotifications drives the real path end to
// end — CFNotificationCenter registration, notifyd delivery to the main
// run loop, the C callback, the //export re-entry into Go — using a
// jit-namespaced notification name. The real screen-lock name is never
// posted: it's OS-owned, and faking it would tell every password manager
// on this machine the screen just locked.
func TestWatchDeliversDistributedNotifications(t *testing.T) {
	name := fmt.Sprintf("com.jitpass.test.screenlock.%d", os.Getpid())
	events := make(chan string, 4)
	if err := watch(map[string]string{name: "test screen lock"}, false, func(cause string) {
		events <- cause
	}); err != nil {
		t.Fatalf("watch: %v", err)
	}

	// A second watch in the same process must refuse rather than
	// double-register process-global observers.
	if err := watch(map[string]string{name: "dup"}, false, func(string) {}); err == nil {
		t.Error("second watch in one process succeeded, want an error — observers are process-global")
	}

	// Delivery through notifyd is asynchronous, so post repeatedly until
	// one lands rather than trusting a single post's timing.
	deadline := time.Now().Add(10 * time.Second)
	for {
		post(name)
		select {
		case cause := <-events:
			if cause != "test screen lock" {
				t.Fatalf("cause = %q, want the mapped cause, not the raw notification name", cause)
			}
			return
		case <-time.After(200 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("no event delivered within 10s of posting the watched distributed notification")
		}
	}
}

// RunMain off the main thread must refuse loudly — a loop running on any
// other thread would never be delivered to, which is exactly the silent
// degradation this package exists to avoid.
func TestRunMainRefusesOffMainThread(t *testing.T) {
	// m.Run tests execute on non-main goroutines (see TestMain), and this
	// one pins itself to whatever non-main OS thread it's on.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := RunMain(context.Background()); err == nil {
		t.Fatal("RunMain succeeded off the main thread — it would have parked a loop nothing ever delivers to")
	}
}
