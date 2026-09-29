// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package authprompt

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestWatchFiresOnWithdraw(t *testing.T) {
	withdraw := make(chan struct{})
	var calls atomic.Int32
	cancelled := make(chan struct{})
	stop := Watch(withdraw, func() { calls.Add(1); close(cancelled) })
	close(withdraw)
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("cancel did not run after the withdrawal")
	}
	if !stop() {
		t.Error("stop reported no withdrawal")
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("cancel ran %d times, want 1", n)
	}
}

func TestWatchNeverFiresAfterStop(t *testing.T) {
	withdraw := make(chan struct{})
	var calls atomic.Int32
	stop := Watch(withdraw, func() { calls.Add(1) })
	if stop() {
		t.Error("stop reported a withdrawal that never came")
	}
	close(withdraw)
	time.Sleep(20 * time.Millisecond)
	if n := calls.Load(); n != 0 {
		t.Errorf("cancel ran %d times after stop, want 0", n)
	}
	if stop() {
		t.Error("a second stop changed its answer")
	}
}

// stop must not return while cancel is still running: the caller frees the
// context cancel invalidates as soon as stop returns.
func TestStopWaitsForARunningCancel(t *testing.T) {
	withdraw := make(chan struct{})
	entered := make(chan struct{})
	var finished atomic.Bool
	stop := Watch(withdraw, func() {
		close(entered)
		time.Sleep(50 * time.Millisecond)
		finished.Store(true)
	})
	close(withdraw)
	<-entered
	stop()
	if !finished.Load() {
		t.Error("stop returned while cancel was still running")
	}
}

func TestNilWithdrawNeverFires(t *testing.T) {
	stop := Watch(nil, func() { t.Error("cancel ran with no withdraw channel") })
	if stop() {
		t.Error("a nil withdraw reported a withdrawal")
	}
}

func TestOutcome(t *testing.T) {
	cancelled := errors.New("Authentication canceled.")
	if err := Outcome(cancelled, true); !errors.Is(err, ErrWithdrawn) || !errors.Is(err, cancelled) {
		t.Errorf("a failure after a withdrawal = %v, want ErrWithdrawn wrapping macOS's error", err)
	}
	if err := Outcome(cancelled, false); errors.Is(err, ErrWithdrawn) {
		t.Errorf("a failure with no withdrawal became ErrWithdrawn: %v", err)
	}
	if err := Outcome(nil, true); err != nil {
		t.Errorf("an approval that won the race became %v, want nil", err)
	}
}
