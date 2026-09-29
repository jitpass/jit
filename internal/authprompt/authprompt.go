// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// Package authprompt is what the vault's two key stores share about taking
// down a Touch ID dialog the service raised and no longer wants answered:
// the error that says so, and the watcher that does it.
//
// Both key stores prompt through an LAContext, and invalidating that context
// from another thread takes the dialog down within about 50 ms, as long as
// the evaluation runs on that context itself (spike/consent-sync,
// FINDINGS.md). The keychain path's evaluatePolicy does. A decrypt with a
// Secure Enclave key from the keychain does not: Security prompts on a
// context of its own, so that path evaluates the key's access control on its
// context first (secureenclave, seAuthorize). A context invalidated before
// its prompt starts fails that prompt at once, so a withdrawal that beats
// the dialog needs no special case.
//
// Only the dialog is ever withdrawn. Reading the keychain item and opening
// the sealed key once the dialog is approved are never interrupted halfway.
package authprompt

import (
	"errors"
	"fmt"
	"sync"
)

// ErrWithdrawn is a prompt the service took down itself, because whoever
// asked for it said no before the human answered (the menu bar panel's
// Deny). It is decided on the Go side, from whether the withdrawal was
// requested, never from which code macOS answered with: an invalidated
// context has been measured to fail as LAErrorAppCancel (-9), and the
// Security framework may report the same event as errSecUserCanceled
// (-128), which a human's own Cancel also produces.
var ErrWithdrawn = errors.New("the prompt was withdrawn before it was answered")

// Watch calls cancel, at most once, if withdraw closes before stop is called.
// A nil withdraw never fires. stop reports whether cancel ran, and returns
// only once it can no longer run, so the caller may free what cancel touches
// (the LAContext) as soon as stop returns.
//
// A withdrawal that lands just as the prompt returns is ignored once stop
// has been called; one that lands a moment before may still fire and
// invalidate a context whose prompt was just approved. That is why the
// result only turns a FAILED prompt into ErrWithdrawn (see Outcome): an
// approval that won the race stands, and the caller, not this package,
// decides whether a withdrawal still refuses what the approval released.
func Watch(withdraw <-chan struct{}, cancel func()) (stop func() bool) {
	if withdraw == nil {
		return func() bool { return false }
	}
	done := make(chan struct{})
	exited := make(chan struct{})
	var mu sync.Mutex
	fired := false
	go func() {
		defer close(exited)
		select {
		case <-withdraw:
			// select picks at random when both are ready. A prompt that
			// already returned (done closed: the human answered, or pressed
			// Cancel) is not withdrawn by a Deny arriving an instant later;
			// calling it withdrawn would record "denied in JitPass" for a
			// cancel the human made on the dialog.
			select {
			case <-done:
				return
			default:
			}
			mu.Lock()
			fired = true
			mu.Unlock()
			cancel()
		case <-done:
		}
	}()
	var once sync.Once
	return func() bool {
		once.Do(func() { close(done) })
		<-exited
		mu.Lock()
		defer mu.Unlock()
		return fired
	}
}

// Outcome is a prompt's error once its watcher has stopped: a failure after a
// withdrawal is ErrWithdrawn (wrapping what macOS said), anything else is
// unchanged. An approval is never turned into a refusal.
func Outcome(err error, withdrawn bool) error {
	if err == nil || !withdrawn {
		return err
	}
	return fmt.Errorf("%w: %w", ErrWithdrawn, err)
}

// Withdrawn reports whether withdraw has already closed, without waiting.
// A prompt checks it just before it starts, so a withdrawal that came first
// never reaches macOS at all: an invalidated context is expected to fail its
// prompt at once, but on the Secure Enclave path that is Security's
// behaviour, not a documented promise, so nothing relies on it alone.
func Withdrawn(withdraw <-chan struct{}) bool {
	if withdraw == nil {
		return false
	}
	select {
	case <-withdraw:
		return true
	default:
		return false
	}
}
