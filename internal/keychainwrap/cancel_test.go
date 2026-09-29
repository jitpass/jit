// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package keychainwrap

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/authprompt"
)

// cancelWrapper is testWrapper with a withdrawable challenge as well, over a
// TEST-ONLY item that exists, so a fetch reaches the challenge.
func cancelWrapper(t *testing.T, challenge func(string) error, cancel func(string, <-chan struct{}) error) *Wrapper {
	t.Helper()
	setup := testWrapper(noChallenge)
	cleanupTestMEK(t, setup)
	if err := setup.EnsureMEK(); err != nil {
		t.Fatalf("EnsureMEK: %v", err)
	}
	w := testWrapper(challenge)
	w.challengeCancel = cancel
	return w
}

func refuseChallenge(t *testing.T) func(string) error {
	return func(string) error {
		t.Error("the plain challenge ran for a fetch that should be withdrawable")
		return errors.New("wrong challenge")
	}
}

// FetchMEKCancel prompts through the withdrawable challenge and hands it the
// caller's own channel: that channel is what the panel's Deny closes.
func TestFetchMEKCancelHandsTheChannelToTheChallenge(t *testing.T) {
	withdraw := make(chan struct{})
	var got <-chan struct{}
	w := cancelWrapper(t, refuseChallenge(t), func(_ string, ch <-chan struct{}) error {
		got = ch
		return nil
	})
	if _, err := w.FetchMEKCancel("test", withdraw); err != nil {
		t.Fatalf("FetchMEKCancel: %v", err)
	}
	if got != withdraw {
		t.Error("the challenge did not get the caller's withdraw channel")
	}
}

// FetchMEK is unchanged: the plain challenge, never the withdrawable one.
func TestFetchMEKStillUsesThePlainChallenge(t *testing.T) {
	plain := 0
	w := cancelWrapper(t, func(string) error { plain++; return nil }, func(string, <-chan struct{}) error {
		t.Error("FetchMEK used the withdrawable challenge")
		return nil
	})
	if _, err := w.FetchMEK("test"); err != nil {
		t.Fatalf("FetchMEK: %v", err)
	}
	if plain != 1 {
		t.Errorf("plain challenge ran %d times, want 1", plain)
	}
}

// A withdrawn prompt fails as ErrWithdrawn, and caches nothing: the next
// fetch asks again.
func TestWithdrawnFetchIsErrWithdrawnAndCachesNothing(t *testing.T) {
	withdraw := make(chan struct{})
	asked := 0
	w := cancelWrapper(t, func(string) error { asked++; return nil }, func(_ string, ch <-chan struct{}) error {
		<-ch // the dialog stays up until the withdrawal
		return authprompt.Outcome(errors.New("Authentication canceled."), true)
	})
	go func() { time.Sleep(20 * time.Millisecond); close(withdraw) }()
	if _, err := w.FetchMEKCancel("test", withdraw); !errors.Is(err, authprompt.ErrWithdrawn) {
		t.Fatalf("withdrawn fetch = %v, want ErrWithdrawn", err)
	}
	if _, err := w.FetchMEK("test"); err != nil {
		t.Fatalf("FetchMEK after the withdrawal: %v", err)
	}
	if asked != 1 {
		t.Errorf("the fetch after a withdrawal prompted %d times, want 1 (nothing cached)", asked)
	}
}

// Withdrawn before the fetch: no challenge of either kind runs, so no dialog
// appears, whatever macOS would have done with a dead context.
func TestPreWithdrawnFetchNeverPrompts(t *testing.T) {
	w := cancelWrapper(t, refuseChallenge(t), func(string, <-chan struct{}) error {
		t.Error("a withdrawable challenge ran for a fetch already withdrawn")
		return nil
	})
	withdraw := make(chan struct{})
	close(withdraw)
	if _, err := w.FetchMEKCancel("test", withdraw); !errors.Is(err, authprompt.ErrWithdrawn) {
		t.Fatalf("pre-withdrawn fetch = %v, want ErrWithdrawn", err)
	}
}

// A Wrapper with no withdrawable challenge (a grant key, a staged rekey)
// still prompts through its plain one when handed a channel.
func TestNoWithdrawableChallengeFallsBackToThePlainOne(t *testing.T) {
	plain := 0
	w := cancelWrapper(t, func(string) error { plain++; return nil }, nil)
	if _, err := w.FetchMEKCancel("test", make(chan struct{})); err != nil {
		t.Fatalf("FetchMEKCancel: %v", err)
	}
	if plain != 1 {
		t.Errorf("plain challenge ran %d times, want 1", plain)
	}
}

// New wires the real withdrawable challenge. Without it the service's Deny
// would leave every keychain-backed dialog on screen.
func TestNewWiresTheWithdrawableChallenge(t *testing.T) {
	if New().challengeCancel == nil {
		t.Fatal("New() has no withdrawable challenge")
	}
}

// The real dialog, taken down. Shows a Touch ID dialog for about a second:
// JIT_SE_INTERACTIVE=1 go test ./internal/keychainwrap -run TestHardwareChallengeWithdrawn
// Do not touch the sensor; the dialog must go away by itself.
func TestHardwareChallengeWithdrawn(t *testing.T) {
	if os.Getenv("JIT_SE_INTERACTIVE") != "1" {
		t.Skip("shows a Touch ID dialog: set JIT_SE_INTERACTIVE=1")
	}
	withdraw := make(chan struct{})
	start := time.Now()
	go func() { time.Sleep(time.Second); close(withdraw) }()
	err := realChallengeCancel("check that jit can take its own prompt down (jit test; don't touch the sensor)", withdraw)
	elapsed := time.Since(start)
	if !errors.Is(err, authprompt.ErrWithdrawn) {
		t.Fatalf("withdrawn challenge = %v, want ErrWithdrawn", err)
	}
	if elapsed > 3*time.Second {
		t.Errorf("the withdrawn dialog took %s to go away, want about 1 s", elapsed)
	}
	t.Logf("withdrawn after %s: %v", elapsed.Round(time.Millisecond), err)

	// A withdrawal that slips in after fetchMEK's check meets a dead
	// context: it must fail at once, with no dialog.
	start = time.Now()
	err = challengeOnDeadContext("must never show (jit test)")
	if err == nil {
		t.Fatal("a challenge on an invalidated context was approved")
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Errorf("a challenge on an invalidated context took %s, want it to fail at once", d)
	}
	t.Logf("dead context: %v", err)
}

// A Wrapper holding a key from an earlier fetch still hands nothing over once
// withdrawn: the Deny wins over the cache as it does over the dialog.
func TestWithdrawnFetchNeverReturnsACachedKey(t *testing.T) {
	w := cancelWrapper(t, noChallenge, func(string, <-chan struct{}) error { return nil })
	if _, err := w.FetchMEKCancel("test", make(chan struct{})); err != nil {
		t.Fatalf("setup fetch: %v", err)
	}
	withdraw := make(chan struct{})
	close(withdraw)
	if k, err := w.FetchMEKCancel("test", withdraw); !errors.Is(err, authprompt.ErrWithdrawn) || k != nil {
		t.Fatalf("withdrawn fetch on a cached key = %v (key returned: %v), want ErrWithdrawn and no key", err, k != nil)
	}
}
