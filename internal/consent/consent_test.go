// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package consent

import (
	"errors"
	"testing"
	"time"
)

// clockedEngine is an Engine with a controllable clock, so TTL/expiry behavior
// is deterministic without real sleeps.
func clockedEngine(ttl time.Duration) (*Engine, *time.Time) {
	e := New(ttl)
	nowP := new(time.Time)
	*nowP = time.Unix(1_700_000_000, 0)
	e.now = func() time.Time { return *nowP }
	return e, nowP
}

func gcloud(descends bool) Request {
	return Request{
		Credential: "gcp",
		Caller:     Caller{PID: 4242, ExecPath: "/usr/local/bin/gcloud", Strength: BestEffort, DescendsFromGrant: descends},
	}
}

// countingPrompter records how many times it was asked and returns a fixed
// answer.
func countingPrompter(d Decision, s Scope, calls *int) Prompter {
	return func(Request) (Decision, Scope, error) {
		*calls++
		return d, s, nil
	}
}

func TestDescendsFromGrantSkipsPrompt(t *testing.T) {
	e, _ := clockedEngine(5 * time.Minute)
	calls := 0
	got, err := e.Decide(gcloud(true), countingPrompter(Deny, Once, &calls)) // prompter would DENY if reached
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != Allow {
		t.Errorf("descendant of a grant should be allowed, got %v", got)
	}
	if calls != 0 {
		t.Errorf("a grant descendant must never prompt, prompted %d time(s)", calls)
	}
}

func TestSessionDecisionIsReusedThenExpires(t *testing.T) {
	e, now := clockedEngine(5 * time.Minute)
	calls := 0
	p := countingPrompter(Allow, Session, &calls)

	if got, _ := e.Decide(gcloud(false), p); got != Allow || calls != 1 {
		t.Fatalf("first access: got %v after %d prompt(s), want Allow after 1", got, calls)
	}
	// Second access within the TTL: no re-prompt.
	*now = now.Add(4 * time.Minute)
	if got, _ := e.Decide(gcloud(false), p); got != Allow || calls != 1 {
		t.Fatalf("within TTL: got %v after %d prompt(s), want Allow after 1 (cached)", got, calls)
	}
	// Past the TTL: prompts again.
	*now = now.Add(2 * time.Minute) // total 6m > 5m TTL
	if got, _ := e.Decide(gcloud(false), p); got != Allow || calls != 2 {
		t.Fatalf("after TTL: got %v after %d prompt(s), want Allow after 2 (re-prompted)", got, calls)
	}
}

func TestOnceIsNeverCached(t *testing.T) {
	e, _ := clockedEngine(5 * time.Minute)
	calls := 0
	p := countingPrompter(Allow, Once, &calls)
	for i := 1; i <= 3; i++ {
		if got, _ := e.Decide(gcloud(false), p); got != Allow || calls != i {
			t.Fatalf("access %d: got %v after %d prompt(s), want Allow after %d (Once never caches)", i, got, calls, i)
		}
	}
}

func TestAlwaysNeverExpires(t *testing.T) {
	e, now := clockedEngine(5 * time.Minute)
	calls := 0
	p := countingPrompter(Allow, Always, &calls)
	if got, _ := e.Decide(gcloud(false), p); got != Allow || calls != 1 {
		t.Fatalf("first: got %v after %d prompt(s)", got, calls)
	}
	*now = now.Add(365 * 24 * time.Hour) // a year later
	if got, _ := e.Decide(gcloud(false), p); got != Allow || calls != 1 {
		t.Fatalf("Always must survive indefinitely: got %v after %d prompt(s), want Allow after 1", got, calls)
	}
}

func TestDenyIsCachedForTheSession(t *testing.T) {
	e, _ := clockedEngine(5 * time.Minute)
	calls := 0
	p := countingPrompter(Deny, Session, &calls)
	if got, _ := e.Decide(gcloud(false), p); got != Deny || calls != 1 {
		t.Fatalf("first: got %v after %d prompt(s), want Deny after 1", got, calls)
	}
	// A denied tool that keeps reading must not nag with a fresh prompt each time.
	if got, _ := e.Decide(gcloud(false), p); got != Deny || calls != 1 {
		t.Fatalf("second: got %v after %d prompt(s), want Deny after 1 (cached)", got, calls)
	}
}

func TestPromptErrorFailsClosed(t *testing.T) {
	e, _ := clockedEngine(5 * time.Minute)
	headless := func(Request) (Decision, Scope, error) {
		return Undecided, Once, errors.New("no UI available")
	}
	got, err := e.Decide(gcloud(false), headless)
	if err == nil {
		t.Fatal("expected an error to surface for the caller to fail closed")
	}
	if got != Undecided {
		t.Errorf("a failed prompt must return Undecided (caller denies), got %v", got)
	}
}

func TestClearDropsStandingDecisions(t *testing.T) {
	e, _ := clockedEngine(5 * time.Minute)
	calls := 0
	p := countingPrompter(Allow, Session, &calls)
	_, _ = e.Decide(gcloud(false), p)
	e.Clear() // session re-locked
	if got, _ := e.Decide(gcloud(false), p); got != Allow || calls != 2 {
		t.Fatalf("after Clear: got %v after %d prompt(s), want Allow after 2 (re-prompted)", got, calls)
	}
}

func TestDecisionIsPerToolAndPerCredential(t *testing.T) {
	e, _ := clockedEngine(5 * time.Minute)
	calls := 0
	p := countingPrompter(Allow, Session, &calls)

	_, _ = e.Decide(gcloud(false), p) // approve gcloud->gcp (calls=1)

	// A DIFFERENT tool reaching for the same credential must prompt on its own.
	other := Request{Credential: "gcp", Caller: Caller{ExecPath: "/tmp/sneaky", Strength: BestEffort}}
	if _, _ = e.Decide(other, p); calls != 2 {
		t.Errorf("a different tool must not ride gcloud's approval: prompts=%d, want 2", calls)
	}

	// Same tool, DIFFERENT credential must also prompt on its own.
	sameToolOtherCred := Request{Credential: "aws", Caller: Caller{ExecPath: "/usr/local/bin/gcloud", Strength: Hard}}
	if _, _ = e.Decide(sameToolOtherCred, p); calls != 3 {
		t.Errorf("same tool, other credential must prompt: prompts=%d, want 3", calls)
	}
}
