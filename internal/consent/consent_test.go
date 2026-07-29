// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package consent

import (
	"errors"
	"sync"
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

// TestUnidentifiedCallerIsNeverCached pins the empty-ExecPath fix: a caller with
// no resolved identity must re-decide every access, so one anonymous process's
// approval can't leak to every other anonymous process this session.
func TestUnidentifiedCallerIsNeverCached(t *testing.T) {
	e, _ := clockedEngine(5 * time.Minute)
	calls := 0
	p := countingPrompter(Allow, Session, &calls) // asks for Session, which for a known tool WOULD cache

	anon := Request{Credential: "gcp", Caller: Caller{PID: 1, ExecPath: "", Strength: BestEffort}}
	if _, _ = e.Decide(anon, p); calls != 1 {
		t.Fatalf("first anonymous access should prompt: prompts=%d, want 1", calls)
	}
	// A second anonymous access to the same credential must prompt AGAIN — the
	// decision is not cached, because there is no stable identity to cache under.
	if _, _ = e.Decide(anon, p); calls != 2 {
		t.Errorf("an unidentified caller's decision must never be cached: prompts=%d, want 2", calls)
	}
}

// TestConcurrentFirstAccessPromptsOnce pins the single-flight fix: many callers
// reaching for the same credential at once produce ONE prompt, and the rest ride
// the answer it caches.
func TestConcurrentFirstAccessPromptsOnce(t *testing.T) {
	e, _ := clockedEngine(5 * time.Minute)

	var mu sync.Mutex
	calls := 0
	release := make(chan struct{})
	// A slow prompter: it blocks until released, so all goroutines are guaranteed
	// to be past the cache lookup and contending before any answer is cached.
	p := func(Request) (Decision, Scope, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		<-release
		return Allow, Session, nil
	}

	const n = 16
	var wg sync.WaitGroup
	got := make([]Decision, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d, _ := e.Decide(gcloud(false), p)
			got[i] = d
		}(i)
	}
	// Give every goroutine time to reach the prompt or queue behind the leader,
	// then let the single in-flight prompt complete.
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Errorf("concurrent first accesses should single-flight to one prompt, got %d", calls)
	}
	for i, d := range got {
		if d != Allow {
			t.Errorf("caller %d got %v, want Allow from the shared decision", i, d)
		}
	}
}

// TestRefusalFloodDoesNotBecomeAPromptStorm is the whole point of the backoff.
// A refused request is never cached as a standing Deny — it can't be, since a
// declined prompt is indistinguishable from a keychain failure — so before the
// pause existed, a caller asking in a loop got one dialog per iteration and the
// cheapest way for the user to make it stop was to approve.
func TestRefusalFloodDoesNotBecomeAPromptStorm(t *testing.T) {
	e, now := clockedEngine(5 * time.Minute)
	calls := 0
	refuse := countingPrompter(Deny, Once, &calls)

	// Five minutes of a caller retrying once a second.
	for i := 0; i < 300; i++ {
		if got, _ := e.Decide(gcloud(false), refuse); got != Allow {
			*now = now.Add(time.Second)
			continue
		}
		t.Fatalf("iteration %d: a refused request must never come back Allow", i)
	}

	// The schedule tops out at 30s, so five minutes can't produce many more
	// than ten prompts however hard the caller tries. The bound is deliberately
	// loose — this pins "a flood no longer scales with the caller's effort",
	// not one particular schedule.
	if calls > 20 {
		t.Errorf("300 refused requests produced %d prompts, want the backoff to hold it near 10", calls)
	}
	if calls == 0 {
		t.Error("the first request must still reach the user; a throttle that never asks is a lockout")
	}
}

// The unidentified path has no decision cache, so for a long time it also had
// no queue — every concurrent anonymous caller prompted for itself. An
// attacker that simply declines to be identifiable would have had a prompt
// generator that scaled with goroutines.
func TestConcurrentUnidentifiedBurstPromptsOnce(t *testing.T) {
	e, _ := clockedEngine(5 * time.Minute)

	var mu sync.Mutex
	calls := 0
	release := make(chan struct{})
	p := func(Request) (Decision, Scope, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		<-release
		return Deny, Once, nil
	}

	anon := Request{Credential: "gcp", Caller: Caller{PID: 1, ExecPath: "", Strength: BestEffort}}
	const n = 64
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = e.Decide(anon, p)
		}()
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Errorf("%d concurrent anonymous refused requests produced %d prompts, want 1", n, calls)
	}
}

// An anonymous caller must still never have its decision cached — the queue
// added for the burst above must not have quietly turned into a cache.
func TestUnidentifiedApprovalIsStillNeverCached(t *testing.T) {
	e, _ := clockedEngine(5 * time.Minute)
	calls := 0
	p := countingPrompter(Allow, Session, &calls) // asks for Session, which for a known tool WOULD cache

	anon := Request{Credential: "gcp", Caller: Caller{PID: 1, ExecPath: "", Strength: BestEffort}}
	for i := 1; i <= 3; i++ {
		if got, _ := e.Decide(anon, p); got != Allow || calls != i {
			t.Fatalf("access %d: got %v after %d prompt(s), want Allow after %d", i, got, calls, i)
		}
	}
}

// The pause keys on the caller's launcher, which is coarse enough that
// refusals earned by one program can pause an honest one. `jit unlock` — a
// human at the keyboard saying "now" — is the override that makes that
// tradeoff acceptable, and it must not also hand out approvals.
func TestClearBackoffFreesThePauseWithoutGrantingAnything(t *testing.T) {
	e, _ := clockedEngine(5 * time.Minute)
	calls := 0
	refuse := countingPrompter(Deny, Once, &calls)

	_, _ = e.Decide(gcloud(false), refuse)
	if _, err := e.Decide(gcloud(false), refuse); err == nil {
		t.Fatal("expected the second request to be paused")
	}

	e.ClearBackoff()

	if _, err := e.Decide(gcloud(false), refuse); err != nil {
		t.Errorf("after ClearBackoff the request should reach the user again, got %v", err)
	}
	if calls != 2 {
		t.Errorf("prompts=%d, want 2 — the override restores asking, it does not skip it", calls)
	}
}

// Clearing pauses must not clear standing approvals: they are different
// session state answering different questions.
func TestClearBackoffLeavesDecisionsAlone(t *testing.T) {
	e, _ := clockedEngine(5 * time.Minute)
	calls := 0
	p := countingPrompter(Allow, Session, &calls)

	_, _ = e.Decide(gcloud(false), p)
	e.ClearBackoff()
	if got, _ := e.Decide(gcloud(false), p); got != Allow || calls != 1 {
		t.Errorf("got %v after %d prompt(s), want Allow after 1 (the standing decision survives)", got, calls)
	}
}

func TestThrottleReportsWhyItRefused(t *testing.T) {
	e, _ := clockedEngine(5 * time.Minute)
	calls := 0
	refuse := countingPrompter(Deny, Once, &calls)

	_, _ = e.Decide(gcloud(false), refuse)
	got, err := e.Decide(gcloud(false), refuse)

	var throttled *Throttled
	if !errors.As(err, &throttled) {
		t.Fatalf("second request returned err %v, want a *Throttled", err)
	}
	if got != Deny {
		t.Errorf("a throttled request must fail closed, got %v", got)
	}
	if throttled.RetryAfter != backoffSchedule[0] {
		t.Errorf("RetryAfter = %s, want the first step of the schedule (%s)", throttled.RetryAfter, backoffSchedule[0])
	}
	if calls != 1 {
		t.Errorf("the throttled request must not have reached the user: prompts=%d, want 1", calls)
	}
}

// The pause escalates only while refusals keep coming, and an approval ends it
// outright — a user who declines once and then approves must not be left
// serving out a penalty.
func TestApprovalClearsTheBackoff(t *testing.T) {
	e, now := clockedEngine(5 * time.Minute)
	calls := 0
	answer := Deny
	p := func(Request) (Decision, Scope, error) {
		calls++
		return answer, Once, nil
	}

	_, _ = e.Decide(gcloud(false), p) // refused: 2s pause
	*now = now.Add(3 * time.Second)
	answer = Allow
	if got, _ := e.Decide(gcloud(false), p); got != Allow {
		t.Fatalf("after the pause elapsed the request must reach the user again, got %v", got)
	}

	answer = Deny
	if _, err := e.Decide(gcloud(false), p); err != nil {
		t.Fatalf("the next refusal should start over at no pause, got %v", err)
	}
	if calls != 3 {
		t.Errorf("prompts=%d, want 3 (refuse, approve, refuse)", calls)
	}
}

// A caller with no resolved identity must not be able to dodge the pause by
// staying anonymous — that would make being unidentifiable the cheapest way to
// hold the user's attention.
func TestUnidentifiedCallerIsThrottledToo(t *testing.T) {
	e, _ := clockedEngine(5 * time.Minute)
	calls := 0
	refuse := countingPrompter(Deny, Once, &calls)
	anon := Request{Credential: "gcp", Caller: Caller{PID: 1, ExecPath: "", Strength: BestEffort}}

	for i := 0; i < 20; i++ {
		_, _ = e.Decide(anon, refuse)
	}
	if calls != 1 {
		t.Errorf("20 anonymous refused requests produced %d prompts, want 1 inside the pause", calls)
	}
}

func TestClearDropsTheBackoff(t *testing.T) {
	e, _ := clockedEngine(5 * time.Minute)
	calls := 0
	refuse := countingPrompter(Deny, Once, &calls)

	_, _ = e.Decide(gcloud(false), refuse)
	e.Clear() // session re-locked: the user is back at the machine
	if _, err := e.Decide(gcloud(false), refuse); err != nil {
		t.Fatalf("a re-lock must not leave a pause behind for the returning user: %v", err)
	}
	if calls != 2 {
		t.Errorf("prompts=%d, want 2 (the post-Clear request reaches the user)", calls)
	}
}

// The prompt has to be able to say "this is the fourth time" — without the
// count, a repeated dialog is indistinguishable from a first one.
func TestPriorRefusalsReachThePrompter(t *testing.T) {
	e, now := clockedEngine(5 * time.Minute)
	var seen []int
	refuse := func(r Request) (Decision, Scope, error) {
		seen = append(seen, r.PriorRefusals)
		return Deny, Once, nil
	}

	for _, step := range []time.Duration{0, 3 * time.Second, 10 * time.Second} {
		*now = now.Add(step)
		_, _ = e.Decide(gcloud(false), refuse)
	}

	want := []int{0, 1, 2}
	if len(seen) != len(want) {
		t.Fatalf("prompted %d times with %v, want %d", len(seen), seen, len(want))
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Errorf("prompt %d saw PriorRefusals=%d, want %d", i+1, seen[i], want[i])
		}
	}
}

// The single-flight collapses a concurrent burst into one prompt only when it
// is APPROVED — the answer it caches is what the waiters read. A refusal caches
// nothing, so before the backoff each released waiter went on to become the
// next leader and prompt in turn: the burst was serialized, not collapsed.
func TestConcurrentRefusedBurstPromptsOnce(t *testing.T) {
	e, _ := clockedEngine(5 * time.Minute)

	var mu sync.Mutex
	calls := 0
	release := make(chan struct{})
	p := func(Request) (Decision, Scope, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		<-release
		return Deny, Once, nil
	}

	const n = 64
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = e.Decide(gcloud(false), p)
		}()
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Errorf("%d concurrent refused requests produced %d prompts, want 1", n, calls)
	}
}
