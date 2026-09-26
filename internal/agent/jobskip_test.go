// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// lastJobEvent is the newest event the server recorded.
func lastJobEvent(t *testing.T, s *Server) SessionEvent {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.events) == 0 {
		t.Fatal("no event was recorded")
	}
	return s.events[len(s.events)-1]
}

// statusOf is the job as job_list reports it.
func (r *jobRig) statusOf(t *testing.T, name string) JobStatus {
	t.Helper()
	jobs, err := r.c.JobList()
	if err != nil {
		t.Fatal(err)
	}
	for _, j := range jobs {
		if j.Name == name {
			return j
		}
	}
	t.Fatalf("%s is not in job_list", name)
	return JobStatus{}
}

// skipOnce runs the job with its key unable to open right now and returns
// the event that run recorded.
func (r *jobRig) skipOnce(t *testing.T) SessionEvent {
	t.Helper()
	r.keys.mu.Lock()
	r.keys.openErr = notNow("grant key: reading the key in the keychain without asking failed, OSStatus=-25308")
	r.keys.mu.Unlock()
	if _, err := r.c.JobRun("notion-guests"); err == nil {
		t.Fatal("ran with a key that couldn't open")
	}
	return lastJobEvent(t, r.s)
}

const skipWhy = "the job's key couldn't open NOTION_API_KEY (the key can't be used right now: grant key: reading the key in the keychain without asking failed, OSStatus=-25308)"

// A skip is not a stop, and a skip that goes on is told: the third skipped
// run in a row records a persisting-skip event, saying how many since
// when, once per streak. The job is never stopped by it, and a run that
// runs ends the streak, so the next skip starts a new one.
func TestAJobSkippedThreeTimesInARowIsTold(t *testing.T) {
	r := newJobRig(t)
	if _, err := r.c.JobAllow("notion-guests", r.neverSpec()); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 2; i++ {
		e := r.skipOnce(t)
		if e.JobOutcome != JobOutcomeSkip || e.Cause != "notion-guests: didn't run, "+skipWhy {
			t.Fatalf("skip %d: outcome %q, cause %q", i, e.JobOutcome, e.Cause)
		}
		if st := r.statusOf(t, "notion-guests"); st.Stopped || st.Outcome != JobOutcomeSkip || st.Skips != i || st.SkippingSinceUnix == 0 {
			t.Fatalf("skip %d: status stopped %v, outcome %q, skips %d since %d", i, st.Stopped, st.Outcome, st.Skips, st.SkippingSinceUnix)
		}
	}
	e := r.skipOnce(t)
	since := time.Unix(r.stored(t).SkippingSinceUnix, 0).Format("Jan 2 15:04")
	if want := "notion-guests: didn't run 3 times in a row since " + since + ", " + skipWhy; e.JobOutcome != JobOutcomePersistingSkip || e.Cause != want {
		t.Fatalf("the third skip: outcome %q, cause\n got %q\nwant %q", e.JobOutcome, e.Cause, want)
	}
	if strings.Contains(e.Cause, "refused") {
		t.Errorf("a persisting skip reads as a stop to an app matching words: %q", e.Cause)
	}
	if j := r.stored(t); j.Stopped != "" {
		t.Fatalf("a persisting skip stopped the job: %q", j.Stopped)
	}
	if st := r.statusOf(t, "notion-guests"); st.Stopped || st.Outcome != JobOutcomePersistingSkip || st.Skips != 3 {
		t.Fatalf("after the third: stopped %v, outcome %q, skips %d", st.Stopped, st.Outcome, st.Skips)
	}
	// Told once: the fourth is a plain skip again, the status still says
	// the streak goes on.
	if e := r.skipOnce(t); e.JobOutcome != JobOutcomeSkip {
		t.Fatalf("the fourth skip: outcome %q, want a plain skip (told once per streak)", e.JobOutcome)
	}
	if st := r.statusOf(t, "notion-guests"); st.Outcome != JobOutcomePersistingSkip || st.Skips != 4 {
		t.Fatalf("after the fourth: outcome %q, skips %d", st.Outcome, st.Skips)
	}

	// The key opens again: the run runs, and the streak is over.
	r.keys.mu.Lock()
	r.keys.openErr = nil
	r.keys.mu.Unlock()
	if _, err := r.c.JobRun("notion-guests"); err != nil || r.runs() != 1 {
		t.Fatalf("the run with the key back: %v (runs %d)", err, r.runs())
	}
	if e := lastJobEvent(t, r.s); e.JobOutcome != "" {
		t.Errorf("a run that ran has outcome %q", e.JobOutcome)
	}
	if st := r.statusOf(t, "notion-guests"); st.Stopped || st.Outcome != "" || st.Skips != 0 || st.SkippingSinceUnix != 0 {
		t.Fatalf("after a run: stopped %v, outcome %q, skips %d since %d", st.Stopped, st.Outcome, st.Skips, st.SkippingSinceUnix)
	}
	if e := r.skipOnce(t); e.JobOutcome != JobOutcomeSkip {
		t.Fatalf("a new streak's first skip: %q", e.JobOutcome)
	}
}

// Or a day: a streak whose first skip is a day old is told at its next
// skip, however few there were. Just under a day is not.
func TestAJobSkippedForADayIsTold(t *testing.T) {
	for _, tc := range []struct {
		age  time.Duration
		want string
	}{
		{24*time.Hour + time.Minute, JobOutcomePersistingSkip},
		{23 * time.Hour, JobOutcomeSkip},
	} {
		t.Run(tc.age.String(), func(t *testing.T) {
			r := newJobRig(t)
			if _, err := r.c.JobAllow("notion-guests", r.neverSpec()); err != nil {
				t.Fatal(err)
			}
			r.skipOnce(t)
			first := time.Now().Add(-tc.age).Unix()
			r.s.jobMu.Lock()
			r.s.jobs["notion-guests"].SkippingSinceUnix = first
			r.s.jobMu.Unlock()
			e := r.skipOnce(t)
			if e.JobOutcome != tc.want {
				t.Fatalf("the second skip, the first %s ago: outcome %q, want %q (%s)", tc.age, e.JobOutcome, tc.want, e.Cause)
			}
			if tc.want == JobOutcomePersistingSkip {
				want := fmt.Sprintf("notion-guests: didn't run 2 times in a row since %s, %s", time.Unix(first, 0).Format("Jan 2 15:04"), skipWhy)
				if e.Cause != want {
					t.Fatalf("cause\n got %q\nwant %q", e.Cause, want)
				}
			}
			if r.stored(t).Stopped != "" {
				t.Fatal("a persisting skip stopped the job")
			}
		})
	}
}

// A stop is told apart from a skip by a field, not by words: the run that
// stops the job is JobOutcomeStop, a later run of the stopped job is
// JobOutcomeStillStopped, and job_list says stopped: true. A stop ends a
// streak of skips (the stop is what the owner hears).
func TestJobOutcomeTellsAStopFromASkip(t *testing.T) {
	r := newJobRig(t)
	if _, err := r.c.JobAllow("notion-guests", r.neverSpec()); err != nil {
		t.Fatal(err)
	}
	if st := r.statusOf(t, "notion-guests"); st.Stopped || st.Outcome != "" {
		t.Fatalf("a new job: stopped %v, outcome %q", st.Stopped, st.Outcome)
	}
	r.skipOnce(t)
	r.keys.mu.Lock()
	r.keys.openErr = fmt.Errorf("%w: cipher: message authentication failed", ErrGrantKeyWrongKey)
	r.keys.mu.Unlock()
	if _, err := r.c.JobRun("notion-guests"); err == nil {
		t.Fatal("ran with a wrong key")
	}
	e := lastJobEvent(t, r.s)
	if e.JobOutcome != JobOutcomeStop || e.Cause != "notion-guests: refused, NOTION_API_KEY does not open under the job's key" {
		t.Fatalf("the stop: outcome %q, cause %q", e.JobOutcome, e.Cause)
	}
	st := r.statusOf(t, "notion-guests")
	if !st.Stopped || st.Outcome != JobOutcomeStop || st.Skips != 0 {
		t.Fatalf("stopped job: stopped %v, outcome %q, skips %d", st.Stopped, st.Outcome, st.Skips)
	}
	if _, err := r.c.JobRun("notion-guests"); err == nil {
		t.Fatal("a stopped job ran")
	}
	if e := lastJobEvent(t, r.s); e.JobOutcome != JobOutcomeStillStopped || !strings.HasPrefix(e.Cause, "notion-guests: refused, stopped: ") {
		t.Fatalf("a stopped job's next run: outcome %q, cause %q", e.JobOutcome, e.Cause)
	}

	// The wire: the fields the app reads, by their JSON names.
	ev, _ := json.Marshal(lastJobEvent(t, r.s))
	sj, _ := json.Marshal(st)
	var evm, stm map[string]any
	if err := errors.Join(json.Unmarshal(ev, &evm), json.Unmarshal(sj, &stm)); err != nil {
		t.Fatal(err)
	}
	if evm["job_outcome"] != JobOutcomeStillStopped || stm["stopped"] != true || stm["outcome"] != JobOutcomeStop {
		t.Fatalf("wire: event %s\nstatus %s", ev, sj)
	}
	// And a ready job says stopped: false, not nothing.
	r2 := newJobRig(t)
	if _, err := r2.c.JobAllow("notion-guests", r2.neverSpec()); err != nil {
		t.Fatal(err)
	}
	ready, _ := json.Marshal(r2.statusOf(t, "notion-guests"))
	if !strings.Contains(string(ready), `"stopped":false`) || strings.Contains(string(ready), `"outcome"`) {
		t.Fatalf("a ready job on the wire: %s", ready)
	}
}
