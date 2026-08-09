// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/agent"
)

// collector is a serveAuditor sink that keeps what was written, so a test can
// assert on the events rather than on the file they'd land in.
type collector struct {
	mu     sync.Mutex
	events []agent.SessionEvent
}

func (c *collector) append(e agent.SessionEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func (c *collector) all() []agent.SessionEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]agent.SessionEvent{}, c.events...)
}

func newTestAuditor(window time.Duration) (*serveAuditor, *collector) {
	c := &collector{}
	return &serveAuditor{window: window, emit: c.append}, c
}

func decoyRead(pid int32, exec string) serveRecord {
	return serveRecord{
		decoy:  true,
		reader: readerIdentity{pid: pid, execPath: exec, launchedBy: "Code", identified: true},
	}
}

// The property the whole design exists for: agent-history.jsonl and the
// in-memory ring both evict oldest-first, so a watcher loop re-reading a mount
// must NOT be able to write one event per read — that would push every real
// unlock and denial out of the trail it is being added to.
func TestServeAuditCollapsesAReadStorm(t *testing.T) {
	a, c := newTestAuditor(time.Minute)
	start := time.Unix(1_700_000_000, 0)

	for i := 0; i < 5000; i++ {
		a.record(start.Add(time.Duration(i)*time.Millisecond), "/tmp/m.env",
			serveReason(true, false, true, ""), decoyRead(4321, "/usr/local/bin/node"))
	}
	if got := len(c.all()); got != 0 {
		t.Fatalf("5000 reads inside one window wrote %d events, want 0 until the window closes", got)
	}

	a.emitAll(a.take(true, start))
	events := c.all()
	if len(events) != 1 {
		t.Fatalf("a read storm produced %d events, want exactly 1 collapsed event", len(events))
	}
	if events[0].Count != 5000 {
		t.Errorf("collapsed event Count = %d, want 5000 — the count is the whole reason the line is interesting", events[0].Count)
	}
	if events[0].Kind != agent.KindServe || events[0].Op != agent.OpServeDecoy {
		t.Errorf("collapsed event = kind %q op %q, want %q/%q", events[0].Kind, events[0].Op, agent.KindServe, agent.OpServeDecoy)
	}
}

// Collapsing must never merge two facts an investigation needs apart. The key
// is (mount, reader, verdict), so a different reader or a different verdict is
// always its own line even inside one window.
func TestServeAuditKeepsDistinctFactsApart(t *testing.T) {
	a, c := newTestAuditor(time.Hour)
	now := time.Unix(1_700_000_000, 0)

	real := serveRecord{reader: readerIdentity{pid: 4321, execPath: "/usr/local/bin/node", identified: true}}

	a.record(now, "/tmp/a.env", "r1", decoyRead(4321, "/usr/local/bin/node"))
	a.record(now, "/tmp/b.env", "r1", decoyRead(4321, "/usr/local/bin/node")) // other mount
	a.record(now, "/tmp/a.env", "r1", decoyRead(9999, "/usr/bin/python3"))    // other reader
	a.record(now, "/tmp/a.env", "r2", real)                                   // other verdict

	a.emitAll(a.take(true, now))
	if got := len(c.all()); got != 4 {
		t.Fatalf("4 distinct (mount, reader, verdict) triples collapsed into %d events, want 4", got)
	}
}

// An aggregate must be written once its window closes even if the machine goes
// quiet — a single decoy read on an idle machine is exactly the one most worth
// seeing, and it must not wait for a lock or a shutdown to appear.
func TestServeAuditFlushesWhenTheWindowCloses(t *testing.T) {
	a, c := newTestAuditor(time.Minute)
	start := time.Unix(1_700_000_000, 0)
	lookups := 0
	a.labelFn = func(mount string) string {
		lookups++
		if mount == "/tmp/m.env" {
			return "gcp"
		}
		return "aws"
	}

	a.record(start, "/tmp/m.env", "r", decoyRead(1, "/bin/cat"))
	if got := len(c.all()); got != 0 {
		t.Fatalf("wrote %d events immediately, want 0 while the window is open", got)
	}
	// A later read of a DIFFERENT mount, past the window: the first aggregate
	// is now due and must go out.
	a.record(start.Add(2*time.Minute), "/tmp/other.env", "r", decoyRead(2, "/bin/cat"))

	events := c.all()
	if len(events) != 1 {
		t.Fatalf("an expired aggregate wrote %d events, want 1", len(events))
	}
	if len(events[0].Labels) == 0 || events[0].Labels[0] != "gcp" {
		t.Errorf("the expired event = %+v, want the gcp mount's", events[0])
	}
	if lookups != 2 {
		t.Errorf("resolved the mount label %d times, want one per distinct mount", lookups)
	}
}

// The label lookup walks jit's global-mount table, so it must be memoized:
// paying it once per rendezvous is exactly the per-read cost the mount code
// has twice been bitten by.
func TestServeAuditMemoizesTheMountLabel(t *testing.T) {
	a, _ := newTestAuditor(time.Hour)
	lookups := 0
	a.labelFn = func(string) string { lookups++; return "gcp" }
	now := time.Unix(1_700_000_000, 0)

	// Distinct readers, so each gets its own aggregate and every one of them
	// needs the label — but the mount is the same, so the lookup is not.
	for i := 0; i < 20; i++ {
		a.record(now, "/tmp/m.env", "r", decoyRead(int32(i+1), "/bin/sh"))
	}
	if lookups != 1 {
		t.Errorf("resolved the same mount's label %d times, want 1", lookups)
	}
}

// The pending map is keyed partly on pid, so a burst of short-lived readers
// each claim a key. It needs a ceiling that isn't "however many processes the
// machine can spawn" — and hitting it must flush, never drop.
func TestServeAuditBoundsPendingAggregates(t *testing.T) {
	a, c := newTestAuditor(time.Hour)
	now := time.Unix(1_700_000_000, 0)

	for i := 0; i < maxPendingServes*3; i++ {
		a.record(now, "/tmp/m.env", "r", decoyRead(int32(i+1), "/bin/sh"))
	}

	a.mu.Lock()
	pending := len(a.pending)
	a.mu.Unlock()
	if pending > maxPendingServes {
		t.Errorf("pending aggregates = %d, want at most %d", pending, maxPendingServes)
	}
	if got := len(c.all()); got == 0 {
		t.Error("hitting the ceiling dropped every aggregate; it must flush them instead")
	}
}

// A nil emit is the zero value every test's bare mountManager has. It must be
// inert rather than a panic, and cost nothing on the serve path.
func TestServeAuditWithoutASinkIsInert(t *testing.T) {
	var a serveAuditor
	a.record(time.Unix(1, 0), "/tmp/m.env", "r", decoyRead(1, "/bin/cat"))
	a.start()
	a.stopFlusher()
	if a.pending != nil {
		t.Error("an auditor with no sink accumulated state")
	}
}

// stopFlusher is the service shutting down: whatever window it was in the
// middle of must be written, not discarded.
func TestServeAuditStopFlusherWritesPending(t *testing.T) {
	a, c := newTestAuditor(time.Hour)
	a.start()
	a.record(time.Unix(1_700_000_000, 0), "/tmp/m.env", "r", decoyRead(7, "/bin/cat"))
	a.stopFlusher()

	if got := len(c.all()); got != 1 {
		t.Fatalf("shutdown wrote %d events, want the 1 still pending", got)
	}
}

// Every mount has its own Serve goroutine, so record() is called concurrently
// while the background flusher walks the same map. Under -race this is the
// test that matters: no read of a credential mount may ever be lost to, or
// corrupted by, the bookkeeping that records it.
func TestServeAuditIsConcurrencySafe(t *testing.T) {
	a, c := newTestAuditor(time.Millisecond)
	a.start()
	defer a.stopFlusher()

	var wg sync.WaitGroup
	for m := 0; m < 8; m++ {
		wg.Add(1)
		go func(m int) {
			defer wg.Done()
			mount := "/tmp/mount" + string(rune('a'+m)) + ".env"
			for i := 0; i < 200; i++ {
				a.record(time.Now(), mount, "r", decoyRead(int32(m+1), "/bin/sh"))
			}
		}(m)
	}
	wg.Wait()
	a.stopFlusher()

	// Every read is accounted for: collapsed into some number of events, but
	// never dropped.
	var total int64
	for _, e := range c.all() {
		total += e.Count
	}
	if total != 8*200 {
		t.Errorf("recorded %d reads across the collapsed events, want %d", total, 8*200)
	}
}

// The reason is the durable answer to "why is my app reading decoys", which
// before this existed lived only as prose in the service's own log.
func TestServeReasonNamesTheCause(t *testing.T) {
	cases := []struct {
		name                     string
		decoy, grant, hadReal    bool
		resolveErr, wantFragment string
	}{
		{name: "granted", decoy: false, grant: true, wantFragment: "jit run grant"},
		{name: "consent", decoy: false, grant: false, wantFragment: "consent prompt"},
		{name: "ungranted", decoy: true, hadReal: true, wantFragment: "no jit run grant or consent"},
		{name: "locked", decoy: true, hadReal: false, wantFragment: "session is locked"},
		{name: "resolve failed", decoy: true, hadReal: false, resolveErr: "keychain said no", wantFragment: "keychain said no"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := serveReason(tc.decoy, tc.grant, tc.hadReal, tc.resolveErr)
			if !strings.Contains(got, tc.wantFragment) {
				t.Errorf("serveReason = %q, want it to mention %q", got, tc.wantFragment)
			}
		})
	}
}
