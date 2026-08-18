// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/vault"
)

// TestEnsureServingConcurrentCallsClaimSlotOnce is the regression test for
// a real TOCTOU race: ensureServing's "already served?" check and its map
// insert used to be two separate lock acquisitions with profile loading in
// between, and ensureServing is genuinely reachable concurrently (OnUnlock
// fires from a fresh challenge after ensureUnlocked releases its lock;
// OnRefresh fires from a connection-handling goroutine — jit migrate's
// own flow can overlap the two, since the unlock its first vault write
// triggers can still be scanning when its explicit Refresh RPC arrives).
// Two goroutines could then both pass the check for the same brand-new
// entry and both spawn a Serve goroutine on the same FIFO — the second
// insert overwriting the first servedMount, orphaning a goroutine whose
// CancelFunc nothing could ever reach again, which made shutdown()'s
// wg.Wait() block forever. The claim now happens in the same critical
// section as the re-check; this test drives 8 concurrent calls at one
// fresh entry and requires both a single served slot and a shutdown()
// that actually completes.

// serveNoGrant runs the unified content decision (serveContent) with no
// grant runs active — the fast path: always decoy, since real content flows
// only to a run-scoped grant's own process tree.
// serveNoGrant is one COMPLETED read: the content decision plus the
// cycle-end fold (delivered), the way mount.Serve drives the two hooks.
func serveNoGrant(sm *servedMount) []byte {
	m := &mountManager{stdout: io.Discard, stderr: io.Discard}
	content := m.serveContent("/tmp/fixture/.env", sm)
	m.finalizeServe("/tmp/fixture/.env", sm, true)
	return content
}

func TestEnsureServingConcurrentCallsClaimSlotOnce(t *testing.T) {
	dir := t.TempDir()
	profilePath := filepath.Join(dir, "profile.yaml")
	if err := os.WriteFile(profilePath, []byte("API_KEY: fixture/API_KEY\n"), 0o600); err != nil {
		t.Fatalf("writing fixture profile: %v", err)
	}
	mountPath := filepath.Join(dir, ".env")
	if err := mount.CreateFIFO(mountPath); err != nil {
		t.Fatalf("creating fixture FIFO: %v", err)
	}

	// io.Discard, not a bytes.Buffer: several Serve goroutines (in the
	// buggy version) plus ensureServing itself may write logs concurrently,
	// and this test must fail on the mountManager race, not on its own
	// unsynchronized test buffer.
	m := &mountManager{root: dir, stdout: io.Discard, stderr: io.Discard}
	entries := []mount.Entry{{MountPath: mountPath, ProfilePath: profilePath}}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.ensureServing(entries)
		}()
	}
	wg.Wait()

	m.mu.Lock()
	n := len(m.served)
	m.mu.Unlock()
	if n != 1 {
		t.Fatalf("len(served) after concurrent ensureServing = %d, want exactly 1", n)
	}

	done := make(chan struct{})
	go func() {
		m.shutdown()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown() hung, an ensureServing race left a Serve goroutine no CancelFunc can reach, the exact orphan the single-critical-section claim exists to prevent")
	}
}

// newTestServedMount is a bare servedMount with no Serve goroutine behind
// it — enough to unit-test reveal/hide/content-selection logic without the
// full ensureServing pipeline (a real registry entry, a real profile
// file, an actual FIFO). cancel defaults to a no-op, and done starts
// pre-closed (as if the goroutine had already exited) so tests that
// don't care about stopMount's wait behavior can skip setting one up —
// see TestMountManagerStopMountWaitsForGoroutineToExit for the test that
// does care.
func newTestServedMount() *servedMount {
	done := make(chan struct{})
	close(done)
	// real content is pre-resolved (armed in memory); it serves only to a
	// run-scoped grant's process tree, decoy to everyone else.
	return &servedMount{cancel: func() {}, done: done, real: []byte("API_KEY=real\n")}
}
func TestMountManagerStopClearsRealContentWithoutCancelling(t *testing.T) {
	cancelled := false
	sm := &servedMount{decoy: []byte("decoy"), real: []byte("real"), cancel: func() { cancelled = true }}
	m := &mountManager{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, served: map[string]*servedMount{"/tmp/fixture/.env": sm}}

	// A mount serves decoys with no grant active, whether or not real content
	// is armed — real flows only to a run-scoped grant's process tree.
	if got := serveNoGrant(sm); string(got) != "decoy" {
		t.Fatalf("setup: serveNoGrant = %q, want decoy with no grant active", got)
	}

	m.stop()

	if cancelled {
		t.Error("stop() must not cancel a mount's Serve goroutine (GAPS.md #35), only forget real content")
	}
	sm.mu.Lock()
	real := sm.real
	sm.mu.Unlock()
	if real != nil {
		t.Error("expected real content forgotten after stop, so a later grant can't serve stale plaintext")
	}
	if got := serveNoGrant(sm); string(got) != "decoy" {
		t.Errorf("serveNoGrant after stop = %q, want decoy", got)
	}
}

// TestMountManagerStopMountCancelsOnlyThatMount is GAPS.md #35's
// regression test for the per-mount stop that replaced "lock the whole
// agent first" in jit unmount: stopping one mount must never disturb
// any other mount's serving.
func TestMountManagerStopMountCancelsOnlyThatMount(t *testing.T) {
	cancelledA, cancelledB := false, false
	smA := newTestServedMount()
	smA.cancel = func() { cancelledA = true }
	smB := newTestServedMount()
	smB.cancel = func() { cancelledB = true }
	m := &mountManager{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, served: map[string]*servedMount{
		"/tmp/fixture/a.env": smA,
		"/tmp/fixture/b.env": smB,
	}}

	m.stopMount("/tmp/fixture/a.env")

	if !cancelledA {
		t.Error("expected a.env's Serve goroutine to be cancelled")
	}
	if cancelledB {
		t.Error("expected b.env to be left undisturbed")
	}
	if _, ok := m.served["/tmp/fixture/a.env"]; ok {
		t.Error("expected a.env removed from the served map")
	}
	if _, ok := m.served["/tmp/fixture/b.env"]; !ok {
		t.Error("expected b.env to remain in the served map")
	}
}

// TestNoteReaderConnectedCollapsesStormLogging is GAPS.md #47's log-cost
// half: a watcher re-read loop produces one reader-connected line per
// read — 635k log lines in one afternoon on a real machine — so repeat
// reads within readLogMinGap must collapse into the NEXT logged line's
// suppressed-count suffix, not each get their own line. The lineage scan
// (the actual CPU cost) is likewise rate-limited to lineageScanMinGap.
func TestNoteReaderConnectedCollapsesStormLogging(t *testing.T) {
	sm := newTestServedMount()
	var stderr bytes.Buffer
	m := &mountManager{stdout: io.Discard, stderr: &stderr, served: map[string]*servedMount{"/tmp/fixture/.env": sm}}

	for i := 0; i < 25; i++ {
		m.noteReaderConnected("/tmp/fixture/.env", sm)
	}

	if got := strings.Count(stderr.String(), "reader"); got != 1 {
		t.Errorf("25 rapid reads produced %d reader log lines, want exactly 1 (the rest collapsed into the next line's suppressed count)", got)
	}
	sm.mu.Lock()
	suppressed, count := sm.readLogSuppressed, sm.readWindowCount
	sm.mu.Unlock()
	if suppressed != 24 {
		t.Errorf("readLogSuppressed = %d, want 24", suppressed)
	}
	if count != 25 {
		t.Errorf("readWindowCount = %d, want 25, the rolling counter must count every read, logged or not", count)
	}
}

// TestMountRevealStatusesReportsReadsLastMinute: the rolling read counter
// must ride the status RPC, so `jit agent status` can name a watcher
// re-read loop instead of it burning CPU invisibly (GAPS.md #47).
func TestMountRevealStatusesReportsReadsLastMinute(t *testing.T) {
	sm := newTestServedMount()
	m := &mountManager{stdout: io.Discard, stderr: io.Discard, served: map[string]*servedMount{"/tmp/fixture/.env": sm}}

	for i := 0; i < 3; i++ {
		m.noteReaderConnected("/tmp/fixture/.env", sm)
	}

	statuses := m.mountRevealStatuses()
	if len(statuses) != 1 {
		t.Fatalf("got %d statuses, want 1", len(statuses))
	}
	if statuses[0].ReadsLastMinute != 3 {
		t.Errorf("ReadsLastMinute = %d, want 3", statuses[0].ReadsLastMinute)
	}
}

// TestProvideContentRecordsLastServe: every content decision records
// what was served, when, and (best-effort) to whom — the raw material
// for "my dev server got decoy values and nothing anywhere said so"
// becoming visible in `jit agent status`/`jit status`.
func TestProvideContentRecordsLastServe(t *testing.T) {
	sm := newTestServedMount()
	sm.decoy = []byte("decoy")

	if got := serveNoGrant(sm); string(got) != "decoy" {
		t.Fatalf("provideContent = %q, want decoy while hidden", got)
	}
	sm.mu.Lock()
	ls := sm.lastServe
	sm.mu.Unlock()
	if ls == nil || !ls.decoy {
		t.Fatalf("lastServe after a decoy read = %+v, want recorded with decoy=true", ls)
	}
	if ls.reader.identified {
		t.Errorf("lastServe.reader = %+v, want unidentified (no onReaderConnected ran)", ls.reader)
	}
	// The real-content, reader-identity-carried-through path only happens
	// under a run-scoped grant now (there is no reveal window), so it's
	// exercised by the grant e2e tests (rungrant_e2e_test.go) rather than
	// here, where no grant machinery is wired.
}

// TestKnownReaderFastPathNamesASweepReader is the sweep fix end to end at
// the unit level: the full-table walk identifies the reader on mount A and
// feeds the service-wide recent list; mount B's scan — where the walk would
// lose the race — re-finds that same reader with the targeted one-pid check,
// names it flatly (a direct observation, not a carry-forward), and never
// pays for a second walk.
func TestKnownReaderFastPathNamesASweepReader(t *testing.T) {
	m := &mountManager{stdout: io.Discard, stderr: io.Discard}
	fullScans := 0
	m.identifyFn = func(path string) (int32, string, bool) {
		fullScans++
		if path == "/tmp/fixture/a.env" {
			return 555, "/usr/libexec/sharingd", true
		}
		return 0, "", false
	}
	m.describeFn = func(pid int32) (string, bool) {
		if pid == 555 {
			return "/usr/libexec/sharingd", true
		}
		return "", false
	}
	m.holdsFIFOFn = func(pid int32, path string) bool { return pid == 555 }
	m.launcherFn = func(int32) string { return "" }

	got := m.identifyReader("/tmp/fixture/a.env", readerIdentity{})
	if !got.identified || got.pid != 555 || got.likely {
		t.Fatalf("mount A: identifyReader = %+v, want the walk's flat identification", got)
	}
	if fullScans != 1 {
		t.Fatalf("mount A: full scans = %d, want 1", fullScans)
	}

	got = m.identifyReader("/tmp/fixture/b.env", readerIdentity{})
	if !got.identified || got.pid != 555 || got.likely {
		t.Errorf("mount B: identifyReader = %+v, want the fast check's flat identification", got)
	}
	if fullScans != 1 {
		t.Errorf("mount B: full scans = %d, want still 1 — the fast check must answer before the walk", fullScans)
	}
}

// TestKnownReaderFastPathEvictsAReusedPID: a remembered pid now running a
// different binary can never match again; it must be dropped from the recent
// list, never matched against, and the scan must fall through to the walk.
func TestKnownReaderFastPathEvictsAReusedPID(t *testing.T) {
	m := &mountManager{stdout: io.Discard, stderr: io.Discard}
	m.noteRecentReader(readerIdentity{pid: 555, execPath: "/usr/libexec/sharingd", identified: true})
	m.identifyFn = func(string) (int32, string, bool) { return 0, "", false }
	m.describeFn = func(int32) (string, bool) { return "/usr/bin/python3", true } // recycled
	m.holdsFIFOFn = func(int32, string) bool {
		t.Error("holds check ran for a candidate the pid-reuse guard should have dropped")
		return false
	}

	if got := m.identifyReader("/tmp/fixture/a.env", readerIdentity{}); got.identified {
		t.Errorf("identifyReader = %+v, want unidentified after the eviction", got)
	}
	m.readersMu.Lock()
	left := len(m.recentReaders)
	m.readersMu.Unlock()
	if left != 0 {
		t.Errorf("recent list still holds %d entries, want the reused pid evicted", left)
	}
}

// TestKnownReaderUpgradesPreviousToDirectObservation: a mount's previous
// reader that provably still holds the pipe is a fresh observation, not a
// carry-forward — the row it produces must not be hedged as "likely".
func TestKnownReaderUpgradesPreviousToDirectObservation(t *testing.T) {
	m := &mountManager{stdout: io.Discard, stderr: io.Discard}
	m.identifyFn = func(string) (int32, string, bool) {
		t.Error("full walk ran although the previous reader answered the targeted check")
		return 0, "", false
	}
	m.describeFn = func(int32) (string, bool) { return "/usr/local/bin/node", true }
	m.holdsFIFOFn = func(pid int32, _ string) bool { return pid == 700 }

	previous := readerIdentity{pid: 700, execPath: "/usr/local/bin/node", launchedBy: "Code", identified: true}
	got := m.identifyReader("/tmp/fixture/a.env", previous)
	if !got.identified || got.pid != 700 || got.likely {
		t.Errorf("identifyReader = %+v, want the previous reader confirmed flatly, not marked likely", got)
	}
	if got.launchedBy != "Code" {
		t.Errorf("launchedBy = %q, want it carried without a fresh ancestry walk", got.launchedBy)
	}
}

// TestNoteRecentReadersCapDedupeAndDoctrine: newest first, one entry per
// pid, capped — and likely-marked identities are never admitted, or the fast
// check's own inference would compound.
func TestNoteRecentReadersCapDedupeAndDoctrine(t *testing.T) {
	m := &mountManager{stdout: io.Discard, stderr: io.Discard}
	for i := 0; i < recentReadersCap+4; i++ {
		m.noteRecentReader(readerIdentity{pid: int32(100 + i), execPath: "/bin/x", identified: true})
	}
	m.readersMu.Lock()
	n, first := len(m.recentReaders), m.recentReaders[0].pid
	m.readersMu.Unlock()
	if n != recentReadersCap {
		t.Errorf("recent list holds %d entries, want capped at %d", n, recentReadersCap)
	}
	if first != int32(100+recentReadersCap+3) {
		t.Errorf("front of the list = pid %d, want the newest observation", first)
	}

	m.noteRecentReader(readerIdentity{pid: int32(100 + recentReadersCap), execPath: "/bin/x", identified: true})
	m.readersMu.Lock()
	n, first = len(m.recentReaders), m.recentReaders[0].pid
	m.readersMu.Unlock()
	if n != recentReadersCap || first != int32(100+recentReadersCap) {
		t.Errorf("re-noting an existing pid: len=%d front=%d, want moved to front without growing", n, first)
	}

	m.noteRecentReader(readerIdentity{pid: 9999, execPath: "/bin/x", identified: true, likely: true})
	m.readersMu.Lock()
	first = m.recentReaders[0].pid
	m.readersMu.Unlock()
	if first == 9999 {
		t.Error("a likely-marked identity entered the recent list; only direct observations may feed the fast check")
	}
}

// TestFinalizeServeRecordsUndelivered pins the record's two-moment shape:
// nothing is published at decision time, and an EPIPE cycle (the reader was
// gone before the write — it received nothing) reaches lastServe and the
// durable trail marked undelivered, instead of as the "decoy served" it
// used to be logged as.
func TestFinalizeServeRecordsUndelivered(t *testing.T) {
	sm := newTestServedMount()
	sm.decoy = []byte("decoy")
	c := &collector{}
	m := &mountManager{stdout: io.Discard, stderr: io.Discard}
	m.serveAudit = serveAuditor{window: time.Hour, emit: c.append}

	if got := m.serveContent("/tmp/fixture/.env", sm); string(got) != "decoy" {
		t.Fatalf("serveContent = %q, want decoy", got)
	}
	sm.mu.Lock()
	published := sm.lastServe
	sm.mu.Unlock()
	if published != nil {
		t.Fatalf("lastServe = %+v before the cycle ended, want nil until the outcome is known", published)
	}

	m.finalizeServe("/tmp/fixture/.env", sm, false)

	sm.mu.Lock()
	ls := sm.lastServe
	sm.mu.Unlock()
	if ls == nil || !ls.undelivered || !ls.decoy {
		t.Fatalf("lastServe = %+v, want a decoy record marked undelivered", ls)
	}
	m.serveAudit.stopFlusher()
	events := c.all()
	if len(events) != 1 || !events[0].Undelivered {
		t.Fatalf("durable trail = %+v, want one event marked Undelivered", events)
	}
}

// TestFinalizeServeIdentityRetryGating: the post-write identity scan is spent
// only where it can pay — content was delivered (an EPIPE reader is provably
// gone) AND this cycle's own scan ran and found nobody. Its find is marked
// likely (a post-hoc observation, not the open itself) and feeds the
// carry-forward so the next cycle starts with a name.
func TestFinalizeServeIdentityRetryGating(t *testing.T) {
	run := func(t *testing.T, delivered, missed bool) (*servedMount, int) {
		t.Helper()
		sm := newTestServedMount()
		sm.decoy = []byte("decoy")
		m := &mountManager{stdout: io.Discard, stderr: io.Discard}
		retries := 0
		m.identifyFn = func(string) (int32, string, bool) {
			retries++
			return 777, "/usr/libexec/sharingd", true
		}
		if got := m.serveContent("/tmp/fixture/.env", sm); string(got) != "decoy" {
			t.Fatalf("serveContent = %q, want decoy", got)
		}
		sm.mu.Lock()
		sm.scanMissed = missed
		sm.mu.Unlock()
		m.finalizeServe("/tmp/fixture/.env", sm, delivered)
		return sm, retries
	}

	sm, retries := run(t, true, true)
	if retries != 1 {
		t.Fatalf("delivered+missed: retries = %d, want 1", retries)
	}
	sm.mu.Lock()
	ls, carried := sm.lastServe, sm.pendingReader
	if sm.scanMissed {
		t.Error("scanMissed not cleared by finalizeServe")
	}
	sm.mu.Unlock()
	if ls == nil || !ls.reader.identified || !ls.reader.likely || ls.reader.pid != 777 {
		t.Errorf("lastServe.reader = %+v, want the retry's find, marked likely", ls.reader)
	}
	if !carried.identified || carried.pid != 777 || !carried.likely {
		t.Errorf("pendingReader = %+v, want the retry's find fed to the carry-forward", carried)
	}

	if _, retries := run(t, false, true); retries != 0 {
		t.Errorf("undelivered cycle: retries = %d, want 0 — an EPIPE reader is provably gone", retries)
	}
	if _, retries := run(t, true, false); retries != 0 {
		t.Errorf("no missed scan: retries = %d, want 0 — the rate limit must bound the extra walk", retries)
	}
}

// TestMountRevealStatusesIncludesLastServe confirms the serve record crosses
// the status RPC boundary — pid/path only when the lineage scan actually
// identified the reader, never zero-valued noise.
func TestMountRevealStatusesIncludesLastServe(t *testing.T) {
	read := newTestServedMount()
	read.decoy = []byte("decoy")
	read.mu.Lock()
	read.pendingReader = readerIdentity{pid: 4823, execPath: "/usr/local/bin/node", identified: true}
	read.mu.Unlock()
	serveNoGrant(read)
	neverRead := newTestServedMount()
	m := &mountManager{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, served: map[string]*servedMount{
		"/tmp/fixture/read.env":  read,
		"/tmp/fixture/never.env": neverRead,
	}}

	byPath := map[string]agent.MountRevealStatus{}
	for _, s := range m.mountRevealStatuses() {
		byPath[s.Path] = s
	}

	got := byPath["/tmp/fixture/read.env"]
	if got.LastServe == nil {
		t.Fatal("LastServe missing for a mount that was read")
	}
	if !got.LastServe.Decoy || got.LastServe.ReaderPID != 4823 || got.LastServe.ReaderPath != "/usr/local/bin/node" {
		t.Errorf("LastServe = %+v, want decoy=true with the identified reader", got.LastServe)
	}
	if got.LastServe.UnixTime == 0 {
		t.Error("LastServe.UnixTime = 0, want the read's actual time")
	}
	if byPath["/tmp/fixture/never.env"].LastServe != nil {
		t.Errorf("LastServe for a never-read mount = %+v, want nil", byPath["/tmp/fixture/never.env"].LastServe)
	}
}

// TestPrintMountStatusesShowsLastServe pins the user-facing copy: one
// sorted bullet per mount showing whether it's grant-serving real values or
// decoy, the most recent read (kind of values, reader, relative time)
// indented under it, the fixing command inline on a decoy read — and every
// registered mount present, including a never-read, never-granted one (the
// section's shape stays stable; only the states change between runs).
func TestPrintMountStatusesShowsLastServe(t *testing.T) {
	var buf bytes.Buffer
	printMountStatuses(&buf, []agent.MountRevealStatus{
		{Path: "/p/decoy.env", LastServe: &agent.MountServeEvent{
			UnixTime: time.Now().Add(-2 * time.Minute).Unix(), Decoy: true, ReaderPID: 4823, ReaderPath: "/usr/local/bin/node",
		}},
		{Path: "/p/real.env", Grants: []agent.MountGrantStatus{{PID: 111, Command: "docker compose up", SinceUnix: time.Now().Add(-time.Minute).Unix()}}, LastServe: &agent.MountServeEvent{
			UnixTime: time.Now().Add(-30 * time.Second).Unix(), Decoy: false, GrantServed: true,
		}},
		{Path: "/p/quiet.env"},
	})
	out := buf.String()

	for _, want := range []string{
		"○ /p/decoy.env",
		"read 2m ago by node (pid 4823) · decoy",
		"jit run --live",
		"● /p/real.env",
		"real to 1 active grant",
		"read 30s ago by an unidentified process · real (run-scoped grant)",
		"○ /p/quiet.env",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, out)
		}
	}
	// Sorted by path, one bullet each — never the map-order event-log
	// stream this used to be.
	if di, ri := strings.Index(out, "/p/decoy.env"), strings.Index(out, "/p/quiet.env"); di > ri {
		t.Errorf("mounts not sorted by path, got:\n%s", out)
	}
}

// TestEnsureServingDecoyCarriesNotice: the decoy content a mount serves
// must open with the self-diagnosing comment line naming the reveal command
// — and the real content must never carry it (its absence is part of the
// "you're looking at real values" signal).
func TestEnsureServingDecoyCarriesNotice(t *testing.T) {
	dir := t.TempDir()
	profilePath := filepath.Join(dir, "profile.yaml")
	if err := os.WriteFile(profilePath, []byte("API_KEY: fixture/API_KEY\n"), 0o600); err != nil {
		t.Fatalf("writing fixture profile: %v", err)
	}
	mountPath := filepath.Join(dir, ".env")
	if err := mount.CreateFIFO(mountPath); err != nil {
		t.Fatalf("creating fixture FIFO: %v", err)
	}

	m := &mountManager{root: dir, stdout: io.Discard, stderr: io.Discard}
	m.ensureServing([]mount.Entry{{MountPath: mountPath, ProfilePath: profilePath}})
	defer m.shutdown()

	m.mu.Lock()
	sm := m.served[mountPath]
	m.mu.Unlock()
	if sm == nil {
		t.Fatal("mount not served")
	}
	sm.mu.Lock()
	decoy := string(sm.decoy)
	sm.mu.Unlock()

	if !strings.HasPrefix(decoy, "# jit:") {
		t.Errorf("decoy content = %q, want it to OPEN with the self-diagnosing notice", decoy)
	}
	if !strings.Contains(decoy, "jit run") {
		t.Errorf("decoy content = %q, want the self-diagnosing notice naming a jit run grant", decoy)
	}
}

// TestResolveRealReResolvesUpdatedSecret is GAPS.md #43's regression
// test: a mount whose real content had already been resolved used to be
// skipped by every later resolveReal ("already resolved"), so `jit
// vault set` on a secret the mount references kept serving the OLD value
// indefinitely — nothing short of a full lock/unlock cycle ever
// invalidated it. resolveReal must re-resolve on every unlock/refresh.
func TestResolveRealReResolvesUpdatedSecret(t *testing.T) {
	root := t.TempDir()
	kw := newFakeKeyWrapper()
	v := &vault.Vault{Root: root, KeyWrapper: kw, RecipientID: "test-device"}
	if err := v.Set("fixture/API_KEY", []byte("first-value")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	profilePath := filepath.Join(root, "profile.yaml")
	if err := os.WriteFile(profilePath, []byte("API_KEY: fixture/API_KEY\n"), 0o600); err != nil {
		t.Fatalf("writing fixture profile: %v", err)
	}

	sm := newTestServedMount()
	m := &mountManager{root: root, stdout: io.Discard, stderr: &bytes.Buffer{}, served: map[string]*servedMount{
		"/tmp/fixture/.env": sm,
	}}
	entries := []mount.Entry{{MountPath: "/tmp/fixture/.env", ProfilePath: profilePath}}

	realContent := func() string {
		sm.mu.Lock()
		defer sm.mu.Unlock()
		return string(sm.real)
	}

	m.resolveReal(entries, v)
	if got := realContent(); !strings.Contains(got, "first-value") {
		t.Fatalf("real content after first resolve = %q, want it to contain first-value", got)
	}
	if got := realContent(); strings.Contains(got, "# jit:") {
		t.Errorf("real content = %q carries the decoy notice, its absence is part of the revealed signal", got)
	}

	if err := v.Set("fixture/API_KEY", []byte("second-value")); err != nil {
		t.Fatalf("Set (update): %v", err)
	}
	m.resolveReal(entries, v)
	if got := realContent(); !strings.Contains(got, "second-value") {
		t.Errorf("real content after re-resolve = %q, want the UPDATED second-value, a stale mount serving a replaced secret forever is the exact GAPS.md #43 bug", got)
	}
}

// TestEnsureServingRemovesDeadMountFromServed is GAPS.md #44's regression
// test: a mount whose Serve loop exited with a structural error (not
// cancellation) used to stay in m.served forever — never restarted by a
// later unlock/refresh, still reported as served by mountRevealStatuses,
// and revealable with apparent success while nothing was actually writing
// to the pipe. The dying goroutine must remove its own entry so the next
// ensureServing genuinely retries it. The structural failure here is
// recreateFIFO hitting a write-protected directory right after the first
// reader is served — the same class of error (path's directory gone bad)
// that Serve's own doc comment declares fatal.
func TestEnsureServingRemovesDeadMountFromServed(t *testing.T) {
	mountDir := t.TempDir()
	profileDir := t.TempDir()
	profilePath := filepath.Join(profileDir, "profile.yaml")
	if err := os.WriteFile(profilePath, []byte("API_KEY: fixture/API_KEY\n"), 0o600); err != nil {
		t.Fatalf("writing fixture profile: %v", err)
	}
	mountPath := filepath.Join(mountDir, ".env")
	if err := mount.CreateFIFO(mountPath); err != nil {
		t.Fatalf("creating fixture FIFO: %v", err)
	}

	m := &mountManager{root: mountDir, stdout: io.Discard, stderr: io.Discard}
	m.ensureServing([]mount.Entry{{MountPath: mountPath, ProfilePath: profilePath}})

	// Make the serve cycle's recreateFIFO fail: the directory stops being
	// writable, so mkfifo for the replacement pipe gets EACCES.
	if err := os.Chmod(mountDir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(mountDir, 0o700) })

	// A reader that drains the content and then LINGERS (fd held open) is
	// what drives the cycle into the isolation rename that hits the
	// failure — since GAPS.md #47, a reader that closes promptly gets the
	// pipe reused with no recreateFIFO call at all (hasLingeringReader
	// sees this very test process holding the fd — PathHeldOpen
	// deliberately includes its own pid).
	f, err := os.Open(mountPath) // #nosec G304 -- fixture path
	if err != nil {
		t.Fatalf("opening mount: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if _, err := io.ReadAll(f); err != nil {
		t.Fatalf("reading mount: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		n := len(m.served)
		m.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("dead mount still in m.served 5s after its Serve loop exited, it would never be restarted and still look alive to status/reveal (GAPS.md #44)")
}

// TestMountManagerStopMountWaitsForGoroutineToExit is GAPS.md #36's
// regression test for the exact race a real unmount run hit: stopMount
// must not return until the mount's Serve goroutine has actually
// finished, not merely been asked to via cancel(). cancel() alone only
// asks the goroutine to stop at its NEXT chance to check — if a reader
// was already connected, the in-flight cycle still finishes writing and
// calls recreateFIFO (putting a fresh pipe back at the path)
// unconditionally before it ever notices the cancellation. A caller
// (jit unmount) that replaces the file the instant stopMount returns
// can lose that race if stopMount doesn't actually wait — confirmed on
// real hardware: one unmount call raced this way and left an empty,
// unregistered FIFO where the plaintext file should have been.
func TestMountManagerStopMountWaitsForGoroutineToExit(t *testing.T) {
	done := make(chan struct{})
	sm := &servedMount{cancel: func() {}, done: done}
	m := &mountManager{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, served: map[string]*servedMount{"/tmp/fixture/.env": sm}}

	returned := make(chan struct{})
	go func() {
		m.stopMount("/tmp/fixture/.env")
		close(returned)
	}()

	select {
	case <-returned:
		t.Fatal("stopMount returned before the Serve goroutine signaled done, this is the exact race that let recreateFIFO clobber a file jit unmount had just replaced")
	case <-time.After(50 * time.Millisecond):
		// Still blocked, as expected — simulate the goroutine finishing
		// its in-flight cycle now.
	}

	close(done)

	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("stopMount never returned after the goroutine signaled done")
	}
}

// TestServedMountGenGuardDropsResolveRacedByLock pins the fix for the
// "serves real values while locked" race: a resolveReal that captured the
// generation before its decrypt must NOT install real content if a lock
// (invalidateReal) bumped the generation while it was decrypting.
func TestServedMountGenGuardDropsResolveRacedByLock(t *testing.T) {
	sm := &servedMount{}

	// A resolve begins, capturing the generation before its (slow) decrypt.
	gen := sm.captureGen()

	// The session locks mid-decrypt: real is cleared, generation advances.
	if sm.invalidateReal() {
		t.Fatal("invalidateReal reported clearing real content on a mount that had none")
	}

	// The now-stale resolve completes and tries to install its bytes. It must
	// be refused, leaving the mount decoy (real == nil) while locked.
	if sm.setRealIfGen([]byte("SECRET"), gen) {
		t.Fatal("setRealIfGen installed real content despite an intervening lock")
	}
	sm.mu.Lock()
	got := sm.real
	sm.mu.Unlock()
	if got != nil {
		t.Fatalf("real content leaked onto a locked mount: %q", got)
	}

	// A resolve with no intervening lock installs normally.
	if !sm.setRealIfGen([]byte("SECRET"), sm.captureGen()) {
		t.Fatal("setRealIfGen refused a resolve with an unchanged generation")
	}
	sm.mu.Lock()
	got = sm.real
	sm.mu.Unlock()
	if string(got) != "SECRET" {
		t.Fatalf("real = %q, want SECRET", got)
	}

	// And a later lock clears it and reports it did.
	if !sm.invalidateReal() {
		t.Fatal("invalidateReal should report clearing the real content just installed")
	}
}

// TestMountSkipLogsOnTransitionOnly pins the incident's log-storm fix at the
// source: a mount that fails the same way on every unlock logs ONCE, a
// changed reason logs once more, and the recovery line carries how many
// attempts the suppression absorbed. The steady state stays observable
// through lastResolveErr on the status surfaces, not through repetition.
func TestMountSkipLogsOnTransitionOnly(t *testing.T) {
	var errBuf, outBuf bytes.Buffer
	m := &mountManager{stdout: &outBuf, stderr: &errBuf}

	for i := 0; i < 50; i++ {
		m.logMountSkip("/tmp/a.env", errors.New("no such file or directory"))
	}
	if got := strings.Count(errBuf.String(), "skipped,"); got != 1 {
		t.Fatalf("50 identical failures logged %d lines, want 1:\n%s", got, errBuf.String())
	}

	m.logMountSkip("/tmp/a.env", errors.New("envelope version 4, newer than this jit understands"))
	if got := strings.Count(errBuf.String(), "skipped,"); got != 2 {
		t.Fatalf("a CHANGED reason must log, got %d lines:\n%s", got, errBuf.String())
	}

	m.logMountRecovered("/tmp/a.env")
	if !strings.Contains(outBuf.String(), "recovered, serving again (51 skipped attempts before this)") {
		t.Errorf("recovery must carry the absorbed attempts (49 suppressed + 2 logged), got:\n%s", outBuf.String())
	}

	// A mount that was never failing recovers silently — this is every
	// ordinary resolve, and it must not add a line per unlock.
	outBuf.Reset()
	m.logMountRecovered("/tmp/b.env")
	if outBuf.Len() != 0 {
		t.Errorf("an ordinary resolve must not log a recovery, got: %s", outBuf.String())
	}
}
