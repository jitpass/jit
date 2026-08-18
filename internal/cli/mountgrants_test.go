// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/migrate"
)

// fakeReaderConsent is a stand-in for the agent's best-effort consent decision
// (readerConsent), so serveContent's consent fallback can be exercised without
// a real agent, engine, or Touch ID.
type fakeReaderConsent struct {
	allow bool
	calls int
}

func (f *fakeReaderConsent) ConsentReaders(cred string, holders []int32) bool {
	f.calls++
	return f.allow
}

// newGrantTestManager is a mountManager with the grant gate's kernel
// lookups faked and the kqueue exit watcher disabled (grantKq = -1, the
// same "permanently unavailable" state a real Kqueue() failure leaves —
// pruneStaleRuns' liveness check is the correctness path either way).
// Defaults describe the happy path: one live target (pid 100, start stamp
// 1000), holders all in-tree; individual tests override what they exercise.

// runMountsGrant/runMountsSwap build a RunMount list of one mode for the
// revealForPID calls (which now carry per-mount modes).
func runMountsGrant(paths ...string) []agent.RunMount {
	out := make([]agent.RunMount, len(paths))
	for i, p := range paths {
		out[i] = agent.RunMount{Path: p, Mode: agent.MountModeGrant}
	}
	return out
}

func runMountsSwap(paths ...string) []agent.RunMount {
	out := make([]agent.RunMount, len(paths))
	for i, p := range paths {
		out[i] = agent.RunMount{Path: p, Mode: agent.MountModeSwap}
	}
	return out
}

func newGrantTestManager(sm *servedMount) *mountManager {
	m := &mountManager{
		stdout:  &bytes.Buffer{},
		stderr:  &bytes.Buffer{},
		served:  map[string]*servedMount{"/tmp/fixture/.env": sm},
		grantKq: -1,
		grantHoldersFn: func(string) ([]int32, bool) {
			return []int32{200}, true
		},
		grantAncestryFn: func(pid, root int32) bool {
			return root == 100 // pid 200 (and any other holder) is in pid 100's tree
		},
		grantStartFn: func(pid int32) (int64, bool) {
			if pid == 100 {
				return 1000, true
			}
			return 0, false
		},
	}
	return m
}

// installGrant registers a grant attachment for pid covering path directly
// in the registry — the same state grantForPID would leave, without needing
// a real served mount with resolved content.
func installGrant(m *mountManager, path string, pid int32, startMicro int64) {
	m.runsMu.Lock()
	if m.runs == nil {
		m.runs = map[int32]*runAttachment{}
	}
	m.runs[pid] = &runAttachment{
		pid: pid, startMicro: startMicro,
		mounts: []attachedMount{{path: path, mode: attachGrant}}, since: time.Now(), hardCap: time.Now().Add(runHardCap),
	}
	m.runsMu.Unlock()
	atomic.AddInt32(&m.grantModeRuns, 1)
}

func TestGrantForPIDRegistersAttachment(t *testing.T) {
	sm := newTestServedMount()
	m := newGrantTestManager(sm)

	if err := m.revealForPID(runMountsGrant("/tmp/fixture/.env"), 100); err != nil {
		t.Fatalf("grantForPID: %v", err)
	}
	m.runsMu.Lock()
	defer m.runsMu.Unlock()
	att, ok := m.runs[100]
	if !ok {
		t.Fatal("no run attachment registered for pid 100")
	}
	if att.startMicro != 1000 || len(att.mounts) != 1 || att.mounts[0].mode != attachGrant {
		t.Errorf("attachment = %+v, want a grant for start 1000 on one mount", att)
	}
	if atomic.LoadInt32(&m.grantModeRuns) != 1 {
		t.Errorf("grantModeRuns = %d, want 1", m.grantModeRuns)
	}
}

// TestGrantForPIDRefusedWithNothingRealToServe applies the GAPS.md #46
// honesty rule: a grant that could only ever authorize decoys must be
// refused, with the resolve error carried in the refusal.
func TestGrantForPIDRefusedWithNothingRealToServe(t *testing.T) {
	sm := newTestServedMount()
	sm.real = nil
	sm.lastResolveErr = "resolving API_KEY (fixture/MISSING): secret not found"
	m := newGrantTestManager(sm)

	err := m.revealForPID(runMountsGrant("/tmp/fixture/.env"), 100)
	if err == nil {
		t.Fatal("expected an error granting on a mount with nothing real to serve")
	}
	if !strings.Contains(err.Error(), "secret not found") {
		t.Errorf("error %q should carry the recorded resolve failure", err)
	}
	m.runsMu.Lock()
	defer m.runsMu.Unlock()
	if len(m.runs) != 0 {
		t.Errorf("runs = %d, want 0 after refusal", len(m.runs))
	}
}

func TestGrantForPIDUnknownMountAndDeadTargetFail(t *testing.T) {
	sm := newTestServedMount()
	m := newGrantTestManager(sm)

	if err := m.revealForPID(runMountsGrant("/tmp/fixture/other.env"), 100); err == nil {
		t.Error("expected an error for an unserved mount path")
	}
	if err := m.revealForPID(runMountsGrant("/tmp/fixture/.env"), 999); err == nil {
		t.Error("expected an error for a target pid the kernel can't see")
	}
}

// TestServeContentConsentFallback pins phase 2: with no run-scoped grant, a
// credential mount (gcp) consults best-effort consent — real on allow, decoy
// on deny — while a project mount is never consent-gated and consent-off keeps
// the pre-consent decoy behavior.
func TestServeContentConsentFallback(t *testing.T) {
	home := t.TempDir()
	gcpPath := migrate.GCPADCPath(home)
	sm := newTestServedMount() // real = "API_KEY=real\n"
	sm.decoy = []byte("decoy")

	m := &mountManager{
		home:           home,
		stdout:         &bytes.Buffer{},
		stderr:         &bytes.Buffer{},
		grantKq:        -1,
		grantHoldersFn: func(string) ([]int32, bool) { return []int32{200}, true },
	}

	// Credential mount + consent allows -> real.
	m.consent = &fakeReaderConsent{allow: true}
	if got := m.serveContent(gcpPath, sm); string(got) != "API_KEY=real\n" {
		t.Errorf("consent allow: serveContent = %q, want real", got)
	}

	// Credential mount + consent denies -> decoy (fail closed). Clear the
	// per-mount consent verdict first: the amortization cache would otherwise
	// (correctly) reuse the allow decision above for this same holder set — the
	// test flips the decider mid-session only to exercise both branches.
	sm.mu.Lock()
	sm.consentVerdict = nil
	sm.mu.Unlock()
	m.consent = &fakeReaderConsent{allow: false}
	if got := m.serveContent(gcpPath, sm); string(got) != "decoy" {
		t.Errorf("consent deny: serveContent = %q, want decoy", got)
	}

	// Consent off (nil) -> decoy, exactly the pre-consent behavior.
	m.consent = nil
	if got := m.serveContent(gcpPath, sm); string(got) != "decoy" {
		t.Errorf("consent off: serveContent = %q, want decoy", got)
	}

	// A non-credential (project) mount is never consent-gated, even when the
	// decider would allow.
	m.consent = &fakeReaderConsent{allow: true}
	if got := m.serveContent("/tmp/fixture/.env", sm); string(got) != "decoy" {
		t.Errorf("project mount must not be consent-gated: serveContent = %q, want decoy", got)
	}
}

// TestServeContentConsentAmortized pins that repeated reads by the SAME holder
// set consult the decider once (the per-mount verdict cache), while a CHANGED
// holder set re-decides — the fail-safe part: a new set can't ride the cache.
func TestServeContentConsentAmortized(t *testing.T) {
	home := t.TempDir()
	gcpPath := migrate.GCPADCPath(home)
	sm := newTestServedMount()
	sm.decoy = []byte("decoy")

	holders := []int32{200}
	fake := &fakeReaderConsent{allow: true}
	m := &mountManager{
		home:           home,
		stdout:         &bytes.Buffer{},
		stderr:         &bytes.Buffer{},
		grantKq:        -1,
		consent:        fake,
		grantHoldersFn: func(string) ([]int32, bool) { return holders, true },
	}

	for i := 0; i < 5; i++ {
		if got := m.serveContent(gcpPath, sm); string(got) != "API_KEY=real\n" {
			t.Fatalf("read %d: serveContent = %q, want real", i, got)
		}
	}
	if fake.calls != 1 {
		t.Errorf("same holder set over 5 reads consulted the decider %d times, want 1 (amortized)", fake.calls)
	}

	// A changed holder set must not ride the cached verdict: it re-decides.
	holders = []int32{200, 300}
	if got := m.serveContent(gcpPath, sm); string(got) != "API_KEY=real\n" {
		t.Fatalf("changed holder set: serveContent = %q, want real", got)
	}
	if fake.calls != 2 {
		t.Errorf("a changed holder set consulted the decider %d times total, want 2 (cache missed as it must)", fake.calls)
	}
}

func TestServeContentServesRealToInTreeHolders(t *testing.T) {
	sm := newTestServedMount()
	sm.decoy = []byte("decoy")
	m := newGrantTestManager(sm)
	installGrant(m, "/tmp/fixture/.env", 100, 1000)

	if got := m.serveContent("/tmp/fixture/.env", sm); string(got) != "API_KEY=real\n" {
		t.Fatalf("serveContent = %q, want real content for an all-in-tree holder set", got)
	}
	m.finalizeServe("/tmp/fixture/.env", sm, true)
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sm.lastServe == nil || !sm.lastServe.grantServed || sm.lastServe.decoy {
		t.Errorf("lastServe = %+v, want a grant-served real record", sm.lastServe)
	}
}

func TestServeContentFailsClosedOnStrangerHolder(t *testing.T) {
	sm := newTestServedMount()
	sm.decoy = []byte("decoy")
	m := newGrantTestManager(sm)
	installGrant(m, "/tmp/fixture/.env", 100, 1000)
	// Two holders at one rendezvous: one in-tree (200), one stranger (666).
	m.grantHoldersFn = func(string) ([]int32, bool) { return []int32{200, 666}, true }
	m.grantAncestryFn = func(pid, root int32) bool { return pid == 200 && root == 100 }

	if got := m.serveContent("/tmp/fixture/.env", sm); string(got) != "decoy" {
		t.Fatalf("serveContent = %q, want decoy when any holder is out-of-tree", got)
	}
	m.finalizeServe("/tmp/fixture/.env", sm, true)
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sm.lastServe == nil || !sm.lastServe.decoy || sm.lastServe.grantServed {
		t.Errorf("lastServe = %+v, want a decoy record", sm.lastServe)
	}
}

func TestServeContentFailsClosedOnScanUncertaintyAndZeroHolders(t *testing.T) {
	sm := newTestServedMount()
	sm.decoy = []byte("decoy")
	m := newGrantTestManager(sm)
	installGrant(m, "/tmp/fixture/.env", 100, 1000)

	m.grantHoldersFn = func(string) ([]int32, bool) { return []int32{200}, false } // truncated scan
	if got := m.serveContent("/tmp/fixture/.env", sm); string(got) != "decoy" {
		t.Errorf("serveContent = %q, want decoy on an untrustworthy holder scan", got)
	}

	m.grantHoldersFn = func(string) ([]int32, bool) { return nil, true } // nobody attached
	if got := m.serveContent("/tmp/fixture/.env", sm); string(got) != "decoy" {
		t.Errorf("serveContent = %q, want decoy with zero enumerable holders", got)
	}
}

// TestServeContentPrunesDeadAndRecycledTargets: a grant whose target exited
// or whose pid now belongs to a different process (stamp mismatch) must be
// dropped at the gate, serving decoys.
func TestServeContentPrunesDeadAndRecycledTargets(t *testing.T) {
	sm := newTestServedMount()
	sm.decoy = []byte("decoy")
	m := newGrantTestManager(sm)

	installGrant(m, "/tmp/fixture/.env", 100, 1000)
	m.grantStartFn = func(int32) (int64, bool) { return 0, false } // exited
	if got := m.serveContent("/tmp/fixture/.env", sm); string(got) != "decoy" {
		t.Errorf("serveContent = %q, want decoy after target exit", got)
	}
	m.runsMu.Lock()
	remaining := len(m.runs)
	m.runsMu.Unlock()
	if remaining != 0 {
		t.Errorf("runs = %d, want 0 after prune", remaining)
	}

	installGrant(m, "/tmp/fixture/.env", 100, 1000)
	m.grantStartFn = func(int32) (int64, bool) { return 2222, true } // recycled pid
	if got := m.serveContent("/tmp/fixture/.env", sm); string(got) != "decoy" {
		t.Errorf("serveContent = %q, want decoy for a recycled target pid", got)
	}
}

func TestServeContentEnforcesHardCap(t *testing.T) {
	sm := newTestServedMount()
	sm.decoy = []byte("decoy")
	m := newGrantTestManager(sm)
	installGrant(m, "/tmp/fixture/.env", 100, 1000)
	m.runsMu.Lock()
	m.runs[100].hardCap = time.Now().Add(-time.Second)
	m.runsMu.Unlock()

	if got := m.serveContent("/tmp/fixture/.env", sm); string(got) != "decoy" {
		t.Errorf("serveContent = %q, want decoy past the hard cap", got)
	}
}

// TestServeContentNoGrantsTakesFastPath: with no grant runs anywhere, the
// gate is skipped entirely (grantModeRuns==0) and every read is decoy —
// real content flows only through a grant, never on its own.
func TestServeContentNoGrantsTakesFastPath(t *testing.T) {
	sm := newTestServedMount()
	sm.decoy = []byte("decoy")
	m := newGrantTestManager(sm)
	m.grantHoldersFn = func(string) ([]int32, bool) {
		t.Fatal("holder scan ran with no grant runs — fast path was not taken")
		return nil, false
	}
	if got := m.serveContent("/tmp/fixture/.env", sm); string(got) != "decoy" {
		t.Errorf("serveContent = %q, want decoy (no grant active)", got)
	}
}

// TestServeContentVerdictCacheAmortizesAncestryWalks: within grantVerdictTTL,
// repeated reads by the same holder must not re-walk its ancestry.
func TestServeContentVerdictCacheAmortizesAncestryWalks(t *testing.T) {
	sm := newTestServedMount()
	m := newGrantTestManager(sm)
	installGrant(m, "/tmp/fixture/.env", 100, 1000)
	var walks int32
	m.grantAncestryFn = func(pid, root int32) bool {
		atomic.AddInt32(&walks, 1)
		return true
	}

	for i := 0; i < 10; i++ {
		if got := m.serveContent("/tmp/fixture/.env", sm); string(got) != "API_KEY=real\n" {
			t.Fatalf("read %d: serveContent = %q, want real", i, got)
		}
	}
	if got := atomic.LoadInt32(&walks); got != 1 {
		t.Errorf("ancestry walks = %d for 10 reads inside the TTL, want 1", got)
	}
}

func TestOnRunExitDropsOnlyThatPID(t *testing.T) {
	sm := newTestServedMount()
	m := newGrantTestManager(sm)
	installGrant(m, "/tmp/fixture/.env", 100, 1000)
	m.grantStartFn = func(pid int32) (int64, bool) { return 1000, true } // both live
	installGrant(m, "/tmp/fixture/.env", 101, 1000)

	m.onRunExit(100, "process exited", false)

	m.runsMu.Lock()
	defer m.runsMu.Unlock()
	if _, ok := m.runs[100]; ok {
		t.Error("pid 100's attachment survived onRunExit")
	}
	if _, ok := m.runs[101]; !ok {
		t.Error("pid 101's attachment was wrongly dropped")
	}
	if atomic.LoadInt32(&m.grantModeRuns) != 1 {
		t.Errorf("grantModeRuns = %d, want 1 after one of two grants ended", m.grantModeRuns)
	}
}

func TestClearAllRunsDropsGrantsAndClearsCache(t *testing.T) {
	sm := newTestServedMount()
	sm.grantVerdicts = map[grantVerdictKey]grantVerdict{{holder: 200, root: 100}: {inTree: true, expires: time.Now().Add(time.Hour)}}
	m := newGrantTestManager(sm)
	installGrant(m, "/tmp/fixture/.env", 100, 1000)

	m.clearAllRuns()

	m.runsMu.Lock()
	nRuns := len(m.runs)
	m.runsMu.Unlock()
	sm.mu.Lock()
	verdicts := sm.grantVerdicts
	sm.mu.Unlock()
	if nRuns != 0 || verdicts != nil || atomic.LoadInt32(&m.grantModeRuns) != 0 {
		t.Errorf("after clearAllRuns: runs=%d verdicts=%v grantModeRuns=%d, want all cleared", nRuns, verdicts, m.grantModeRuns)
	}
}

func TestMountRevealStatusesReportsGrant(t *testing.T) {
	sm := newTestServedMount()
	sm.decoy = []byte("decoy")
	m := newGrantTestManager(sm)
	installGrant(m, "/tmp/fixture/.env", 100, 1000)
	m.runsMu.Lock()
	m.runs[100].command = "./run_all_exports.sh"
	m.runsMu.Unlock()

	// One grant-served read on record.
	if got := m.serveContent("/tmp/fixture/.env", sm); string(got) != "API_KEY=real\n" {
		t.Fatalf("setup: serveContent = %q, want real", got)
	}
	m.finalizeServe("/tmp/fixture/.env", sm, true)

	statuses := m.mountRevealStatuses()
	if len(statuses) != 1 {
		t.Fatalf("statuses = %d, want 1", len(statuses))
	}
	st := statuses[0]
	if len(st.Grants) != 1 || st.Grants[0].PID != 100 || st.Grants[0].Command != "./run_all_exports.sh" {
		t.Errorf("Grants = %+v, want pid 100 with its command", st.Grants)
	}
	if st.Swapped {
		t.Error("a grant-mode mount must not be reported Swapped")
	}
	if st.LastServe == nil || !st.LastServe.GrantServed || st.LastServe.Decoy {
		t.Errorf("LastServe = %+v, want a grant-served real record", st.LastServe)
	}

	// A dead target must be pruned from status, not reported.
	m.grantStartFn = func(int32) (int64, bool) { return 0, false }
	statuses = m.mountRevealStatuses()
	if len(statuses[0].Grants) != 0 {
		t.Errorf("Grants = %+v after target death, want none reported", statuses[0].Grants)
	}
}

func TestPrintMountStatusesShowsGrants(t *testing.T) {
	var out bytes.Buffer
	printMountStatuses(&out, []agent.MountRevealStatus{{
		Path:   "/tmp/fixture/.env",
		Grants: []agent.MountGrantStatus{{PID: 4242, Command: "./run_all_exports.sh", SinceUnix: time.Now().Add(-30 * time.Second).Unix()}},
		LastServe: &agent.MountServeEvent{
			UnixTime:    time.Now().Unix(),
			Decoy:       false,
			GrantServed: true,
			ReaderPID:   4243,
			ReaderPath:  "/bin/cat",
		},
	}})
	s := out.String()
	if !strings.Contains(s, "serving real values to jit run pid 4242 (./run_all_exports.sh)") {
		t.Errorf("output missing the grant line: %q", s)
	}
	if !strings.Contains(s, "real (run-scoped grant)") {
		t.Errorf("output missing the grant-served read qualifier: %q", s)
	}
}
