// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"bytes"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/agent"
)

// newGrantTestManager is a mountManager with the grant gate's kernel
// lookups faked and the kqueue exit watcher disabled (grantKq = -1, the
// same "permanently unavailable" state a real Kqueue() failure leaves —
// pruneStaleRuns' liveness check is the correctness path either way).
// Defaults describe the happy path: one live target (pid 100, start stamp
// 1000), holders all in-tree; individual tests override what they exercise.
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
		pid: pid, startMicro: startMicro, mode: attachGrant,
		mounts: []string{path}, since: time.Now(), hardCap: time.Now().Add(runHardCap),
	}
	m.runsMu.Unlock()
	atomic.AddInt32(&m.grantModeRuns, 1)
}

func TestGrantForPIDRegistersAttachment(t *testing.T) {
	sm := newTestServedMount()
	m := newGrantTestManager(sm)

	if err := m.grantForPID([]string{"/tmp/fixture/.env"}, 100); err != nil {
		t.Fatalf("grantForPID: %v", err)
	}
	m.runsMu.Lock()
	defer m.runsMu.Unlock()
	att, ok := m.runs[100]
	if !ok {
		t.Fatal("no run attachment registered for pid 100")
	}
	if att.mode != attachGrant || att.startMicro != 1000 || len(att.mounts) != 1 {
		t.Errorf("attachment = %+v, want a grant for start 1000 on one mount", att)
	}
	if atomic.LoadInt32(&m.grantModeRuns) != 1 {
		t.Errorf("grantModeRuns = %d, want 1", m.grantModeRuns)
	}
}

// TestGrantForPIDRefusedWithNothingRealToServe mirrors revealMount's
// GAPS.md #46 honesty rule: a grant that could only ever authorize decoys
// must be refused, with the resolve error carried in the refusal.
func TestGrantForPIDRefusedWithNothingRealToServe(t *testing.T) {
	sm := newTestServedMount()
	sm.real = nil
	sm.lastResolveErr = "resolving API_KEY (fixture/MISSING): secret not found"
	m := newGrantTestManager(sm)

	err := m.grantForPID([]string{"/tmp/fixture/.env"}, 100)
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

	if err := m.grantForPID([]string{"/tmp/fixture/other.env"}, 100); err == nil {
		t.Error("expected an error for an unserved mount path")
	}
	if err := m.grantForPID([]string{"/tmp/fixture/.env"}, 999); err == nil {
		t.Error("expected an error for a target pid the kernel can't see")
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

// TestServeContentRevealWindowStillWins: an active reveal window serves real
// exactly as before grants existed, and the record must NOT claim a grant.
func TestServeContentRevealWindowStillWins(t *testing.T) {
	sm := newTestServedMount()
	sm.decoy = []byte("decoy")
	m := newGrantTestManager(sm)
	installGrant(m, "/tmp/fixture/.env", 100, 1000)
	m.grantHoldersFn = func(string) ([]int32, bool) { return []int32{666}, true } // stranger, irrelevant under a window
	m.grantAncestryFn = func(int32, int32) bool { return false }
	sm.reveal.Reveal(time.Minute)

	if got := m.serveContent("/tmp/fixture/.env", sm); string(got) != "API_KEY=real\n" {
		t.Fatalf("serveContent = %q, want real under an active reveal window", got)
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sm.lastServe == nil || sm.lastServe.grantServed {
		t.Errorf("lastServe = %+v, want grantServed=false for a window-authorized serve", sm.lastServe)
	}
}

// TestServeContentNoGrantsTakesFastPath: with no grant runs anywhere, the
// gate is skipped entirely (grantModeRuns==0) and the decision is a pure
// reveal-window one.
func TestServeContentNoGrantsTakesFastPath(t *testing.T) {
	sm := newTestServedMount()
	sm.decoy = []byte("decoy")
	m := newGrantTestManager(sm)
	m.grantHoldersFn = func(string) ([]int32, bool) {
		t.Fatal("holder scan ran with no grant runs — fast path was not taken")
		return nil, false
	}
	if got := m.serveContent("/tmp/fixture/.env", sm); string(got) != "decoy" {
		t.Errorf("serveContent = %q, want decoy (hidden, no grant)", got)
	}
	sm.reveal.Reveal(time.Minute)
	if got := m.serveContent("/tmp/fixture/.env", sm); string(got) != "API_KEY=real\n" {
		t.Errorf("serveContent = %q, want real (revealed, no grant)", got)
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

	m.onRunExit(100, "process exited")

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
	if !strings.Contains(s, "real values (run-scoped grant)") {
		t.Errorf("output missing the grant-served read qualifier: %q", s)
	}
}
