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
)

// newGrantTestManager is a mountManager with the grant gate's kernel
// lookups faked and the kqueue exit watcher disabled (grantKq = -1, the
// same "permanently unavailable" state a real Kqueue() failure leaves —
// the gate's per-use liveness check is the correctness path either way).
// Defaults describe the happy path: one live target (pid 100, start stamp
// 1000), holders all in-tree; individual tests override the fields they
// exercise.
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

func grantFor(pid int32, startMicro int64) mountGrant {
	now := time.Now()
	return mountGrant{pid: pid, startMicro: startMicro, since: now, hardCap: now.Add(grantHardCap)}
}

func TestRevealForPIDCreatesGrantOnServedMountWithRealContent(t *testing.T) {
	sm := newTestServedMount()
	m := newGrantTestManager(sm)

	if err := m.revealForPID([]string{"/tmp/fixture/.env"}, 100); err != nil {
		t.Fatalf("revealForPID: %v", err)
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if len(sm.grants) != 1 {
		t.Fatalf("grants = %d, want 1", len(sm.grants))
	}
	if sm.grants[0].pid != 100 || sm.grants[0].startMicro != 1000 {
		t.Errorf("grant = pid %d start %d, want pid 100 start 1000", sm.grants[0].pid, sm.grants[0].startMicro)
	}
}

func TestRevealForPIDReplacesExistingGrantForSamePID(t *testing.T) {
	sm := newTestServedMount()
	sm.grants = []mountGrant{grantFor(100, 555)} // stale stamp from an earlier (hypothetical) run
	m := newGrantTestManager(sm)

	if err := m.revealForPID([]string{"/tmp/fixture/.env"}, 100); err != nil {
		t.Fatalf("revealForPID: %v", err)
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if len(sm.grants) != 1 {
		t.Fatalf("grants = %d, want 1 (replaced, not appended)", len(sm.grants))
	}
	if sm.grants[0].startMicro != 1000 {
		t.Errorf("grant startMicro = %d, want the fresh 1000", sm.grants[0].startMicro)
	}
}

// TestRevealForPIDRefusedWithNothingRealToServe mirrors revealMount's
// GAPS.md #46 honesty rule at the grant level: a grant that could only
// ever authorize decoys must be refused, with the resolve error carried in
// the refusal.
func TestRevealForPIDRefusedWithNothingRealToServe(t *testing.T) {
	sm := newTestServedMount()
	sm.real = nil
	sm.lastResolveErr = "resolving API_KEY (fixture/MISSING): secret not found"
	m := newGrantTestManager(sm)

	err := m.revealForPID([]string{"/tmp/fixture/.env"}, 100)
	if err == nil {
		t.Fatal("expected an error granting on a mount with nothing real to serve")
	}
	if !strings.Contains(err.Error(), "secret not found") {
		t.Errorf("error %q should carry the recorded resolve failure", err)
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if len(sm.grants) != 0 {
		t.Errorf("grants = %d, want 0 after refusal", len(sm.grants))
	}
}

func TestRevealForPIDUnknownMountAndDeadTargetFail(t *testing.T) {
	sm := newTestServedMount()
	m := newGrantTestManager(sm)

	if err := m.revealForPID([]string{"/tmp/fixture/other.env"}, 100); err == nil {
		t.Error("expected an error for an unserved mount path")
	}
	if err := m.revealForPID([]string{"/tmp/fixture/.env"}, 999); err == nil {
		t.Error("expected an error for a target pid the kernel can't see")
	}
}

// TestRevealForPIDPartialGrantSucceeds: one grantable mount plus one
// unknown must create the grant and succeed — jit run sends every merged
// layer, and one broken layer shouldn't strip the working ones of their
// grant (the skipped one is logged agent-side).
func TestRevealForPIDPartialGrantSucceeds(t *testing.T) {
	sm := newTestServedMount()
	m := newGrantTestManager(sm)

	if err := m.revealForPID([]string{"/tmp/fixture/.env", "/tmp/fixture/gone.env"}, 100); err != nil {
		t.Fatalf("revealForPID with one grantable mount: %v", err)
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if len(sm.grants) != 1 {
		t.Errorf("grants = %d, want 1", len(sm.grants))
	}
}

func TestGrantGateServesRealToInTreeHolders(t *testing.T) {
	sm := newTestServedMount()
	sm.decoy = []byte("decoy")
	sm.grants = []mountGrant{grantFor(100, 1000)}
	m := newGrantTestManager(sm)

	if got := m.provideMountContent("/tmp/fixture/.env", sm); string(got) != "API_KEY=real\n" {
		t.Fatalf("provideMountContent = %q, want real content for an all-in-tree holder set", got)
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sm.lastServe == nil || !sm.lastServe.grantServed || sm.lastServe.decoy {
		t.Errorf("lastServe = %+v, want a grant-served real record", sm.lastServe)
	}
}

func TestGrantGateFailsClosedOnStrangerHolder(t *testing.T) {
	sm := newTestServedMount()
	sm.decoy = []byte("decoy")
	sm.grants = []mountGrant{grantFor(100, 1000)}
	m := newGrantTestManager(sm)
	// Two holders attached at one rendezvous: one in-tree (200), one
	// stranger (666) — the spike's mixed-concurrent scenario.
	m.grantHoldersFn = func(string) ([]int32, bool) { return []int32{200, 666}, true }
	m.grantAncestryFn = func(pid, root int32) bool { return pid == 200 && root == 100 }

	if got := m.provideMountContent("/tmp/fixture/.env", sm); string(got) != "decoy" {
		t.Fatalf("provideMountContent = %q, want decoy when any holder is out-of-tree", got)
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sm.lastServe == nil || !sm.lastServe.decoy || sm.lastServe.grantServed {
		t.Errorf("lastServe = %+v, want a decoy record", sm.lastServe)
	}
}

func TestGrantGateFailsClosedOnScanUncertaintyAndZeroHolders(t *testing.T) {
	sm := newTestServedMount()
	sm.decoy = []byte("decoy")
	sm.grants = []mountGrant{grantFor(100, 1000)}
	m := newGrantTestManager(sm)

	m.grantHoldersFn = func(string) ([]int32, bool) { return []int32{200}, false } // truncated scan
	if got := m.provideMountContent("/tmp/fixture/.env", sm); string(got) != "decoy" {
		t.Errorf("provideMountContent = %q, want decoy on an untrustworthy holder scan", got)
	}

	m.grantHoldersFn = func(string) ([]int32, bool) { return nil, true } // nobody attached
	if got := m.provideMountContent("/tmp/fixture/.env", sm); string(got) != "decoy" {
		t.Errorf("provideMountContent = %q, want decoy with zero enumerable holders", got)
	}
}

// TestGrantGatePrunesDeadAndRecycledTargets: a grant whose target exited
// (start lookup fails) or whose pid now belongs to a different process
// (stamp mismatch) must be dropped at the gate, serving decoys.
func TestGrantGatePrunesDeadAndRecycledTargets(t *testing.T) {
	sm := newTestServedMount()
	sm.decoy = []byte("decoy")
	m := newGrantTestManager(sm)

	sm.grants = []mountGrant{grantFor(100, 1000)}
	m.grantStartFn = func(int32) (int64, bool) { return 0, false } // exited
	if got := m.provideMountContent("/tmp/fixture/.env", sm); string(got) != "decoy" {
		t.Errorf("provideMountContent = %q, want decoy after target exit", got)
	}
	sm.mu.Lock()
	remaining := len(sm.grants)
	sm.mu.Unlock()
	if remaining != 0 {
		t.Errorf("grants = %d, want 0 after prune", remaining)
	}

	sm.grants = []mountGrant{grantFor(100, 1000)}
	m.grantStartFn = func(int32) (int64, bool) { return 2222, true } // recycled pid
	if got := m.provideMountContent("/tmp/fixture/.env", sm); string(got) != "decoy" {
		t.Errorf("provideMountContent = %q, want decoy for a recycled target pid", got)
	}
}

func TestGrantGateEnforcesHardCap(t *testing.T) {
	sm := newTestServedMount()
	sm.decoy = []byte("decoy")
	g := grantFor(100, 1000)
	g.hardCap = time.Now().Add(-time.Second)
	sm.grants = []mountGrant{g}
	m := newGrantTestManager(sm)

	if got := m.provideMountContent("/tmp/fixture/.env", sm); string(got) != "decoy" {
		t.Errorf("provideMountContent = %q, want decoy past the hard cap", got)
	}
}

// TestGrantGateRevealWindowStillWins: an active reveal window serves real
// exactly as before grants existed, and the record must NOT claim the
// grant did it.
func TestGrantGateRevealWindowStillWins(t *testing.T) {
	sm := newTestServedMount()
	sm.decoy = []byte("decoy")
	sm.grants = []mountGrant{grantFor(100, 1000)}
	m := newGrantTestManager(sm)
	m.grantHoldersFn = func(string) ([]int32, bool) { return []int32{666}, true } // stranger — irrelevant under a window
	m.grantAncestryFn = func(int32, int32) bool { return false }
	sm.reveal.Reveal(time.Minute)

	if got := m.provideMountContent("/tmp/fixture/.env", sm); string(got) != "API_KEY=real\n" {
		t.Fatalf("provideMountContent = %q, want real under an active reveal window", got)
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sm.lastServe == nil || sm.lastServe.grantServed {
		t.Errorf("lastServe = %+v, want grantServed=false for a window-authorized serve", sm.lastServe)
	}
}

// TestGrantVerdictCacheAmortizesAncestryWalks: within grantVerdictTTL,
// repeated reads by the same holder must not re-walk its ancestry — the
// read-storm cost control the gate cannot get from skipping scans.
func TestGrantVerdictCacheAmortizesAncestryWalks(t *testing.T) {
	sm := newTestServedMount()
	sm.grants = []mountGrant{grantFor(100, 1000)}
	m := newGrantTestManager(sm)
	var walks int32
	m.grantAncestryFn = func(pid, root int32) bool {
		atomic.AddInt32(&walks, 1)
		return true
	}

	for i := 0; i < 10; i++ {
		if got := m.provideMountContent("/tmp/fixture/.env", sm); string(got) != "API_KEY=real\n" {
			t.Fatalf("read %d: provideMountContent = %q, want real", i, got)
		}
	}
	if got := atomic.LoadInt32(&walks); got != 1 {
		t.Errorf("ancestry walks = %d for 10 reads inside the TTL, want 1", got)
	}
}

func TestMountManagerStopDropsGrants(t *testing.T) {
	sm := newTestServedMount()
	sm.grants = []mountGrant{grantFor(100, 1000)}
	sm.grantVerdicts = map[grantVerdictKey]grantVerdict{{holder: 200, root: 100}: {inTree: true, expires: time.Now().Add(time.Hour)}}
	m := newGrantTestManager(sm)

	m.stop()

	sm.mu.Lock()
	defer sm.mu.Unlock()
	if len(sm.grants) != 0 || sm.grantVerdicts != nil {
		t.Errorf("grants = %d, verdicts = %v after stop, want both cleared on lock", len(sm.grants), sm.grantVerdicts)
	}
}

func TestDropGrantsForPIDRemovesOnlyThatPID(t *testing.T) {
	sm := newTestServedMount()
	sm.grants = []mountGrant{grantFor(100, 1000), grantFor(101, 2000)}
	m := newGrantTestManager(sm)

	m.dropGrantsForPID(100, "process exited")

	sm.mu.Lock()
	defer sm.mu.Unlock()
	if len(sm.grants) != 1 || sm.grants[0].pid != 101 {
		t.Errorf("grants = %+v, want only pid 101's to survive", sm.grants)
	}
}

func TestMountRevealStatusesReportsGrantsAndGrantServed(t *testing.T) {
	sm := newTestServedMount()
	sm.decoy = []byte("decoy")
	sm.grants = []mountGrant{grantFor(100, 1000)}
	sm.grants[0].command = "./run_all_exports.sh"
	m := newGrantTestManager(sm)

	// One grant-served read on record.
	if got := m.provideMountContent("/tmp/fixture/.env", sm); string(got) != "API_KEY=real\n" {
		t.Fatalf("setup: provideMountContent = %q, want real", got)
	}

	statuses := m.mountRevealStatuses()
	if len(statuses) != 1 {
		t.Fatalf("statuses = %d, want 1", len(statuses))
	}
	st := statuses[0]
	if len(st.Grants) != 1 || st.Grants[0].PID != 100 || st.Grants[0].Command != "./run_all_exports.sh" {
		t.Errorf("Grants = %+v, want pid 100 with its command", st.Grants)
	}
	if st.LastServe == nil || !st.LastServe.GrantServed || st.LastServe.Decoy {
		t.Errorf("LastServe = %+v, want a grant-served real record", st.LastServe)
	}

	// The same snapshot must prune a dead target rather than report it.
	m.grantStartFn = func(int32) (int64, bool) { return 0, false }
	statuses = m.mountRevealStatuses()
	if len(statuses[0].Grants) != 0 {
		t.Errorf("Grants = %+v after target death, want none reported", statuses[0].Grants)
	}
}
