// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"fmt"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jitpass/jit/internal/lineage"
)

// This file is the UNIFIED RUN ENGINE: one registry of "a jit run is
// attached to some mounts until it exits", covering both ways jit run makes
// a mount usable during a run —
//
//   - grant (jit run --live): the FIFO stays and this run's process tree is
//     served real content per read, gated by ancestry (the gate lives in
//     mountgrants.go). For file-value tools like docker compose env_file.
//   - swap (jit run default): the FIFO is replaced by an inert
//     compatibility pointer file for the run, so regular-file guards pass
//     and re-reads set nothing (the swap mechanics live in mountswap.go).
//
// The two modes differ in what a mount IS during the run, but share ONE
// lifecycle: registered on jit run, torn down when the run's pid exits
// (NOTE_EXIT), the session locks, the pid is recycled, or a hard cap
// elapses. Before this engine, grant and swap each had their own
// near-duplicate teardown/prune/status/watcher; here every one of those is
// a single function that switches on mode. A mount's authorization state
// (grant) is sourced from this registry by the read gate; a mount's
// physical state (swap) is driven from here too — one owner, not two.
//
// Locking: runsMu guards the registry and is taken briefly (never held
// across a blocking call). The read gate takes it only when grantModeRuns
// > 0 (an atomic fast-path: with no grant runs, a read pays nothing). Swap
// filesystem transitions are serialized by swapMu (mountmanager.go),
// which the read path never touches, so a swap-in holding swapMu across
// stopMount can't deadlock an in-flight serve cycle.

// runHardCap bounds an attachment's lifetime even if every teardown signal
// is missed (kqueue registration failed AND nothing ever reads the mount):
// a run that genuinely needs longer re-attaches on its next jit run.
const runHardCap = 4 * time.Hour

type attachMode int

const (
	attachGrant attachMode = iota
	attachSwap
)

func (r attachMode) String() string {
	if r == attachSwap {
		return "swap"
	}
	return "grant"
}

// runAttachment is one jit run attached to a set of mounts in one mode.
// startMicro is the target's fork-time stamp, recorded while jit run was
// provably alive (mid-RPC) and re-checked before every use — stable across
// execve (spike-verified), so a recycled pid can never inherit a dead run's
// attachment. command is kernel-derived (never caller-reported), matching
// SessionEvent.By's convention.
type runAttachment struct {
	pid        int32
	startMicro int64
	command    string
	mode       attachMode
	mounts     []string
	since      time.Time
	hardCap    time.Time
}

// revealForPID is OnRevealPID's handler (the agent RPC jit run sends right
// before execve), dispatching on the mode jit run asked for: swap replaces
// each mount with a compatibility pointer file (the default — swapForPID in
// mountswap.go), grant keeps the FIFO and gates reads by process tree (jit
// run --live — grantForPID in mountgrants.go). Both register into the one
// run registry and share this file's teardown.
func (m *mountManager) revealForPID(mountPaths []string, pid int32, swap bool) error {
	if swap {
		return m.swapForPID(mountPaths, pid)
	}
	return m.grantForPID(mountPaths, pid)
}

// newRunAttachment resolves the kernel facts an attachment needs. ok is
// false when the target pid can't be seen (already gone) — the caller turns
// that into the RPC's own failure.
func (m *mountManager) newRunAttachment(pid int32, mode attachMode) (*runAttachment, bool) {
	startMicro, ok := m.grantStart(pid)
	if !ok {
		return nil, false
	}
	command := ""
	if p, ok := lineage.Describe(pid); ok {
		command = p.Command()
	}
	now := time.Now()
	return &runAttachment{pid: pid, startMicro: startMicro, command: command, mode: mode, since: now, hardCap: now.Add(runHardCap)}, true
}

// registerRun records att in the registry (replacing any prior attachment
// for the same pid) and keeps grantModeRuns — the read path's fast-path
// counter — in step. Returns after arming the exit watcher.
func (m *mountManager) registerRun(att *runAttachment) {
	m.runsMu.Lock()
	if m.runs == nil {
		m.runs = map[int32]*runAttachment{}
	}
	prev := m.runs[att.pid]
	if prev != nil && prev.mode == attachGrant {
		atomic.AddInt32(&m.grantModeRuns, -1)
	}
	if att.mode == attachGrant {
		atomic.AddInt32(&m.grantModeRuns, 1)
	}
	m.runs[att.pid] = att
	m.runsMu.Unlock()
	m.watchRunPID(att.pid)
}

// mountSwapHeldByOther reports whether any run OTHER than exceptPID holds
// path swapped — the refcount check that keeps the FIFO out until the last
// swapping run exits. Caller holds runsMu.
func (m *mountManager) mountSwapHeldByOtherLocked(path string, exceptPID int32) bool {
	for pid, att := range m.runs {
		if pid == exceptPID || att.mode != attachSwap {
			continue
		}
		for _, p := range att.mounts {
			if p == path {
				return true
			}
		}
	}
	return false
}

// onRunExit is the single teardown for a finished (or vanished) run pid,
// shared by the NOTE_EXIT watcher and the already-exited registration
// path: drop the attachment, and for a swap restore the FIFO of every
// mount no other run still holds swapped. Grant teardown is just the
// registry removal — the gate stops authorizing the instant the
// attachment is gone.
func (m *mountManager) onRunExit(pid int32, why string) {
	m.runsMu.Lock()
	att, ok := m.runs[pid]
	if !ok {
		m.runsMu.Unlock()
		return
	}
	delete(m.runs, pid)
	if att.mode == attachGrant {
		atomic.AddInt32(&m.grantModeRuns, -1)
	}
	var toRestore []string
	if att.mode == attachSwap {
		for _, path := range att.mounts {
			if !m.mountSwapHeldByOtherLocked(path, pid) {
				toRestore = append(toRestore, path)
			}
		}
	}
	m.runsMu.Unlock()

	for _, path := range toRestore {
		m.restoreSwappedMount(path, why)
	}
	if att.mode == attachGrant {
		for _, path := range att.mounts {
			fmt.Fprintf(m.stdout, "jit agent: mount %s: run-scoped grant for pid %d ended (%s)\n", path, pid, why)
		}
	}
}

// clearAllRuns tears down every attachment — OnLock's path. A lock means
// the session dropped; grants can't be honored (no real content resolves)
// and a swap left in place past a lock would misreport state, so both end.
// A swapped mount's run keeps working: jit run already injected its env,
// and the restored decoy FIFO is what any later read gets.
func (m *mountManager) clearAllRuns() {
	m.runsMu.Lock()
	grants, swaps := 0, 0
	restore := map[string]bool{}
	for _, att := range m.runs {
		if att.mode == attachSwap {
			swaps++
			for _, p := range att.mounts {
				restore[p] = true
			}
		} else {
			grants++
		}
	}
	m.runs = nil
	atomic.StoreInt32(&m.grantModeRuns, 0)
	m.runsMu.Unlock()

	for path := range restore {
		m.restoreSwappedMount(path, "session locked")
	}
	// Grant verdict caches are per-mount read caches; clear them so a lock
	// leaves nothing that could be consulted before the next attachment.
	m.mu.Lock()
	served := make([]*servedMount, 0, len(m.served))
	for _, sm := range m.served {
		served = append(served, sm)
	}
	m.mu.Unlock()
	for _, sm := range served {
		sm.mu.Lock()
		sm.grantVerdicts = nil
		sm.mu.Unlock()
	}
	if grants > 0 || swaps > 0 {
		fmt.Fprintf(m.stdout, "jit agent: %d grant(s) and %d compatibility swap(s) ended (session locked)\n", grants, swaps)
	}
}

// pruneStaleRuns is the lazy backstop to the event-driven watcher: drop any
// attachment whose target exited, was recycled (fork-time stamp mismatch),
// or outlived the hard cap, restoring swapped FIFOs as onRunExit would.
// Runs on status reads, so teardown holds even if kqueue never fired.
func (m *mountManager) pruneStaleRuns() {
	now := time.Now()
	m.runsMu.Lock()
	var deadPIDs []int32
	for pid, att := range m.runs {
		start, ok := m.grantStart(pid)
		dead := now.After(att.hardCap) || !ok || start != att.startMicro
		if dead {
			deadPIDs = append(deadPIDs, pid)
		}
	}
	m.runsMu.Unlock()
	for _, pid := range deadPIDs {
		m.onRunExit(pid, "run gone")
	}
}

// runHolders is one attachment's status projection.
type runHolder struct {
	pid     int32
	command string
	since   time.Time
	mode    attachMode
}

// runStatusesByPath projects the registry into per-mount holders for
// status rendering, pruning stale attachments first so status never shows
// a run that already exited.
func (m *mountManager) runStatusesByPath() map[string][]runHolder {
	m.pruneStaleRuns()
	m.runsMu.Lock()
	defer m.runsMu.Unlock()
	out := map[string][]runHolder{}
	for pid, att := range m.runs {
		for _, path := range att.mounts {
			out[path] = append(out[path], runHolder{pid: pid, command: att.command, since: att.since, mode: att.mode})
		}
	}
	return out
}

// grantRootsForPath returns the live grant-mode roots covering path (pid +
// its recorded start stamp), pruning any that died — the read gate's view
// of the registry. Caller must NOT hold runsMu.
func (m *mountManager) grantRootsForPath(path string) []int32 {
	now := time.Now()
	m.runsMu.Lock()
	var roots []int32
	var deadPIDs []int32
	for pid, att := range m.runs {
		if att.mode != attachGrant {
			continue
		}
		covers := false
		for _, p := range att.mounts {
			if p == path {
				covers = true
				break
			}
		}
		if !covers {
			continue
		}
		start, ok := m.grantStart(pid)
		if now.After(att.hardCap) || !ok || start != att.startMicro {
			deadPIDs = append(deadPIDs, pid)
			continue
		}
		roots = append(roots, pid)
	}
	m.runsMu.Unlock()
	for _, pid := range deadPIDs {
		m.onRunExit(pid, "run gone")
	}
	return roots
}

// watchRunPID arms the event-driven half of teardown: a kqueue
// EVFILT_PROC/NOTE_EXIT watch on the target (spike-verified to survive
// execve and fire ~1ms after exit). Purely an optimization for promptness
// and log clarity — pruneStaleRuns' per-status liveness check is what
// teardown CORRECTNESS rests on — so every failure here degrades to that
// lazy path instead of failing the attachment.
func (m *mountManager) watchRunPID(pid int32) {
	m.watchMu.Lock()
	defer m.watchMu.Unlock()
	if m.grantWatched == nil {
		m.grantWatched = map[int32]bool{}
	}
	if m.grantWatched[pid] {
		return
	}
	if m.grantKq == 0 {
		kq, err := unix.Kqueue()
		if err != nil {
			fmt.Fprintf(m.stderr, "jit agent: run exit watcher unavailable (%v), relying on per-status liveness checks\n", err)
			m.grantKq = -1
		} else {
			m.grantKq = kq
			// Daemon-lifetime goroutine, deliberately NOT in m.wg:
			// shutdown()'s wg.Wait exists so no in-flight FILESYSTEM write
			// races process teardown, and this goroutine never touches the
			// filesystem — it dies with the process.
			go m.runWatchLoop(kq)
		}
	}
	if m.grantKq < 0 {
		return
	}
	ev := unix.Kevent_t{
		Ident:  uint64(pid),
		Filter: unix.EVFILT_PROC,
		Flags:  unix.EV_ADD | unix.EV_ENABLE,
		Fflags: unix.NOTE_EXIT,
	}
	if _, err := unix.Kevent(m.grantKq, []unix.Kevent_t{ev}, nil, nil); err != nil {
		// ESRCH: the target exited between attachment and here — the exact
		// race the registration exists to catch, just earlier.
		m.onRunExit(pid, "process already exited")
		return
	}
	m.grantWatched[pid] = true
}

func (m *mountManager) runWatchLoop(kq int) {
	for {
		events := make([]unix.Kevent_t, 8)
		n, err := unix.Kevent(kq, nil, events, nil)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return
		}
		for _, ev := range events[:n] {
			if ev.Filter != unix.EVFILT_PROC || ev.Fflags&unix.NOTE_EXIT == 0 {
				continue
			}
			pid := int32(ev.Ident) // #nosec G115 -- kqueue's Ident carries the pid we registered, always in int32 range
			m.watchMu.Lock()
			delete(m.grantWatched, pid)
			m.watchMu.Unlock()
			m.onRunExit(pid, "process exited")
		}
	}
}
