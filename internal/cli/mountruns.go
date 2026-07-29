// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jitpass/jit/internal/agent"
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
// filesystem transitions are serialized by swapMu (mountmanager.go), which
// the serve/read goroutine never takes inline — when the read gate discovers
// a dead run it defers the swapMu-taking FIFO restore to a detached
// goroutine (onRunExit's restoreAsync), so a swap-in holding swapMu across
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

// attachedMount is one mount within a run, with its own mode — a run can
// swap its .env while granting its .npmrc, so mode lives per mount, not per
// run.
type attachedMount struct {
	path string
	mode attachMode
}

// runAttachment is one jit run attached to a set of mounts, each in its own
// mode. startMicro is the target's fork-time stamp, recorded while jit run
// was provably alive (mid-RPC) and re-checked before every use — stable
// across execve (spike-verified), so a recycled pid can never inherit a dead
// run's attachment. command is kernel-derived (never caller-reported),
// matching SessionEvent.By's convention.
type runAttachment struct {
	pid        int32
	startMicro int64
	command    string
	mounts     []attachedMount
	since      time.Time
	hardCap    time.Time
}

// grantMountCount is how many of att's mounts are grant-mode — what
// grantModeRuns (the read path's fast-path counter) is a running sum of.
func (att *runAttachment) grantMountCount() int {
	n := 0
	for _, am := range att.mounts {
		if am.mode == attachGrant {
			n++
		}
	}
	return n
}

// revealForPID is OnRevealPID's handler (the agent RPC jit run sends right
// before execve). It builds ONE attachment covering every mount the run
// asked for, each in its requested mode — swap (compatibility file) or
// grant (keep the FIFO, gate reads by process tree) — so a single run can
// mix modes. Mounts that can't be attached are skipped with a logged
// reason; the RPC fails only when NONE could be attached.
func (m *mountManager) revealForPID(mounts []agent.RunMount, pid int32) error {
	att, ok := m.newRunAttachment(pid)
	if !ok {
		return fmt.Errorf("reveal_pid: target pid %d not found", pid)
	}

	var grantPaths, swapPaths []string
	for _, rm := range mounts {
		switch rm.Mode {
		case agent.MountModeSwap:
			swapPaths = append(swapPaths, rm.Path)
		case agent.MountModeGrant:
			grantPaths = append(grantPaths, rm.Path)
		default:
			fmt.Fprintf(m.stderr, "jit service: reveal_pid: unknown mode %q for %s, skipped\n", rm.Mode, rm.Path)
		}
	}

	var problems []string
	// Grant mounts first — no swapMu needed, they keep their FIFO.
	for _, path := range grantPaths {
		if err := m.validateGrantMount(path); err != nil {
			problems = append(problems, err.Error())
			continue
		}
		att.mounts = append(att.mounts, attachedMount{path: path, mode: attachGrant})
		fmt.Fprintf(m.stdout, "jit service: mount %s: serving real content to pid %d's process tree (%s) until it exits\n", path, pid, att.command)
	}

	// Swap mounts under swapMu, held through registerRun so the
	// check-and-swap refcount stays atomic with registration.
	m.swapMu.Lock()
	for _, path := range swapPaths {
		entry, ok := m.registryEntryForPath(path)
		if !ok {
			problems = append(problems, fmt.Sprintf("no such mount: %s", path))
			continue
		}
		m.runsMu.Lock()
		already := m.mountSwapHeldByOtherLocked(path, pid)
		m.runsMu.Unlock()
		if !already {
			if err := m.performSwapIn(path, entry); err != nil {
				problems = append(problems, fmt.Sprintf("%s: %v", path, err))
				continue
			}
		}
		att.mounts = append(att.mounts, attachedMount{path: path, mode: attachSwap})
		fmt.Fprintf(m.stdout, "jit service: mount %s: swapped to a compatibility file for pid %d's run (%s) until it exits\n", path, pid, att.command)
	}
	for _, p := range problems {
		fmt.Fprintf(m.stderr, "jit service: reveal_pid skipped: %s\n", p)
	}
	if len(att.mounts) == 0 {
		m.swapMu.Unlock()
		return fmt.Errorf("reveal_pid: nothing attached: %s", strings.Join(problems, "; "))
	}
	isNew := m.registerRun(att)
	m.swapMu.Unlock()
	// Arm the exit watcher AFTER releasing swapMu, never under it: if the
	// target already exited, watchRunPID tears the attachment down inline
	// (onRunExit -> restoreSwappedMount, which takes swapMu). Doing that while
	// still holding swapMu re-locked a non-reentrant mutex and hung the RPC
	// goroutine forever, wedging every future swap. The window between
	// registerRun and here is covered by the lazy prune either way.
	if isNew {
		m.watchRunPID(att.pid)
	}
	return nil
}

// newRunAttachment resolves the kernel facts an attachment needs. ok is
// false when the target pid can't be seen (already gone) — the caller turns
// that into the RPC's own failure.
func (m *mountManager) newRunAttachment(pid int32) (*runAttachment, bool) {
	startMicro, ok := m.grantStart(pid)
	if !ok {
		return nil, false
	}
	command := ""
	if p, ok := lineage.Describe(pid); ok {
		command = p.Command()
	}
	now := time.Now()
	return &runAttachment{pid: pid, startMicro: startMicro, command: command, since: now, hardCap: now.Add(runHardCap)}, true
}

// registerRun records att in the registry and keeps grantModeRuns — the read
// path's fast-path counter, a running sum of active grant-mode mounts — in
// step. Returns after arming the exit watcher.
//
// jit run sends a SECOND reveal_pid for the same pid when a run mixes its own
// project mounts with a --with global grant: the project mounts ride the
// run's own unlock, the global grant a separate disclosed challenge, so they
// can't share one RPC. When that second attachment arrives for a pid that is
// provably the same process (matching fork-time stamp), its mounts are MERGED
// into the existing attachment rather than replacing it — replacing would
// orphan the first call's swaps and grants, losing their teardown (a swapped
// .env would never be restored). A stamp mismatch means a recycled pid whose
// prior attachment the watcher/prune will drop, so that case still replaces.
// isNew is true when this call created a fresh registration the caller must
// arm the exit watcher for (done OUTSIDE swapMu, see revealForPID); false on
// a merge into an existing same-pid attachment, whose watcher is already
// armed.
func (m *mountManager) registerRun(att *runAttachment) (isNew bool) {
	m.runsMu.Lock()
	if m.runs == nil {
		m.runs = map[int32]*runAttachment{}
	}
	if prev := m.runs[att.pid]; prev != nil {
		if prev.startMicro == att.startMicro {
			prev.mounts = append(prev.mounts, att.mounts...)
			atomic.AddInt32(&m.grantModeRuns, int32(att.grantMountCount())) // #nosec G115 -- a run's grant-mount count is a tiny non-negative int, always in int32 range
			m.runsMu.Unlock()
			return false // merged; watcher already armed by the first registration
		}
		atomic.AddInt32(&m.grantModeRuns, int32(-prev.grantMountCount())) // #nosec G115 -- a run's grant-mount count is a tiny int, always in int32 range
	}
	atomic.AddInt32(&m.grantModeRuns, int32(att.grantMountCount())) // #nosec G115 -- a run's grant-mount count is a tiny non-negative int, always in int32 range
	m.runs[att.pid] = att
	m.runsMu.Unlock()
	return true
}

// mountSwapHeldByOtherLocked reports whether any run OTHER than exceptPID
// holds path swapped — the refcount check that keeps the FIFO out until the
// last swapping run exits. Caller holds runsMu.
func (m *mountManager) mountSwapHeldByOtherLocked(path string, exceptPID int32) bool {
	for pid, att := range m.runs {
		if pid == exceptPID {
			continue
		}
		for _, am := range att.mounts {
			if am.mode == attachSwap && am.path == path {
				return true
			}
		}
	}
	return false
}

// mountSwapHeldByAnyLocked reports whether ANY currently-registered run holds
// path swapped — restoreSwappedMount's authoritative re-check under swapMu
// that no run re-claimed the path after teardown decided to restore it (the
// exiting run is already deleted from the registry by then, so "any" is the
// right question, not "any other"). Caller holds runsMu.
func (m *mountManager) mountSwapHeldByAnyLocked(path string) bool {
	for _, att := range m.runs {
		for _, am := range att.mounts {
			if am.mode == attachSwap && am.path == path {
				return true
			}
		}
	}
	return false
}

// onRunExit is the single teardown for a finished (or vanished) run pid,
// shared by the NOTE_EXIT watcher and the already-exited registration
// path: drop the attachment, restore the FIFO of every swap-mount no other
// run still holds swapped, and log every grant-mount ending. Grant teardown
// is just the registry removal — the gate stops authorizing the instant the
// attachment is gone.
// restoreAsync controls whether the swap-mount FIFO restores run on this
// goroutine or a detached one. The read gate (grantRootsForPath) and the
// status prune (pruneStaleRuns) MUST pass true: restoreSwappedMount takes
// swapMu, and taking it on the serve/read path deadlocks against a
// concurrent performSwapIn that holds swapMu while blocked on that same serve
// cycle's sm.done. The kqueue watch loop and the already-exited registration
// path hold no locks, so they restore inline (false) for prompt teardown.
// Grant deregistration (the registry delete above) is always synchronous, so
// the gate stops authorizing the instant this returns regardless.
func (m *mountManager) onRunExit(pid int32, why string, restoreAsync bool) {
	m.runsMu.Lock()
	att, ok := m.runs[pid]
	if !ok {
		m.runsMu.Unlock()
		return
	}
	delete(m.runs, pid)
	atomic.AddInt32(&m.grantModeRuns, int32(-att.grantMountCount())) // #nosec G115 -- a run's grant-mount count is a tiny int, always in int32 range
	var toRestore, endedGrants []string
	for _, am := range att.mounts {
		switch am.mode {
		case attachSwap:
			if !m.mountSwapHeldByOtherLocked(am.path, pid) {
				toRestore = append(toRestore, am.path)
			}
		case attachGrant:
			endedGrants = append(endedGrants, am.path)
		}
	}
	m.runsMu.Unlock()

	for _, path := range toRestore {
		if restoreAsync {
			go m.restoreSwappedMount(path, why)
		} else {
			m.restoreSwappedMount(path, why)
		}
	}
	for _, path := range endedGrants {
		fmt.Fprintf(m.stdout, "jit service: mount %s: run-scoped grant for pid %d ended (%s)\n", path, pid, why)
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
		for _, am := range att.mounts {
			if am.mode == attachSwap {
				swaps++
				restore[am.path] = true
			} else {
				grants++
			}
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
		fmt.Fprintf(m.stdout, "jit service: %s and %s ended (session locked)\n",
			countWord(grants, "grant", "grants"),
			countWord(swaps, "compatibility swap", "compatibility swaps"))
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
		// Synchronous restore: pruneStaleRuns runs on the status goroutine,
		// never on a serve goroutine, so taking swapMu here is only a lock
		// wait, not the read-path cycle that forces grantRootsForPath to
		// defer. Keeping it inline means a status read that prunes a dead run
		// has the FIFO genuinely restored by the time it returns.
		m.onRunExit(pid, "run gone", false)
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
		for _, am := range att.mounts {
			out[am.path] = append(out[am.path], runHolder{pid: pid, command: att.command, since: att.since, mode: am.mode})
		}
	}
	return out
}

// grantRoot is one live grant-mode root: its pid AND the fork-time stamp
// that pid was attached with. The stamp travels with the pid into the read
// gate's verdict cache key so a recycled pid (same number, new process) can
// never reuse an ancestry verdict computed for the process that held it
// before.
type grantRoot struct {
	pid        int32
	startMicro int64
}

// grantRootsForPath returns the live grant-mode roots covering path (pid +
// its recorded start stamp), pruning any that died — the read gate's view
// of the registry. Caller must NOT hold runsMu.
func (m *mountManager) grantRootsForPath(path string) []grantRoot {
	now := time.Now()
	m.runsMu.Lock()
	var roots []grantRoot
	var deadPIDs []int32
	for pid, att := range m.runs {
		covers := false
		for _, am := range att.mounts {
			if am.mode == attachGrant && am.path == path {
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
		roots = append(roots, grantRoot{pid: pid, startMicro: att.startMicro})
	}
	m.runsMu.Unlock()
	for _, pid := range deadPIDs {
		m.onRunExit(pid, "run gone", true)
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
			fmt.Fprintf(m.stderr, "jit service: run exit watcher unavailable (%v), relying on per-status liveness checks\n", err)
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
		Ident:  uint64(pid), // #nosec G115 -- a real pid is a positive int32, always fits uint64
		Filter: unix.EVFILT_PROC,
		Flags:  unix.EV_ADD | unix.EV_ENABLE,
		Fflags: unix.NOTE_EXIT,
	}
	if _, err := unix.Kevent(m.grantKq, []unix.Kevent_t{ev}, nil, nil); err != nil {
		// ESRCH: the target exited between attachment and here — the exact
		// race the registration exists to catch, just earlier.
		m.onRunExit(pid, "process already exited", false)
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
			m.onRunExit(pid, "process exited", false)
		}
	}
}
