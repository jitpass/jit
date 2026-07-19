// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jitpass/jit/internal/lineage"
)

// This file is mountManager's run-scoped reveal grants
// (spike/run-scoped-grant/FINDINGS.md): `jit run` registers its own pid
// right before execve (which keeps the pid), and the mounts backing the
// values it injected then serve REAL content to that pid's process tree —
// decided per reader rendezvous, for the run's lifetime, decoys for
// everyone else. The window-based reveal path (revealMount, floor windows)
// is untouched; a grant is an ADDITIONAL way a read can be served real,
// never a change to any existing one.
//
// Doctrine note: spike/fifo-reader-identify ruled reader identity must
// never be a security boundary, and it still isn't one here. The boundary
// is the grant itself — created only after ensureUnlocked, for a caller
// that already holds every one of these values in memory to inject into
// the child's environment. Lineage only NARROWS that grant: every
// classification failure (scan truncation, unreadable ancestry, recycled
// pid, dead target) serves decoys, and the worst an identity-racing
// adversary can win is what the accepted reveal-window baseline already
// hands every same-user process for 60 seconds after each unlock.

// grantHardCap bounds a grant's lifetime even if every teardown signal is
// missed (kqueue registration failed AND the per-read liveness check never
// runs because nothing reads the mount): a grant is meant to cover one
// run, and a run that genuinely needs longer re-requests on its next jit
// run. grantVerdictTTL caches per-(holder,root) ancestry verdicts so a
// read storm doesn't pay the walk per read — same motivation as
// lineageScanMinGap, except a gating scan can't be SKIPPED (that would
// mean guessing), only amortized.
const (
	grantHardCap    = 4 * time.Hour
	grantVerdictTTL = 2 * time.Second
)

// mountGrant is one active run-scoped grant on one mount. startMicro is
// the target's fork-time stamp, recorded while jit run was provably alive
// (mid-RPC) and re-checked before every use — stable across execve
// (spike-verified), so a recycled pid can never inherit a dead run's
// grant. command is kernel-derived at creation (never caller-reported),
// matching SessionEvent.By's convention.
type mountGrant struct {
	pid        int32
	startMicro int64
	command    string
	since      time.Time
	hardCap    time.Time
}

// grantVerdictKey caches "is holder inside root's tree" per PAIR — not per
// holder — so a grant dying can never let a holder classified under it
// keep riding a different, still-live grant's authorization.
type grantVerdictKey struct {
	holder int32
	root   int32
}

type grantVerdict struct {
	inTree  bool
	expires time.Time
}

// revealForPID is OnRevealPID's handler. Grants are created only for
// mounts that are currently served AND have real content resolved — the
// same honesty rule revealMount enforces (GAPS.md #46): a "grant" on a
// mount that can only serve decoys would report success while changing
// nothing. Mounts that can't be granted are skipped with a logged reason;
// the RPC fails only when NO mount could be granted.
func (m *mountManager) revealForPID(mountPaths []string, pid int32) error {
	startMicro, ok := m.grantStart(pid)
	if !ok {
		return fmt.Errorf("reveal_pid: target pid %d not found", pid)
	}
	command := ""
	if p, ok := lineage.Describe(pid); ok {
		command = p.Command()
	}
	now := time.Now()
	grant := mountGrant{pid: pid, startMicro: startMicro, command: command, since: now, hardCap: now.Add(grantHardCap)}

	var granted, problems []string
	for _, path := range mountPaths {
		m.mu.Lock()
		sm, served := m.served[path]
		m.mu.Unlock()
		if !served {
			problems = append(problems, fmt.Sprintf("no such mount: %s", path))
			continue
		}
		sm.mu.Lock()
		hasReal := sm.real != nil
		resolveErr := sm.lastResolveErr
		if hasReal {
			replaced := false
			for i, g := range sm.grants {
				if g.pid == pid {
					sm.grants[i] = grant
					replaced = true
					break
				}
			}
			if !replaced {
				sm.grants = append(sm.grants, grant)
			}
		}
		sm.mu.Unlock()
		if !hasReal {
			msg := fmt.Sprintf("%s has nothing real to serve", path)
			if resolveErr != "" {
				msg = fmt.Sprintf("%s (resolving its secrets failed: %s)", msg, resolveErr)
			}
			problems = append(problems, msg)
			continue
		}
		granted = append(granted, path)
		fmt.Fprintf(m.stdout, "jit agent: mount %s: serving real content to pid %d's process tree (%s) until it exits\n", path, pid, command)
	}
	for _, p := range problems {
		fmt.Fprintf(m.stderr, "jit agent: reveal_pid skipped: %s\n", p)
	}
	if len(granted) == 0 {
		return fmt.Errorf("reveal_pid: no grant created: %s", strings.Join(problems, "; "))
	}
	m.watchGrantPID(pid)
	return nil
}

// provideMountContent is what mount.Serve actually calls per reader
// rendezvous. With no grants on the mount it IS sm.provideContent — same
// decision, same cost, zero new scans — so the entire grant machinery is
// invisible to every mount jit run never touched. With grants, the
// window-based decision still wins first (an active reveal window serves
// real regardless, as today); only a hidden mount consults the grant gate.
func (m *mountManager) provideMountContent(path string, sm *servedMount) []byte {
	sm.mu.Lock()
	hasGrants := len(sm.grants) > 0
	sm.mu.Unlock()
	if !hasGrants {
		return sm.provideContent()
	}

	revealed := sm.reveal.IsRevealed()
	grantOK := false
	if !revealed {
		grantOK = m.grantAuthorizes(path, sm)
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()
	content, decoy := sm.decoy, true
	if sm.real != nil && (revealed || grantOK) {
		content, decoy = sm.real, false
	}
	sm.lastServe = &serveRecord{at: time.Now(), decoy: decoy, reader: sm.pendingReader, grantServed: !decoy && !revealed}
	return content
}

// grantAuthorizes applies the fail-closed rule: real content flows only
// when the holder set is completely enumerable, non-empty, and EVERY
// holder verifies inside some live grant's tree. Any uncertainty at any
// step — truncated scan, no live grant, an unclassifiable holder — means
// decoy. Enumerating all holders (not just one) is what makes a
// piggybacking stranger downgrade the read to decoys instead of riding
// along (spike scenario: mixed concurrent holders).
func (m *mountManager) grantAuthorizes(path string, sm *servedMount) bool {
	grants := m.liveGrants(path, sm)
	if len(grants) == 0 {
		return false
	}
	holders, ok := m.grantHolders(path)
	if !ok || len(holders) == 0 {
		return false
	}
	now := time.Now()
	for _, holder := range holders {
		if !m.holderAuthorized(sm, holder, grants, now) {
			return false
		}
	}
	return true
}

// grantHolders/grantAncestry/grantStart are the gate's kernel lookups,
// indirected through mountManager's test seams (nil = real lineage).
func (m *mountManager) grantHolders(path string) ([]int32, bool) {
	if m.grantHoldersFn != nil {
		return m.grantHoldersFn(path)
	}
	return lineage.FIFOHolders(path)
}

func (m *mountManager) grantAncestry(pid, root int32) bool {
	if m.grantAncestryFn != nil {
		return m.grantAncestryFn(pid, root)
	}
	return lineage.AncestryContainsPID(pid, root)
}

func (m *mountManager) grantStart(pid int32) (int64, bool) {
	if m.grantStartFn != nil {
		return m.grantStartFn(pid)
	}
	return lineage.ProcessStartTime(pid)
}

// holderAuthorized reports whether holder sits inside any of grants'
// trees, consulting (and filling) the per-pair verdict cache. Negative
// verdicts are cached too: a stranger holding the mount open in a read
// loop would otherwise force a full ancestry walk per read.
func (m *mountManager) holderAuthorized(sm *servedMount, holder int32, grants []mountGrant, now time.Time) bool {
	for _, g := range grants {
		key := grantVerdictKey{holder: holder, root: g.pid}
		sm.mu.Lock()
		v, cached := sm.grantVerdicts[key]
		sm.mu.Unlock()
		if cached && now.Before(v.expires) {
			if v.inTree {
				return true
			}
			continue
		}
		inTree := m.grantAncestry(holder, g.pid)
		sm.mu.Lock()
		if sm.grantVerdicts == nil {
			sm.grantVerdicts = map[grantVerdictKey]grantVerdict{}
		}
		if len(sm.grantVerdicts) > 256 {
			// A pathological churn of holder pids could otherwise grow this
			// map for the life of the grant; resetting just re-walks a few
			// ancestries on the next reads.
			sm.grantVerdicts = map[grantVerdictKey]grantVerdict{}
		}
		sm.grantVerdicts[key] = grantVerdict{inTree: inTree, expires: now.Add(grantVerdictTTL)}
		sm.mu.Unlock()
		if inTree {
			return true
		}
	}
	return false
}

// liveGrants prunes and returns path's grants that are still valid right
// now: inside their hard cap, target still alive, and still the SAME
// process (fork-time stamp unchanged — pid recycling shows up as a
// mismatch here). Pruning happens wherever grants are read (the gate and
// status), so teardown holds even if the kqueue watcher never fires.
func (m *mountManager) liveGrants(path string, sm *servedMount) []mountGrant {
	now := time.Now()
	type droppedGrant struct {
		g   mountGrant
		why string
	}
	var dropped []droppedGrant
	sm.mu.Lock()
	live := sm.grants[:0]
	for _, g := range sm.grants {
		switch start, ok := m.grantStart(g.pid); {
		case now.After(g.hardCap):
			dropped = append(dropped, droppedGrant{g, fmt.Sprintf("hard cap %s reached", grantHardCap)})
		case !ok:
			dropped = append(dropped, droppedGrant{g, "process exited"})
		case start != g.startMicro:
			dropped = append(dropped, droppedGrant{g, "pid was recycled by another process"})
		default:
			live = append(live, g)
		}
	}
	sm.grants = live
	out := make([]mountGrant, len(live))
	copy(out, live)
	sm.mu.Unlock()
	for _, d := range dropped {
		fmt.Fprintf(m.stdout, "jit agent: mount %s: run-scoped grant for pid %d ended (%s)\n", path, d.g.pid, d.why)
	}
	return out
}

// dropGrantsForPID removes pid's grants from every mount — the kqueue
// watcher's NOTE_EXIT path, and the immediate path when registration finds
// the target already gone.
func (m *mountManager) dropGrantsForPID(pid int32, why string) {
	type pathMount struct {
		path string
		sm   *servedMount
	}
	m.mu.Lock()
	all := make([]pathMount, 0, len(m.served))
	for path, sm := range m.served {
		all = append(all, pathMount{path, sm})
	}
	m.mu.Unlock()
	for _, e := range all {
		e.sm.mu.Lock()
		kept := e.sm.grants[:0]
		removed := false
		for _, g := range e.sm.grants {
			if g.pid == pid {
				removed = true
				continue
			}
			kept = append(kept, g)
		}
		e.sm.grants = kept
		e.sm.mu.Unlock()
		if removed {
			fmt.Fprintf(m.stdout, "jit agent: mount %s: run-scoped grant for pid %d ended (%s)\n", e.path, pid, why)
		}
	}
}

// clearAllGrants drops every grant on every mount — OnLock's path: a lock
// means "nothing real is being served", and a grant surviving a lock would
// contradict that the moment the next unlock resolved content, without any
// fresh authorization. (Redundantly safe even without this — the gate
// requires real != nil, which stop() clears — but status must not show
// grants a lock already invalidated.)
func (m *mountManager) clearAllGrants() {
	m.mu.Lock()
	served := make([]*servedMount, 0, len(m.served))
	for _, sm := range m.served {
		served = append(served, sm)
	}
	m.mu.Unlock()
	cleared := 0
	for _, sm := range served {
		sm.mu.Lock()
		cleared += len(sm.grants)
		sm.grants = nil
		sm.grantVerdicts = nil
		sm.mu.Unlock()
	}
	if cleared > 0 {
		fmt.Fprintf(m.stdout, "jit agent: %d run-scoped grant(s) dropped (session locked)\n", cleared)
	}
}

// watchGrantPID arms the event-driven half of grant teardown: a kqueue
// EVFILT_PROC/NOTE_EXIT watch on the target (spike-verified to survive
// execve and fire ~1ms after exit). Purely an optimization for promptness
// and log clarity — liveGrants' per-use liveness check is what teardown
// CORRECTNESS rests on — so every failure here degrades to that lazy path
// instead of failing the grant.
func (m *mountManager) watchGrantPID(pid int32) {
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
			fmt.Fprintf(m.stderr, "jit agent: grant exit watcher unavailable (%v), relying on per-read liveness checks\n", err)
			m.grantKq = -1
		} else {
			m.grantKq = kq
			// Daemon-lifetime goroutine, deliberately NOT in m.wg:
			// shutdown()'s wg.Wait exists so no in-flight FILESYSTEM write
			// races the process teardown, and this goroutine never touches
			// the filesystem — it dies with the process.
			go m.grantWatchLoop(kq)
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
		// ESRCH: the target exited between grant creation and here — the
		// exact race the registration exists to catch, just earlier.
		m.dropGrantsForPID(pid, "process already exited")
		return
	}
	m.grantWatched[pid] = true
}

func (m *mountManager) grantWatchLoop(kq int) {
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
			m.dropGrantsForPID(pid, "process exited")
		}
	}
}
