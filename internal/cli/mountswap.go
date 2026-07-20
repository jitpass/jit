// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"fmt"

	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

// This file is the swap MODE's attach step and its filesystem transitions.
// The shared lifecycle (registry, teardown, prune, status, exit watcher)
// lives in mountruns.go. What's here is swap-specific: replacing a mount's
// FIFO with an inert compatibility pointer file while a run holds it, and
// restoring the FIFO when the last such run exits.
//
// swapMu (mountmanager.go) serializes every FIFO<->file transition for a
// path so a swap-in and a concurrent restore can never interleave; it is
// ordered OUTSIDE the registry lock and is never taken ON the serve/read
// goroutine, so a swap-in holding it across stopMount can't deadlock an
// in-flight serve. The read gate (grantRootsForPath) can DISCOVER a dead run
// that needs a swapped FIFO restored, but it dispatches that restore to a
// detached goroutine rather than taking swapMu itself — taking it inline
// would deadlock against a performSwapIn already holding swapMu and blocked
// on that very serve cycle's sm.done.

// performSwapIn stops serving path's FIFO and replaces it with the
// comment-only pointer file. Caller holds swapMu.
func (m *mountManager) performSwapIn(path string, entry mount.Entry) error {
	names, order, err := m.mountVarNames(entry)
	if err != nil {
		return err
	}
	content := mount.SwapPointerContent(names, order)
	// stopMount cancels the Serve goroutine and waits for its in-flight
	// cycle to finish (sm.done) — exactly the race-safety SwapToPointer
	// needs, the same guarantee jit unmount relies on before it replaces a
	// mount's file.
	m.stopMount(path)
	if err := mount.SwapToPointer(path, content); err != nil {
		// Best-effort recovery: put the FIFO back and resume serving, so a
		// failed swap doesn't leave the mount dead.
		_ = mount.RestoreFIFO(path)
		m.resumeServing(entry)
		return err
	}
	return nil
}

// restoreSwappedMount reverses a swap: put the FIFO back and resume
// serving. Called by the unified teardown (onRunExit / clearAllRuns /
// pruneStaleRuns) once no run holds the mount swapped any longer. Takes
// swapMu so it can't race a concurrent swap-in; must NOT be called with
// runsMu held.
func (m *mountManager) restoreSwappedMount(path, why string) {
	m.swapMu.Lock()
	defer m.swapMu.Unlock()
	// Re-check under swapMu, not just at the teardown decision: onRunExit
	// releases runsMu before we get here (and the read/prune paths dispatch
	// this asynchronously), so a fresh run may have swapped this same path in
	// during the gap. Restoring the FIFO then would strand that run's child on
	// a live mount instead of the isolated pointer file it asked for. swapMu
	// serializes us against that run's own swap-in, so this check is
	// authoritative: if anyone still holds it swapped, leave their file alone.
	m.runsMu.Lock()
	stillHeld := m.mountSwapHeldByAnyLocked(path)
	m.runsMu.Unlock()
	if stillHeld {
		return
	}
	entry, ok := m.registryEntryForPath(path)
	if !ok {
		return
	}
	if err := mount.RestoreFIFO(path); err != nil {
		fmt.Fprintf(m.stderr, "jit agent: mount %s: restoring FIFO after run exit failed: %v\n", path, err)
		return
	}
	m.resumeServing(entry)
	fmt.Fprintf(m.stdout, "jit agent: mount %s: compatibility file ended (%s), decoy mount restored\n", path, why)
}

// resumeServing re-establishes decoy serving for one entry after its FIFO
// was restored, and resolves real content if the session is unlocked so a
// reveal window or a subsequent grant has something to serve. Best-effort:
// a resolve failure just leaves the mount decoy-only, exactly as a locked
// agent would. ensureServing/resolveReal take m.mu, never swapMu/runsMu, so
// there's no lock inversion.
func (m *mountManager) resumeServing(entry mount.Entry) {
	m.ensureServing([]mount.Entry{entry})
	// Resolve real content ONLY if the session is already unlocked. This runs
	// from teardown paths that fire while locked — a run exiting, or the lock
	// itself (clearAllRuns) — and resolveReal would otherwise reach
	// KeyWrapper.UnwrapKey and raise a Touch ID prompt from a status read or a
	// lock, the one thing the mount layer must never do. Locked means leave
	// the freshly-restored mount decoy-only, exactly what the next real unlock
	// will fix.
	if !m.sessionUnlocked() {
		return
	}
	deviceID, err := vault.EnsureDeviceID(m.root)
	if err != nil {
		return
	}
	v := &vault.Vault{Root: m.root, KeyWrapper: m.keyWrapper, RecipientID: deviceID}
	// floorReveal=false: restoring a mount after a run must not light up a
	// fresh 60s reveal window on it — that would serve real content to
	// anything, the opposite of the decoy-by-default posture we're
	// returning to.
	m.resolveReal([]mount.Entry{entry}, v, false)
}

// sessionUnlocked reports whether the agent session is currently unlocked,
// without triggering a challenge, so a teardown-time resolve can be skipped
// while locked instead of prompting. Falls back to false (skip, the safe
// default) when the key wrapper can't answer — e.g. a test double, or any
// wrapper that isn't the live *agent.Server.
func (m *mountManager) sessionUnlocked() bool {
	u, ok := m.keyWrapper.(interface{ SessionUnlocked() bool })
	return ok && u.SessionUnlocked()
}

// mountVarNames loads entry's profile for the variable NAMES the pointer
// file lists (never values — this needs no vault access, same as the decoy
// path), plus their source order.
func (m *mountManager) mountVarNames(entry mount.Entry) (names, order []string, err error) {
	p, order, err := profile.LoadFileOrdered(entry.ProfilePath)
	if err != nil {
		return nil, nil, fmt.Errorf("loading profile for swap: %w", err)
	}
	names = make([]string, 0, len(p))
	for name := range p {
		names = append(names, name)
	}
	return names, order, nil
}

// registryEntryForPath finds the registry entry for a mount path — needed
// to re-serve and to render pointer content, since the servedMount record
// is torn down by the swap. Best-effort: a read failure yields ok=false.
func (m *mountManager) registryEntryForPath(path string) (mount.Entry, bool) {
	entries, ok := m.loadRegistry()
	if !ok {
		return mount.Entry{}, false
	}
	for _, e := range entries {
		if e.MountPath == path {
			return e, true
		}
	}
	return mount.Entry{}, false
}
