// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jitpass/jit/internal/lineage"
)

// This file is the grant MODE's attach step and its per-read gate. The
// shared lifecycle (registry, teardown, prune, status, exit watcher) lives
// in mountruns.go; the swap mode's attach lives in mountswap.go. What's
// here is grant-specific: registering a --live run and deciding, per FIFO
// rendezvous, whether the reader is inside the granted process tree.
//
// Doctrine note: spike/fifo-reader-identify ruled reader identity must
// never be a security boundary, and it still isn't one here. The boundary
// is the attachment itself — created only after ensureUnlocked, for a
// caller that already holds every one of these values in memory to inject
// into the child's environment. Lineage only NARROWS that grant: every
// classification failure (scan truncation, unreadable ancestry, recycled
// pid, dead target) serves decoys, and the worst an identity-racing
// adversary can win is what the accepted reveal-window baseline already
// hands every same-user process for 60 seconds after each unlock.

// grantVerdictTTL caches per-(holder,root) ancestry verdicts so a read
// storm doesn't pay the ancestry walk per read — same motivation as
// lineageScanMinGap, except a gating scan can't be SKIPPED (that would mean
// guessing), only amortized.
const grantVerdictTTL = 2 * time.Second

// grantVerdictKey caches "is holder inside root's tree" per PAIR — not per
// holder — so one grant root dying can never let a holder classified under
// it keep riding a different, still-live root's authorization.
type grantVerdictKey struct {
	holder int32
	root   int32
}

type grantVerdict struct {
	inTree  bool
	expires time.Time
}

// grantForPID is revealForPID's grant-mode attach: register a --live run
// against every mount that is currently served AND has real content
// resolved. The real-content rule is revealMount's honesty rule (GAPS.md
// #46): a "grant" on a mount that can only serve decoys would report
// success while changing nothing. Mounts that can't be granted are skipped
// with a logged reason; the RPC fails only when NO mount could be granted.
func (m *mountManager) grantForPID(mountPaths []string, pid int32) error {
	att, ok := m.newRunAttachment(pid, attachGrant)
	if !ok {
		return fmt.Errorf("reveal_pid: target pid %d not found", pid)
	}

	var problems []string
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
		sm.mu.Unlock()
		if !hasReal {
			msg := fmt.Sprintf("%s has nothing real to serve", path)
			if resolveErr != "" {
				msg = fmt.Sprintf("%s (resolving its secrets failed: %s)", msg, resolveErr)
			}
			problems = append(problems, msg)
			continue
		}
		att.mounts = append(att.mounts, path)
		fmt.Fprintf(m.stdout, "jit agent: mount %s: serving real content to pid %d's process tree (%s) until it exits\n", path, pid, att.command)
	}
	for _, p := range problems {
		fmt.Fprintf(m.stderr, "jit agent: reveal_pid skipped: %s\n", p)
	}
	if len(att.mounts) == 0 {
		return fmt.Errorf("reveal_pid: no grant created: %s", strings.Join(problems, "; "))
	}
	m.registerRun(att)
	return nil
}

// serveContent is the ONE content decision, called by mount.Serve on every
// reader rendezvous. Real content flows when the mount is revealed (a
// window) OR authorized by a run-scoped grant (this run's tree); decoy
// otherwise. With no grant runs anywhere the grant gate is skipped outright
// (the grantModeRuns fast path), so an ungranted mount pays exactly what it
// did before grants existed. A swapped mount never reaches here — it's a
// plain file with no Serve goroutine.
func (m *mountManager) serveContent(path string, sm *servedMount) []byte {
	revealed := sm.reveal.IsRevealed()
	authorized := revealed
	grantServed := false
	if !authorized && atomic.LoadInt32(&m.grantModeRuns) > 0 {
		if m.grantAuthorizes(path, sm) {
			authorized = true
			grantServed = true
		}
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()
	content, decoy := sm.decoy, true
	if sm.real != nil && authorized {
		content, decoy = sm.real, false
	}
	sm.lastServe = &serveRecord{at: time.Now(), decoy: decoy, reader: sm.pendingReader, grantServed: !decoy && grantServed}
	return content
}

// grantAuthorizes applies the fail-closed rule: real content flows only
// when the holder set is completely enumerable, non-empty, and EVERY holder
// verifies inside some live grant root's tree. Any uncertainty at any step
// — no live root, truncated scan, an unclassifiable holder — means decoy.
// Enumerating all holders (not just one) is what makes a piggybacking
// stranger downgrade the read to decoys instead of riding along (spike
// scenario: mixed concurrent holders).
func (m *mountManager) grantAuthorizes(path string, sm *servedMount) bool {
	roots := m.grantRootsForPath(path)
	if len(roots) == 0 {
		return false
	}
	holders, ok := m.grantHolders(path)
	if !ok || len(holders) == 0 {
		return false
	}
	now := time.Now()
	for _, holder := range holders {
		if !m.holderAuthorized(sm, holder, roots, now) {
			return false
		}
	}
	return true
}

// holderAuthorized reports whether holder sits inside any of roots' trees,
// consulting (and filling) the per-pair verdict cache. Negative verdicts
// are cached too: a stranger holding the mount open in a read loop would
// otherwise force a full ancestry walk per read.
func (m *mountManager) holderAuthorized(sm *servedMount, holder int32, roots []int32, now time.Time) bool {
	for _, root := range roots {
		key := grantVerdictKey{holder: holder, root: root}
		sm.mu.Lock()
		v, cached := sm.grantVerdicts[key]
		sm.mu.Unlock()
		if cached && now.Before(v.expires) {
			if v.inTree {
				return true
			}
			continue
		}
		inTree := m.grantAncestry(holder, root)
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
