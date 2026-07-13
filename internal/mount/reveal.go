// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package mount

import (
	"sync"
	"time"
)

// RevealState is the decoy-by-default mount's real gate (RFC.md B10, GAPS.md
// #2): a mount serves DecoyValues content by default and only serves the
// real profile values while revealed. Revealing is time-boxed on purpose — the
// whole point is to shrink "real value available" down to a short,
// explicitly-triggered window instead of the full agent session TTL, since
// spike/fifo-reader-identify/FINDINGS.md found no reliable way to instead
// gate by identifying the reader's process (Endpoint Security is
// impractical for jit's distribution shape; the cheaper libproc scan has a
// real, adversary-exploitable timing race — see internal/lineage).
//
// Safe for concurrent use: Serve's own goroutine calls IsRevealed on every
// re-open cycle while an entirely different goroutine (an agent RPC handler)
// calls Reveal.
type RevealState struct {
	mu     sync.Mutex
	expiry time.Time
}

// NewRevealState returns a state that starts hidden (decoy content only)
// until the first Reveal call — a brand-new mount must never default to
// serving real content before any trust signal has fired.
func NewRevealState() *RevealState {
	return &RevealState{}
}

// Reveal makes the mount serve real content for the next d — re-revealing while
// already revealed extends (or shortens) the window to end d from now, it
// doesn't stack. A caller enforcing a maximum window (internal/cli/agent.go
// clamps explicit `jit agent reveal` requests) does so before calling Reveal;
// this type has no opinion on what d should be.
func (s *RevealState) Reveal(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expiry = time.Now().Add(d)
}

// Hide ends the revealed window immediately, before its natural expiry —
// used when a mount is being torn down (jit unmount, agent lock) so
// nothing lingers revealed past the event that's supposed to end access.
// An active window's expiry is pulled back to now rather than zeroed, so
// WindowEnded still reports when access actually stopped — "the window
// ended at lock time" is exactly what a status line should say.
func (s *RevealState) Hide() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Now().Before(s.expiry) {
		s.expiry = time.Now()
	}
}

// IsRevealed reports whether real content should be served right now.
func (s *RevealState) IsRevealed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return time.Now().Before(s.expiry)
}

// Remaining reports how much of the current reveal window is left, or 0 if
// hidden/expired — the basis for showing "revealed for Ns" in `jit
// status` instead of just a bare yes/no (GAPS.md #37).
func (s *RevealState) Remaining() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	remaining := time.Until(s.expiry)
	if remaining <= 0 {
		return 0
	}
	return remaining
}

// WindowEnded reports when the most recent reveal window ended (naturally or
// via Hide), and false if the mount is currently revealed or was never
// revealed at all. Expiry is lazy — nothing fires at the moment a window
// ends — so this is how `jit agent status` can still say "the window
// ended Xm ago" instead of the revealed line just silently disappearing, a
// real, reported confusion ("it's not switching to hidden": it did, but
// nothing anywhere said so).
func (s *RevealState) WindowEnded() (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.expiry.IsZero() || time.Now().Before(s.expiry) {
		return time.Time{}, false
	}
	return s.expiry, true
}
