// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package agent

import (
	"sort"
	"time"
)

// This file is the session-event trail: the in-memory ring every surface
// reads, the durable hand-off the CLI layer wires to agent-history.jsonl, and
// the use-aggregation that keeps a busy caller from flooding either. The
// aggregation is the reason this is worth its own file: several distinct
// collapse windows and key choices live here, each with a misattribution or
// eviction hazard behind it, and they are easier to keep consistent side by
// side than scattered through the server.

// unlockEvent snapshots who caused a fresh unlock, at the moment it happened
// — the caller may well have exec'd (jit run) or exited by the time anyone
// runs `jit agent status` to ask.
func unlockEvent(op string, c *caller) *SessionEvent {
	e := &SessionEvent{UnixTime: time.Now().Unix(), Kind: KindUnlock, Op: op}
	if c != nil {
		e.By = c.command()
		e.ByPID = c.pid
		e.LaunchedBy = c.launchedBy()
	}
	return e
}

// MaxSessionEvents bounds the in-memory history ring. An agent process
// lives for weeks across launchd restarts, so this must not grow without
// limit; 200 events is several days of ordinary use (a handful of
// unlock/lock pairs a day) and a few kilobytes. Exported because the CLI
// layer seeds the ring from the durable history file and caps its read to
// the same number — anything older is still in the file for whoever wants
// to read it directly.
const MaxSessionEvents = 200

// SeedHistory pre-populates the ring with events restored from the durable
// history file (oldest first, the order they were appended), keeping the
// newest MaxSessionEvents. Call before Listen — it replaces the ring, and
// racing live recordEvent appends would drop them. This is what lets `jit
// agent history` answer for prompts that happened before the most recent
// launchd restart, which is exactly when "why was I being prompted all
// afternoon?" gets asked (the restart happens at login, i.e. the next
// morning). lastUnlock/lastLock stay process-local on purpose: they
// describe THIS process's session, and a restart is why it's locked now.
func (s *Server) SeedHistory(events []SessionEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(events) > MaxSessionEvents {
		events = events[len(events)-MaxSessionEvents:]
	}
	s.events = append([]SessionEvent(nil), events...)
}

// recordEvent appends to the ring, shifting out the oldest in place once
// the cap is reached — the slice is bounded, so shifting beats allocating
// a fresh 200-entry array on every event past the cap. Caller must hold
// s.mu.
func (s *Server) recordEvent(e SessionEvent) {
	s.events = append(s.events, e)
	if len(s.events) > MaxSessionEvents {
		n := copy(s.events, s.events[len(s.events)-MaxSessionEvents:])
		s.events = s.events[:n]
	}
}

// useKey groups uses that collapse into one KindUse event: same op, same
// caller command line. Keyed on the command, not the pid, deliberately —
// a relaunching MCP server is a new pid every time with an identical
// argv, and it's exactly the caller whose uses need collapsing.
type useKey struct {
	op string
	by string
}

// useAggregate is one pending KindUse event still inside its collapse
// window. event holds the FIRST use's full provenance snapshot (pid,
// launcher — later uses from the same command line add nothing but
// count); start is that first use, which becomes the event's time.
type useAggregate struct {
	start time.Time
	event SessionEvent
}

// maxUseLabels caps how many distinct caller-reported secret names one
// collapsed use event carries. Eight names the typical profile in full;
// past that, Count still says how much flowed, the list just stops
// growing.
const maxUseLabels = 8

// recordUse notes a wrap/unwrap/reveal that rode the ALREADY-unlocked
// session — the events history used to be blind to: unlocks said who
// opened the session, locks said what closed it, and everything that
// flowed through in between left no record at all. Collapsed per
// caller+op over useWindow (the same discipline the mount read-storm
// logging applies), so a profile resolution's burst of unwraps is one
// event, not ten. Fresh challenges never come here — the unlock event
// itself carries that use's provenance and label.
//
// Aggregates flush lazily: any later use flushes every EXPIRED aggregate
// (so ongoing activity keeps history current), and lock()/history()
// flush everything (the session boundary, and the moment someone
// actually reads). A crash loses at most the still-pending window —
// bounded, and the durable file gets everything else.
func (s *Server) recordUse(op string, c *caller, label string) {
	// The collapse key is the RAW command line, not the redacted one the
	// event will carry: redaction can map two different callers' argvs onto
	// one string, and merging their aggregates would stamp the first
	// caller's pid onto the second's uses. The raw string never leaves the
	// in-memory pendingUses map (see caller.rawCommand).
	s.recordAggregated(KindUse, op, c.rawCommand(), c, label)
}

// opClassMismatch is the op label for an unwrap rejected because the class the
// caller claimed doesn't match the ciphertext it sent (verifyClassBinding).
// Named in the same terse style as the other socket-boundary rejections
// ("reject", "decode", "accept") because that is what it is.
const opClassMismatch = "class-mismatch"

// recordRejectedClass notes an unwrap turned away by verifyClassBinding.
//
// It collapses on the op ALONE — every caller's rejections merge into one
// aggregate — which is the difference between an audit line and an attack.
// The ring holds MaxSessionEvents and evicts oldest-first, so any event an
// unauthenticated caller can mint on demand is an eviction primitive, and
// collapsing per caller does not help when the caller is what varies:
// useKey.by is the peer's own argv, so one fork per event buys a fresh
// aggregate, and a few hundred execs push every real unlock and denial out of
// `jit audit` — the attack erasing the record of itself.
//
// The cost is that a collapsed line names only the first caller in the window.
// That is the right trade: the count and the fact of a flood are what an
// investigation needs first, and per-caller attribution bought at the price of
// an evictable history is worth nothing.
func (s *Server) recordRejectedClass(c *caller) {
	s.recordAggregated(KindError, opClassMismatch, "", c, "")
}

// recordAggregated is recordUse's general form. collapseBy is the second half
// of the aggregation key: the caller's identity for ordinary uses (so one
// tool's burst is one line), or a constant for events a caller can trigger at
// will (so a flood is one line no matter how many identities it wears).
func (s *Server) recordAggregated(kind, op, collapseBy string, c *caller, label string) {
	now := time.Now()
	key := useKey{op: op, by: collapseBy}

	s.mu.Lock()
	flushed := s.flushUsesLocked(false, now)
	agg := s.pendingUses[key]
	if agg == nil {
		e := unlockEvent(op, c)
		e.Kind = kind
		e.UnixTime = now.Unix()
		agg = &useAggregate{start: now, event: *e}
		if s.pendingUses == nil {
			s.pendingUses = map[useKey]*useAggregate{}
		}
		s.pendingUses[key] = agg
	}
	agg.event.Count++
	if label != "" && len(agg.event.Labels) < maxUseLabels && !containsString(agg.event.Labels, label) {
		agg.event.Labels = append(agg.event.Labels, label)
	}
	s.mu.Unlock()

	s.notifySessionEvents(flushed)
}

// flushUsesLocked materializes pending use aggregates into the ring —
// every one when all is set (a lock or a history read), otherwise only
// those whose collapse window has closed — returning them (oldest first)
// for the caller to hand to OnSessionEvent OUTSIDE s.mu, per that
// callback's contract. Caller must hold s.mu.
func (s *Server) flushUsesLocked(all bool, now time.Time) []SessionEvent {
	if len(s.pendingUses) == 0 {
		return nil
	}
	var out []SessionEvent
	for k, agg := range s.pendingUses {
		if all || now.Sub(agg.start) >= s.useWindow {
			out = append(out, agg.event)
			delete(s.pendingUses, k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UnixTime < out[j].UnixTime })
	for _, e := range out {
		s.recordEvent(e)
	}
	return out
}

// notifySessionEvents hands flushed use events to OnSessionEvent, if set.
// Its own function because three flush sites share the loop.
func (s *Server) notifySessionEvents(events []SessionEvent) {
	if s.OnSessionEvent == nil {
		return
	}
	for _, e := range events {
		s.OnSessionEvent(e)
	}
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// history returns the ring NEWEST FIRST — the order it will be read in, and
// the order `jit agent history` prints. Reversing here (rather than in the
// CLI) keeps every consumer, including a --format json one, from having to
// know which end is which. Pending use aggregates flush first — the moment
// someone actually reads history is exactly when it must be current, and
// an aggregate mid-window would otherwise be invisible right then.
func (s *Server) history() []SessionEvent {
	s.mu.Lock()
	flushed := s.flushUsesLocked(true, time.Now())
	out := make([]SessionEvent, 0, len(s.events))
	for i := len(s.events) - 1; i >= 0; i-- {
		out = append(out, s.events[i])
	}
	s.mu.Unlock()
	s.notifySessionEvents(flushed)
	return out
}

// pendingUnlock returns a copy of the challenge currently awaiting the
// human's answer, or nil when none is. Only answerable at all because
// status no longer queues behind the challenge itself — the whole point of
// challengeMu — and it turns that fix into an affirmative answer: status
// during a prompt doesn't just return, it explains the prompt.
func (s *Server) pendingUnlock() *SessionEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pendingChallenge == nil {
		return nil
	}
	p := *s.pendingChallenge
	return &p
}

// provenance returns copies, so a status response can never hand a caller a
// pointer into state the agent keeps mutating under its own lock.
func (s *Server) provenance() (lastUnlock, lastLock *SessionEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastUnlock != nil {
		u := *s.lastUnlock
		lastUnlock = &u
	}
	if s.lastLock != nil {
		l := *s.lastLock
		lastLock = &l
	}
	return lastUnlock, lastLock
}
