// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"sync"
	"time"

	"github.com/jitpass/jit/internal/agent"
)

// Making a mount read durable in `jit audit` is mostly a volume problem, not
// a plumbing one.
//
// The signal is worth having: a process with no business reading a credential
// file, quietly handed a decoy, is honeytoken-shaped, and jit already knows
// the mount, the verdict and (best-effort, via internal/lineage) who read it.
// It produced that on EVERY read and kept only the newest one per mount, in
// memory, discarded at the next service restart.
//
// The reason it can't simply be appended is that serveContent runs once per
// reader rendezvous, and the readers that matter most are exactly the ones
// that loop: a dev server's file watcher re-reads a mount continuously
// (readStormThreshold and readLogMinGap exist because 635k identical stderr
// lines in one afternoon was a reported bug). agent-history.jsonl is capped
// at historyMaxBytes and the ring at MaxSessionEvents, both evicting
// oldest-first — so an uncollapsed serve event is an eviction primitive
// against the very trail it is being added to, quietly pushing out every real
// unlock and denial. That is the hazard recordRejectedClass documents,
// reached from the other direction: there a hostile caller mints events, here
// an ordinary watcher does it by accident, and the trail is destroyed either
// way.
//
// So serves collapse BEFORE they are written. Same discipline as the agent's
// use events, with the aggregation key chosen so a collapse can never merge
// two facts a reader would need apart: mount, reader identity, and the
// decoy/real verdict. A watcher hammering one mount is one line carrying a
// count; the same mount read by a DIFFERENT process, or handed different
// content, is always its own line.
type serveAuditor struct {
	// window is how long one aggregate accumulates before it is written.
	window time.Duration
	// emit appends a finished event to the durable trail. Nil disables the
	// auditor entirely (every test that doesn't care, and any future caller
	// with no history file), which is why every method tolerates a nil
	// receiver field rather than requiring a constructor.
	emit func(agent.SessionEvent)
	// labelFn names the credential a mount holds. Resolved through labels
	// below rather than called per read: the lookup walks jit's global-mount
	// table building candidate paths, which is cheap once and wasteful on
	// every rendezvous of a mount being read in a loop. Nil falls back to the
	// mount path, which is always identifiable if not always pretty.
	labelFn func(mount string) string

	mu      sync.Mutex
	pending map[serveKey]*serveAggregate
	// labels caches labelFn per mount path. A mount's credential name cannot
	// change while it is mounted, so this never needs invalidating.
	labels map[string]string
	// stop closes the flusher goroutine; nil until start() is called.
	stop chan struct{}
	done chan struct{}
}

// serveAuditWindow is how long same-mount, same-reader, same-verdict serves
// merge into one durable event.
//
// Chosen against the two failure modes, not for a round number. Too short and
// a watcher loop still floods the trail: at readLogMinGap's 30s a single
// looping mount would mint 2,880 events a day, enough to evict a week of real
// unlocks. Too long and `jit audit --follow` stops being a live view of what
// is reading your credentials, which is most of the point of recording it.
// Two minutes keeps a looping mount to ~720 events/day worst case while still
// surfacing a read well inside the time it takes to notice something is off.
const serveAuditWindow = 2 * time.Minute

// serveAuditFlushInterval paces the background flush. An aggregate is written
// when its window closes even if nothing reads the mount again — without this
// a single decoy read on an otherwise idle machine would sit unwritten until
// the next lock or shutdown, which is precisely the read most worth seeing
// promptly. Deliberately finer than serveAuditWindow so an aggregate is never
// held much past it.
const serveAuditFlushInterval = 15 * time.Second

// maxPendingServes bounds the pending map. The ordinary key space is small
// (mounts × live readers), but a burst of short-lived readers each get their
// own pid and therefore their own key, so the map needs a ceiling that isn't
// "however many processes the machine can spawn". Hitting it flushes
// everything rather than dropping anything: the events are already collapsed,
// and writing them early costs a slightly shorter window, not a lost fact.
const maxPendingServes = 64

// serveKey is one aggregate's identity. Deliberately includes the reader and
// the verdict: collapsing across either would merge facts an investigation
// needs separated ("who read it" and "what did they get").
type serveKey struct {
	mount     string
	readerPID int32
	reader    string
	decoy     bool
}

type serveAggregate struct {
	start time.Time
	event agent.SessionEvent
}

// start launches the background flusher. Safe to call with no emit set (it
// does nothing), and safe to call once — the manager owns the lifecycle and
// calls stopFlusher from shutdown.
func (a *serveAuditor) start() {
	if a == nil || a.emit == nil || a.stop != nil {
		return
	}
	a.stop = make(chan struct{})
	a.done = make(chan struct{})
	go func() {
		defer close(a.done)
		t := time.NewTicker(serveAuditFlushInterval)
		defer t.Stop()
		for {
			select {
			case <-a.stop:
				return
			case now := <-t.C:
				a.emitAll(a.take(false, now))
			}
		}
	}()
}

// stopFlusher ends the background flusher and writes everything still
// pending, so a service shutting down doesn't discard the window it was in
// the middle of.
func (a *serveAuditor) stopFlusher() {
	if a == nil {
		return
	}
	if a.stop != nil {
		close(a.stop)
		<-a.done
		a.stop, a.done = nil, nil
	}
	a.emitAll(a.take(true, time.Now()))
}

// record folds one completed serve into its aggregate, writing out any
// aggregate whose window has closed. reason is why this reader got this
// content.
func (a *serveAuditor) record(now time.Time, mount, reason string, rec serveRecord) {
	if a == nil || a.emit == nil {
		return
	}
	key := serveKey{mount: mount, readerPID: rec.reader.pid, reader: rec.reader.execPath, decoy: rec.decoy}

	a.mu.Lock()
	if a.pending == nil {
		a.pending = map[serveKey]*serveAggregate{}
	}
	agg := a.pending[key]
	if agg == nil {
		label := a.labelLocked(mount)
		op := agent.OpServeReal
		if rec.decoy {
			op = agent.OpServeDecoy
		}
		e := agent.SessionEvent{
			UnixTime: now.Unix(),
			Kind:     agent.KindServe,
			Op:       op,
			Cause:    reason,
		}
		if rec.reader.identified {
			e.By = rec.reader.execPath
			e.ByPID = rec.reader.pid
			e.LaunchedBy = rec.reader.launchedBy
			e.ByLikely = rec.reader.likely
		}
		if label != "" {
			e.Labels = []string{label}
		}
		agg = &serveAggregate{start: now, event: e}
		a.pending[key] = agg
	}
	agg.event.Count++
	// A verdict that changes mid-window is a different key, so the reason
	// recorded here can only drift within one verdict (a lock arriving between
	// two decoy reads, say). Keep the LATEST, because "why am I getting decoys
	// right now" is the question, and the newest answer is the true one.
	if reason != "" {
		agg.event.Cause = reason
	}
	// An identity can arrive late: the scan that missed this reader's open may
	// find it on the next read, and both reads share a key only when the pid
	// matches, so this fills in a launcher rather than overwriting a name.
	if agg.event.LaunchedBy == "" && rec.reader.identified {
		agg.event.LaunchedBy = rec.reader.launchedBy
	}
	over := len(a.pending) >= maxPendingServes
	a.mu.Unlock()

	a.emitAll(a.take(over, now))
}

// take removes and returns the aggregates ready to be written — every one
// when all is set, otherwise those whose window has closed — oldest first so
// the trail stays chronological.
func (a *serveAuditor) take(all bool, now time.Time) []agent.SessionEvent {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.pending) == 0 {
		return nil
	}
	var out []agent.SessionEvent
	for k, agg := range a.pending {
		if all || now.Sub(agg.start) >= a.windowOrDefault() {
			out = append(out, agg.event)
			delete(a.pending, k)
		}
	}
	sortEventsByTime(out)
	return out
}

// labelLocked resolves a mount's credential name, memoized. Caller holds a.mu.
func (a *serveAuditor) labelLocked(mount string) string {
	if a.labelFn == nil {
		return mount
	}
	if l, ok := a.labels[mount]; ok {
		return l
	}
	l := a.labelFn(mount)
	if a.labels == nil {
		a.labels = map[string]string{}
	}
	a.labels[mount] = l
	return l
}

func (a *serveAuditor) windowOrDefault() time.Duration {
	if a.window > 0 {
		return a.window
	}
	return serveAuditWindow
}

// emitAll writes finished events, never under a.mu: emit appends to a file,
// and holding the auditor's lock across it would put a disk write on the
// serve path's critical section.
func (a *serveAuditor) emitAll(events []agent.SessionEvent) {
	if a == nil || a.emit == nil {
		return
	}
	for _, e := range events {
		a.emit(e)
	}
}

func sortEventsByTime(events []agent.SessionEvent) {
	for i := 1; i < len(events); i++ {
		for j := i; j > 0 && events[j].UnixTime < events[j-1].UnixTime; j-- {
			events[j], events[j-1] = events[j-1], events[j]
		}
	}
}

// serveReason says, in the user's terms, why a reader got what it got. It is
// the durable form of the one question the mount design provokes — "why is my
// app reading decoys" — which until now was answerable only by reading the
// service's raw log.
func serveReason(decoy, viaGrant, hadReal bool, resolveErr string) string {
	if !decoy {
		if viaGrant {
			return "authorized by a jit run grant"
		}
		return "approved by a per-process consent prompt"
	}
	if hadReal {
		return "no jit run grant or consent approval covered the reader"
	}
	if resolveErr != "" {
		return "no real value is resolved: " + resolveErr
	}
	return "the vault session is locked, so no real value is resolved"
}
