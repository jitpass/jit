// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/inject"
	"github.com/jitpass/jit/internal/lineage"
	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

// This file is mountManager and nothing else — the most concurrency-
// sensitive code in the CLI layer, deliberately separated from agent.go's
// cobra command wiring so its locking invariants can be read (and
// reviewed) in one place without plist templates and flag registration in
// between. The agent commands that drive it stay in agent.go.

// revealDefaultWindow is how long a mount serves real content automatically
// after a fresh unlock or an explicit jit migrate refresh (OnUnlock/
// OnRefresh) — the ergonomic default so a dev server started right after
// unlocking "just works" without a human remembering to reveal anything by
// hand. revealMaxWindow bounds an explicit `jit agent reveal --for` request:
// without a ceiling, "reveal forever" would silently recreate the exact
// always-real exposure the decoy gate exists to avoid (GAPS.md #2).
const (
	revealDefaultWindow = 60 * time.Second
	revealMaxWindow     = 10 * time.Minute
)

// A file watcher that re-reads a mount on every change can drive serve
// cycles continuously (GAPS.md #47: the EPIPE-reuse fix starves the loop
// for early-close watcher reads, but a read that DRAINS the content still
// requires the stale-reader isolation rename, and that rename is the
// filesystem event the watcher reacts to — VS Code interleaves both kinds,
// so the loop survives at the drained-read rate). These bound its cost:
// lineage scans (a full libproc pid walk, the actual CPU hog — 63
// CPU-minutes in one afternoon) run at most once per lineageScanMinGap
// per mount; per-read log lines collapse to one summary line per
// readLogMinGap; and a mount read at least readStormThreshold times in a
// rolling minute gets a named heads-up in `jit agent status`, since the
// only real kill for the loop is excluding the file from the watcher.
const (
	lineageScanMinGap  = 2 * time.Second
	readLogMinGap      = 30 * time.Second
	readStormThreshold = 60
)

// lingerGrace/lingerRecheck pace hasLingeringReader (mount.Serve's
// GAPS.md #47 reuse decision — see its construction in ensureServing): a
// reader that just drained its content needs a beat to process the EOF
// and close its fd before the scan looks, or nearly every well-behaved
// reader would be classified as a lingerer and renamed around anyway,
// keeping the watcher loop alive. One short recheck before giving up
// covers a slow-but-honest closer; a genuine holder (the actual
// stale-reader hazard) survives both and gets isolated.
const (
	lingerGrace   = 5 * time.Millisecond
	lingerRecheck = 25 * time.Millisecond
)

// mountManager serves every registered .env mount. GAPS.md #35 split what
// used to be one all-or-nothing lifecycle into two independent layers:
//
//  1. DECOY SERVING needs no vault access at all — mount.DecoyValues only
//     ever reads a profile's variable NAMES, never a resolved value — so
//     ensureServing (called at raw agent startup, and again from
//     OnUnlock/OnRefresh for anything registered since) starts a Serve
//     goroutine per mount unconditionally. This is what makes opening a
//     mount never hang: there's always a writer behind the pipe from the
//     moment the agent process is running, locked or not, unlocked-but-
//     never-revealed or not. A real, reported incident motivated this: with
//     no writer at all (the old design while locked, or before the first
//     unlock ever), any reader — an editor, a backup tool, `cat` — blocked
//     on open() forever, hanging the whole app on close in one case.
//  2. REAL CONTENT resolution (resolveReal, needs the vault unlocked) is
//     layered on top, independently: it fills in a servedMount's `real`
//     field once resolved, and stop() (OnLock) clears it back to nil plus
//     hides — WITHOUT touching the already-running Serve goroutine.
//     provideContent reads both live on every reader connection (Serve
//     calls it fresh per cycle, never once), so locking/unlocking changes
//     what's served without ever tearing down or restarting anything.
//
// Still deliberately NOT resolving REAL content at process startup (see
// agentCmd's doc comment: a launchd RunAtLoad agent starting before
// anyone's at their desk must never trigger a surprise Touch ID prompt
// just because mounts exist) — only decoy serving is safe to start
// unconditionally, since it needs no Touch ID at all.
type mountManager struct {
	root       string
	keyWrapper vault.KeyWrapper
	stdout     io.Writer
	stderr     io.Writer

	mu     sync.Mutex
	wg     sync.WaitGroup
	served map[string]*servedMount
}

// readerIdentity is internal/lineage's best-effort answer to "who just
// opened this mount" — audit-only (RFC.md §5.1), never consulted by the
// content decision itself. identified=false means the scan missed the
// reader, which a fast-closing reader legitimately can.
type readerIdentity struct {
	pid        int32
	execPath   string
	identified bool
}

// serveRecord is one completed content decision: what a connected reader
// was served, when, and (best-effort) by whom. Kept as each mount's
// single most recent event — enough for `jit agent status` to answer
// "why did my app get decoys" without a log spelunk, and the natural
// first cut of RFC.md §5's anomaly-signal scope without building any of
// its persistence.
type serveRecord struct {
	at     time.Time
	decoy  bool
	reader readerIdentity
}

// servedMount is one mount's live, dynamic state — read fresh by
// provideContent on every reader connection, so a lock/unlock/reveal cycle
// never needs to touch the underlying Serve goroutine at all.
type servedMount struct {
	cancel context.CancelFunc
	// done is closed when this mount's Serve goroutine actually returns —
	// NOT the same moment cancel() is called. A real, reported bug
	// (GAPS.md #36): mount.Serve's loop only checks ctx.Err() at the TOP
	// of each cycle; if a reader is already connected when cancel() is
	// called, the in-flight cycle still finishes its write, then calls
	// recreateFIFO (which unconditionally puts a FRESH pipe at path)
	// unconditionally, THEN closes, and only THEN notices cancellation on
	// the next iteration. stopMount MUST wait on done before returning,
	// or a caller (jit unmount) that replaces the file right after
	// cancel() can have that in-flight cycle's recreateFIFO clobber its
	// fresh plaintext right back into an empty FIFO — confirmed on real
	// hardware: one unmount call raced this way and left an empty,
	// unregistered FIFO; a second, otherwise-identical call on a
	// different mount with no reader connected at that moment worked
	// fine, which is what pointed at a timing race rather than a
	// deterministic bug.
	done   chan struct{}
	reveal *mount.RevealState

	mu    sync.Mutex
	decoy []byte
	real  []byte // nil until resolveReal succeeds; cleared again by stop()
	// lastResolveErr is why real is still nil (or last failed to refresh) —
	// what revealMount puts in its refusal so `jit agent reveal` can say WHY
	// revealing can't serve anything real, instead of that living only in the
	// agent's own log (GAPS.md #46). Cleared on every successful resolve.
	lastResolveErr string
	// pendingReader is set by the onReaderConnected hook (which mount.Serve
	// guarantees fires before provideContent in the same cycle, on the same
	// goroutine); provideContent folds it into lastServe when it decides
	// what that reader actually gets.
	pendingReader readerIdentity
	lastServe     *serveRecord

	// Watcher-loop cost bookkeeping (see the lineageScanMinGap block's doc
	// comment): when the lineage scan last actually ran, when a reader-
	// connected/serve-error line was last actually logged (with how many
	// occurrences were collapsed since), and a rolling one-minute read
	// counter behind MountRevealStatus.ReadsLastMinute.
	scanLast          time.Time
	readLogLast       time.Time
	readLogSuppressed int
	errLogLast        time.Time
	errSuppressed     int
	readWindowStart   time.Time
	readWindowCount   int64
}

func (sm *servedMount) setReal(b []byte) {
	sm.mu.Lock()
	sm.real = b
	sm.lastResolveErr = ""
	sm.mu.Unlock()
}

func (sm *servedMount) setResolveErr(err error) {
	sm.mu.Lock()
	sm.lastResolveErr = err.Error()
	sm.mu.Unlock()
}

func (sm *servedMount) provideContent() []byte {
	revealed := sm.reveal.IsRevealed()
	sm.mu.Lock()
	defer sm.mu.Unlock()
	content, decoy := sm.decoy, true
	if sm.real != nil && revealed {
		content, decoy = sm.real, false
	}
	sm.lastServe = &serveRecord{at: time.Now(), decoy: decoy, reader: sm.pendingReader}
	return content
}

// loadRegistry reads the mount registry, logging (not erroring — this
// runs from hooks with no caller to return an error to) on failure.
func (m *mountManager) loadRegistry() ([]mount.Entry, bool) {
	entries, err := mount.LoadRegistry(mount.RegistryPath(m.root))
	if err != nil {
		fmt.Fprintf(m.stderr, "jit agent: reading the list of mounted files: %v\n", err)
		return nil, false
	}
	return entries, true
}

// ensureServing starts a Serve goroutine — decoy content only, no vault
// access — for every entry not already being served. Idempotent and
// incremental, matching this file's existing "safe to call repeatedly,
// only starts what's new" convention (a real case depends on it: `jit
// migrate`'s own first vault write triggers the unlock that fires
// OnUnlock, but that happens BEFORE the new mount gets registered, so
// that first scan finds nothing yet — the explicit OpRefresh migrate
// sends right after registering the mount is what picks it up).
//
// Concurrency-safe against itself: OnUnlock (fired after ensureUnlocked
// releases its lock) and OnRefresh (fired from a connection-handling
// goroutine) can both land here at the same time — jit migrate's own
// flow makes that overlap real, since the unlock its first vault write
// triggers can still be scanning when its explicit Refresh RPC arrives.
// The early not-already-served check is only a fast path; the decision
// that counts is the second check, made in the SAME critical section as
// the map insert. Without that, two goroutines could each pass the first
// check for the same brand-new entry and each start a Serve goroutine on
// the same FIFO — interleaved duplicate content for readers, and, worse,
// the second insert overwriting the first servedMount in the map,
// orphaning a goroutine whose CancelFunc nothing can ever reach again:
// shutdown()'s wg.Wait() would then block forever on a goroutine it has
// no way to cancel.
func (m *mountManager) ensureServing(entries []mount.Entry) {
	for _, entry := range entries {
		m.mu.Lock()
		_, already := m.served[entry.MountPath]
		m.mu.Unlock()
		if already {
			continue
		}

		p, err := profile.LoadFile(entry.ProfilePath)
		if err != nil {
			fmt.Fprintf(m.stderr, "jit agent: skipping mount %s: %v\n", entry.MountPath, err)
			continue
		}
		// DecoyValues only ever reads p's KEYS (variable names) — never a
		// resolved value — which is exactly why this needs no vault
		// access and is safe to run before any unlock has ever happened.
		decoyValues := mount.DecoyValues(p)
		var decoy []byte
		if entry.TemplatePath != "" {
			tmpl, err := os.ReadFile(entry.TemplatePath) // #nosec G304 -- path comes from jit's own mount registry, not external input
			if err != nil {
				fmt.Fprintf(m.stderr, "jit agent: skipping mount %s: reading template: %v\n", entry.MountPath, err)
				continue
			}
			decoy = mount.FormatTemplate(tmpl, decoyValues)
		} else {
			decoy = mount.FormatDotenv(decoyValues)
		}
		// Decoy content self-diagnoses: whoever opens the file sees what
		// these values are and the one command that fixes it, instead of
		// debugging `jit-hidden-*` strings through their app's own
		// error output. Real content never carries this line.
		decoy = append(mount.DecoyNotice(entry.MountPath), decoy...)

		sm := &servedMount{reveal: mount.NewRevealState(), decoy: decoy, done: make(chan struct{})}
		ctx, cancel := context.WithCancel(context.Background())
		sm.cancel = cancel

		// Claim the slot and re-check under ONE lock — see the function
		// doc comment for the real race a check-then-insert with the lock
		// released in between allowed. wg.Add happens in the same section
		// so shutdown()'s snapshot-then-Wait can never see a goroutine the
		// map doesn't also know how to cancel.
		m.mu.Lock()
		if m.served == nil {
			m.served = map[string]*servedMount{}
		}
		if _, already := m.served[entry.MountPath]; already {
			m.mu.Unlock()
			cancel() // a concurrent call won the claim; discard ours before any goroutine exists
			continue
		}
		m.served[entry.MountPath] = sm
		m.wg.Add(1)
		m.mu.Unlock()

		onReaderConnected := func(path string, sm *servedMount) func() {
			return func() { m.noteReaderConnected(path, sm) }
		}(entry.MountPath, sm)

		// hasLingeringReader is mount.Serve's GAPS.md #47 reuse decision:
		// after a drained cycle, isolate (rename — a filesystem event a
		// watcher will re-read on) only if something still holds the pipe
		// open. lineage.PathHeldOpen is passive (an fd-table scan) — it
		// cannot rendezvous with a reader blocked in open(2), which is what
		// makes it safe where an open()-based probe wasn't — and it errs
		// toward "held" on any structural uncertainty, so a scan problem
		// degrades to the old rename-every-cycle behavior, never to reuse
		// on a guess. The grace/recheck pacing gives the just-served reader
		// time to close before deciding it's a lingerer.
		hasLingeringReader := func(path string) func() bool {
			return func() bool {
				time.Sleep(lingerGrace)
				if !lineage.PathHeldOpen(path) {
					return false
				}
				time.Sleep(lingerRecheck)
				return lineage.PathHeldOpen(path)
			}
		}(entry.MountPath)

		go func(path string, sm *servedMount) {
			defer m.wg.Done()
			defer close(sm.done)
			onError := func(err error) {
				m.noteServeError(path, sm, err)
			}
			if err := mount.Serve(ctx, path, sm.provideContent, onError, onReaderConnected, hasLingeringReader); err != nil && !errors.Is(err, context.Canceled) {
				fmt.Fprintf(m.stderr, "jit agent: mount %s stopped: %v\n", path, err)
				// A mount whose Serve loop died structurally must not
				// stay in the map looking alive (GAPS.md #44): a stale
				// entry made every later ensureServing skip it (never
				// restarted), mountRevealStatuses report it as served, and
				// reveal "succeed" against a pipe nothing was writing to.
				// Removing it means the next unlock/refresh genuinely
				// retries it. Guarded on identity: a concurrent
				// stopMount (or a refresh that already re-claimed the
				// path) must never have ITS entry deleted by this dying
				// goroutine's cleanup.
				m.mu.Lock()
				if cur, ok := m.served[path]; ok && cur == sm {
					delete(m.served, path)
				}
				m.mu.Unlock()
			}
		}(entry.MountPath, sm)
	}
}

// resolveReal decrypts every entry's real content (needs the vault
// unlocked) and stores it on the already-running servedMount —
// re-resolving even a mount that already has real content, on purpose
// (GAPS.md #43): `jit vault set` on a secret a mount references used to
// keep serving the OLD value indefinitely, because an "already resolved"
// skip here meant nothing ever invalidated it short of a full lock. The
// decrypt cost is per unlock/refresh EVENT, not per read, so always
// re-resolving is cheap; a resolution failure logs and keeps whatever
// content the mount already had rather than downgrading it. Every
// entry that resolves successfully also gets the ergonomic default reveal
// window (GAPS.md #2): a human just proved presence (Touch ID) or jit
// migrate just registered a mount it wants to work immediately, so a dev
// server started right after either event gets real content without
// anyone typing `jit agent reveal` by hand. A mount whose resolution FAILED
// gets no window — revealing it would only put a live "revealed" countdown in
// status while every read keeps serving decoys (GAPS.md #46).
//
// That default window is a FLOOR, never a reset (GAPS.md #38, a real,
// reported bug: an explicit `jit agent reveal --for 5m` got silently cut
// down to revealDefaultWindow — 60s — the moment ANY later OnUnlock/OnRefresh
// fired, e.g. an unrelated command triggering a fresh Touch ID challenge
// or another `jit migrate` run's own Refresh call). RevealState.Reveal always
// sets the expiry to exactly d from now, so calling it unconditionally
// here would shorten a deliberately-longer window right along with
// extending a shorter or expired one — only bump a mount up to the
// default when it currently has LESS time left than that, never when it
// has more.
//
// floorReveal gates only that default-window grant, not the resolution: an
// reveal-driven unlock (OnUnlockForReveal → startForReveal) still resolves every
// mount's real content — so the explicit `jit agent reveal <path>` that
// triggered it can't be refused for "nothing real resolved" — but passes
// floorReveal=false so it floor-reveals NONE of them, leaving revealMount to reveal the
// single path the user actually named. A plain unlock/refresh passes true.
func (m *mountManager) resolveReal(entries []mount.Entry, v *vault.Vault, floorReveal bool) {
	for _, entry := range entries {
		m.mu.Lock()
		sm, ok := m.served[entry.MountPath]
		m.mu.Unlock()
		if !ok {
			continue // ensureServing should always run first; nothing to resolve into otherwise
		}

		p, err := profile.LoadFile(entry.ProfilePath)
		if err != nil {
			fmt.Fprintf(m.stderr, "jit agent: skipping mount %s: %v\n", entry.MountPath, err)
			sm.setResolveErr(err)
			continue
		}
		values, err := inject.Resolve(v, p)
		if err != nil {
			fmt.Fprintf(m.stderr, "jit agent: skipping mount %s: %v\n", entry.MountPath, err)
			sm.setResolveErr(err)
			continue
		}

		var real []byte
		if entry.TemplatePath != "" {
			tmpl, err := os.ReadFile(entry.TemplatePath) // #nosec G304 -- path comes from jit's own mount registry, not external input
			if err != nil {
				fmt.Fprintf(m.stderr, "jit agent: skipping mount %s: reading template: %v\n", entry.MountPath, err)
				sm.setResolveErr(err)
				continue
			}
			real = mount.FormatTemplate(tmpl, values)
		} else {
			real = mount.FormatDotenv(values)
		}
		sm.setReal(real)

		// The ergonomic default reveal window is granted only AFTER a
		// successful resolve — revealing a mount that has nothing real to
		// serve would make status show a live "revealed" countdown while
		// every read keeps getting decoys (the same dishonesty revealMount
		// refuses, GAPS.md #46), and it's the failure paths above that
		// make that state reachable. A resolve failure that kept an older
		// still-valid real content also deliberately gets no fresh window:
		// "couldn't re-verify" shouldn't extend exposure, only an actual
		// resolution should.
		if floorReveal && sm.reveal.Remaining() < revealDefaultWindow {
			sm.reveal.Reveal(revealDefaultWindow)
		}
	}
}

// noteReaderConnected is every mount's onReaderConnected hook (mount.Serve
// guarantees it fires after the reader connects, before provideContent, on
// the Serve goroutine). It keeps the rolling read counter, refreshes the
// best-effort lineage identity (rate-limited: the scan is a full libproc
// pid walk, and a watcher loop calling it per read is where the agent's
// CPU actually went), and logs — collapsing a storm's per-read lines into
// one summary per readLogMinGap, since 635k identical lines in one
// afternoon was itself part of the reported problem. A skipped scan keeps
// the previous pendingReader: in a storm that's overwhelmingly the same
// reader, and lineage is audit-only either way (RFC.md §5.1).
func (m *mountManager) noteReaderConnected(path string, sm *servedMount) {
	now := time.Now()
	sm.mu.Lock()
	if now.Sub(sm.readWindowStart) > time.Minute {
		sm.readWindowStart = now
		sm.readWindowCount = 0
	}
	sm.readWindowCount++
	doScan := sm.scanLast.IsZero() || now.Sub(sm.scanLast) >= lineageScanMinGap
	doLog := sm.readLogLast.IsZero() || now.Sub(sm.readLogLast) >= readLogMinGap
	suppressed := sm.readLogSuppressed
	if doScan {
		sm.scanLast = now
	}
	if doLog {
		sm.readLogLast = now
		sm.readLogSuppressed = 0
	} else {
		sm.readLogSuppressed++
	}
	sm.mu.Unlock()

	if doScan {
		pid, execPath, ok := lineage.IdentifyFIFOReader(path)
		sm.mu.Lock()
		sm.pendingReader = readerIdentity{pid: pid, execPath: execPath, identified: ok}
		sm.mu.Unlock()
	}
	if !doLog {
		return
	}
	sm.mu.Lock()
	r := sm.pendingReader
	sm.mu.Unlock()
	suffix := ""
	if suppressed > 0 {
		suffix = fmt.Sprintf(" (+%d reads since the last logged one)", suppressed)
	}
	if r.identified {
		fmt.Fprintf(m.stderr, "jit agent: mount %s: reader pid=%d (%s)%s\n", path, r.pid, r.execPath, suffix)
		return
	}
	fmt.Fprintf(m.stderr, "jit agent: mount %s: reader connected (not identified — best-effort scan missed it)%s\n", path, suffix)
}

// noteServeError logs a mount's transient write/close errors with the same
// collapse as noteReaderConnected — a watcher loop produces one broken-pipe
// line per read, which is pure repetition once the first has said what's
// happening. Never fatal, matching internal/mount's own "a write/close
// error must never stop the loop" rule.
func (m *mountManager) noteServeError(path string, sm *servedMount, err error) {
	now := time.Now()
	sm.mu.Lock()
	doLog := sm.errLogLast.IsZero() || now.Sub(sm.errLogLast) >= readLogMinGap
	suppressed := sm.errSuppressed
	if doLog {
		sm.errLogLast = now
		sm.errSuppressed = 0
	} else {
		sm.errSuppressed++
	}
	sm.mu.Unlock()
	if !doLog {
		return
	}
	suffix := ""
	if suppressed > 0 {
		suffix = fmt.Sprintf(" (+%d similar since the last logged one)", suppressed)
	}
	fmt.Fprintf(m.stderr, "jit agent: mount %s: %v (still serving)%s\n", path, err, suffix)
}

// revealMount is OnReveal's handler: an explicit `jit agent reveal` RPC, clamped to
// revealMaxWindow so "reveal forever" can never sneak back in through a caller
// requesting an enormous duration. The error return is OpReveal's own
// success/failure — a mount-path mismatch (e.g. the CLI forwarding a
// relative path that never matches this map's absolute keys) used to
// silently reveal nothing while still printing "Revealed ... for 5m0s."
//
// Revealing a mount with no real content resolved is refused, not silently
// granted (GAPS.md #46, a real defect found by investigation): the
// session is guaranteed unlocked by the time OpReveal gets here (Server
// ensureUnlocked's a fresh challenge fires OnUnlock → resolveReal before
// OnReveal), so real == nil means resolution itself FAILED — and "Revealed for
// 5m0s" plus a live status countdown while every read kept serving decoys,
// with the actual error visible only in the agent's own log file, is
// exactly the "reveal isn't working and nothing says why" experience.
func (m *mountManager) revealMount(mountPath string, requested time.Duration) error {
	m.mu.Lock()
	sm, ok := m.served[mountPath]
	m.mu.Unlock()
	if !ok {
		fmt.Fprintf(m.stderr, "jit agent: reveal requested for %s, which isn't currently served\n", mountPath)
		return fmt.Errorf("no such mount: %s", mountPath)
	}

	sm.mu.Lock()
	hasReal := sm.real != nil
	resolveErr := sm.lastResolveErr
	sm.mu.Unlock()
	if !hasReal {
		msg := fmt.Sprintf("%s has nothing real to serve — revealing it would only keep serving placeholder values", mountPath)
		if resolveErr != "" {
			msg = fmt.Sprintf("%s (resolving its secrets failed: %s)", msg, resolveErr)
		}
		fmt.Fprintf(m.stderr, "jit agent: reveal refused: %s\n", msg)
		return errors.New(msg)
	}

	d := requested
	if d <= 0 {
		d = revealDefaultWindow
	}
	if d > revealMaxWindow {
		d = revealMaxWindow
	}
	sm.reveal.Reveal(d)
	fmt.Fprintf(m.stdout, "jit agent: revealed %s for %s\n", mountPath, d.Round(time.Second))
	return nil
}

// mountRevealStatuses is OnMountStatus's handler (GAPS.md #37) — a snapshot
// of every currently-served mount's reveal state, needing no vault access
// at all (same reasoning as stopMount/OnStopMount), so it's answered
// regardless of lock state. `jit status`/`jit agent status` use this
// to show "which mount is revealed and for how long" instead of leaving
// that entirely invisible outside the agent process itself — a real,
// reported point of confusion: a reveal appearing to silently "not work"
// was actually the agent's own session lock racing the mount's reveal
// window, with no way to see either timer from outside the process.
func (m *mountManager) mountRevealStatuses() []agent.MountRevealStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]agent.MountRevealStatus, 0, len(m.served))
	for path, sm := range m.served {
		remaining := sm.reveal.Remaining()
		status := agent.MountRevealStatus{
			Path:               path,
			Revealed:           remaining > 0,
			RevealedForSeconds: int64(remaining.Round(time.Second).Seconds()),
		}
		// Expiry is lazy — nothing fires when a window ends — so status is
		// the only place "the timer ended" can become visible at all;
		// without this, the revealed line just silently disappears (a real,
		// reported confusion: "it's not switching to hidden").
		if ended, ok := sm.reveal.WindowEnded(); ok {
			status.RevealEndedUnix = ended.Unix()
		}
		sm.mu.Lock()
		if ls := sm.lastServe; ls != nil {
			status.LastServe = &agent.MountServeEvent{UnixTime: ls.at.Unix(), Decoy: ls.decoy}
			if ls.reader.identified {
				status.LastServe.ReaderPID = ls.reader.pid
				status.LastServe.ReaderPath = ls.reader.execPath
			}
		}
		if time.Since(sm.readWindowStart) <= time.Minute {
			status.ReadsLastMinute = sm.readWindowCount
		}
		sm.mu.Unlock()
		out = append(out, status)
	}
	return out
}

// startDecoyOnly ensures every registered mount has at least decoy
// serving running. Safe to call unconditionally, including at raw agent
// startup before any unlock has ever happened — see the type doc comment
// for why that's true (no vault access, so no Touch ID risk).
func (m *mountManager) startDecoyOnly() {
	entries, ok := m.loadRegistry()
	if !ok {
		return
	}
	m.ensureServing(entries)
}

// start is OnUnlock/OnRefresh's handler: makes sure decoy serving is
// running for anything registered since the last call (startDecoyOnly's
// own job, repeated here since a mount can appear in between), then
// resolves real content for anything not yet resolved — the part that
// actually needs the vault, which is why this is never called from raw
// agent startup, only after an actual unlock. Floor-reveals every
// successfully-resolved mount (the ergonomic "a human just unlocked"
// default) — see startForReveal for the scoped variant.
func (m *mountManager) start() { m.startResolving(true) }

// startForReveal is OnUnlockForReveal's handler: identical to start EXCEPT it
// floor-reveals nothing. Used only for the fresh challenge an explicit `jit
// agent reveal <path>` triggers, so that reveal lights up only the path the user
// named (revealMount, running right after, reveals it) instead of every mount.
func (m *mountManager) startForReveal() { m.startResolving(false) }

func (m *mountManager) startResolving(floorReveal bool) {
	entries, ok := m.loadRegistry()
	if !ok {
		return
	}
	m.ensureServing(entries)

	deviceID, err := vault.EnsureDeviceID(m.root)
	if err != nil {
		fmt.Fprintf(m.stderr, "jit agent: determining device recipient ID: %v\n", err)
		return
	}
	v := &vault.Vault{Root: m.root, KeyWrapper: m.keyWrapper, RecipientID: deviceID}
	m.resolveReal(entries, v, floorReveal)
}

// stop is OnLock's handler — GAPS.md #35's core change from the previous
// design: it no longer cancels anything. Every servedMount's real
// content is forgotten and its reveal window ended immediately (Hide, not
// waiting for natural expiry), so provideContent instantly falls back to
// decoy on the very next reader — but the Serve goroutine itself, and
// therefore the pipe's writer, is left running. Locking no longer means
// "nothing is listening"; it only means "nothing real is being served."
func (m *mountManager) stop() {
	m.mu.Lock()
	served := make([]*servedMount, 0, len(m.served))
	for _, sm := range m.served {
		served = append(served, sm)
	}
	m.mu.Unlock()

	for _, sm := range served {
		sm.setReal(nil)
		sm.reveal.Hide()
	}
	if len(served) > 0 {
		fmt.Fprintln(m.stdout, "jit agent: session locked, mounts now serving decoy content only")
	}
}

// stopMount is OnStopMount's handler — the per-mount stop this file's
// previous design didn't have yet (its own comment used to note "no
// per-mount stop yet, only mountManager's shared context" as the reason
// jit unmount locked the WHOLE agent first). `jit unmount` uses this
// instead now: cancel just the one mount actually being reversed, so
// replacing its FIFO with a regular file can never race an active
// Serve() write cycle, without disturbing any other mount's decoy/real
// serving at all.
//
// Waiting on sm.done (GAPS.md #36) is not optional: cancel() only asks
// the goroutine to stop at its next chance to check — if a reader was
// already connected when cancel() was called, the in-flight cycle still
// finishes writing and calls recreateFIFO (which unconditionally puts a
// fresh pipe back at path) before it ever notices the cancellation. A
// caller that replaces the file the instant cancel() returns can lose
// that race: their fresh plaintext gets clobbered back into an empty
// FIFO by the cycle that was already in flight. Blocking here until the
// goroutine has actually returned is what makes it safe for jit unmount
// to touch the file immediately afterward.
func (m *mountManager) stopMount(path string) {
	m.mu.Lock()
	sm, ok := m.served[path]
	if ok {
		delete(m.served, path)
	}
	m.mu.Unlock()
	if ok {
		sm.cancel()
		<-sm.done
	}
}

// shutdown tears down every mount's Serve goroutine — used only when the
// agent PROCESS itself is exiting (unlike stop/OnLock, which now leaves
// decoy serving running through a lock). Waits for every goroutine to
// actually return before returning itself, so a caller that immediately
// closes the listening socket afterward never races an in-flight write.
func (m *mountManager) shutdown() {
	m.mu.Lock()
	served := m.served
	m.served = nil
	m.mu.Unlock()

	for _, sm := range served {
		sm.cancel()
	}
	m.wg.Wait()
}
