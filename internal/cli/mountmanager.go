// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

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
// rolling minute gets a named heads-up in `jit service status`, since the
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

// readerConsent decides best-effort per-reader consent for a FIFO credential
// mount. Implemented by *agent.Server (ConsentReaders); nil on mountManager
// means consent is off, and the serve path keeps its exact pre-consent
// behavior (grant-or-decoy).
type readerConsent interface {
	ConsentReaders(cred string, holders []int32) bool
}

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
	home       string
	keyWrapper vault.KeyWrapper
	// refResolver resolves reference-kind secrets (1Password links) during
	// resolveReal — one shared instance, so the op binary's signature is
	// verified once per service process, not once per refresh. Resolution
	// fires only at unlock/refresh (the user just passed Touch ID, so they
	// are present for a 1Password prompt too) and is bounded by the
	// resolver's own timeout; a failure keeps the mount on decoys via the
	// existing lastResolveErr path. Nil in tests that never resolve.
	refResolver vault.RefResolver
	consent     readerConsent
	stdout      io.Writer
	stderr      io.Writer

	// serveAudit turns mount reads into durable `jit audit` events, collapsed
	// so a watcher loop can't evict the trail it is being written to. Zero
	// value (no emit) is inert, so every test that constructs a bare
	// mountManager keeps working and pays nothing.
	serveAudit serveAuditor

	mu     sync.Mutex
	wg     sync.WaitGroup
	served map[string]*servedMount
	// skipReason/skipSuppressed make mount-skip logging transitional: a
	// mount that structurally cannot serve or resolve (deleted profile, an
	// envelope version newer than this build) is retried on EVERY unlock and
	// refresh, and each pass used to log the identical line — the 2026-08-17
	// incident's log was hours of it, every few minutes, drowning the
	// startup and serve-error lines the log exists to surface. A skip now
	// logs when its reason CHANGES (appears, changes text, clears); the
	// steady state stays visible through lastResolveErr on the status
	// surfaces. Keyed by mount path, guarded by mu; both the ensureServing
	// skips (mount never entered served) and the resolveReal skips share it.
	skipReason   map[string]string
	skipAttempts map[string]int
	// shuttingDown is set once by shutdown() (under mu) so ensureServing
	// refuses to start — and wg.Add — a new Serve goroutine after shutdown
	// snapshotted served and began wg.Wait(). Without it, an in-flight RPC's
	// OnUnlock -> ensureServing racing process teardown could Add to a
	// WaitGroup already being Waited (panic) or leak an un-cancellable
	// goroutine into a fresh map shutdown no longer consults.
	shuttingDown bool

	// Run-scoped grant exit watcher (mountgrants.go): the kqueue fd (0
	// unstarted, -1 permanently unavailable) and which pids are armed on
	// it. Its own mutex — watch registration happens on RPC goroutines and
	// must never contend with the serve-path's m.mu.
	watchMu      sync.Mutex
	grantKq      int
	grantWatched map[runWatchKey]bool

	// The unified run engine (mountruns.go): runs is the single registry of
	// jit-run attachments, in either mode (grant or swap), keyed by pid.
	// runsMu guards it and is taken only briefly — never across a blocking
	// call. grantModeRuns is the read path's fast-path counter: with no
	// grant-mode run active, serveContent skips the grant gate entirely and
	// a read costs exactly what it did before grants existed. swapMu
	// serializes swap-mode FILESYSTEM transitions (swap-in vs restore) and
	// is never taken ON the serve/read goroutine (the read gate defers a
	// swapMu-taking FIFO restore to a detached goroutine), so a swap-in
	// holding it across stopMount can't deadlock an in-flight serve cycle.
	runsMu        sync.Mutex
	runs          map[int32]*runAttachment
	grantModeRuns int32
	swapMu        sync.Mutex

	// Test seams for the grant gate's kernel lookups (mountgrants.go);
	// nil means the real internal/lineage implementations. The gate's
	// logic — fail-closed rules, verdict caching, pruning — is what unit
	// tests need to pin down, and none of it should require spawning real
	// process trees to observe.
	grantHoldersFn  func(path string) (pids []int32, ok bool)
	grantAncestryFn func(pid, root int32) bool
	grantStartFn    func(pid int32) (unixMicro int64, ok bool)

	// identifyRetryFn is finalizeServe's post-write identity scan; nil means
	// lineage.IdentifyFIFOReader. A seam for the same reason the grant ones
	// are: the retry's gating (delivered-only, missed-scan-only) is what
	// tests pin down, and none of it should need a real lingering reader.
	identifyRetryFn func(path string) (pid int32, execPath string, ok bool)
}

// readerIdentity is internal/lineage's best-effort answer to "who just
// opened this mount" — audit-only (RFC.md §5.1), never consulted by the
// content decision itself. identified=false means the scan missed the
// reader, which a fast-closing reader legitimately can.
type readerIdentity struct {
	pid      int32
	execPath string
	// launchedBy is what launched the reader ("claude", "Code") — the same
	// question the agent answers about whoever unlocked the vault, asked of
	// whoever read the secret. "python3 read your Wiz credentials" is a fact;
	// "python3, launched by claude, read your Wiz credentials" is the one you
	// can act on.
	launchedBy string
	identified bool
	// likely marks an identity carried over from this mount's previous scan
	// rather than found by this one. The scan is rate-limited and a
	// fast-closing reader evades it outright, so a mount being re-read in a
	// watcher loop produced a stream of "an unidentified process" lines —
	// about a process jit had identified seconds earlier, and which is still
	// holding the file open. Carrying it forward (only while that same pid is
	// still alive and still running the same executable, so pid reuse can't
	// launder one process's identity onto another) turns a useless line into a
	// useful one. Marked "likely", never asserted: it is an inference, and the
	// display says so.
	likely bool
}

// serveRecord is one completed content decision: what a connected reader
// was served, when, and (best-effort) by whom. Two consumers, deliberately
// different in lifetime: each mount keeps its single most recent record so
// `jit service status` can answer "why did my app get decoys" about right
// now, and every record is also handed to serveAuditor, which collapses
// them into the durable `jit audit` trail (RFC.md §5's anomaly signal).
// The in-memory one answers "what is happening"; the durable one answers
// "what happened last Tuesday", and neither substitutes for the other.
type serveRecord struct {
	at     time.Time
	decoy  bool
	reader readerIdentity
	// grantServed marks a real serve authorized by a run-scoped grant
	// (mountgrants.go) — which is the only way real content ever flows now.
	// Status reports it so a real serve reads as "only this run's tree could
	// have read it", never an ambient exposure.
	grantServed bool
	// undelivered marks a cycle whose reader received nothing: the write hit
	// EPIPE, proof that zero processes held the read end when content was
	// sent. The decision (decoy/real) still happened; delivery didn't — and
	// recording the two as the same fact was overstating exposure, which for
	// a tripwire trail is the wrong direction to be wrong in.
	undelivered bool
}

// pendingServe is a serveRecord between its two moments: the content
// DECISION (serveContent, before the write) and the cycle's OUTCOME
// (finalizeServe, after it — did the reader actually receive anything).
// The reason is captured at decision time because it explains the verdict,
// which is decided then; the outcome only annotates it.
type pendingServe struct {
	rec    serveRecord
	reason string
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
	done chan struct{}

	mu    sync.Mutex
	decoy []byte
	real  []byte // nil until resolveReal succeeds; cleared again by stop()
	// gen advances every time the session locks (invalidateReal). resolveReal
	// captures it before its decrypt and only installs real content if it is
	// still unchanged afterward, so a resolve that was mid-decrypt when the
	// session locked can't re-arm real content on a mount the lock just
	// cleared — the race that let a mount serve real values while `jit service
	// status` reported "locked". serveContent gates real content on real !=
	// nil + an active grant, never on the session directly, so keeping real
	// truthfully nil while locked is what the whole guarantee rests on.
	gen uint64
	// lastResolveErr is why real is still nil (or last failed to refresh) —
	// what a grant's refusal carries so `jit run --live/--with` can say WHY
	// it can't serve anything real, instead of that living only in the
	// agent's own log (GAPS.md #46). Cleared on every successful resolve.
	lastResolveErr string
	// pendingReader is set by the onReaderConnected hook (which mount.Serve
	// guarantees fires before provideContent in the same cycle, on the same
	// goroutine); provideContent captures it into pendingServe when it
	// decides what that reader gets, and finalizeServe — the onCycleEnd
	// hook, same cycle, same goroutine — folds that into lastServe and the
	// durable trail once the write's outcome is known.
	pendingReader readerIdentity
	pendingServe  *pendingServe
	// scanMissed is true when THIS cycle's lineage scan actually ran and
	// found nobody (not when the rate limit skipped it) — the one case
	// finalizeServe spends a second scan on. Set by noteReaderConnected,
	// consumed and cleared by finalizeServe, both on the Serve goroutine.
	scanMissed bool
	lastServe  *serveRecord

	// grantVerdicts is this mount's per-(holder,root) ancestry verdict
	// cache — the read gate's amortization of the libproc ancestry walk
	// (mountgrants.go). Nil for any mount no grant run ever touched. The
	// grant attachments themselves live in the run registry (mountruns.go),
	// not here: this is only the gate's cache.
	grantVerdicts map[grantVerdictKey]grantVerdict

	// consentVerdict caches the best-effort per-reader consent decision
	// (mountgrants.go's consent fallback) so a mount read repeatedly by the
	// same holder set doesn't re-run the per-holder libproc identity scan and
	// trust-ancestry walk on every read. Keyed on the exact holder pid-set: a
	// changed set (a new stranger joins, a holder leaves) misses and
	// re-evaluates, so the cache can never let a reader who wasn't in the
	// authorized set ride another's verdict. Nil for any mount consent never
	// gated. Same short TTL and best-effort doctrine as grantVerdicts.
	consentVerdict *consentVerdict

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

// captureGen reads the mount's current resolve generation, for resolveReal
// to hand back to setRealIfGen after its decrypt.
func (sm *servedMount) captureGen() uint64 {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.gen
}

// setRealIfGen installs resolved real content only if the generation is
// unchanged since gen was captured — i.e. no invalidateReal (a session lock)
// intervened during the decrypt. Returns false when a lock raced the resolve,
// discarding the content so the mount stays decoy rather than re-arming real
// values the lock had just cleared.
func (sm *servedMount) setRealIfGen(b []byte, gen uint64) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sm.gen != gen {
		return false
	}
	sm.real = b
	sm.lastResolveErr = ""
	return true
}

// invalidateReal drops any resolved real content and advances the generation
// so an in-flight resolveReal can't install stale real bytes afterward
// (setRealIfGen). Returns whether there was real content to drop, so a lock
// that clears nothing can stay silent.
func (sm *servedMount) invalidateReal() bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	had := sm.real != nil
	sm.gen++
	sm.real = nil
	sm.lastResolveErr = ""
	return had
}

func (sm *servedMount) setResolveErr(err error) {
	sm.mu.Lock()
	sm.lastResolveErr = err.Error()
	sm.mu.Unlock()
}

// noteMountSkip records that path was skipped for err and reports whether to
// log it: only on a transition (the first failure, or the reason changing).
// Identical repeats are counted, not logged; noteMountRecovered surfaces the
// count when the mount comes back.
func (m *mountManager) noteMountSkip(path string, err error) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.skipReason == nil {
		m.skipReason = map[string]string{}
		m.skipAttempts = map[string]int{}
	}
	m.skipAttempts[path]++
	cur := err.Error()
	if m.skipReason[path] == cur {
		return false
	}
	m.skipReason[path] = cur
	return true
}

// noteMountRecovered clears path's skip state. attempts is how many times
// the mount was skipped in total since it started failing (across reason
// changes); recovered is false when the mount was never failing, which is
// every ordinary resolve.
func (m *mountManager) noteMountRecovered(path string) (attempts int, recovered bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.skipReason[path]; !ok {
		return 0, false
	}
	attempts = m.skipAttempts[path]
	delete(m.skipReason, path)
	delete(m.skipAttempts, path)
	return attempts, true
}

// logMountSkip is every skip site's one exit: transition-gated, and phrased
// as "mount <path>: skipped, <reason>" so `jit service log` folds and
// path-shortens it like any other mount row (the old "skipping mount X"
// shape matched none of the view's machinery and rendered green).
func (m *mountManager) logMountSkip(path string, err error) {
	if m.noteMountSkip(path, err) {
		fmt.Fprintf(m.stderr, "jit service: mount %s: skipped, %v\n", path, err)
	}
}

// logMountRecovered is the clear half of the transition: one line saying the
// mount is back, carrying how many attempts the suppression absorbed.
func (m *mountManager) logMountRecovered(path string) {
	if attempts, recovered := m.noteMountRecovered(path); recovered {
		fmt.Fprintf(m.stdout, "jit service: mount %s: recovered, serving again (%s before this)\n",
			path, countWord(attempts, "skipped attempt", "skipped attempts"))
	}
}

// loadRegistry reads the mount registry, logging (not erroring — this
// runs from hooks with no caller to return an error to) on failure.
func (m *mountManager) loadRegistry() ([]mount.Entry, bool) {
	entries, err := mount.LoadRegistry(mount.RegistryPath(m.root))
	if err != nil {
		fmt.Fprintf(m.stderr, "jit service: reading the list of mounted files: %v\n", err)
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

		p, varOrder, err := profile.LoadFileOrdered(entry.ProfilePath)
		if err != nil {
			m.logMountSkip(entry.MountPath, err)
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
				m.logMountSkip(entry.MountPath, fmt.Errorf("reading template: %w", err))
				continue
			}
			decoy = mount.FormatTemplate(tmpl, decoyValues)
		} else {
			decoy = mount.FormatDotenv(decoyValues, varOrder)
		}
		// Decoy content self-diagnoses: whoever opens the file sees what
		// these values are and the one command that fixes it, instead of
		// debugging `jit-hidden-*` strings through their app's own
		// error output. Real content never carries this line.
		decoy = append(mount.DecoyNotice(), decoy...)

		sm := &servedMount{decoy: decoy, done: make(chan struct{})}
		ctx, cancel := context.WithCancel(context.Background())
		sm.cancel = cancel

		// Claim the slot and re-check under ONE lock — see the function
		// doc comment for the real race a check-then-insert with the lock
		// released in between allowed. wg.Add happens in the same section
		// so shutdown()'s snapshot-then-Wait can never see a goroutine the
		// map doesn't also know how to cancel.
		m.mu.Lock()
		if m.shuttingDown {
			// The process is tearing down; do not start (and wg.Add) a new
			// goroutine shutdown's snapshot can't cancel and its wg.Wait would
			// then block on forever.
			m.mu.Unlock()
			cancel()
			continue
		}
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
		// A mount that had been skipped (deleted profile, unreadable
		// template) and now serves again closes its skip transition here —
		// resolveReal closes the resolve-failure kind on its own success.
		m.logMountRecovered(entry.MountPath)

		onReaderConnected := func(path string, sm *servedMount) func() {
			return func() { m.noteReaderConnected(path, sm) }
		}(entry.MountPath, sm)

		// serveContent (mountgrants.go) is the single content decision:
		// real only to a run-scoped grant's process tree, decoy otherwise.
		// It needs the mount path for the grant gate's holder scan; with no
		// grant run active the gate is skipped and a read costs exactly what
		// a bare decoy decision did.
		provideContent := func(path string, sm *servedMount) func() []byte {
			return func() []byte { return m.serveContent(path, sm) }
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

		// finalizeServe is the record's second half: serveContent decided
		// what to serve, this learns whether it was received, and only then
		// does the record reach lastServe and the durable trail.
		onCycleEnd := func(path string, sm *servedMount) func(bool) {
			return func(delivered bool) { m.finalizeServe(path, sm, delivered) }
		}(entry.MountPath, sm)

		go func(path string, sm *servedMount) {
			defer m.wg.Done()
			defer close(sm.done)
			onError := func(err error) {
				m.noteServeError(path, sm, err)
			}
			if err := mount.Serve(ctx, path, provideContent, onError, onReaderConnected, hasLingeringReader, onCycleEnd); err != nil && !errors.Is(err, context.Canceled) {
				fmt.Fprintf(m.stderr, "jit service: mount %s stopped: %v\n", path, err)
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
// content the mount already had rather than downgrading it.
//
// Resolution ARMS real content in memory but NEVER reveals it: unlocking
// the vault does not make any mount serve real values. A mount's real
// content flows only to a run-scoped grant's own process tree (jit run
// --live / --with); every other reader, at every other time, gets decoys.
// There is no automatic reveal window and no manual reveal command.
func (m *mountManager) resolveReal(entries []mount.Entry, v *vault.Vault) {
	for _, entry := range entries {
		m.mu.Lock()
		sm, ok := m.served[entry.MountPath]
		m.mu.Unlock()
		if !ok {
			continue // ensureServing should always run first; nothing to resolve into otherwise
		}

		// Capture the resolve generation BEFORE the slow decrypt below. If a
		// lock (invalidateReal) lands while inject.Resolve is running,
		// setRealIfGen sees the bumped generation and discards this content,
		// so a resolve can never re-arm real values on a mount the lock just
		// hid (the "serves real while status says locked" race).
		gen := sm.captureGen()

		p, varOrder, err := profile.LoadFileOrdered(entry.ProfilePath)
		if err != nil {
			m.logMountSkip(entry.MountPath, err)
			sm.setResolveErr(err)
			continue
		}
		values, err := inject.Resolve(v, p)
		if err != nil {
			m.logMountSkip(entry.MountPath, err)
			sm.setResolveErr(err)
			continue
		}

		var real []byte
		if entry.TemplatePath != "" {
			tmpl, err := os.ReadFile(entry.TemplatePath) // #nosec G304 -- path comes from jit's own mount registry, not external input
			if err != nil {
				m.logMountSkip(entry.MountPath, fmt.Errorf("reading template: %w", err))
				sm.setResolveErr(err)
				continue
			}
			real = mount.FormatTemplate(tmpl, values)
		} else {
			real = mount.FormatDotenv(values, varOrder)
		}
		if !sm.setRealIfGen(real, gen) {
			continue // a lock raced this resolve; leave the mount decoy
		}
		m.logMountRecovered(entry.MountPath)
		// Resolution only ARMS the real content in memory; it never opens a
		// window. A mount serves that real content solely to a run-scoped
		// grant's own process tree (jit run --live / --with) — there is no
		// automatic reveal. Every other reader gets decoys.
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
		sm.mu.Lock()
		previous := sm.pendingReader
		sm.mu.Unlock()

		next := identifyReader(path, previous)

		sm.mu.Lock()
		sm.pendingReader = next
		// A scan that ran and found nobody (not one the rate limit skipped)
		// is finalizeServe's cue to try once more after the write, when a
		// slow reader is still holding the pipe. Cleared there.
		sm.scanMissed = !next.identified
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
		qualifier := ""
		if r.likely {
			qualifier = " (still holding it open; this scan missed the open itself)"
		}
		launcher := ""
		if r.launchedBy != "" {
			launcher = fmt.Sprintf(", launched by %s", r.launchedBy)
		}
		fmt.Fprintf(m.stderr, "jit service: mount %s: reader pid=%d (%s)%s%s%s\n", path, r.pid, r.execPath, launcher, qualifier, suffix)
		return
	}
	fmt.Fprintf(m.stderr, "jit service: mount %s: reader connected (not identified, best-effort scan missed it)%s\n", path, suffix)
}

// identifyReader is the best-effort "who is reading this mount" scan, with a
// fallback to whoever this mount's PREVIOUS scan found.
//
// The fallback exists because the plain scan produced a genuinely useless log:
// a mount in an editor's watcher loop alternated between "reader pid=57346
// (…/Code)" and "reader connected (not identified — best-effort scan missed
// it)" — the same editor both times, one of which jit had just named. The scan
// is rate-limited and races a reader that closes fast, so misses are normal,
// not exceptional.
//
// Carried forward only while the remembered pid is still alive AND still
// running the same executable: pids get reused, and without that check a
// recycled pid would let jit attribute one process's read to another program
// entirely — an audit log that lies is worse than one that admits it doesn't
// know. The result is marked likely, and every display of it says so.
func identifyReader(path string, previous readerIdentity) readerIdentity {
	if pid, execPath, ok := lineage.IdentifyFIFOReader(path); ok {
		return readerIdentity{
			pid:        pid,
			execPath:   execPath,
			launchedBy: launcherOf(pid),
			identified: true,
		}
	}
	if previous.identified && stillRunning(previous) {
		previous.likely = true
		return previous
	}
	return readerIdentity{}
}

// stillRunning reports whether a remembered reader is still the same live
// process — same pid, still executing the same binary. The exec-path check is
// what makes pid reuse safe to ignore.
func stillRunning(r readerIdentity) bool {
	p, ok := lineage.Describe(r.pid)
	return ok && p.ExecPath == r.execPath
}

// launcherOf names what launched pid, skipping relay shells — the mount's
// answer to the same question `jit service status` answers about an unlock.
func launcherOf(pid int32) string {
	chain := lineage.Ancestry(pid)
	if len(chain) < 2 {
		return ""
	}
	return lineage.LaunchedBy(chain[1:])
}

// finalizeServe is every mount's onCycleEnd hook (mount.Serve guarantees it
// fires once per cycle, after the write and close, on the Serve goroutine).
// It completes the record serveContent opened: folds in whether the reader
// actually RECEIVED the content (delivered=false is EPIPE — proof it got
// nothing), spends one more identity scan when this cycle's scan ran and
// missed a reader that turned out to linger, and only then publishes the
// record to lastServe and the durable trail. Recording at decision time —
// the old shape — wrote "decoy served" for cycles that delivered nothing,
// and left a late-found identity with no record to land in.
func (m *mountManager) finalizeServe(path string, sm *servedMount, delivered bool) {
	sm.mu.Lock()
	ps := sm.pendingServe
	sm.pendingServe = nil
	missed := sm.scanMissed
	sm.scanMissed = false
	sm.mu.Unlock()
	if ps == nil {
		return // no decision this cycle (cannot happen in Serve's contract; refuse to invent one)
	}
	rec := ps.rec
	rec.undelivered = !delivered

	// The second scan, bounded on purpose: only when content was delivered
	// (an EPIPE reader is provably gone), only when this cycle's own scan ran
	// and found nobody (so it inherits noteReaderConnected's rate limit — at
	// most one extra walk per lineageScanMinGap per mount, and none at all in
	// an identified reader's storm). Marked likely, never asserted: whoever
	// holds the pipe now almost certainly is this cycle's reader, but a
	// brand-new non-blocking reader could have arrived in the gap.
	if delivered && missed && !rec.reader.identified {
		identify := m.identifyRetryFn
		if identify == nil {
			identify = lineage.IdentifyFIFOReader
		}
		if pid, execPath, ok := identify(path); ok {
			r := readerIdentity{
				pid:        pid,
				execPath:   execPath,
				launchedBy: launcherOf(pid),
				identified: true,
				likely:     true,
			}
			rec.reader = r
			// Feed the carry-forward too: the next cycle's skipped or missed
			// scan can now name this reader instead of starting from nothing.
			sm.mu.Lock()
			sm.pendingReader = r
			sm.mu.Unlock()
		}
	}

	sm.mu.Lock()
	sm.lastServe = &rec
	sm.mu.Unlock()
	// Outside sm.mu for the same reason serveContent kept it there: the
	// auditor takes its own lock and may append to a file.
	m.serveAudit.record(rec.at, path, ps.reason, rec)
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
	fmt.Fprintf(m.stderr, "jit service: mount %s: %v (still serving)%s\n", path, err, suffix)
}

// mountRevealStatuses is OnMountStatus's handler (GAPS.md #37) — a snapshot
// of every currently-served mount's state, needing no vault access at all
// (same reasoning as stopMount/OnStopMount), so it's answered regardless of
// lock state. `jit status`/`jit service status` use this to show which mounts
// are currently grant-served (and to which run) versus serving decoys, plus
// what the most recent reader was actually handed.
func (m *mountManager) mountRevealStatuses() []agent.MountRevealStatus {
	// Gather run holders FIRST, before taking m.mu: runStatusesByPath prunes
	// stale runs, and a pruned swap restores its FIFO via ensureServing,
	// which takes m.mu — so nesting this inside m.mu would deadlock. The two
	// locks are only ever taken sequentially, never nested.
	holdersByPath := m.runStatusesByPath()

	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]agent.MountRevealStatus, 0, len(m.served))
	for path, sm := range m.served {
		status := agent.MountRevealStatus{Path: path}
		// Grant-mode runs covering this served mount, from the registry.
		for _, h := range holdersByPath[path] {
			if h.mode == attachGrant {
				status.Grants = append(status.Grants, agent.MountGrantStatus{PID: h.pid, Command: h.command, SinceUnix: h.since.Unix()})
			}
		}
		sm.mu.Lock()
		if ls := sm.lastServe; ls != nil {
			status.LastServe = &agent.MountServeEvent{UnixTime: ls.at.Unix(), Decoy: ls.decoy, GrantServed: ls.grantServed, Undelivered: ls.undelivered}
			if ls.reader.identified {
				status.LastServe.ReaderPID = ls.reader.pid
				status.LastServe.ReaderPath = ls.reader.execPath
				status.LastServe.ReaderLaunchedBy = ls.reader.launchedBy
				status.LastServe.ReaderLikely = ls.reader.likely
			}
		}
		if time.Since(sm.readWindowStart) <= time.Minute {
			status.ReadsLastMinute = sm.readWindowCount
		}
		sm.mu.Unlock()
		out = append(out, status)
	}
	// Swapped mounts aren't in m.served (their Serve goroutine is stopped
	// while they're a plain file), so add them separately — one status entry
	// per swapped path, its holding run(s) in Grants.
	for path, holders := range holdersByPath {
		if _, served := m.served[path]; served {
			continue // already covered above (a grant-mode mount stays served)
		}
		st := agent.MountRevealStatus{Path: path, Swapped: true}
		for _, h := range holders {
			st.Grants = append(st.Grants, agent.MountGrantStatus{PID: h.pid, Command: h.command, SinceUnix: h.since.Unix()})
		}
		out = append(out, st)
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
	m.reconcileSwappedMounts(entries)
	m.ensureServing(entries)
}

// reconcileSwappedMounts repairs the one state a crash mid-run can leave:
// a registry entry whose path is a leftover compatibility pointer file (the
// agent died while a jit run had it swapped), which ensureServing would
// then try to serve as if it were a FIFO — its blocking O_WRONLY open would
// instead succeed against the regular file and write decoy bytes into it.
// For each such path that is provably jit's OWN swap artifact
// (IsSwapPointerFile — the provenance gate), restore the FIFO before
// serving. A regular file at a mount path that is NOT jit's swap artifact
// (a user restored real content by hand) is left untouched and surfaced,
// never clobbered — the swap file holds no secret, so a leftover is only an
// availability blip, and overwriting a user's deliberate file would be far
// worse. Safe at raw startup: no vault access, same as the rest of this
// path.
func (m *mountManager) reconcileSwappedMounts(entries []mount.Entry) {
	for _, e := range entries {
		if !mount.IsSwapPointerFile(e.MountPath) {
			continue
		}
		if err := mount.RestoreFIFO(e.MountPath); err != nil {
			fmt.Fprintf(m.stderr, "jit service: mount %s: restoring FIFO from a leftover compatibility file failed: %v\n", e.MountPath, err)
			continue
		}
		fmt.Fprintf(m.stdout, "jit service: mount %s: restored the decoy mount from a compatibility file left by an interrupted run\n", e.MountPath)
	}
}

// start is OnUnlock/OnRefresh's handler: makes sure decoy serving is
// running for anything registered since the last call (startDecoyOnly's
// own job, repeated here since a mount can appear in between), then
// resolves real content for anything not yet resolved — the part that
// actually needs the vault, which is why this is never called from raw
// agent startup, only after an actual unlock. Resolving ARMS real content
// in memory but reveals nothing: a mount serves it only to a run-scoped
// grant's process tree (jit run --live / --with).
func (m *mountManager) start() {
	entries, ok := m.loadRegistry()
	if !ok {
		return
	}
	m.ensureServing(entries)

	deviceID, err := vault.EnsureDeviceID(m.root)
	if err != nil {
		fmt.Fprintf(m.stderr, "jit service: determining device recipient ID: %v\n", err)
		return
	}
	v := &vault.Vault{Root: m.root, KeyWrapper: m.keyWrapper, RecipientID: deviceID, RefResolver: m.refResolver}
	m.resolveReal(entries, v)
}

// stop is OnLock's handler — GAPS.md #35's core change from the previous
// design: it no longer cancels anything. Every servedMount's real
// content is forgotten immediately, so provideContent instantly falls back
// to decoy on the very next reader — but the Serve goroutine itself, and
// therefore the pipe's writer, is left running. Locking no longer means
// "nothing is listening"; it only means "nothing real is being served."
func (m *mountManager) stop() {
	m.mu.Lock()
	served := make([]*servedMount, 0, len(m.served))
	for _, sm := range m.served {
		served = append(served, sm)
	}
	m.mu.Unlock()

	cleared := false
	for _, sm := range served {
		if sm.invalidateReal() {
			cleared = true
		}
	}
	// Every run attachment ends with the session — see clearAllRuns for
	// why this isn't only hygiene.
	m.clearAllRuns()
	if cleared {
		// Print only when this lock actually hid something (some mount had
		// real content): stop() now also runs on a
		// lazy-expiry lock where the MEK was already nil'd, and a lock that
		// changed nothing should stay silent. Deliberately no longer says
		// "session locked" — Server's own OnSessionEvent line, written
		// immediately before this one, announces the lock AND names its cause
		// (idle timeout vs. explicit). This line reports only what it alone
		// knows: the consequence for the mounts.
		fmt.Fprintln(m.stdout, "jit service: mounts now serving decoy content only")
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
	m.shuttingDown = true
	served := m.served
	m.served = nil
	m.mu.Unlock()

	for _, sm := range served {
		sm.cancel()
	}
	m.wg.Wait()
	// After wg.Wait, so the last in-flight serve's event is already recorded
	// and gets written by this flush rather than being dropped.
	m.serveAudit.stopFlusher()
}
