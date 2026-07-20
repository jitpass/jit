// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/vault"
)

// TestEnsureServingConcurrentCallsClaimSlotOnce is the regression test for
// a real TOCTOU race: ensureServing's "already served?" check and its map
// insert used to be two separate lock acquisitions with profile loading in
// between, and ensureServing is genuinely reachable concurrently (OnUnlock
// fires from a fresh challenge after ensureUnlocked releases its lock;
// OnRefresh fires from a connection-handling goroutine — jit migrate's
// own flow can overlap the two, since the unlock its first vault write
// triggers can still be scanning when its explicit Refresh RPC arrives).
// Two goroutines could then both pass the check for the same brand-new
// entry and both spawn a Serve goroutine on the same FIFO — the second
// insert overwriting the first servedMount, orphaning a goroutine whose
// CancelFunc nothing could ever reach again, which made shutdown()'s
// wg.Wait() block forever. The claim now happens in the same critical
// section as the re-check; this test drives 8 concurrent calls at one
// fresh entry and requires both a single served slot and a shutdown()
// that actually completes.

// serveNoGrant runs the unified content decision (serveContent) with no
// grant runs active — the fast path, behaviorally identical to the old
// sm.provideContent: decoy unless the reveal window is open.
func serveNoGrant(sm *servedMount) []byte {
	m := &mountManager{stdout: io.Discard, stderr: io.Discard}
	return m.serveContent("/tmp/fixture/.env", sm)
}

func TestEnsureServingConcurrentCallsClaimSlotOnce(t *testing.T) {
	dir := t.TempDir()
	profilePath := filepath.Join(dir, "profile.yaml")
	if err := os.WriteFile(profilePath, []byte("API_KEY: fixture/API_KEY\n"), 0o600); err != nil {
		t.Fatalf("writing fixture profile: %v", err)
	}
	mountPath := filepath.Join(dir, ".env")
	if err := mount.CreateFIFO(mountPath); err != nil {
		t.Fatalf("creating fixture FIFO: %v", err)
	}

	// io.Discard, not a bytes.Buffer: several Serve goroutines (in the
	// buggy version) plus ensureServing itself may write logs concurrently,
	// and this test must fail on the mountManager race, not on its own
	// unsynchronized test buffer.
	m := &mountManager{root: dir, stdout: io.Discard, stderr: io.Discard}
	entries := []mount.Entry{{MountPath: mountPath, ProfilePath: profilePath}}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.ensureServing(entries)
		}()
	}
	wg.Wait()

	m.mu.Lock()
	n := len(m.served)
	m.mu.Unlock()
	if n != 1 {
		t.Fatalf("len(served) after concurrent ensureServing = %d, want exactly 1", n)
	}

	done := make(chan struct{})
	go func() {
		m.shutdown()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown() hung, an ensureServing race left a Serve goroutine no CancelFunc can reach, the exact orphan the single-critical-section claim exists to prevent")
	}
}

// newTestServedMount is a bare servedMount with no Serve goroutine behind
// it — enough to unit-test reveal/hide/content-selection logic without the
// full ensureServing pipeline (a real registry entry, a real profile
// file, an actual FIFO). cancel defaults to a no-op, and done starts
// pre-closed (as if the goroutine had already exited) so tests that
// don't care about stopMount's wait behavior can skip setting one up —
// see TestMountManagerStopMountWaitsForGoroutineToExit for the test that
// does care.
func newTestServedMount() *servedMount {
	done := make(chan struct{})
	close(done)
	// real content is pre-resolved: revealMount refuses a mount with nothing
	// real to serve (GAPS.md #46), and these tests exercise the reveal
	// mechanics, not that refusal — TestRevealMountRefusedWithNothingRealToServe
	// covers it.
	return &servedMount{reveal: mount.NewRevealState(), cancel: func() {}, done: done, real: []byte("API_KEY=real\n")}
}

func TestRevealMountClampsToMaxWindow(t *testing.T) {
	sm := newTestServedMount()
	m := &mountManager{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, served: map[string]*servedMount{"/tmp/fixture/.env": sm}}

	if err := m.revealMount("/tmp/fixture/.env", 24*time.Hour); err != nil {
		t.Fatalf("revealMount: %v", err)
	}
	if !sm.reveal.IsRevealed() {
		t.Fatal("expected revealed immediately after revealMount")
	}
	// Can't directly observe the clamped expiry without exposing internal
	// state, so assert the documented ceiling indirectly: revealMaxWindow
	// itself must be a small, bounded value, not something that could be
	// mistaken for "effectively forever." This is a guard against silently
	// widening the constant later without reconsidering GAPS.md #2's whole
	// premise (bounding exposure, not eliminating identification).
	if revealMaxWindow > 30*time.Minute {
		t.Errorf("revealMaxWindow = %v, suspiciously large for a decoy-by-default gate's ceiling", revealMaxWindow)
	}
}

func TestRevealMountZeroDurationUsesDefaultWindow(t *testing.T) {
	sm := newTestServedMount()
	m := &mountManager{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, served: map[string]*servedMount{"/tmp/fixture/.env": sm}}

	if err := m.revealMount("/tmp/fixture/.env", 0); err != nil {
		t.Fatalf("revealMount: %v", err)
	}
	if !sm.reveal.IsRevealed() {
		t.Error("revealMount(path, 0) should fall back to revealDefaultWindow, not leave the mount hidden")
	}
}

// TestRevealMountRefusedWithNothingRealToServe is GAPS.md #46's unit-level
// half (the e2e half is TestRevealRefusedWhenNothingRealToServe): revealing a
// mount whose real content never resolved must fail — with the recorded
// resolve error included — and must leave the mount hidden, instead of
// granting a countdown on a mount that can only ever serve decoys.
func TestRevealMountRefusedWithNothingRealToServe(t *testing.T) {
	sm := newTestServedMount()
	sm.real = nil
	sm.lastResolveErr = "resolving API_KEY (fixture/MISSING): secret not found"
	m := &mountManager{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, served: map[string]*servedMount{"/tmp/fixture/.env": sm}}

	err := m.revealMount("/tmp/fixture/.env", time.Minute)
	if err == nil {
		t.Fatal("revealMount succeeded on a mount with no real content, the reveal would be a silent no-op serving decoys")
	}
	if !strings.Contains(err.Error(), "secret not found") {
		t.Errorf("revealMount error = %q, want the recorded resolve error included", err)
	}
	if sm.reveal.IsRevealed() {
		t.Error("a refused reveal must leave the mount hidden")
	}
}

// TestRevealMountUnservedPathIsANoOp confirms revealing a path that isn't
// currently served logs and returns rather than panicking or silently
// creating orphaned state — a real behavior change from the old
// revealStateFor, which lazily created a RevealState for ANY path. Revealing now
// only makes sense once a mount is actually being served (ensureServing
// creates the RevealState alongside the Serve goroutine, GAPS.md #35); in
// real usage `jit migrate`'s own Refresh call (or the agent's own
// startup startDecoyOnly) always runs first, so this path is only ever
// hit by a stale/mistyped mount_path.
func TestRevealMountUnservedPathIsANoOp(t *testing.T) {
	m := &mountManager{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	m.revealMount("/tmp/fixture/never-served.env", time.Minute) // must not panic
}

func TestMountManagerStopClearsRevealAndRealContentWithoutCancelling(t *testing.T) {
	cancelled := false
	sm := &servedMount{reveal: mount.NewRevealState(), decoy: []byte("decoy"), real: []byte("real"), cancel: func() { cancelled = true }}
	sm.reveal.Reveal(time.Minute)
	m := &mountManager{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, served: map[string]*servedMount{"/tmp/fixture/.env": sm}}

	if got := serveNoGrant(sm); string(got) != "real" {
		t.Fatalf("setup: provideContent = %q, want real content while revealed", got)
	}

	m.stop()

	if cancelled {
		t.Error("stop() must not cancel a mount's Serve goroutine (GAPS.md #35), only clear real content and hide")
	}
	if sm.reveal.IsRevealed() {
		t.Error("expected hidden after stop, locking must not leave a mount revealed")
	}
	if got := serveNoGrant(sm); string(got) != "decoy" {
		t.Errorf("provideContent after stop = %q, want decoy, real content must be forgotten", got)
	}
}

// TestMountManagerStopMountCancelsOnlyThatMount is GAPS.md #35's
// regression test for the per-mount stop that replaced "lock the whole
// agent first" in jit unmount: stopping one mount must never disturb
// any other mount's serving.
func TestMountManagerStopMountCancelsOnlyThatMount(t *testing.T) {
	cancelledA, cancelledB := false, false
	smA := newTestServedMount()
	smA.cancel = func() { cancelledA = true }
	smB := newTestServedMount()
	smB.cancel = func() { cancelledB = true }
	m := &mountManager{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, served: map[string]*servedMount{
		"/tmp/fixture/a.env": smA,
		"/tmp/fixture/b.env": smB,
	}}

	m.stopMount("/tmp/fixture/a.env")

	if !cancelledA {
		t.Error("expected a.env's Serve goroutine to be cancelled")
	}
	if cancelledB {
		t.Error("expected b.env to be left undisturbed")
	}
	if _, ok := m.served["/tmp/fixture/a.env"]; ok {
		t.Error("expected a.env removed from the served map")
	}
	if _, ok := m.served["/tmp/fixture/b.env"]; !ok {
		t.Error("expected b.env to remain in the served map")
	}
}

// TestResolveRealRevealFloorNeverShortensLongerWindow is GAPS.md #38's
// regression test for a real, reported bug: an explicit `jit agent reveal
// --for 5m` got silently cut down to the 60s revealDefaultWindow the moment
// ANY later OnUnlock/OnRefresh fired (an unrelated command's fresh Touch
// ID challenge, or another jit migrate run's own Refresh call) —
// resolveReal used to call sm.reveal.Reveal(revealDefaultWindow) unconditionally,
// and RevealState.Reveal always sets the expiry to exactly that duration from
// now, shortening a deliberately-longer window right along with
// extending a shorter one. The profile path here deliberately doesn't
// exist, so resolution fails (logged, skipped) — which must leave the
// existing window exactly as it was, doubly so now that a failed resolve
// grants no window at all (GAPS.md #46).
func TestResolveRealRevealFloorNeverShortensLongerWindow(t *testing.T) {
	sm := newTestServedMount()
	sm.reveal.Reveal(5 * time.Minute)
	m := &mountManager{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, served: map[string]*servedMount{
		"/tmp/fixture/.env": sm,
	}}

	m.resolveReal([]mount.Entry{{MountPath: "/tmp/fixture/.env", ProfilePath: "/tmp/fixture/profile.yaml"}}, nil, true)

	if remaining := sm.reveal.Remaining(); remaining < 4*time.Minute {
		t.Errorf("Remaining() after resolveReal = %v, want close to the original 5m window, not shortened to revealDefaultWindow (%v)", remaining, revealDefaultWindow)
	}
}

// TestResolveRealRevealFloorExtendsShorterWindow confirms the other half:
// after a SUCCESSFUL resolve, the ergonomic default window still applies
// as a FLOOR — a hidden or short-revealed mount gets bumped up to
// revealDefaultWindow, exactly the original GAPS.md #2 ergonomics the
// floor-not-reset fix must not break.
func TestResolveRealRevealFloorExtendsShorterWindow(t *testing.T) {
	root := t.TempDir()
	kw := newFakeKeyWrapper()
	v := &vault.Vault{Root: root, KeyWrapper: kw, RecipientID: "test-device"}
	if err := v.Set("fixture/API_KEY", []byte("real-value")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	profilePath := filepath.Join(root, "profile.yaml")
	if err := os.WriteFile(profilePath, []byte("API_KEY: fixture/API_KEY\n"), 0o600); err != nil {
		t.Fatalf("writing fixture profile: %v", err)
	}

	sm := newTestServedMount()
	// Starts hidden (Remaining() == 0) — newTestServedMount never reveals.
	m := &mountManager{root: root, stdout: io.Discard, stderr: &bytes.Buffer{}, served: map[string]*servedMount{
		"/tmp/fixture/.env": sm,
	}}

	m.resolveReal([]mount.Entry{{MountPath: "/tmp/fixture/.env", ProfilePath: profilePath}}, v, true)

	remaining := sm.reveal.Remaining()
	if remaining <= 0 || remaining > revealDefaultWindow {
		t.Errorf("Remaining() after a successful resolveReal on a hidden mount = %v, want a positive value up to revealDefaultWindow (%v)", remaining, revealDefaultWindow)
	}
}

// TestResolveRealScopedRevealResolvesButFloorRevealsNothing is the regression
// test for a reveal-driven unlock (OnUnlockForReveal → startForReveal →
// resolveReal with floorReveal=false): running `jit agent reveal <one-file>`
// while the agent is LOCKED triggers a fresh challenge, and that unlock
// used to blanket floor-reveal every OTHER mount for the 60s default window
// too — a real, reported "I revealed one file and four got revealed" confusion.
// With floorReveal=false, resolveReal must still resolve every mount's real
// content (so the explicit reveal that follows can't be refused for "nothing
// real resolved") while revealing NONE of them — revealMount reveals the single
// named path afterward.
func TestResolveRealScopedRevealResolvesButFloorRevealsNothing(t *testing.T) {
	root := t.TempDir()
	kw := newFakeKeyWrapper()
	v := &vault.Vault{Root: root, KeyWrapper: kw, RecipientID: "test-device"}
	if err := v.Set("fixture/API_KEY", []byte("real-value")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	profilePath := filepath.Join(root, "profile.yaml")
	if err := os.WriteFile(profilePath, []byte("API_KEY: fixture/API_KEY\n"), 0o600); err != nil {
		t.Fatalf("writing fixture profile: %v", err)
	}

	// Two hidden mounts sharing the same resolvable profile — the "other"
	// mounts the blanket reveal used to light up.
	smA := newTestServedMount()
	smB := newTestServedMount()
	m := &mountManager{root: root, stdout: io.Discard, stderr: &bytes.Buffer{}, served: map[string]*servedMount{
		"/tmp/fixture/a/.env": smA,
		"/tmp/fixture/b/.env": smB,
	}}
	entries := []mount.Entry{
		{MountPath: "/tmp/fixture/a/.env", ProfilePath: profilePath},
		{MountPath: "/tmp/fixture/b/.env", ProfilePath: profilePath},
	}

	m.resolveReal(entries, v, false)

	for name, sm := range map[string]*servedMount{"a": smA, "b": smB} {
		sm.mu.Lock()
		hasReal := sm.real != nil
		sm.mu.Unlock()
		if !hasReal {
			t.Errorf("mount %s: real content not resolved, revealMount would then refuse the explicit reveal for 'nothing real resolved'", name)
		}
		if sm.reveal.IsRevealed() {
			t.Errorf("mount %s: floor-revealed by a reveal-driven unlock, that's exactly the blanket reveal the scoped path removes", name)
		}
	}
}

// TestResolveRealGrantsNoWindowOnFailedResolve is the flip side (GAPS.md
// #46): a mount whose resolution failed has nothing real to serve, so the
// unlock/refresh auto-reveal must NOT put it in an "revealed" state — that
// would show a live countdown in status while every read keeps getting
// decoys, the same dishonesty revealMount now refuses.
func TestResolveRealGrantsNoWindowOnFailedResolve(t *testing.T) {
	sm := newTestServedMount()
	sm.real = nil // nothing resolved yet
	m := &mountManager{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, served: map[string]*servedMount{
		"/tmp/fixture/.env": sm,
	}}

	// Nonexistent profile path — resolution fails and is logged.
	m.resolveReal([]mount.Entry{{MountPath: "/tmp/fixture/.env", ProfilePath: "/tmp/fixture/nope.yaml"}}, nil, true)

	if sm.reveal.IsRevealed() {
		t.Error("resolveReal revealed a mount whose resolution failed, status would report a revealed countdown on a decoy-only mount")
	}
	sm.mu.Lock()
	resolveErr := sm.lastResolveErr
	sm.mu.Unlock()
	if resolveErr == "" {
		t.Error("expected the resolve failure recorded in lastResolveErr for revealMount's refusal message")
	}
}

// TestNoteReaderConnectedCollapsesStormLogging is GAPS.md #47's log-cost
// half: a watcher re-read loop produces one reader-connected line per
// read — 635k log lines in one afternoon on a real machine — so repeat
// reads within readLogMinGap must collapse into the NEXT logged line's
// suppressed-count suffix, not each get their own line. The lineage scan
// (the actual CPU cost) is likewise rate-limited to lineageScanMinGap.
func TestNoteReaderConnectedCollapsesStormLogging(t *testing.T) {
	sm := newTestServedMount()
	var stderr bytes.Buffer
	m := &mountManager{stdout: io.Discard, stderr: &stderr, served: map[string]*servedMount{"/tmp/fixture/.env": sm}}

	for i := 0; i < 25; i++ {
		m.noteReaderConnected("/tmp/fixture/.env", sm)
	}

	if got := strings.Count(stderr.String(), "reader"); got != 1 {
		t.Errorf("25 rapid reads produced %d reader log lines, want exactly 1 (the rest collapsed into the next line's suppressed count)", got)
	}
	sm.mu.Lock()
	suppressed, count := sm.readLogSuppressed, sm.readWindowCount
	sm.mu.Unlock()
	if suppressed != 24 {
		t.Errorf("readLogSuppressed = %d, want 24", suppressed)
	}
	if count != 25 {
		t.Errorf("readWindowCount = %d, want 25, the rolling counter must count every read, logged or not", count)
	}
}

// TestMountRevealStatusesReportsReadsLastMinute: the rolling read counter
// must ride the status RPC, so `jit agent status` can name a watcher
// re-read loop instead of it burning CPU invisibly (GAPS.md #47).
func TestMountRevealStatusesReportsReadsLastMinute(t *testing.T) {
	sm := newTestServedMount()
	m := &mountManager{stdout: io.Discard, stderr: io.Discard, served: map[string]*servedMount{"/tmp/fixture/.env": sm}}

	for i := 0; i < 3; i++ {
		m.noteReaderConnected("/tmp/fixture/.env", sm)
	}

	statuses := m.mountRevealStatuses()
	if len(statuses) != 1 {
		t.Fatalf("got %d statuses, want 1", len(statuses))
	}
	if statuses[0].ReadsLastMinute != 3 {
		t.Errorf("ReadsLastMinute = %d, want 3", statuses[0].ReadsLastMinute)
	}
}

// TestProvideContentRecordsLastServe: every content decision records
// what was served, when, and (best-effort) to whom — the raw material
// for "my dev server got decoy values and nothing anywhere said so"
// becoming visible in `jit agent status`/`jit status`.
func TestProvideContentRecordsLastServe(t *testing.T) {
	sm := newTestServedMount()
	sm.decoy = []byte("decoy")

	if got := serveNoGrant(sm); string(got) != "decoy" {
		t.Fatalf("provideContent = %q, want decoy while hidden", got)
	}
	sm.mu.Lock()
	ls := sm.lastServe
	sm.mu.Unlock()
	if ls == nil || !ls.decoy {
		t.Fatalf("lastServe after a decoy read = %+v, want recorded with decoy=true", ls)
	}
	if ls.reader.identified {
		t.Errorf("lastServe.reader = %+v, want unidentified (no onReaderConnected ran)", ls.reader)
	}

	sm.setRealIfGen([]byte("real"), sm.captureGen())
	sm.reveal.Reveal(time.Minute)
	sm.mu.Lock()
	sm.pendingReader = readerIdentity{pid: 4823, execPath: "/usr/local/bin/node", identified: true}
	sm.mu.Unlock()

	if got := serveNoGrant(sm); string(got) != "real" {
		t.Fatalf("provideContent = %q, want real while revealed and resolved", got)
	}
	sm.mu.Lock()
	ls = sm.lastServe
	sm.mu.Unlock()
	if ls == nil || ls.decoy {
		t.Fatalf("lastServe after a real read = %+v, want recorded with decoy=false", ls)
	}
	if !ls.reader.identified || ls.reader.pid != 4823 || ls.reader.execPath != "/usr/local/bin/node" {
		t.Errorf("lastServe.reader = %+v, want the pending reader identity carried through", ls.reader)
	}
}

// TestMountRevealStatusesIncludesLastServe confirms the serve record crosses
// the status RPC boundary — pid/path only when the lineage scan actually
// identified the reader, never zero-valued noise.
func TestMountRevealStatusesIncludesLastServe(t *testing.T) {
	read := newTestServedMount()
	read.decoy = []byte("decoy")
	read.mu.Lock()
	read.pendingReader = readerIdentity{pid: 4823, execPath: "/usr/local/bin/node", identified: true}
	read.mu.Unlock()
	serveNoGrant(read)
	neverRead := newTestServedMount()
	m := &mountManager{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, served: map[string]*servedMount{
		"/tmp/fixture/read.env":  read,
		"/tmp/fixture/never.env": neverRead,
	}}

	byPath := map[string]agent.MountRevealStatus{}
	for _, s := range m.mountRevealStatuses() {
		byPath[s.Path] = s
	}

	got := byPath["/tmp/fixture/read.env"]
	if got.LastServe == nil {
		t.Fatal("LastServe missing for a mount that was read")
	}
	if !got.LastServe.Decoy || got.LastServe.ReaderPID != 4823 || got.LastServe.ReaderPath != "/usr/local/bin/node" {
		t.Errorf("LastServe = %+v, want decoy=true with the identified reader", got.LastServe)
	}
	if got.LastServe.UnixTime == 0 {
		t.Error("LastServe.UnixTime = 0, want the read's actual time")
	}
	if byPath["/tmp/fixture/never.env"].LastServe != nil {
		t.Errorf("LastServe for a never-read mount = %+v, want nil", byPath["/tmp/fixture/never.env"].LastServe)
	}
}

// TestPrintMountStatusesShowsLastServe pins the user-facing copy: one
// sorted bullet per mount with its reveal state, the most recent read (kind
// of values, reader, relative time) indented under it, the fixing command
// inline on a decoy read — and every registered mount present, including
// a never-read, never-revealed one (the section's shape stays stable; only
// the states change between runs).
func TestPrintMountStatusesShowsLastServe(t *testing.T) {
	var buf bytes.Buffer
	printMountStatuses(&buf, []agent.MountRevealStatus{
		{Path: "/p/decoy.env", LastServe: &agent.MountServeEvent{
			UnixTime: time.Now().Add(-2 * time.Minute).Unix(), Decoy: true, ReaderPID: 4823, ReaderPath: "/usr/local/bin/node",
		}},
		{Path: "/p/real.env", Revealed: true, RevealedForSeconds: 90, LastServe: &agent.MountServeEvent{
			UnixTime: time.Now().Add(-30 * time.Second).Unix(), Decoy: false,
		}},
		{Path: "/p/quiet.env"},
	})
	out := buf.String()

	for _, want := range []string{
		"• /p/decoy.env, not revealed",
		"read 2m ago by node (pid 4823): decoy values",
		"jit agent reveal /p/decoy.env",
		"• /p/real.env, revealed, 1m30s left",
		"read 30s ago by an unidentified process: real values",
		"• /p/quiet.env, not revealed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, out)
		}
	}
	// Sorted by path, one bullet each — never the map-order event-log
	// stream this used to be.
	if di, ri := strings.Index(out, "/p/decoy.env"), strings.Index(out, "/p/quiet.env"); di > ri {
		t.Errorf("mounts not sorted by path, got:\n%s", out)
	}
}

// TestEnsureServingDecoyCarriesNotice: the decoy content a mount serves
// must open with the self-diagnosing comment line naming the reveal command
// — and the real content must never carry it (its absence is part of the
// "you're looking at real values" signal).
func TestEnsureServingDecoyCarriesNotice(t *testing.T) {
	dir := t.TempDir()
	profilePath := filepath.Join(dir, "profile.yaml")
	if err := os.WriteFile(profilePath, []byte("API_KEY: fixture/API_KEY\n"), 0o600); err != nil {
		t.Fatalf("writing fixture profile: %v", err)
	}
	mountPath := filepath.Join(dir, ".env")
	if err := mount.CreateFIFO(mountPath); err != nil {
		t.Fatalf("creating fixture FIFO: %v", err)
	}

	m := &mountManager{root: dir, stdout: io.Discard, stderr: io.Discard}
	m.ensureServing([]mount.Entry{{MountPath: mountPath, ProfilePath: profilePath}})
	defer m.shutdown()

	m.mu.Lock()
	sm := m.served[mountPath]
	m.mu.Unlock()
	if sm == nil {
		t.Fatal("mount not served")
	}
	sm.mu.Lock()
	decoy := string(sm.decoy)
	sm.mu.Unlock()

	if !strings.HasPrefix(decoy, "# jit:") {
		t.Errorf("decoy content = %q, want it to OPEN with the self-diagnosing notice", decoy)
	}
	if !strings.Contains(decoy, "jit agent reveal "+mountPath) {
		t.Errorf("decoy content = %q, want the reveal command with this mount's own path", decoy)
	}
}

// TestResolveRealReResolvesUpdatedSecret is GAPS.md #43's regression
// test: a mount whose real content had already been resolved used to be
// skipped by every later resolveReal ("already resolved"), so `jit
// vault set` on a secret the mount references kept serving the OLD value
// indefinitely — nothing short of a full lock/unlock cycle ever
// invalidated it. resolveReal must re-resolve on every unlock/refresh.
func TestResolveRealReResolvesUpdatedSecret(t *testing.T) {
	root := t.TempDir()
	kw := newFakeKeyWrapper()
	v := &vault.Vault{Root: root, KeyWrapper: kw, RecipientID: "test-device"}
	if err := v.Set("fixture/API_KEY", []byte("first-value")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	profilePath := filepath.Join(root, "profile.yaml")
	if err := os.WriteFile(profilePath, []byte("API_KEY: fixture/API_KEY\n"), 0o600); err != nil {
		t.Fatalf("writing fixture profile: %v", err)
	}

	sm := newTestServedMount()
	m := &mountManager{root: root, stdout: io.Discard, stderr: &bytes.Buffer{}, served: map[string]*servedMount{
		"/tmp/fixture/.env": sm,
	}}
	entries := []mount.Entry{{MountPath: "/tmp/fixture/.env", ProfilePath: profilePath}}

	realContent := func() string {
		sm.mu.Lock()
		defer sm.mu.Unlock()
		return string(sm.real)
	}

	m.resolveReal(entries, v, true)
	if got := realContent(); !strings.Contains(got, "first-value") {
		t.Fatalf("real content after first resolve = %q, want it to contain first-value", got)
	}
	if got := realContent(); strings.Contains(got, "# jit:") {
		t.Errorf("real content = %q carries the decoy notice, its absence is part of the revealed signal", got)
	}

	if err := v.Set("fixture/API_KEY", []byte("second-value")); err != nil {
		t.Fatalf("Set (update): %v", err)
	}
	m.resolveReal(entries, v, true)
	if got := realContent(); !strings.Contains(got, "second-value") {
		t.Errorf("real content after re-resolve = %q, want the UPDATED second-value, a stale mount serving a replaced secret forever is the exact GAPS.md #43 bug", got)
	}
}

// TestEnsureServingRemovesDeadMountFromServed is GAPS.md #44's regression
// test: a mount whose Serve loop exited with a structural error (not
// cancellation) used to stay in m.served forever — never restarted by a
// later unlock/refresh, still reported as served by mountRevealStatuses,
// and revealable with apparent success while nothing was actually writing
// to the pipe. The dying goroutine must remove its own entry so the next
// ensureServing genuinely retries it. The structural failure here is
// recreateFIFO hitting a write-protected directory right after the first
// reader is served — the same class of error (path's directory gone bad)
// that Serve's own doc comment declares fatal.
func TestEnsureServingRemovesDeadMountFromServed(t *testing.T) {
	mountDir := t.TempDir()
	profileDir := t.TempDir()
	profilePath := filepath.Join(profileDir, "profile.yaml")
	if err := os.WriteFile(profilePath, []byte("API_KEY: fixture/API_KEY\n"), 0o600); err != nil {
		t.Fatalf("writing fixture profile: %v", err)
	}
	mountPath := filepath.Join(mountDir, ".env")
	if err := mount.CreateFIFO(mountPath); err != nil {
		t.Fatalf("creating fixture FIFO: %v", err)
	}

	m := &mountManager{root: mountDir, stdout: io.Discard, stderr: io.Discard}
	m.ensureServing([]mount.Entry{{MountPath: mountPath, ProfilePath: profilePath}})

	// Make the serve cycle's recreateFIFO fail: the directory stops being
	// writable, so mkfifo for the replacement pipe gets EACCES.
	if err := os.Chmod(mountDir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(mountDir, 0o700) })

	// A reader that drains the content and then LINGERS (fd held open) is
	// what drives the cycle into the isolation rename that hits the
	// failure — since GAPS.md #47, a reader that closes promptly gets the
	// pipe reused with no recreateFIFO call at all (hasLingeringReader
	// sees this very test process holding the fd — PathHeldOpen
	// deliberately includes its own pid).
	f, err := os.Open(mountPath) // #nosec G304 -- fixture path
	if err != nil {
		t.Fatalf("opening mount: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if _, err := io.ReadAll(f); err != nil {
		t.Fatalf("reading mount: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		n := len(m.served)
		m.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("dead mount still in m.served 5s after its Serve loop exited, it would never be restarted and still look alive to status/reveal (GAPS.md #44)")
}

// TestMountRevealStatusesReportsRevealedAndHidden is GAPS.md #37's regression
// test: `jit status`/`jit agent status` used to have no way at all to
// see which mount was revealed or for how long — a real, reported point of
// confusion when a mount's reveal window appeared to silently "not work"
// (it had actually been wiped out early by the agent's own session
// lock, a completely separate timer with no visibility either).
func TestMountRevealStatusesReportsRevealedAndHidden(t *testing.T) {
	revealed := newTestServedMount()
	revealed.reveal.Reveal(time.Minute)
	hidden := newTestServedMount()
	m := &mountManager{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, served: map[string]*servedMount{
		"/tmp/fixture/revealed.env": revealed,
		"/tmp/fixture/hidden.env":   hidden,
	}}

	statuses := m.mountRevealStatuses()
	if len(statuses) != 2 {
		t.Fatalf("len(statuses) = %d, want 2", len(statuses))
	}

	byPath := map[string]agent.MountRevealStatus{}
	for _, s := range statuses {
		byPath[s.Path] = s
	}

	got, ok := byPath["/tmp/fixture/revealed.env"]
	if !ok {
		t.Fatal("missing status for revealed.env")
	}
	if !got.Revealed || got.RevealedForSeconds <= 0 || got.RevealedForSeconds > 60 {
		t.Errorf("revealed.env status = %+v, want Revealed=true and 0 < RevealedForSeconds <= 60", got)
	}

	got, ok = byPath["/tmp/fixture/hidden.env"]
	if !ok {
		t.Fatal("missing status for hidden.env")
	}
	if got.Revealed || got.RevealedForSeconds != 0 {
		t.Errorf("hidden.env status = %+v, want Revealed=false and RevealedForSeconds=0", got)
	}
}

// TestMountManagerStopMountWaitsForGoroutineToExit is GAPS.md #36's
// regression test for the exact race a real unmount run hit: stopMount
// must not return until the mount's Serve goroutine has actually
// finished, not merely been asked to via cancel(). cancel() alone only
// asks the goroutine to stop at its NEXT chance to check — if a reader
// was already connected, the in-flight cycle still finishes writing and
// calls recreateFIFO (putting a fresh pipe back at the path)
// unconditionally before it ever notices the cancellation. A caller
// (jit unmount) that replaces the file the instant stopMount returns
// can lose that race if stopMount doesn't actually wait — confirmed on
// real hardware: one unmount call raced this way and left an empty,
// unregistered FIFO where the plaintext file should have been.
func TestMountManagerStopMountWaitsForGoroutineToExit(t *testing.T) {
	done := make(chan struct{})
	sm := &servedMount{reveal: mount.NewRevealState(), cancel: func() {}, done: done}
	m := &mountManager{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, served: map[string]*servedMount{"/tmp/fixture/.env": sm}}

	returned := make(chan struct{})
	go func() {
		m.stopMount("/tmp/fixture/.env")
		close(returned)
	}()

	select {
	case <-returned:
		t.Fatal("stopMount returned before the Serve goroutine signaled done, this is the exact race that let recreateFIFO clobber a file jit unmount had just replaced")
	case <-time.After(50 * time.Millisecond):
		// Still blocked, as expected — simulate the goroutine finishing
		// its in-flight cycle now.
	}

	close(done)

	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("stopMount never returned after the goroutine signaled done")
	}
}

// TestServedMountGenGuardDropsResolveRacedByLock pins the fix for the
// "serves real values while locked" race: a resolveReal that captured the
// generation before its decrypt must NOT install real content if a lock
// (invalidateReal) bumped the generation while it was decrypting.
func TestServedMountGenGuardDropsResolveRacedByLock(t *testing.T) {
	sm := &servedMount{}

	// A resolve begins, capturing the generation before its (slow) decrypt.
	gen := sm.captureGen()

	// The session locks mid-decrypt: real is cleared, generation advances.
	if sm.invalidateReal() {
		t.Fatal("invalidateReal reported clearing real content on a mount that had none")
	}

	// The now-stale resolve completes and tries to install its bytes. It must
	// be refused, leaving the mount decoy (real == nil) while locked.
	if sm.setRealIfGen([]byte("SECRET"), gen) {
		t.Fatal("setRealIfGen installed real content despite an intervening lock")
	}
	sm.mu.Lock()
	got := sm.real
	sm.mu.Unlock()
	if got != nil {
		t.Fatalf("real content leaked onto a locked mount: %q", got)
	}

	// A resolve with no intervening lock installs normally.
	if !sm.setRealIfGen([]byte("SECRET"), sm.captureGen()) {
		t.Fatal("setRealIfGen refused a resolve with an unchanged generation")
	}
	sm.mu.Lock()
	got = sm.real
	sm.mu.Unlock()
	if string(got) != "SECRET" {
		t.Fatalf("real = %q, want SECRET", got)
	}

	// And a later lock clears it and reports it did.
	if !sm.invalidateReal() {
		t.Fatal("invalidateReal should report clearing the real content just installed")
	}
}
