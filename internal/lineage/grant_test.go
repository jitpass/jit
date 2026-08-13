// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package lineage

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The gate-logic tests live with mountManager (internal/cli), against
// faked lookups; these pin the real kernel primitives to the live
// process tree the test itself runs in.

func TestAncestryContainsPIDRealTree(t *testing.T) {
	self := int32(os.Getpid())
	parent := int32(os.Getppid())

	if !AncestryContainsPID(self, self) {
		t.Error("a pid must count as inside its own tree (jit run's target can read its own mount)")
	}
	if !AncestryContainsPID(self, parent) {
		t.Error("self must be inside its parent's tree")
	}
	if AncestryContainsPID(parent, self) {
		t.Error("a parent must NOT be inside its child's tree")
	}
	if AncestryContainsPID(self, -1) || AncestryContainsPID(-1, self) {
		t.Error("invalid pids must classify out-of-tree, never in")
	}
}

// TestAncestryNamedWithinRealTree pins the tree-grant serve gate to the live
// process tree: the name must appear on the chain at or below the root the
// chain then reaches, and either condition failing answers false.
func TestAncestryNamedWithinRealTree(t *testing.T) {
	self := int32(os.Getpid())
	parent := int32(os.Getppid())
	ownName := ""
	if p, ok := Describe(self); ok {
		ownName = p.Name()
	}
	if ownName == "" {
		t.Fatal("Describe(self) yields no name; the fixture below is meaningless")
	}

	if !AncestryNamedWithin(self, parent, ownName) {
		t.Errorf("self (named %q) under its parent must be served", ownName)
	}
	if AncestryNamedWithin(self, parent, "no-such-name-zz9") {
		t.Error("a name absent from the chain must not be served")
	}
	if AncestryNamedWithin(parent, self, ownName) {
		t.Error("a caller outside the root's tree must not be served, whatever the name")
	}

	// A child named sleep: the name sits BELOW the caller-to-root walk's
	// start, i.e. the child itself carries it.
	child := exec.Command("sleep", "60")
	if err := child.Start(); err != nil {
		t.Fatalf("starting child: %v", err)
	}
	defer func() {
		_ = child.Process.Kill()
		_, _ = child.Process.Wait()
	}()
	childPID := int32(child.Process.Pid) // #nosec G115 -- a pid always fits int32 on darwin
	if !AncestryNamedWithin(childPID, self, "sleep") {
		t.Error("a child named sleep under this test must be served")
	}
	if AncestryNamedWithin(childPID, self, "claude") {
		t.Error("the child's chain carries no claude; it must not be served")
	}

	// launchd may never be the root: everything descends from pid 1, so the
	// walk answering true there would let the name decide alone.
	if AncestryNamedWithin(childPID, 1, "sleep") {
		t.Error("a launchd-rooted walk must always answer false")
	}
}

// TestSessionRootIsAProperAncestor pins the anchor derivation: the session
// root must be a real, describable ancestor of the caller, strictly above
// it, and never launchd itself.
func TestSessionRootIsAProperAncestor(t *testing.T) {
	self := int32(os.Getpid())
	root, ok := SessionRoot(self)
	if !ok {
		t.Skip("this test process is launchd's own child (bare CI runner); no session root to derive")
	}
	if root.PID == self || root.PID <= 1 {
		t.Fatalf("SessionRoot(self) = pid %d, want a proper ancestor above self and above launchd", root.PID)
	}
	if !AncestryContainsPID(self, root.PID) {
		t.Errorf("SessionRoot returned pid %d which is not an ancestor of the caller", root.PID)
	}
	if _, ok := SessionRoot(0); ok {
		t.Error("SessionRoot(0) must fail")
	}
}

func TestProcessStartTimeSelfStableAndDeadPIDFails(t *testing.T) {
	first, ok := ProcessStartTime(int32(os.Getpid()))
	if !ok || first == 0 {
		t.Fatalf("ProcessStartTime(self) = %d, %v — want a nonzero stamp", first, ok)
	}
	second, ok := ProcessStartTime(int32(os.Getpid()))
	if !ok || second != first {
		t.Errorf("ProcessStartTime(self) unstable: %d then %d", first, second)
	}
	if _, ok := ProcessStartTime(0); ok {
		t.Error("ProcessStartTime(0) must fail")
	}
}

func TestFIFOHoldersNoHoldersOnUntouchedPath(t *testing.T) {
	holders, ok := FIFOHolders("/tmp/jit-test-definitely-not-a-mount")
	if !ok {
		t.Skip("holder enumeration reported structural uncertainty on this machine; the gate would fail closed")
	}
	if len(holders) != 0 {
		t.Errorf("holders = %v for a path nothing holds, want none", holders)
	}
}

// TestFIFOHoldersSeesARealHolderAndExcludesSelf is the positive half of the
// primitive the Tier 3-4 real-vs-decoy gate reads (internal/cli/mountgrants.go
// calls this for real; the gate-logic tests there fake it through
// grantHoldersFn, so this file is the only place the kernel walk itself is
// observed).
//
// The one test that existed pointed at a path nothing holds, so pids was
// always nil and the whole positive contract went unenforced — a stub
// `return nil, true` passed it. What that stub would do in production is
// serve decoy content to a legitimately granted reader forever, since a
// holder set that never contains anyone can never contain the grant's tree.
//
// The writer side is opened by the TEST process on purpose. That is not a
// convenience: it reproduces the exact condition FIFOHolders documents as its
// reason for excluding the caller — "the agent holds the write side of its own
// mount at scan time". A self-exclusion regression would put the agent's own
// pid in the holder set of every mount it serves.
func TestFIFOHoldersSeesARealHolderAndExcludesSelf(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mount.fifo")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}

	// A real FIFO that exists but nobody has opened — distinct from the
	// nonexistent path above, and the state every mount is in between serves.
	holders, ok := FIFOHolders(path)
	if !ok {
		t.Skip("holder enumeration reported structural uncertainty on this machine; the gate would fail closed")
	}
	if len(holders) != 0 {
		t.Fatalf("holders = %v on a FIFO nobody has opened, want none", holders)
	}

	cmd := exec.Command("cat", path)
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting holder: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	holder := int32(cmd.Process.Pid) // #nosec G115 -- a pid always fits int32 on darwin

	// cat blocks in open() until a writer appears, and a blocked open holds no
	// fd yet. Connect the write end so its open completes and it genuinely
	// holds the read fd — same rendezvous TestPathHeldOpenSeesRealHolder...
	// relies on.
	opened := make(chan *os.File, 1)
	openErr := make(chan error, 1)
	go func() {
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			openErr <- err
			return
		}
		opened <- f
	}()
	var w *os.File
	select {
	case w = <-opened:
	case err := <-openErr:
		t.Fatalf("opening for write: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the holder to connect")
	}
	defer func() { _ = w.Close() }()

	// Both opens return at the rendezvous, but "returned" and "visible in the
	// fd table proc_pidfdinfo reports" are not the same instant. Poll rather
	// than assert once: this guards a security gate, and a flaky test on one
	// is worse than a slow one. Self-exclusion is checked on every pass, since
	// a violation there is not timing-dependent.
	deadline := time.Now().Add(5 * time.Second)
	self := int32(os.Getpid()) // #nosec G115 -- a pid always fits int32 on darwin
	var sawHolder, lastOK bool
	var last []int32
	for time.Now().Before(deadline) {
		last, lastOK = FIFOHolders(path)
		if !lastOK {
			t.Skip("holder enumeration reported structural uncertainty mid-test; the gate would fail closed")
		}
		for _, p := range last {
			if p == self {
				t.Fatalf("FIFOHolders returned the calling process (pid %d) while it held the write side; "+
					"the agent would appear as a holder of every mount it serves", self)
			}
			if p == holder {
				sawHolder = true
			}
		}
		if sawHolder {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !sawHolder {
		t.Errorf("FIFOHolders = %v, missing pid %d (cat) which provably holds the FIFO's read end; "+
			"a missed holder means a granted reader is served decoys", last, holder)
	}
}
