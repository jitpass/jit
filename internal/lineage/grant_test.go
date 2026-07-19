// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package lineage

import (
	"os"
	"testing"
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
