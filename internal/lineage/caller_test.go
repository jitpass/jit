// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package lineage

import (
	"os"
	"testing"
)

// TestProcessNameSurvivesVersionNamedBinaries is a regression test for a bug
// the tests never would have caught, because it took running the real thing
// to see: Claude Code's binary IS its version number
// (~/.local/share/claude/versions/2.1.209), so a Touch ID prompt built from
// the base name read "launched by 2.1.209" — an answer that names a release
// and identifies nothing.
func TestProcessNameSurvivesVersionNamedBinaries(t *testing.T) {
	for _, tc := range []struct {
		execPath string
		want     string
	}{
		{"/Users/menit/.local/share/claude/versions/2.1.209", "claude"},
		{"/Users/menit/go/bin/jit", "jit"},
		{"/Applications/Visual Studio Code.app/Contents/MacOS/Code", "Code"},
		{"/opt/homebrew/Cellar/node/22.1.0/bin/node", "node"},
		{"/usr/bin/zsh", "zsh"},
		{"", ""},
	} {
		if got := (Process{ExecPath: tc.execPath}).Name(); got != tc.want {
			t.Errorf("Name(%q) = %q, want %q", tc.execPath, got, tc.want)
		}
	}
}

// Describe must actually work against a live process — this one. The syscalls
// it wraps are the foundation everything else in this file rests on, so a
// silent failure here (wrong sysctl name, misparsed argv buffer) would leave
// every prompt and status line quietly empty rather than wrong.
func TestDescribeReadsThisProcessFromTheKernel(t *testing.T) {
	p, ok := Describe(int32(os.Getpid()))
	if !ok {
		t.Fatal("Describe couldn't identify this very process")
	}
	if p.ExecPath == "" {
		t.Error("no exec path for this process")
	}
	if len(p.Argv) == 0 {
		t.Error("no argv for this process — kern.procargs2 parsing is broken")
	}
	if p.PPID <= 0 {
		t.Errorf("PPID = %d, want the go test parent's pid", p.PPID)
	}
}

// The chain must reach past this test binary to its parents; a walk that
// stops at the caller can never answer "what launched the thing that asked".
func TestAncestryWalksUpwards(t *testing.T) {
	chain := Ancestry(int32(os.Getpid()))
	if len(chain) < 2 {
		t.Fatalf("Ancestry returned %d process(es), want this one plus at least one parent", len(chain))
	}
	if chain[0].PID != int32(os.Getpid()) {
		t.Errorf("chain[0] = pid %d, want this process (%d) first", chain[0].PID, os.Getpid())
	}
	if chain[1].PID != chain[0].PPID {
		t.Errorf("chain[1] (pid %d) is not chain[0]'s parent (ppid %d)", chain[1].PID, chain[0].PPID)
	}
}
