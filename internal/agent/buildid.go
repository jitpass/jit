// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package agent

import "runtime/debug"

// BuildID identifies which build of jit this process is running — the VCS
// revision Go stamped into the binary, "+dirty" when built from an
// uncommitted tree, or "unknown" when no VCS info was embedded (e.g. a
// `go test` binary). Deliberately portable (no darwin build tag) and
// deliberately in this package: both sides of the socket use it — Server
// reports its own on every OpStatus, and the CLI compares against its own
// (GAPS.md #49). launchd's KeepAlive keeps an agent process alive across
// rebuilds and reinstalls indefinitely, so a mismatch is the ONLY signal
// that fixes in the binary on disk aren't what's actually answering the
// socket — a real investigation trap: the running agent predated the
// binary by 21 minutes and nothing anywhere could say so.
//
// Two dirty builds from the same revision get the same ID — this catches
// "committed, rebuilt, old agent still running" (the common case), not
// every possible rebuild-in-place while iterating uncommitted.
func BuildID() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	var rev string
	var dirty bool
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev == "" {
		return "unknown"
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if dirty {
		rev += "+dirty"
	}
	return rev
}
