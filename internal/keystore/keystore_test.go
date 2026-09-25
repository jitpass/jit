// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package keystore

import (
	"testing"

	"github.com/jitpass/jit/internal/agent"
)

// A Store's fetcher is what agent.NewServer builds per unlock; if it stopped
// being a ClosableFetcher the agent would silently skip wiping it.
var _ agent.ClosableFetcher = Fetcher(nil)

// Nothing here calls Presence, Init or Delete on the real backend: those
// reach the production keychain item, and keychainwrap's TEST-ONLY rule says
// no test may (its package comment has the incident). Construction is safe:
// keychainwrap.New touches nothing until used.

func TestOpenIsTheKeychainUntilB3(t *testing.T) {
	if k := Open(t.TempDir()).Kind(); k != KindKeychain {
		t.Fatalf("Open chose %q; until plan step B3 every vault is %q", k, KindKeychain)
	}
}

// Fresh per call is load-bearing: a wrapper caches the MEK for its whole
// life, so handing out one shared wrapper would let every later unlock or
// command skip its challenge.
func TestFetchersAndWrappersAreFreshEachTime(t *testing.T) {
	s := Open(t.TempDir())
	if s.NewFetcher() == s.NewFetcher() {
		t.Fatal("NewFetcher returned the same fetcher twice")
	}
	if s.NewWrapper() == s.NewWrapper() {
		t.Fatal("NewWrapper returned the same wrapper twice")
	}
}

func TestPresenceZeroValueIsIndeterminate(t *testing.T) {
	var p Presence
	if p != Indeterminate {
		t.Fatal("an unset Presence must never read as Absent or Present")
	}
}
