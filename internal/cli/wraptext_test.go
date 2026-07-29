// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"regexp"
	"strings"
	"testing"
)

// Every report now wraps its prose to the window (80 columns when stdout
// isn't a terminal, which is every test run). That is the point — but it
// means a sentence a test asserts on can straddle a line break, and
// strings.Contains would report a regression that isn't one.
//
// unwrap rejoins a wrapped block so an assertion can be written the way the
// sentence reads. It collapses a newline plus its continuation indent back to
// a single space, and leaves genuine blank-line separations and unindented
// new rows alone — so it undoes wrapping without also gluing distinct rows
// together.
var wrapJoin = regexp.MustCompile(`\n {2,}`)

func unwrap(s string) string {
	return wrapJoin.ReplaceAllString(s, " ")
}

func TestUnwrapRejoinsAWrappedSentenceOnly(t *testing.T) {
	got := unwrap("○ [service] running a different build than this\n            CLI right now.\n✓ 4 profiles")
	want := "○ [service] running a different build than this CLI right now.\n✓ 4 profiles"
	if got != want {
		t.Errorf("unwrap:\n got %q\nwant %q", got, want)
	}
}

// A row that starts at column 0 is a new row, not a continuation — gluing
// those together would let a test pass on text that never appeared on one
// logical line.
func TestUnwrapLeavesSeparateRowsApart(t *testing.T) {
	in := "vault    57 secrets\nbackup   no export\n"
	if got := unwrap(in); got != in {
		t.Errorf("unwrap joined distinct rows: %q", got)
	}
}

func TestUnwrapIsANoOpOnUnwrappedText(t *testing.T) {
	in := "a single short line\n"
	if got := unwrap(in); !strings.EqualFold(got, in) {
		t.Errorf("got %q", got)
	}
}
