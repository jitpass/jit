// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package agent

import (
	"testing"
	"time"
)

// TestLockCauseDuration pins the format a human reads. The first case is the
// one that found this: the menu bar panel's subtitle showed "5m0s idle
// timeout", time.Duration's String() straight through fmt's %s.
func TestLockCauseDuration(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{5 * time.Minute, "5 min"}, // the default --ttl, and the reported bug
		{time.Minute, "1 min"},     // "min" is an abbreviation: never "1 mins"
		{15 * time.Minute, "15 min"},
		{30 * time.Second, "30 sec"},
		{90 * time.Second, "1 min 30 sec"},
		{time.Hour, "1 hour"}, // a whole word, so it does take its plural
		{8 * time.Hour, "8 hours"},
		{90 * time.Minute, "1 hour 30 min"},
		{2*time.Hour + 5*time.Minute, "2 hours 5 min"},
		// A remainder stops one unit down: nobody needs the seconds in a
		// two-hour ceiling to understand why they were re-prompted.
		{2*time.Hour + 5*time.Minute + 12*time.Second, "2 hours 5 min"},
		{1500 * time.Millisecond, "2 sec"}, // rounded, not truncated to "1 sec"
		{0, "0 sec"},
		{-1 * time.Minute, "0 sec"}, // a clock step-back must not print "-1 min"
	}
	for _, c := range cases {
		if got := lockCauseDuration(c.in); got != c.want {
			t.Errorf("lockCauseDuration(%s) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestLockCauseDurationNeverLeaksGoDurationSyntax is the negative control: a
// Go duration's tell is a unit letter jammed straight against a digit
// ("5m0s"), and no rendering of any plausible bound may contain one. Without
// this the table above passes on a formatter that special-cases five minutes
// and leaks everywhere else.
func TestLockCauseDurationNeverLeaksGoDurationSyntax(t *testing.T) {
	for d := time.Second; d <= 9*time.Hour; d += 37 * time.Second {
		got := lockCauseDuration(d)
		for i := 1; i < len(got); i++ {
			prev, ch := got[i-1], got[i]
			if prev >= '0' && prev <= '9' && (ch|0x20) >= 'a' && (ch|0x20) <= 'z' {
				t.Fatalf("lockCauseDuration(%s) = %q: %q sits straight against a digit, which is time.Duration syntax, not a sentence",
					d, got, string(ch))
			}
		}
	}

	// And the control on the control: the raw Duration this replaced does
	// trip that check, so the check is capable of failing.
	raw := (5 * time.Minute).String()
	tripped := false
	for i := 1; i < len(raw); i++ {
		prev, ch := raw[i-1], raw[i]
		if prev >= '0' && prev <= '9' && (ch|0x20) >= 'a' && (ch|0x20) <= 'z' {
			tripped = true
		}
	}
	if !tripped {
		t.Fatalf("time.Duration(5m).String() = %q did not trip the guard — the guard proves nothing", raw)
	}
}
