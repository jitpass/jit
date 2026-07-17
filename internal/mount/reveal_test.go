// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package mount

import (
	"testing"
	"time"
)

func TestRevealStateStartsHidden(t *testing.T) {
	s := NewRevealState()
	if s.IsRevealed() {
		t.Error("a brand-new RevealState must start hidden, a mount must never default to serving real content")
	}
}

func TestRevealStateRevealedWithinWindow(t *testing.T) {
	s := NewRevealState()
	s.Reveal(100 * time.Millisecond)
	if !s.IsRevealed() {
		t.Fatal("expected revealed immediately after Reveal")
	}
	time.Sleep(150 * time.Millisecond)
	if s.IsRevealed() {
		t.Error("expected hidden after the window elapsed")
	}
}

func TestRevealStateHideEndsWindowEarly(t *testing.T) {
	s := NewRevealState()
	s.Reveal(time.Minute)
	if !s.IsRevealed() {
		t.Fatal("expected revealed right after Reveal")
	}
	s.Hide()
	if s.IsRevealed() {
		t.Error("expected hidden immediately after Hide, not after the original window would have elapsed")
	}
}

// TestRevealStateRemaining is GAPS.md #37's regression test for the basis
// of "jit status"/"jit agent status" showing "revealed for Ns" instead of
// a bare yes/no.
func TestRevealStateRemaining(t *testing.T) {
	s := NewRevealState()
	if r := s.Remaining(); r != 0 {
		t.Errorf("Remaining() on a fresh, hidden state = %v, want 0", r)
	}

	s.Reveal(time.Minute)
	r := s.Remaining()
	if r <= 0 || r > time.Minute {
		t.Errorf("Remaining() right after Reveal(1m) = %v, want a positive value no greater than 1m", r)
	}

	s.Hide()
	if r := s.Remaining(); r != 0 {
		t.Errorf("Remaining() after Hide = %v, want 0", r)
	}
}

// TestRevealStateWindowEnded covers the "the timer ended and nothing said
// so" visibility gap: after a window ends — naturally or via Hide —
// WindowEnded must report when, so status can say "ended Xm ago" instead
// of the revealed line just silently disappearing.
func TestRevealStateWindowEnded(t *testing.T) {
	s := NewRevealState()
	if _, ended := s.WindowEnded(); ended {
		t.Error("WindowEnded on a never-revealed state = true, want false, there was never a window to end")
	}

	s.Reveal(time.Minute)
	if _, ended := s.WindowEnded(); ended {
		t.Error("WindowEnded while still revealed = true, want false")
	}

	s.Hide()
	at, ended := s.WindowEnded()
	if !ended {
		t.Fatal("WindowEnded after Hide = false, want true")
	}
	if since := time.Since(at); since < 0 || since > time.Second {
		t.Errorf("WindowEnded after Hide reported %v ago, want just now", since)
	}

	// Natural expiry, not just Hide.
	s2 := NewRevealState()
	s2.Reveal(10 * time.Millisecond)
	time.Sleep(30 * time.Millisecond)
	if _, ended := s2.WindowEnded(); !ended {
		t.Error("WindowEnded after natural expiry = false, want true")
	}
}

func TestRevealStateReRevealExtendsWindow(t *testing.T) {
	s := NewRevealState()
	s.Reveal(50 * time.Millisecond)
	time.Sleep(30 * time.Millisecond)
	s.Reveal(200 * time.Millisecond) // re-reveal before the first window expires
	time.Sleep(80 * time.Millisecond)
	if !s.IsRevealed() {
		t.Error("re-revealing should extend the window from the second call, not stack on top of the first")
	}
}
