// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// Package ui holds small, dependency-light terminal-feedback helpers shared
// across commands. It exists so long-running commands (scan, migrate, vault
// rekey) can show that work is happening instead of looking hung, without any
// command having to reimplement spinner/line-clearing mechanics.
package ui

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/fatih/color"
)

// spinnerFrames is a braille cycle — the same one most modern CLIs use. It
// reads as motion at ~11fps and every frame is a single fixed-width rune, so
// the in-place redraw never changes the line's length.
var spinnerFrames = []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'}

const spinnerInterval = 90 * time.Millisecond

// Tracker renders a live status trail to an io.Writer (always stderr in
// practice, so stdout stays byte-clean for pipes and captured reports). It has
// three modes, decided once by the caller and fixed for the tracker's life:
//
//	enabled && animate  a spinner animates the current step in place; each
//	                    finished step settles into a persistent "✓ …" line.
//	enabled && !animate  a dumb terminal — each step prints one plain line,
//	                     no animation, no ANSI. (TERM=dumb.)
//	!enabled            every method is a no-op (piped, CI, --quiet, or a
//	                    machine --format), so behavior is byte-for-byte as if
//	                    the tracker weren't there at all.
//
// Every method is safe to call in any mode; callers never branch on the mode
// themselves. Stop is idempotent and must be called (via defer) before any
// prompt or stdout result so the spinner line can never interleave with it.
type Tracker struct {
	w       io.Writer
	enabled bool
	animate bool

	mu       sync.Mutex
	running  string // present-tense label of the current (spinning) step
	doneText string // past-tense label the step settles to
	suffix   string // optional trailing text, e.g. a "12/47" counter
	frame    int
	active   bool // an animated step is currently on screen (needs settling)
	stopCh   chan struct{}
	doneCh   chan struct{}
}

// New builds a Tracker. enabled turns all output on/off; animate additionally
// requires a real terminal that can handle the carriage-return redraw. The
// caller decides both (see newProgress in the cli package) so this package
// stays free of any TTY/flag policy.
func New(w io.Writer, enabled, animate bool) *Tracker {
	return &Tracker{w: w, enabled: enabled, animate: animate}
}

// Step settles the previous step (if any) as "✓ <done>" and begins a new one.
// running is the present-tense line shown while it spins ("Scanning .env
// files…"); done is the past-tense line it settles to ("Scanned .env files").
// An empty done reuses running.
func (t *Tracker) Step(running, done string) {
	if !t.enabled {
		return
	}
	if done == "" {
		done = running
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	t.settleLocked()
	t.running = running
	t.doneText = done
	t.suffix = ""
	t.frame = 0

	if t.animate {
		t.active = true
		t.renderLocked()
		t.ensureTickerLocked()
	} else {
		// Dumb terminal: one plain line per step, nothing to settle later.
		fmt.Fprintln(t.w, running)
	}
}

// Update replaces the current step's trailing text (a live counter like
// "12/47"). It only does anything in animate mode; a dumb terminal or a
// disabled tracker ignores it, so callers can call it in a tight loop freely.
func (t *Tracker) Update(suffix string) {
	if !t.enabled || !t.animate {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.active {
		t.suffix = suffix
		t.renderLocked()
	}
}

// Stop settles the final step and halts the animation. It's idempotent and, in
// animate mode, waits for the ticker goroutine to exit before returning so no
// stray frame can print after the caller moves on to its result output.
func (t *Tracker) Stop() {
	if !t.enabled {
		return
	}
	t.mu.Lock()
	stop, done := t.stopCh, t.doneCh
	t.stopCh, t.doneCh = nil, nil
	t.mu.Unlock()

	if stop != nil {
		close(stop)
		<-done // ticker goroutine has now exited; no further renders can race
	}

	t.mu.Lock()
	t.settleLocked()
	t.mu.Unlock()
}

// settleLocked promotes the active animated step to its persistent "✓ <done>"
// line. A no-op unless an animated step is on screen (plain and disabled modes
// never set active), so it's safe to call from Step and Stop unconditionally.
func (t *Tracker) settleLocked() {
	if !t.active {
		return
	}
	check := color.New(color.FgGreen).Sprint("✓")
	fmt.Fprintf(t.w, "\r\033[K%s %s\n", check, t.doneText)
	t.active = false
}

// renderLocked repaints the current spinner line in place. \r returns to
// column 0 and \033[K clears to end-of-line, so a shorter frame never leaves
// tail characters from the previous one.
func (t *Tracker) renderLocked() {
	frame := color.New(color.Faint).Sprint(string(spinnerFrames[t.frame]))
	line := t.running
	if t.suffix != "" {
		line += " " + t.suffix
	}
	fmt.Fprintf(t.w, "\r\033[K%s %s", frame, line)
}

// ensureTickerLocked starts the single animation goroutine on the first
// animated step and leaves it running until Stop. Subsequent steps reuse it.
func (t *Tracker) ensureTickerLocked() {
	if t.stopCh != nil {
		return
	}
	t.stopCh = make(chan struct{})
	t.doneCh = make(chan struct{})
	go t.animateLoop(t.stopCh, t.doneCh)
}

func (t *Tracker) animateLoop(stop, done chan struct{}) {
	defer close(done)
	tick := time.NewTicker(spinnerInterval)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			t.mu.Lock()
			if t.active {
				t.frame = (t.frame + 1) % len(spinnerFrames)
				t.renderLocked()
			}
			t.mu.Unlock()
		}
	}
}
