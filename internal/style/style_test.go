// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package style

import (
	"strings"
	"testing"

	"github.com/fatih/color"
)

// TestPlainColorEmitsNothing pins the one non-obvious thing in this package.
// PlainColor has to be a *color.Color so it can sit in a severity map beside
// real inks, but it must write the string and nothing else — a color.New()
// with no attributes would emit ESC[m, which is a RESET and would strip any
// attribute the caller had already opened around it.
func TestPlainColorEmitsNothing(t *testing.T) {
	restore := color.NoColor
	color.NoColor = false // force styling on, as if writing to a terminal
	defer func() { color.NoColor = restore }()

	if got := PlainColor.Sprint("hello"); got != "hello" {
		t.Errorf("PlainColor.Sprint = %q, want %q (no escape bytes)", got, "hello")
	}
	// Sanity check the opposite direction, so a fatih/color upgrade that made
	// every Color a no-op would fail here rather than silently un-style jit.
	if got := Risk.Sprint("hello"); !strings.Contains(got, "\x1b[") {
		t.Errorf("Risk.Sprint = %q, want escape bytes — colour is not being applied", got)
	}
}

// TestGlyphsAreSingleRune keeps the glyph block swappable. Everything except
// the lock is one rune wide in the terminals jit targets; a two-rune "glyph"
// would break every column budget that assumes one cell.
func TestGlyphsAreSingleRune(t *testing.T) {
	for name, g := range map[string]string{
		"GlyphOK":        GlyphOK,
		"GlyphWarn":      GlyphWarn,
		"GlyphRisk":      GlyphRisk,
		"GlyphDone":      GlyphDone,
		"GlyphMark":      GlyphMark,
		"GlyphAction":    GlyphAction,
		"GlyphBullet":    GlyphBullet,
		"GlyphBranch":    GlyphBranch,
		"GlyphBarFilled": GlyphBarFilled,
		"GlyphBarEmpty":  GlyphBarEmpty,
		"GlyphRule":      GlyphRule,
	} {
		if n := len([]rune(g)); n != 1 {
			t.Errorf("%s is %d runes, want 1", name, n)
		}
	}
}
