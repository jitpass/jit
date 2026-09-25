// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package keychainwrap

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// The dialog reads "<app> is trying to <reason>.": a reason must start with a
// lowercase verb, fit the 90 runes internal/agent holds its own to, and never
// name the command ("jit vault") when the app is already named first.
func TestDialogReasonsReadAfterTheAppName(t *testing.T) {
	for _, r := range []string{reasonStore, reasonRead} {
		first, _ := utf8.DecodeRuneInString(r)
		if !unicode.IsLower(first) || utf8.RuneCountInString(r) > 90 || strings.Contains(r, "jit vault") {
			t.Errorf("reason %q does not read after \"JitPass is trying to\"", r)
		}
	}
}
