// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// The CLI's fixed dialog reasons, held to the rules the agent's are: a
// lowercase verb that reads after "JitPass is trying to", at most 90 runes,
// and no "jit vault" once the app is named first.
func TestFixedDialogReasonsReadAfterTheAppName(t *testing.T) {
	for _, r := range []string{
		reasonMoveIn, reasonMoveCheck, reasonMoveBack,
		reasonVaultDelete, reasonRekey, reasonRekeyFinish,
	} {
		first, _ := utf8.DecodeRuneInString(r)
		if !unicode.IsLower(first) || utf8.RuneCountInString(r) > 90 || strings.Contains(r, "jit vault") {
			t.Errorf("reason %q does not read after \"JitPass is trying to\"", r)
		}
	}
}
