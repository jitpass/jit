// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package unlockreason

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// The dialog reads "<app> is trying to <reason>.". The words are pinned: a
// change here changes every unlock prompt, in the service and outside it.
// And a reason must start with a lowercase verb, fit the 90 runes
// internal/agent holds its own to, and never name the command ("jit vault")
// when the app is already named first.
func TestDialogReasonsReadAfterTheAppName(t *testing.T) {
	for _, c := range []struct{ got, want string }{
		{Store, "unlock the vault to store a secret"},
		{Read, "unlock the vault to read a secret"},
	} {
		if c.got != c.want {
			t.Errorf("reason %q changed; the dialog says %q", c.got, c.want)
		}
		first, _ := utf8.DecodeRuneInString(c.got)
		if !unicode.IsLower(first) || utf8.RuneCountInString(c.got) > 90 || strings.Contains(c.got, "jit vault") {
			t.Errorf("reason %q does not read after \"JitPass is trying to\"", c.got)
		}
	}
}

// The words live here only. Three copies (keychainwrap, secureenclave, the
// agent), each with its own test, is how a prompt comes to read differently
// depending on which process asked.
func TestDialogReasonsAreSpelledOnce(t *testing.T) {
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && path == filepath.Join(root, "internal", "unlockreason") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		data, err := os.ReadFile(path) // #nosec G304 -- walking this repository's own source
		if err != nil {
			return err
		}
		for _, r := range []string{Store, Read} {
			if strings.Contains(string(data), `"`+r+`"`) {
				t.Errorf("%s spells %q itself; use unlockreason", path, r)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
