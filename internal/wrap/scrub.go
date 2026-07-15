// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package wrap

import (
	"fmt"
	"os"
	"strings"
)

// ScrubToken removes the one line carrying the extracted secret from src's
// file, leaving every other byte alone — the file usually carries
// non-secret settings that must survive (the same discipline as migrate's
// npmrc rewriter). Line-oriented on purpose: both cataloged formats keep
// one credential per line, and a whole-file re-marshal would reorder and
// reformat a config the tool itself wrote.
//
// The line to remove must contain BOTH the selector's final key and the
// secret value — either alone could match an unrelated line (a comment
// naming the key, a second account with a different token). No match is an
// error: the caller already extracted the value from this file, so failing
// to find it again means the file changed underneath us, and scrubbing
// blind would be worse than leaving the token.
//
// The caller is responsible for backing the file up (encrypted, via
// migrate's machinery) BEFORE calling this.
func ScrubToken(home string, src TokenSource, value string) error {
	path := ExpandHome(home, src.Path)
	data, err := os.ReadFile(path) // #nosec G304 -- a fixed catalog path under the user's home dir
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}

	parts := selectorParts(src.Selector)
	key := parts[len(parts)-1]

	lines := strings.Split(string(data), "\n")
	removed := false
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if !removed && strings.Contains(line, key) && strings.Contains(line, value) {
			removed = true
			continue
		}
		kept = append(kept, line)
	}
	if !removed {
		return fmt.Errorf("%s: the extracted token isn't where it was — refusing to scrub a file that changed underneath the wrap", path)
	}

	mode := os.FileMode(0o600)
	if info, statErr := os.Stat(path); statErr == nil {
		mode = info.Mode()
	}
	if err := os.WriteFile(path, []byte(strings.Join(kept, "\n")), mode); err != nil { // #nosec G703 -- path is the catalog-listed config file the token was just extracted from; rewriting it minus the token is what scrub does
		return fmt.Errorf("rewriting %s: %w", path, err)
	}
	return nil
}
