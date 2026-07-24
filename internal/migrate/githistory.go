// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"os/exec"
	"path/filepath"
	"strings"
)

// HasGitHistory reports whether path has ever been committed in its
// enclosing git repository — checked via `git log`, not just "is this
// file currently tracked right now," so a file someone already tried to
// scrub by deleting it and adding it to .gitignore is still correctly
// flagged (RFC.md B7: the old plaintext stays recoverable via `git log -p`/
// `git blame` regardless of the file's current tracked status).
//
// Returns false, nil — not an error — when git isn't installed or path
// isn't inside a git repository at all: RFC.md B7's warning only applies
// when there's actually history to worry about, and a missing/broken git
// installation shouldn't fail the whole migration over an unrelated
// problem.
func HasGitHistory(path string) (bool, error) {
	cmd := exec.Command("git", "log", "--oneline", "--", filepath.Base(path)) // #nosec G204 -- fixed subcommand and flags; the only variable part is a filename used as a git pathspec, never shell-interpreted
	cmd.Dir = filepath.Dir(path)
	out, err := cmd.Output()
	if err != nil {
		return false, nil
	}
	return strings.TrimSpace(string(out)) != "", nil
}
