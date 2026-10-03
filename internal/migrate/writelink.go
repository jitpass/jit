// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"os"
	"path/filepath"

	"github.com/jitpass/jit/internal/atomicfile"
)

// writeThroughLink writes a user's config file atomically without
// replacing a symlink to it: a dotfiles setup keeps ~/.aws/config or
// ~/.kube/config as a link into a repo, and the atomic write renames over
// its target, so the real file is written (RestoreShellConfig's
// reasoning). Its own file, apart from the path recorders
// TestEveryRecorderGoesThroughResolveJitExecutable guards: this resolves a
// user's file, never jit's own path.
func writeThroughLink(path string, data []byte, mode os.FileMode) error {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	return atomicfile.WriteFileMode(path, data, mode)
}
