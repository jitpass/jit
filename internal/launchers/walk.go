// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package launchers

import (
	"io/fs"
	"path/filepath"
	"sort"

	"github.com/jitpass/jit/internal/audit"
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/pointerfile"
)

// homeWalk is what one walk of home finds: everything a fixed path can't.
type homeWalk struct {
	projectRoots []string // directories holding a .jit (home's own excluded)
	envPointers  []string // in-place pointer files with a .env-family name
	mcpFiles     []string // files with an MCP config name
	coverage     Coverage
}

// walkHome walks home ONCE for all three kinds. Directories are pruned the
// way migrate's own discovery walks prune them (migrate.SkipDiscoveryDir:
// audit's noise list, the Go module cache), plus the Trash: a trashed
// project launches nothing. A .jit directory is recorded as a project root
// and never entered; home's own .jit is the global store, read separately.
// A directory the walk can't enter is skipped and recorded in Coverage, as
// every home walk in jit does: one privacy-denied folder must not blind
// the rest.
func walkHome(home string) homeWalk {
	w := homeWalk{coverage: Coverage{Root: home}}
	err := filepath.WalkDir(home, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path == home {
				return err
			}
			if d != nil && d.IsDir() {
				w.coverage.Unreadable = append(w.coverage.Unreadable, path)
				return fs.SkipDir
			}
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if path == home {
				return nil
			}
			if name == ".jit" {
				if parent := filepath.Dir(path); parent != home {
					w.projectRoots = append(w.projectRoots, parent)
				}
				return fs.SkipDir
			}
			if name == ".Trash" || migrate.SkipDiscoveryDir(home, path, name) {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if audit.IsMCPConfigFileName(name) {
			w.mcpFiles = append(w.mcpFiles, path)
		}
		if !pointerfile.IsCompanion(name) && migrate.IsEnvFileName(name) && migrate.IsPointerFile(path) {
			w.envPointers = append(w.envPointers, path)
		}
		return nil
	})
	w.coverage.Walked = err == nil
	sort.Strings(w.projectRoots)
	sort.Strings(w.mcpFiles)
	return w
}
