// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package wrap

import (
	"fmt"
	"os"
	"sort"

	"github.com/jitpass/jit/internal/profile"
)

// UndoResult reports what Undo removed, for the CLI to print.
type UndoResult struct {
	RemovedShim    bool
	RemovedProfile bool
	ProfilePath    string
	VaultPaths     []string // paths the removed profile referenced — the user's to keep or `jit vault rm`
	Remaining      int      // wrap-managed tools left after this undo
}

// Undo unwraps a tool: shim symlink gone, wrap-<tool> profile manifest
// gone, manifest entry gone. Vault secrets the profile referenced are
// deliberately left in place — `jit wrap add` never wrote them, so undo
// never deletes them; their paths are surfaced in the result so the CLI
// can tell the user how. Tolerates a half-installed wrap: a missing shim
// or profile is reported, not fatal, so undo always converges to
// "not wrapped".
func Undo(home, tool string) (UndoResult, error) {
	manifest, err := LoadManifest(home)
	if err != nil {
		return UndoResult{}, err
	}
	entry, ok := manifest.Tools[tool]
	if !ok {
		return UndoResult{}, fmt.Errorf("%s isn't wrap-managed — `jit wrap list` shows what is", tool)
	}

	var res UndoResult
	res.RemovedShim, err = RemoveShim(home, tool)
	if err != nil {
		return res, err
	}

	res.ProfilePath, err = profile.Path(home, entry.Profile)
	if err != nil {
		return res, err
	}
	if p, loadErr := profile.LoadFile(res.ProfilePath); loadErr == nil {
		for _, vaultPath := range p {
			res.VaultPaths = append(res.VaultPaths, vaultPath)
		}
		sort.Strings(res.VaultPaths)
	}
	switch err := os.Remove(res.ProfilePath); {
	case err == nil:
		res.RemovedProfile = true
	case !os.IsNotExist(err):
		return res, fmt.Errorf("removing %s: %w", res.ProfilePath, err)
	}

	delete(manifest.Tools, tool)
	if err := manifest.Save(home); err != nil {
		return res, err
	}
	res.Remaining = len(manifest.Tools)
	return res, nil
}
