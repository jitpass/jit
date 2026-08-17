// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package wrap

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/jitpass/jit/internal/profile"
)

// UndoResult reports what Undo removed, for the CLI to print.
type UndoResult struct {
	RemovedShim    bool
	RemovedProfile bool
	ProfilePath    string
	VaultPaths     []string // paths the removed profile referenced, the user's to keep or `jit vault rm`
	Remaining      int      // wrap-managed tools left after this undo
}

// UndoPreview reports what Undo WOULD remove, for `jit wrap undo
// --dry-run`. Read-only by contract.
type UndoPreview struct {
	ShimPath    string
	ProfilePath string   // "" for grant/capture/run-grant wraps, which have no profile to remove
	VaultPaths  []string // kept either way; listed so the preview matches the real run's output
	LastTool    bool     // true: the real run also removes the shim PATH line from the rc
}

// PreviewUndo resolves what Undo(home, tool) would do, touching nothing.
// It shares Undo's manifest/profile reads rather than re-deriving them,
// so the preview and the real run can't disagree about the same tool.
func PreviewUndo(home, tool string) (UndoPreview, error) {
	manifest, err := LoadManifest(home)
	if err != nil {
		return UndoPreview{}, err
	}
	entry, ok := manifest.Tools[tool]
	if !ok {
		return UndoPreview{}, fmt.Errorf("%s isn't wrap-managed, `jit wrap list` shows what is", tool)
	}
	prev := UndoPreview{
		ShimPath: filepath.Join(ShimDir(home), tool),
		LastTool: len(manifest.Tools) == 1,
	}
	if !entry.IsGrant() && !entry.IsCapture() && !entry.IsRunGrant() {
		prev.ProfilePath, err = profile.Path(home, entry.Profile)
		if err != nil {
			return prev, err
		}
		if p, loadErr := profile.LoadFile(prev.ProfilePath); loadErr == nil {
			for _, vaultPath := range p {
				prev.VaultPaths = append(prev.VaultPaths, vaultPath)
			}
			sort.Strings(prev.VaultPaths)
		}
	}
	return prev, nil
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
		return UndoResult{}, fmt.Errorf("%s isn't wrap-managed, `jit wrap list` shows what is", tool)
	}

	var res UndoResult
	res.RemovedShim, err = RemoveShim(home, tool)
	if err != nil {
		return res, err
	}

	// A grant-wrap has no profile to remove — just the shim and the manifest
	// entry. Same for a capture-wrap: the vault profile its captures fill
	// (aws-<app>) belongs to the AWS credential_process wiring, which keeps
	// serving after the wrap is gone — unwrapping stops future captures,
	// it doesn't unprotect what was already captured. A run-grant-wrap has
	// no profile either: the manifest mount it grants belongs to the
	// k8s-secret migration, which keeps serving (decoys by default) after
	// the wrap is gone. An env-wrap removes its wrap-<tool> profile too.
	if !entry.IsGrant() && !entry.IsCapture() && !entry.IsRunGrant() {
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
	}

	delete(manifest.Tools, tool)
	if err := manifest.Save(home); err != nil {
		return res, err
	}
	res.Remaining = len(manifest.Tools)
	return res, nil
}
