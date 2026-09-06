// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"path/filepath"
	"strings"
)

// archivedDirNames are path components (matched case-insensitively) that
// mark a finding as living under a project that looks archived/backed-up
// rather than actively worked on. The canonical list lives here, not in
// internal/migrate (which consumes it via LooksArchived), because both
// sides of the audit→migrate funnel need it and migrate already imports
// audit: `jit migrate ~` skips these findings by default (GAPS.md #26),
// and the audit report tags them so that skip never reads as migrate
// having lost a finding the audit just showed.
var archivedDirNames = map[string]bool{
	"archive": true, "archived": true, ".trash": true, "trash": true,
	"backup": true, "backups": true,
}

// LooksArchived reports whether any path component of path matches
// archivedDirNames, case-insensitively.
func LooksArchived(path string) bool {
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if archivedDirNames[strings.ToLower(part)] {
			return true
		}
	}
	return false
}

// trashDirNames are the archivedDirNames components that mean "already
// deleted once" rather than "kept on purpose". The distinction earns its own
// remedy in the report: migrating a file out of the Trash would preserve
// what deletion is about to fix, so the reader is told to finish the
// deletion instead of being offered jit migrate.
var trashDirNames = map[string]bool{".trash": true, "trash": true}

// InTrash reports whether any path component of path matches trashDirNames,
// case-insensitively. Every InTrash path also satisfies LooksArchived, so
// callers ordering remedies must test trash FIRST or the archived branch
// swallows it. Exported for the same reason LooksArchived is: both sides of
// the audit→migrate funnel need the one predicate — the triage renderer to
// say "empty the Trash", and `jit migrate --clean` to plan finishing that
// deletion — and two copies would drift.
func InTrash(path string) bool {
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if trashDirNames[strings.ToLower(part)] {
			return true
		}
	}
	return false
}

// dirDiscoverable reports whether naming a DIRECTORY above f's file would
// rediscover it: `jit migrate <dir>` walks project files only (.env, tfvars,
// k8s secret manifests, mcp configs, .npmrc — cli's discoverDirTarget), so a
// finding of any other kind must keep its explicit path in a shortened
// archived-group command, or the short command silently drops it.
func dirDiscoverable(f Finding) bool {
	switch f.FindingType {
	case FindingTypeEnvFilePresent, FindingTypeIACVariableFile, FindingTypeMCPEmbeddedSecret:
		return true
	}
	return filepath.Base(f.FilePath) == ".npmrc"
}

// commonDir returns the deepest directory containing every path, or "" when
// the walk reaches the filesystem root first. Callers gate what the result
// may be used for; this only computes the ancestor.
func commonDir(paths []string) string {
	if len(paths) == 0 {
		return ""
	}
	common := filepath.Dir(paths[0])
	for _, p := range paths[1:] {
		for !strings.HasPrefix(filepath.Dir(p)+"/", common+"/") {
			parent := filepath.Dir(common)
			if parent == common {
				return ""
			}
			common = parent
		}
	}
	return common
}
