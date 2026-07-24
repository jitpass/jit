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
// audit: `jit migrate home` skips these findings by default (GAPS.md #26),
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
