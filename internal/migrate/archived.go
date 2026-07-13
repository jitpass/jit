// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"path/filepath"
	"strings"
)

// archivedDirNames are path components (matched case-insensitively) that
// mark a finding as living under a project that looks archived/backed-up
// rather than actively worked on. `jit migrate home`'s whole-machine
// sweep skips anything under one of these by default (--include-archived
// overrides it) — GAPS.md #26.
//
// Why this matters specifically for .env/MCP/npmrc and not the other
// migrate categories: converting a forgotten project's .env into a live-
// mounted pipe (internal/mount) can turn it from "insecure but readable"
// into "permanently unreadable" — nothing will ever serve that pipe's
// content unless something later runs `jit agent` from that exact
// project again, which is exactly what won't happen for a project nobody
// revisits. Shell-config/AWS/kubeconfig don't have this failure mode (no
// file is left behind at all), so they're never filtered by this.
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

// FilterArchived splits paths into kept (doesn't look archived) and
// skipped (does), preserving order in both. Callers report skipped so a
// whole-machine run never silently drops a finding without saying so
// ("fail safe and loud").
func FilterArchived(paths []string) (kept, skipped []string) {
	for _, p := range paths {
		if LooksArchived(p) {
			skipped = append(skipped, p)
		} else {
			kept = append(kept, p)
		}
	}
	return kept, skipped
}
