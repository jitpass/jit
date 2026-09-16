// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"path/filepath"
	"strings"
)

// Excluded reports whether path lies at or under one of cfg.ExcludePaths.
// Both sides are compared cleaned and absolute; a prefix match is only a
// match at a path boundary, so excluding ~/work never excludes ~/work-old.
func (cfg Config) Excluded(path string) bool {
	if len(cfg.ExcludePaths) == 0 {
		return false
	}
	clean := filepath.Clean(path)
	for _, ex := range cfg.ExcludePaths {
		ex = filepath.Clean(ex)
		if clean == ex || strings.HasPrefix(clean, ex+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// dropExcluded removes every finding whose file lies under an excluded
// path. The walk already skips excluded directories; this is the belt over
// it, for the fixed-location scanners and the agent-cache cross-reference,
// which do not walk.
func dropExcluded(cfg Config, findings []Finding) []Finding {
	if len(cfg.ExcludePaths) == 0 {
		return findings
	}
	kept := findings[:0]
	for _, f := range findings {
		if !cfg.Excluded(f.FilePath) {
			kept = append(kept, f)
		}
	}
	return kept
}
