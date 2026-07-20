// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package wrap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// docFileOverride names a catalog tool whose docs page can't live at the
// default docs/wrap/<tool>.md path. Only "claude" needs one: Claude Code's
// own CLAUDE.md project-instructions discovery matches filenames
// case-insensitively, and APFS (the macOS default) is a case-insensitive
// filesystem — a real docs/wrap/claude.md was confirmed to get loaded as a
// directory-scoped CLAUDE.md the moment it existed, injecting a docs page's
// prose as project instructions for anyone running Claude Code anywhere
// under docs/wrap/ on a stock checkout. jit's own contributors are exactly
// who'd hit this (the agent's own provenance feature literally detects
// "launched by claude"), so this is a standing landmine, not a theoretical
// one. New tools must NOT be added to this map casually — it exists for
// this one filename collision, not as a general escape hatch.
var docFileOverride = map[string]string{
	"claude": "claude-code",
}

func docFileStem(tool string) string {
	if stem, ok := docFileOverride[tool]; ok {
		return stem
	}
	return tool
}

// TestPluginsDocListsEveryCatalogTool is the drift guard between
// catalog_data.go and docs/wrap/: a catalog entry that isn't documented
// (or a doc row for a tool that was removed) fails here, so the public
// supported-tools pages can never silently disagree with the code. Every
// tool must appear in the docs/wrap/index.md catalog tables AND have its
// own docs/wrap/<tool>.md page (docFileOverride's tool aside, which lives
// at a different stem for the reason documented above).
func TestPluginsDocListsEveryCatalogTool(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "wrap", "index.md"))
	if err != nil {
		t.Fatalf("docs/wrap/index.md must exist and list every catalog tool: %v", err)
	}
	doc := string(data)
	for _, tool := range CatalogTools() {
		if !strings.Contains(doc, "`"+tool+"`") {
			t.Errorf("docs/wrap/index.md doesn't list catalog tool %q", tool)
		}
		stem := docFileStem(tool)
		if _, err := os.Stat(filepath.Join("..", "..", "docs", "wrap", stem+".md")); err != nil {
			t.Errorf("catalog tool %q has no docs/wrap/%s.md page: %v", tool, stem, err)
		}
		if _, isOverridden := docFileOverride[tool]; isOverridden {
			if _, err := os.Stat(filepath.Join("..", "..", "docs", "wrap", tool+".md")); err == nil {
				t.Errorf("catalog tool %q must NOT also have a docs/wrap/%s.md — that filename is the exact CLAUDE.md collision docFileOverride exists to avoid", tool, tool)
			}
		}
	}
}
