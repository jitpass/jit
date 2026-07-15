// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package wrap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPluginsDocListsEveryCatalogTool is the drift guard between
// catalog_data.go and docs/wrap/: a catalog entry that isn't documented
// (or a doc row for a tool that was removed) fails here, so the public
// supported-tools pages can never silently disagree with the code. Every
// tool must appear in the docs/wrap/index.md catalog tables AND have its
// own docs/wrap/<tool>.md page.
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
		if _, err := os.Stat(filepath.Join("..", "..", "docs", "wrap", tool+".md")); err != nil {
			t.Errorf("catalog tool %q has no docs/wrap/%s.md page: %v", tool, tool, err)
		}
	}
}
