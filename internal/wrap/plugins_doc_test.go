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
// catalog_data.go and docs/PLUGINS.md: a catalog entry that isn't
// documented (or a doc row for a tool that was removed) fails here, so the
// public supported-tools page can never silently disagree with the code.
func TestPluginsDocListsEveryCatalogTool(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "PLUGINS.md"))
	if err != nil {
		t.Fatalf("docs/PLUGINS.md must exist and list every catalog tool: %v", err)
	}
	doc := string(data)
	for _, tool := range CatalogTools() {
		if !strings.Contains(doc, "`"+tool+"`") {
			t.Errorf("docs/PLUGINS.md doesn't list catalog tool %q", tool)
		}
	}
}
