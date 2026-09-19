// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Every wrapper layer is listed, each with the owner string of its block:
// the file for the top level, "file#projectDir" for a ~/.claude.json
// project, the same string claimMCPNamespace records.
func TestMCPProfileOwnersScopesEachBlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".claude.json")
	content := `{
	"mcpServers":{
		"okta":{"command":"/opt/homebrew/bin/jit","args":["run","--profile","mcp-outer","--","/old/jit","run","--profile","mcp-inner","--","npx","okta"]},
		"plain":{"command":"npx","env":{"K":"v"}}},
	"projects":{"/p/a":{"mcpServers":{
		"gh":{"command":"/opt/homebrew/bin/jit","args":["run","--profile","mcp-gh","--","npx","gh"]}}}}}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := MCPProfileOwners(path)
	if err != nil {
		t.Fatalf("MCPProfileOwners: %v", err)
	}
	want := []MCPProfileOwner{
		{Profile: "mcp-outer", Server: "okta", Owner: path, Layer: 0},
		{Profile: "mcp-inner", Server: "okta", Owner: path, Layer: 1},
		{Profile: "mcp-gh", Server: "gh", Owner: path + "#/p/a", Layer: 0},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("owners = %+v\nwant %+v", got, want)
	}

	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := MCPProfileOwners(path); err == nil {
		t.Error("a malformed config must be an error, not an empty answer")
	}
}
