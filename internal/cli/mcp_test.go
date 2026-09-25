// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A config shaped like the real one on the author's Mac: preferences and no
// mcpServers yet.
const desktopConfig = `{
  "coworkUserFilesPath": "/Users/x/Claude",
  "preferences": {"sidebarMode": "chat", "localAgentModeTrustedFolders": ["/Users/x/custom_scripts"]}
}
`

func TestSetMCPEntryAddsOnlyItsOwnEntryAndBacksUp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "claude_desktop_config.json")
	if err := os.WriteFile(path, []byte(desktopConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	entry := &mcpServerEntry{Command: "/opt/homebrew/bin/jit", Args: []string{"mcp"}}
	changed, backup, err := setMCPEntry(path, entry, time.Unix(0, 0))
	if err != nil || !changed || backup == "" {
		t.Fatalf("install: changed=%v backup=%q err=%v", changed, backup, err)
	}
	if b, _ := os.ReadFile(backup); string(b) != desktopConfig {
		t.Fatal("the backup is not the original file")
	}
	var cfg map[string]any
	raw, _ := os.ReadFile(path)
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["coworkUserFilesPath"] != "/Users/x/Claude" || cfg["preferences"].(map[string]any)["sidebarMode"] != "chat" {
		t.Fatalf("other keys changed: %s", raw)
	}
	jit := cfg["mcpServers"].(map[string]any)["jit"].(map[string]any)
	if jit["command"] != "/opt/homebrew/bin/jit" || jit["args"].([]any)[0] != "mcp" {
		t.Fatalf("entry = %v", jit)
	}

	// Idempotent: the same entry again changes nothing and backs up nothing.
	changed, backup, err = setMCPEntry(path, entry, time.Unix(1, 0))
	if err != nil || changed || backup != "" {
		t.Fatalf("second install: changed=%v backup=%q err=%v", changed, backup, err)
	}

	// Removing takes only its own entry, and leaves the rest.
	if err := os.WriteFile(path, []byte(strings.Replace(string(raw), `"jit"`, `"other": {"command": "/x"}, "jit"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, _, err := setMCPEntry(path, nil, time.Unix(2, 0)); err != nil || !changed {
		t.Fatalf("uninstall: %v %v", changed, err)
	}
	raw, _ = os.ReadFile(path)
	if strings.Contains(string(raw), `"jit"`) || !strings.Contains(string(raw), `"other"`) {
		t.Fatalf("uninstall removed the wrong thing: %s", raw)
	}
}

func TestSetMCPEntryLeavesABrokenFileAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "claude_desktop_config.json")
	if err := os.WriteFile(path, []byte(`{"preferences": {`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := setMCPEntry(path, &mcpServerEntry{Command: "/j", Args: []string{"mcp"}}, time.Now()); err == nil {
		t.Fatal("a broken config was rewritten")
	}
	if b, _ := os.ReadFile(path); string(b) != `{"preferences": {` {
		t.Fatal("the broken file was touched")
	}
}

func TestSetMCPEntryCreatesAMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Claude", "claude_desktop_config.json")
	changed, backup, err := setMCPEntry(path, &mcpServerEntry{Command: "/j", Args: []string{"mcp"}}, time.Now())
	if err != nil || !changed || backup != "" {
		t.Fatalf("changed=%v backup=%q err=%v", changed, backup, err)
	}
}

func TestMCPClientsKnowWhereEachAppKeepsItsServers(t *testing.T) {
	home, _ := os.UserHomeDir()
	for id, want := range map[string]string{
		"claude-desktop": filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
		"cursor":         filepath.Join(home, ".cursor", "mcp.json"),
	} {
		c, path, err := findMCPClient(id)
		if err != nil || path != want {
			t.Errorf("%s: %q %v, want %q", id, path, err, want)
		}
		if id == "cursor" && mcpInstallLine(c) != "jit mcp install --client cursor" {
			t.Errorf("cursor's install line = %q", mcpInstallLine(c))
		}
	}
	if _, _, err := findMCPClient("vscode"); err == nil || !strings.Contains(err.Error(), "claude-desktop, cursor") {
		t.Fatalf("an unknown app: %v", err)
	}
}
