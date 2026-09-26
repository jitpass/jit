// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/audit"
)

// The pre-release finding (2026-09-26): `jit mcp install` saves a copy of the
// app's config beside it, `jit migrate` then protected the config and walked
// past the copy, and the token lived on in the copy alone. A backup is
// discovered and migrated like its original: Cursor's reached by the walk,
// Claude Desktop's beside the fixed path no walk reaches.
func TestJitBackupsOfMCPConfigsAreDiscoveredAndMigrated(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	v := newTestVault(t)

	token := "ghp_" + strings.Repeat("aB3dE5fG7h", 4)[:36]
	config := `{
  "mcpServers": {
    "github": {
      "command": "npx",
      "env": {
        "GITHUB_TOKEN": "` + token + `"
      }
    }
  }
}
`
	stamp := time.Date(2026, 9, 26, 10, 10, 10, 0, time.UTC)
	cursor := filepath.Join(home, ".cursor", "mcp.json")
	cursorBackup := audit.MCPConfigBackupName(cursor, stamp)
	desktop := filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
	desktopBackup := audit.MCPConfigBackupName(desktop, stamp)
	for _, p := range []string{cursor, cursorBackup, desktopBackup} {
		writeFile(t, p, config)
	}
	// Not a jit backup, whatever it is called: left to the other categories.
	writeFile(t, cursor+".jit-backup-old", config)

	found, err := DiscoverMCPConfigs(home, home, true)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{cursor, cursorBackup, desktopBackup}
	slices.Sort(want)
	if !slices.Equal(found, want) {
		t.Fatalf("DiscoverMCPConfigs = %q, want %q", found, want)
	}

	// Migrating the config, then its backup: the backup's identical token
	// lands in the profile the config already uses, not a -2 copy.
	for _, p := range []string{cursor, cursorBackup, desktopBackup} {
		res, err := ApplyMCPConfig(v, p)
		if err != nil {
			t.Fatalf("ApplyMCPConfig(%s): %v", p, err)
		}
		if len(res.Servers) != 1 || res.Servers[0].ProfileName != "mcp-github" {
			t.Fatalf("ApplyMCPConfig(%s) = %+v, want one server in mcp-github", p, res.Servers)
		}
		if got := string(readBytes(t, p)); strings.Contains(got, token) {
			t.Fatalf("%s still holds the token after migrate:\n%s", p, got)
		}
	}
	if got, err := v.Get("mcp-github/GITHUB_TOKEN"); err != nil || string(got) != token {
		t.Fatalf("vault holds %q (err %v), want the token", got, err)
	}
	if found, err := DiscoverMCPConfigs(home, home, true); err != nil || len(found) != 0 {
		t.Fatalf("after migrate, DiscoverMCPConfigs = %q (err %v), want nothing left", found, err)
	}
}
