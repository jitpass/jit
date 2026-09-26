// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// backupFixtureToken is shaped like a GitHub token (ghp_ + 36), built at run
// time so no scanner mistakes this file for one holding a real credential.
var backupFixtureToken = "ghp_" + strings.Repeat("aB3dE5fG7h", 4)[:36]

func backupFixtureConfig() string {
	return `{
  "mcpServers": {
    "github": {
      "command": "npx",
      "env": {
        "GITHUB_TOKEN": "` + backupFixtureToken + `"
      }
    }
  }
}
`
}

// wantBackupFinding checks findings hold exactly the fixture's one token, at
// path and on the line it sits on, the way the same file under its real name
// is reported.
func wantBackupFinding(t *testing.T, findings []Finding, path string) {
	t.Helper()
	var mcp []Finding
	for _, f := range findings {
		if f.FindingType == FindingTypeMCPEmbeddedSecret {
			mcp = append(mcp, f)
		}
	}
	if len(mcp) != 1 {
		t.Fatalf("got %d MCP findings (%d in all), want 1: a jit-backup of an MCP config holding a token must be reported", len(mcp), len(findings))
	}
	f := mcp[0]
	if f.FilePath != path {
		t.Errorf("FilePath = %q, want %q", f.FilePath, path)
	}
	if f.Line == nil || *f.Line != 6 {
		t.Errorf("Line = %v, want 6", f.Line)
	}
	if f.KeyName == nil || *f.KeyName != "github/GITHUB_TOKEN" {
		t.Errorf("KeyName = %v, want github/GITHUB_TOKEN", f.KeyName)
	}
	if f.Severity != SeverityHigh {
		t.Errorf("Severity = %q, want %q", f.Severity, SeverityHigh)
	}
}

// The pre-release finding (2026-09-26): `jit scan <folder>` on a folder
// holding only the copy `jit mcp install` saves reported CLEAN, while the
// same bytes under the config's own name were HIGH.
func TestTargetedScanReportsAJitBackupOfAnMCPConfig(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "Claude")
	mkdirAll(t, dir)
	backup := MCPConfigBackupName(filepath.Join(dir, "claude_desktop_config.json"), time.Date(2026, 9, 26, 10, 10, 10, 0, time.UTC))
	writeFile(t, backup, backupFixtureConfig())

	findings, _, err := TargetedScan(Config{HomeDir: home}, []string{dir})
	if err != nil {
		t.Fatal(err)
	}
	wantBackupFinding(t, findings, backup)

	// Named directly, it is routed to the MCP scanner too, not only swept
	// for vendor tokens: the finding keeps its server/key and its line.
	findings, _, err = TargetedScan(Config{HomeDir: home}, []string{backup})
	if err != nil {
		t.Fatal(err)
	}
	wantBackupFinding(t, findings, backup)
}

// The machine-wide scan: Claude Desktop's backup sits under ~/Library, which
// no walk reaches, so the fixed half must probe beside the fixed config —
// here with the config itself gone. Cursor's is reached by the walk.
func TestScanMCPConfigsFindsJitBackupsBesideKnownConfigs(t *testing.T) {
	stamp := time.Date(2026, 9, 26, 10, 10, 10, 0, time.UTC)

	home := t.TempDir()
	desktop := filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
	mkdirAll(t, filepath.Dir(desktop))
	backup := MCPConfigBackupName(desktop, stamp)
	writeFile(t, backup, backupFixtureConfig())
	findings, err := ScanMCPConfigs(Config{HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	wantBackupFinding(t, findings, backup)

	home = t.TempDir()
	cursor := filepath.Join(home, ".cursor", "mcp.json")
	mkdirAll(t, filepath.Dir(cursor))
	backup = MCPConfigBackupName(cursor, stamp)
	writeFile(t, backup, backupFixtureConfig())
	findings, err = ScanMCPConfigs(Config{HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	wantBackupFinding(t, findings, backup)
}

// The name is recognized strictly: `jit mcp install` deletes older backups
// by it (MCPConfigBackups), so anything looser would let it delete a file jit
// did not write.
func TestMCPConfigBackupNamesAreStrict(t *testing.T) {
	for name, want := range map[string]bool{
		"claude_desktop_config.json.jit-backup-20260926-101010": true,
		"mcp.json.jit-backup-20260926-101010":                   true,
		".mcp.json.jit-backup-20260926-101010":                  true,
		"mcp.json":                                              false,
		"mcp.json.jit-backup-2026":                              false,
		"mcp.json.jit-backup-20260926-101010.bak":               false,
		"mcp.json.jit-backup-20260926-1010100":                  false,
		"mcp.json.jit-backup-2026O926-101010":                   false,
		"mcp.json.bak":                                          false,
		"notes.txt.jit-backup-20260926-101010":                  false,
		"xmcp.json.jit-backup-20260926-101010":                  false,
		".jit-backup-20260926-101010":                           false,
	} {
		if got := IsMCPConfigBackupName(name); got != want {
			t.Errorf("IsMCPConfigBackupName(%q) = %v, want %v", name, got, want)
		}
	}

	dir := t.TempDir()
	config := filepath.Join(dir, "mcp.json")
	older := MCPConfigBackupName(config, time.Date(2026, 9, 25, 9, 0, 0, 0, time.UTC))
	newer := MCPConfigBackupName(config, time.Date(2026, 9, 26, 9, 0, 0, 0, time.UTC))
	for _, p := range []string{config, newer, older,
		config + ".bak",
		config + ".jit-backup-latest",
		filepath.Join(dir, ".mcp.json.jit-backup-20260926-090000"), // another config's
	} {
		writeFile(t, p, "{}")
	}
	if err := os.Symlink(config, MCPConfigBackupName(config, time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC))); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(MCPConfigBackupName(config, time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)), 0o700); err != nil {
		t.Fatal(err)
	}
	if got, want := MCPConfigBackups(config), []string{older, newer}; !slices.Equal(got, want) {
		t.Fatalf("MCPConfigBackups = %q, want %q (oldest first, regular files named for this config only)", got, want)
	}
}
