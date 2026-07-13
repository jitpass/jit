// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"path/filepath"
	"testing"
)

func TestScanMCPConfigsProjectLocal(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, "code", "myproject"))
	writeFile(t, filepath.Join(home, "code", "myproject", ".mcp.json"), `{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_exampletoken123"
      }
    },
    "no-env-server": {
      "command": "npx"
    }
  }
}
`)
	findings, err := ScanMCPConfigs(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanMCPConfigs: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if *findings[0].KeyName != "github/GITHUB_PERSONAL_ACCESS_TOKEN" {
		t.Errorf("KeyName = %q, want %q", *findings[0].KeyName, "github/GITHUB_PERSONAL_ACCESS_TOKEN")
	}
	if findings[0].Severity != SeverityHigh {
		t.Errorf("severity = %q, want %q", findings[0].Severity, SeverityHigh)
	}
	if findings[0].FindingType != FindingTypeMCPEmbeddedSecret {
		t.Errorf("FindingType = %q, want %q", findings[0].FindingType, FindingTypeMCPEmbeddedSecret)
	}
}

func TestScanMCPConfigsVSCodeServersKey(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, "code", "myproject", ".vscode"))
	writeFile(t, filepath.Join(home, "code", "myproject", ".vscode", "mcp.json"), `{
  "servers": {
    "custom-api": {
      "env": {
        "API_KEY": "sk-example123"
      }
    }
  }
}
`)
	findings, err := ScanMCPConfigs(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanMCPConfigs: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if *findings[0].KeyName != "custom-api/API_KEY" {
		t.Errorf("KeyName = %q, want %q", *findings[0].KeyName, "custom-api/API_KEY")
	}
}

func TestScanMCPConfigsClaudeDesktopFixedPath(t *testing.T) {
	home := t.TempDir()
	// This path lives under "Library", which walkHomeDir's noiseDirs would
	// otherwise skip — confirms the fixed-path check actually reaches it.
	mkdirAll(t, filepath.Join(home, "Library", "Application Support", "Claude"))
	writeFile(t, filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"), `{
  "mcpServers": {
    "filesystem": {
      "env": {
        "ALLOWED_PATH_TOKEN": "example-secret-value"
      }
    }
  }
}
`)
	findings, err := ScanMCPConfigs(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanMCPConfigs: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (Claude Desktop config under ~/Library must still be found)", len(findings))
	}
}

// TestScanMCPConfigsBareURLGetsLowerSeverity locks in the real-world case
// (2026-07-06): a plain tool-endpoint URL (the actual example was
// caido/CAIDO_URL) was flagged identically to a real API key. It's still
// reported (URLs CAN embed secrets) but at reduced severity/confidence, not
// suppressed and not treated as equally urgent as an opaque token.
func TestScanMCPConfigsBareURLGetsLowerSeverity(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".mcp.json"), `{
  "mcpServers": {
    "caido": {
      "env": {
        "CAIDO_URL": "http://localhost:8080",
        "CAIDO_API_KEY": "sk-example-opaque-token-value"
      }
    }
  }
}
`)
	findings, err := ScanMCPConfigs(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanMCPConfigs: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (both still reported)", len(findings))
	}

	byKey := map[string]Finding{}
	for _, f := range findings {
		byKey[*f.KeyName] = f
	}

	url := byKey["caido/CAIDO_URL"]
	if url.Severity != SeverityLow || url.Confidence != ConfidenceLow {
		t.Errorf("CAIDO_URL severity/confidence = %s/%s, want %s/%s", url.Severity, url.Confidence, SeverityLow, ConfidenceLow)
	}

	key := byKey["caido/CAIDO_API_KEY"]
	if key.Severity != SeverityHigh || key.Confidence != ConfidenceHigh {
		t.Errorf("CAIDO_API_KEY severity/confidence = %s/%s, want %s/%s (an opaque token must not be downgraded)", key.Severity, key.Confidence, SeverityHigh, ConfidenceHigh)
	}
}

func TestScanMCPConfigsNoneFound(t *testing.T) {
	home := t.TempDir()
	findings, err := ScanMCPConfigs(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanMCPConfigs on empty home dir should not error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}
