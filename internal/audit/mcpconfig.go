// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// mcpConfigFileNames are exact filenames recognized as MCP/AI-tool configs
// during the broad home-directory walk. Claude Desktop's config lives under
// ~/Library, which walkHomeDir deliberately skips (noiseDirs) — it's
// checked separately via a fixed path below.
var mcpConfigFileNames = map[string]bool{
	"mcp.json":                   true,
	".mcp.json":                  true,
	"claude_desktop_config.json": true,
}

// mcpConfigFile covers both "mcpServers" (Claude Desktop, Cursor) and
// "servers" (VS Code's MCP schema) top-level keys, since this is a
// fast-moving ecosystem and tools haven't converged on one key name.
type mcpConfigFile struct {
	MCPServers map[string]mcpServerEntry `json:"mcpServers"`
	Servers    map[string]mcpServerEntry `json:"servers"`
}

type mcpServerEntry struct {
	Env map[string]string `json:"env"`
}

// ScanMCPConfigs implements RFC.md §4 category 4: embedded secrets in
// mcp.json-family files. Findings are per-key inside a server's env block —
// RFC's risk table says "any MCP-embedded secret" (singular), implying each
// embedded credential is its own finding, unlike .env's file-level
// granularity. Every key inside an env block is still flagged (not gated by
// the secret-keyword heuristic shell configs use — an MCP env block exists
// specifically to inject credentials into that server process, so anything
// there is credential-shaped by construction), but a value that looks like
// a bare URL (LooksLikeBareURL) gets lowered severity/confidence rather
// than being treated identically to an opaque API key — real-world review
// (2026-07-06) found a plain tool-endpoint URL (CAIDO_URL) getting flagged
// exactly like a real credential, which is noise, not signal.
func ScanMCPConfigs(cfg Config) ([]Finding, error) {
	var findings []Finding

	claudeDesktopPath := filepath.Join(cfg.HomeDir, "Library", "Application Support", "Claude", "claude_desktop_config.json")
	if _, err := os.Stat(claudeDesktopPath); err == nil {
		f, ferr := scanMCPConfigFile(cfg, claudeDesktopPath)
		if ferr != nil {
			return nil, ferr
		}
		findings = append(findings, f...)
	}

	err := walkHomeDir(cfg.HomeDir, func(path string, d fs.DirEntry) error {
		if !mcpConfigFileNames[d.Name()] || path == claudeDesktopPath {
			return nil
		}
		f, ferr := scanMCPConfigFile(cfg, path)
		if ferr != nil {
			return nil // malformed file — skip it, don't fail the whole audit
		}
		findings = append(findings, f...)
		return nil
	})
	return findings, err
}

func scanMCPConfigFile(cfg Config, path string) ([]Finding, error) {
	file, err := openFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var mc mcpConfigFile
	if err := json.NewDecoder(file).Decode(&mc); err != nil {
		return nil, nil // malformed JSON — not our job to validate it, just skip
	}

	servers := mc.MCPServers
	if len(servers) == 0 {
		servers = mc.Servers
	}

	var findings []Finding
	for serverName, entry := range servers {
		for envKey, envValue := range entry.Env {
			if envValue == "" {
				continue
			}

			severity, confidence, evidence := SeverityHigh, ConfidenceHigh,
				fmt.Sprintf("embedded directly in MCP server %q's env block", serverName)
			if LooksLikeBareURL(envValue) {
				// A plain URL with no embedded credentials is often just a
				// service endpoint (e.g. CAIDO_URL pointing at a local
				// proxy), not a secret — lower confidence rather than
				// suppress, since a URL CAN still embed a secret (a
				// webhook token in the path) that this heuristic misses.
				severity, confidence = SeverityLow, ConfidenceLow
				evidence = fmt.Sprintf(
					"plain URL in MCP server %q's env block — likely just an endpoint, but URLs can embed secrets too (e.g. webhook tokens)",
					serverName,
				)
			}

			findings = append(findings, cfg.ValueFinding(ValueFindingParams{
				FindingType:  FindingTypeMCPEmbeddedSecret,
				FilePath:     path,
				KeyName:      fmt.Sprintf("%s/%s", serverName, envKey),
				RawValue:     envValue,
				BaseSeverity: severity,
				Confidence:   confidence,
				Evidence:     evidence,
			}))
		}
	}
	return findings, nil
}
