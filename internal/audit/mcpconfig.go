// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
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
	fixed, err := scanClaudeDesktopMCPConfig(cfg)
	if err != nil {
		return nil, err
	}
	walked, err := walkForCategory(cfg, classifyMCPFile)
	// Composed exactly as Scan composes the two halves — see
	// ScanCredentialFiles. No walk can currently reach the Claude Desktop
	// config (~/Library is pruned), so nothing is dropped in practice; using
	// the same expression everywhere is what stops that from being a fact
	// someone has to re-verify per category.
	return append(fixed, dropAlreadyReported(fixed, walked)...), err
}

// scanClaudeDesktopMCPConfig is the known-location half of the MCP category:
// Claude Desktop's config lives at one fixed path under ~/Library, which the
// discovery walk deliberately never reaches (noiseDirs prunes Library), so it
// has to be probed directly.
func scanClaudeDesktopMCPConfig(cfg Config) ([]Finding, error) {
	path := filepath.Join(cfg.HomeDir, "Library", "Application Support", "Claude", "claude_desktop_config.json")
	if _, err := os.Stat(path); err != nil {
		return nil, nil // absent (or unstattable) — nothing to scan, never an error
	}
	return scanMCPConfigFile(cfg, path)
}

// classifyMCPFile is the name-gated per-file half of the MCP category, split
// out so the machine-wide walk (see categories) and `jit scan <path>`'s
// targeted walk recognize the same mcp.json / .mcp.json /
// claude_desktop_config.json names. Returns nil for a name that isn't a known
// MCP config file, and for one that is but can't be parsed (skip, never fail).
//
// No guard against re-reporting the Claude Desktop config scanned above is
// needed: walkHomeDir prunes ~/Library outright, so no home walk can reach
// that path. Leaving the guard out is also what keeps `jit scan
// ~/Library/Application\ Support/Claude` — a path the user named explicitly,
// where the known-location half never runs — reporting anything at all.
func classifyMCPFile(cfg Config, path, name string) []Finding {
	if !mcpConfigFileNames[name] {
		return nil
	}
	findings, err := scanMCPConfigFile(cfg, path)
	if err != nil {
		return nil
	}
	return findings
}

func scanMCPConfigFile(cfg Config, path string) ([]Finding, error) {
	file, err := openFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var mc mcpConfigFile
	// Bounded for the same reason inspectK8sSecretFile's decoder is: this runs
	// on any walked mcp.json, and json.Decoder will happily build whatever the
	// file describes.
	if err := json.NewDecoder(io.LimitReader(file, maxStructuredParseSize)).Decode(&mc); err != nil {
		return nil, nil // malformed JSON — not our job to validate it, just skip
	}

	servers := mc.MCPServers
	if len(servers) == 0 {
		servers = mc.Servers
	}

	// Both loops iterate sorted keys rather than raw map order — see
	// scanAWSCredentials for why. This file is where it bit hardest: a single
	// mcp.json commonly holds several servers with several env keys each, so
	// its findings reshuffled on every run.
	var findings []Finding
	for _, serverName := range slices.Sorted(maps.Keys(servers)) {
		entry := servers[serverName]
		for _, envKey := range slices.Sorted(maps.Keys(entry.Env)) {
			envValue := entry.Env[envKey]
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
				// Keep this terse: the reason renders on one line in the
				// report, and the full endpoint-vs-webhook-token nuance made
				// it the longest line on real machines by a wide margin.
				evidence = fmt.Sprintf("plain URL in MCP server %q's env block; URLs can embed tokens", serverName)
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
