// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"maps"
	"path/filepath"
	"slices"
	"strings"
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

// mcpScanOne writes one config under a temp home and returns its findings
// keyed by KeyName, which is what every assertion below actually wants.
func mcpScanOne(t *testing.T, body string) (map[string]Finding, string) {
	t.Helper()
	home := t.TempDir()
	dir := filepath.Join(home, "proj")
	mkdirAll(t, dir)
	writeFile(t, filepath.Join(dir, ".mcp.json"), body)
	findings, err := ScanMCPConfigs(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanMCPConfigs: %v", err)
	}
	byKey := map[string]Finding{}
	for _, f := range findings {
		if f.KeyName != nil {
			byKey[*f.KeyName] = f
		}
	}
	return byKey, dir
}

func TestScanMCPConfigsRemoteHeaders(t *testing.T) {
	got, _ := mcpScanOne(t, `{"mcpServers":{"notion":{
		"type":"http","url":"https://mcp.notion.com/mcp",
		"headers":{"Authorization":"Bearer nTn9Kw2LpQ4vRs7XmZb3","Content-Type":"application/json"}}}}`)

	f, ok := got["notion/header:Authorization"]
	if !ok {
		t.Fatalf("no finding for the Authorization header; got %v", slices.Sorted(maps.Keys(got)))
	}
	if f.Severity != SeverityHigh {
		t.Errorf("severity = %q, want %q", f.Severity, SeverityHigh)
	}
	// Detect-only: jit cannot inject into a request the host makes itself, so
	// promising `jit migrate` here would be a hint that does nothing.
	if f.Remedy != RemedyManual {
		t.Errorf("remedy = %q, want %q", f.Remedy, RemedyManual)
	}
	if _, ok := got["notion/header:Content-Type"]; ok {
		t.Error("Content-Type is a transport header, not a credential")
	}
}

func TestScanMCPConfigsURLEmbeddedToken(t *testing.T) {
	got, _ := mcpScanOne(t, `{"mcpServers":{
		"tokened":{"type":"sse","url":"https://mcp.example.com/sse?api_key=sk-7fKd93MzQp2LxWv8RtYb4Nc6"},
		"plain":{"type":"http","url":"https://mcp.example.com/v1"}}}`)

	if _, ok := got["tokened/url"]; !ok {
		t.Errorf("a credential in the url field went unreported; got %v", slices.Sorted(maps.Keys(got)))
	}
	if _, ok := got["plain/url"]; ok {
		t.Error("a bare endpoint URL is not a credential")
	}
}

// The Slack fixture is assembled from two pieces on purpose. It is a
// synthetic value, but it is synthetic in exactly the format scanners
// match, so as one literal it trips GitHub's push protection and blocks
// the branch. Split, the file holds no complete token and the test still
// sees the whole string at runtime. Don't join it back up.
func TestScanMCPConfigsCommandLineTokens(t *testing.T) {
	got, _ := mcpScanOne(t, `{"mcpServers":{
		"inline":{"command":"npx","args":["-y","srv","--api-key=sk-7fKd93MzQp2LxWv8RtYb4Nc6"]},
		"dockered":{"command":"docker","args":["run","-i","--rm","-e","SLACK_BOT_TOKEN=xoxb-4827193046-`+"Kp9Wm2Lz7Qx4Rv8Nt3Bc"+`","mcp/slack"]}}}`)

	inline, ok := got["inline/args[2]"]
	if !ok {
		t.Fatalf("token in --flag=value form went unreported; got %v", slices.Sorted(maps.Keys(got)))
	}
	// The preview must show the credential, not the flag carrying it.
	if inline.ValuePreview == nil || !strings.HasPrefix(*inline.ValuePreview, "sk-") {
		t.Errorf("preview = %v, want the token half, not the --flag= half", inline.ValuePreview)
	}
	if _, ok := got["dockered/args[4]"]; !ok {
		t.Errorf("docker -e KEY=value went unreported; got %v", slices.Sorted(maps.Keys(got)))
	}
}

func TestScanMCPConfigsEnvFilePointer(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "proj")
	mkdirAll(t, dir)
	// Deliberately NOT named .env: envFileNamePattern gates ScanEnvFiles on
	// the filename, so this file is invisible to every other scanner. That is
	// the gap this finding exists to close.
	writeFile(t, filepath.Join(dir, "credentials.env"), "OKTA_API_TOKEN=00tGx7Kw2LpQ4vRs9XmZb3NcJdF6Yh1Wq8\n")
	writeFile(t, filepath.Join(dir, ".mcp.json"), `{"mcpServers":{
		"okta":{"command":"uv","args":["run","--env-file","./credentials.env","okta-mcp-server"]},
		"dangling":{"command":"uv","args":["run","--env-file","/nonexistent/x.env","srv"]}}}`)

	findings, err := ScanMCPConfigs(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanMCPConfigs: %v", err)
	}
	var okta *Finding
	for i := range findings {
		if findings[i].KeyName != nil && *findings[i].KeyName == "okta" {
			okta = &findings[i]
		}
		if findings[i].KeyName != nil && *findings[i].KeyName == "dangling" {
			t.Error("a pointer at a file that doesn't exist exposes nothing; doctor's job, not scan's")
		}
	}
	if okta == nil {
		t.Fatalf("--env-file target went unreported: %d findings", len(findings))
	}
	// The finding hangs off the CONFIG, naming the file, rather than
	// re-reporting the file itself under another category.
	if filepath.Base(okta.FilePath) != ".mcp.json" {
		t.Errorf("FilePath = %q, want the config file", okta.FilePath)
	}
	if !strings.Contains(okta.Evidence, "credentials.env") {
		t.Errorf("evidence %q must name the file the server reads", okta.Evidence)
	}
}

// A relative --env-file resolves against the entry's own cwd when it sets one.
func TestScanMCPConfigsEnvFileHonorsEntryCwd(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "proj")
	elsewhere := filepath.Join(home, "elsewhere")
	mkdirAll(t, dir)
	mkdirAll(t, elsewhere)
	writeFile(t, filepath.Join(elsewhere, "s.env"), "OKTA_API_TOKEN=00tGx7Kw2LpQ4vRs9XmZb3NcJdF6Yh1Wq8\n")
	writeFile(t, filepath.Join(dir, ".mcp.json"),
		`{"mcpServers":{"srv":{"command":"uv","cwd":"`+elsewhere+`","args":["run","--env-file=./s.env","srv"]}}}`)

	findings, err := ScanMCPConfigs(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanMCPConfigs: %v", err)
	}
	if len(findings) != 1 || !strings.Contains(findings[0].Evidence, "s.env") {
		t.Fatalf("findings = %+v, want the cwd-relative --env-file= target resolved", findings)
	}
}

// An application-state file a TOOL writes carries ordinary settings in the
// same block as credentials, so "everything in an env block is a credential"
// stops holding. De-escalated, never suppressed.
func TestScanMCPConfigsPlainSettingIsLow(t *testing.T) {
	got, _ := mcpScanOne(t, `{"mcpServers":{"crawl":{"command":"uvx","args":["crawl-mcp"],
		"env":{"CRAWL4AI_LANG":"en","CRAWL_API_KEY":"sk-7fKd93MzQp2LxWv8RtYb4Nc6"}}}}`)

	if f := got["crawl/CRAWL4AI_LANG"]; f.Severity != SeverityLow {
		t.Errorf("CRAWL4AI_LANG severity = %q, want %q: a language code is not a credential", f.Severity, SeverityLow)
	}
	if f := got["crawl/CRAWL_API_KEY"]; f.Severity != SeverityHigh {
		t.Errorf("CRAWL_API_KEY severity = %q, want %q", f.Severity, SeverityHigh)
	}
}

// A secret-shaped NAME keeps its finding however short the value: a
// six-character password is still a password.
func TestScanMCPConfigsShortSecretShapedValueStaysHigh(t *testing.T) {
	got, _ := mcpScanOne(t, `{"mcpServers":{"db":{"command":"srv","env":{"DB_PASSWORD":"hunter2"}}}}`)
	if f := got["db/DB_PASSWORD"]; f.Severity != SeverityHigh {
		t.Errorf("severity = %q, want %q", f.Severity, SeverityHigh)
	}
}

func TestScanMCPConfigsClaudeCodeStore(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".claude.json"), `{
		"mcpServers":{"top":{"command":"srv","env":{"TOP_API_KEY":"sk-7fKd93MzQp2LxWv8RtYb4Nc6"}}},
		"projects":{"/Users/x/work":{"mcpServers":{"scoped":{"command":"srv","env":{"SCOPED_TOKEN":"ghp_7fKd93MzQp2LxWv8RtYb4Nc6Jh1Wq8Zx"}}}}}}`)

	findings, err := ScanMCPConfigs(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanMCPConfigs: %v", err)
	}
	keys := map[string]bool{}
	for _, f := range findings {
		if f.KeyName != nil {
			keys[*f.KeyName] = true
		}
	}
	if !keys["top/TOP_API_KEY"] {
		t.Error("a top-level server in ~/.claude.json went unscanned")
	}
	// Qualified by project so two projects defining the same server name stay
	// distinguishable and get distinct record IDs.
	if !keys["work/scoped/SCOPED_TOKEN"] {
		t.Errorf("a project-scoped server went unscanned; got %v", slices.Sorted(maps.Keys(keys)))
	}
}

// A jit pointer file holds vault PATHS, not values. classifyEnvFile guards
// its own scan with isJitPointerContent; reaching buildEnvFileFinding directly
// skipped that, and a neutralized file was reported as "1 plaintext variable"
// -- noise, aimed at a file with nothing left to move.
func TestScanMCPConfigsIgnoresANeutralizedEnvFile(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "proj")
	mkdirAll(t, dir)
	writeFile(t, filepath.Join(dir, "creds.env"),
		"# jit pointer file, no secret values here, only vault paths.\nTOKEN=jit://vault/mcp-srv/TOKEN\n")
	writeFile(t, filepath.Join(dir, ".mcp.json"),
		`{"mcpServers":{"srv":{"command":"uv","args":["run","--env-file","./creds.env","srv"]}}}`)

	findings, err := ScanMCPConfigs(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanMCPConfigs: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("findings = %+v, want none: the target is already neutralized", findings)
	}
}
