// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/profile"
)

func TestDiscoverMCPConfigsFindsClaudeDesktopAndProjectFiles(t *testing.T) {
	home := t.TempDir()
	claudeDir := filepath.Join(home, "Library", "Application Support", "Claude")
	if err := os.MkdirAll(claudeDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	claudePath := filepath.Join(claudeDir, "claude_desktop_config.json")
	writeFile(t, claudePath, `{"mcpServers":{"stripe":{"command":"node","args":["s.js"],"env":{"STRIPE_KEY":"sk_live_x"}}}}`)

	cwd := t.TempDir()
	projectPath := filepath.Join(cwd, ".mcp.json")
	writeFile(t, projectPath, `{"mcpServers":{"local":{"command":"node","args":["s.js"],"env":{"API_KEY":"abc"}}}}`)

	noSecretsPath := filepath.Join(cwd, "mcp.json")
	writeFile(t, noSecretsPath, `{"mcpServers":{"clean":{"command":"node","args":["s.js"]}}}`)

	found, err := DiscoverMCPConfigs(home, cwd, true)
	if err != nil {
		t.Fatalf("DiscoverMCPConfigs: %v", err)
	}
	want := map[string]bool{claudePath: true, projectPath: true}
	if len(found) != len(want) {
		t.Fatalf("found = %v, want exactly %v", found, want)
	}
	for _, f := range found {
		if !want[f] {
			t.Errorf("unexpected file in results: %s", f)
		}
	}
}

func TestDiscoverMCPConfigsSkipsOutsideCwd(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()

	// A project MCP config that exists but sits outside cwd must not be found —
	// real mutation is scoped to the current directory tree only.
	elsewhere := t.TempDir()
	writeFile(t, filepath.Join(elsewhere, ".mcp.json"), `{"mcpServers":{"x":{"command":"node","env":{"K":"v"}}}}`)

	found, err := DiscoverMCPConfigs(home, cwd, true)
	if err != nil {
		t.Fatalf("DiscoverMCPConfigs: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("found = %v, want empty (elsewhere is outside cwd)", found)
	}
}

// TestDiscoverMCPConfigsIncludeClaudeDesktopFlag confirms
// includeClaudeDesktop actually gates the fixed Claude Desktop path —
// jit migrate local passes false since that path has no project-scoped
// form and must never appear in a local-scope plan; only jit migrate
// home passes true.
func TestDiscoverMCPConfigsIncludeClaudeDesktopFlag(t *testing.T) {
	home := t.TempDir()
	claudeDir := filepath.Join(home, "Library", "Application Support", "Claude")
	if err := os.MkdirAll(claudeDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	claudePath := filepath.Join(claudeDir, "claude_desktop_config.json")
	writeFile(t, claudePath, `{"mcpServers":{"stripe":{"command":"node","args":["s.js"],"env":{"STRIPE_KEY":"sk_live_x"}}}}`)

	cwd := t.TempDir()

	found, err := DiscoverMCPConfigs(home, cwd, false)
	if err != nil {
		t.Fatalf("DiscoverMCPConfigs: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("found = %v, want empty, includeClaudeDesktop=false must exclude it", found)
	}

	found, err = DiscoverMCPConfigs(home, cwd, true)
	if err != nil {
		t.Fatalf("DiscoverMCPConfigs: %v", err)
	}
	if len(found) != 1 || found[0] != claudePath {
		t.Errorf("found = %v, want [%s], includeClaudeDesktop=true must include it", found, claudePath)
	}
}

// TestDiscoverMCPConfigsToleratesUnreadableDirectory is the MCP-config
// counterpart to apply_test.go's identical regression test — see its
// comment for the real report this comes from (GAPS.md #26's home-wide
// walk hitting a permission-denied ~/.Trash and aborting outright).
func TestDiscoverMCPConfigsToleratesUnreadableDirectory(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root ignores directory permissions, can't exercise this")
	}
	home := t.TempDir()
	cwd := t.TempDir()
	projectPath := filepath.Join(cwd, "myapp", ".mcp.json")
	writeFile(t, projectPath, `{"mcpServers":{"local":{"command":"node","args":["s.js"],"env":{"API_KEY":"abc"}}}}`)

	blocked := filepath.Join(cwd, "blocked")
	if err := os.MkdirAll(blocked, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Chmod(blocked, 0o000); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o700) })

	found, err := DiscoverMCPConfigs(home, cwd, true)
	if err != nil {
		t.Fatalf("DiscoverMCPConfigs must tolerate an unreadable subdirectory, not abort: %v", err)
	}
	if len(found) != 1 || found[0] != projectPath {
		t.Errorf("found = %v, want [%s], the unreadable dir must be skipped, not stop discovery of everything else", found, projectPath)
	}
}

func TestApplyMCPConfigMovesSecretsAndRewritesCommand(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, "mcp.json")
	writeFile(t, path, `{
		"mcpServers": {
			"stripe": {
				"command": "node",
				"args": ["server.js", "--verbose"],
				"cwd": "/opt/stripe-mcp",
				"env": {"STRIPE_KEY": "sk_live_secret"}
			}
		}
	}`)

	v := newTestVault(t)
	result, err := ApplyMCPConfig(v, path)
	if err != nil {
		t.Fatalf("ApplyMCPConfig: %v", err)
	}
	if len(result.Servers) != 1 {
		t.Fatalf("Servers = %v, want 1 entry", result.Servers)
	}
	sm := result.Servers[0]
	if sm.ServerName != "stripe" || sm.ProfileName != "mcp-stripe" {
		t.Errorf("ServerName/ProfileName = %q/%q, want stripe/mcp-stripe", sm.ServerName, sm.ProfileName)
	}
	if len(sm.Variables) != 1 || sm.Variables[0] != "STRIPE_KEY" {
		t.Errorf("Variables = %v, want [STRIPE_KEY]", sm.Variables)
	}

	got, err := v.Get("mcp-stripe/STRIPE_KEY")
	if err != nil || string(got) != "sk_live_secret" {
		t.Errorf("vault secret = (%q, %v), want (sk_live_secret, nil)", got, err)
	}

	raw, err := os.ReadFile(path) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading rewritten file: %v", err)
	}
	if strings.Contains(string(raw), "sk_live_secret") {
		t.Fatal("rewritten MCP config must not contain the raw secret value")
	}

	var rewritten struct {
		MCPServers map[string]struct {
			Command string            `json:"command"`
			Args    []string          `json:"args"`
			Cwd     string            `json:"cwd"`
			Env     map[string]string `json:"env"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(raw, &rewritten); err != nil {
		t.Fatalf("rewritten file is not valid JSON: %v", err)
	}
	entry, ok := rewritten.MCPServers["stripe"]
	if !ok {
		t.Fatal("rewritten file lost the stripe server entry")
	}
	if entry.Env != nil {
		t.Errorf("expected env block removed, got %v", entry.Env)
	}
	if entry.Cwd != "/opt/stripe-mcp" {
		t.Errorf("Cwd = %q, want the original field preserved untouched", entry.Cwd)
	}
	wantArgs := []string{"run", "--profile", "mcp-stripe", "--", "node", "server.js", "--verbose"}
	if len(entry.Args) != len(wantArgs) {
		t.Fatalf("Args = %v, want %v", entry.Args, wantArgs)
	}
	for i := range wantArgs {
		if entry.Args[i] != wantArgs[i] {
			t.Errorf("Args[%d] = %q, want %q", i, entry.Args[i], wantArgs[i])
		}
	}
	if entry.Command == "node" || entry.Command == "" {
		t.Errorf("Command = %q, want jit's own resolved executable path", entry.Command)
	}

	// The profile lives in the home-rooted global store, resolvable via
	// jit run regardless of what cwd the MCP host launches the subprocess in.
	p, err := profile.Load(t.TempDir(), "mcp-stripe")
	if err != nil {
		t.Fatalf("loading migrated profile via the global fallback: %v", err)
	}
	if p["STRIPE_KEY"] != "mcp-stripe/STRIPE_KEY" {
		t.Errorf("profile entry = %q, want mcp-stripe/STRIPE_KEY", p["STRIPE_KEY"])
	}
}

func TestApplyMCPConfigWritesBackup(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, "mcp.json")
	original := `{"mcpServers":{"s":{"command":"node","env":{"K":"v"}}}}`
	writeFile(t, path, original)

	v := newTestVault(t)
	result, err := ApplyMCPConfig(v, path)
	if err != nil {
		t.Fatalf("ApplyMCPConfig: %v", err)
	}
	backup, err := v.Get(result.BackupPath)
	if err != nil {
		t.Fatalf("reading backup from vault: %v", err)
	}
	if string(backup) != original {
		t.Errorf("backup content = %q, want the original file content %q", backup, original)
	}
}

func TestApplyMCPConfigSanitizesServerNameForProfile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, "mcp.json")
	writeFile(t, path, `{"mcpServers":{"my server/v2":{"command":"node","env":{"K":"v"}}}}`)

	v := newTestVault(t)
	result, err := ApplyMCPConfig(v, path)
	if err != nil {
		t.Fatalf("ApplyMCPConfig: %v", err)
	}
	if strings.ContainsAny(result.Servers[0].ProfileName, " /") {
		t.Errorf("ProfileName = %q, still contains unsafe characters", result.Servers[0].ProfileName)
	}
}

func TestApplyMCPConfigNoSecretsErrors(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, "mcp.json")
	writeFile(t, path, `{"mcpServers":{"clean":{"command":"node"}}}`)

	v := newTestVault(t)
	if _, err := ApplyMCPConfig(v, path); err == nil {
		t.Fatal("expected an error migrating a file with no server secrets")
	}
}

func TestApplyMCPConfigServersSchema(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, "mcp.json")
	writeFile(t, path, `{"servers":{"vscode-style":{"command":"node","env":{"K":"v"}}}}`)

	v := newTestVault(t)
	result, err := ApplyMCPConfig(v, path)
	if err != nil {
		t.Fatalf("ApplyMCPConfig with VS Code's servers schema: %v", err)
	}
	if len(result.Servers) != 1 || result.Servers[0].ServerName != "vscode-style" {
		t.Errorf("Servers = %v, want one entry for vscode-style", result.Servers)
	}

	raw, err := os.ReadFile(path) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading rewritten file: %v", err)
	}
	if !strings.Contains(string(raw), `"servers"`) {
		t.Errorf("rewritten file lost the servers key, got:\n%s", raw)
	}
}

// TestApplyMCPConfigSameServerNameDifferentConfigs is GAPS.md #56's
// regression test: a server named "github" in two DIFFERENT config files
// used to land both migrations on the same global-store profile and the
// same mcp-github/<VAR> vault paths — the later run silently overwriting
// the earlier one's live token, and both rewritten configs then launching
// with whichever migrated last. The second config must move to
// "mcp-github-2" (recorded ownership via the .source sidecar), leaving the
// first untouched.
func TestApplyMCPConfigSameServerNameDifferentConfigs(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	v := newTestVault(t)

	pathA := filepath.Join(home, "projA", "mcp.json")
	pathB := filepath.Join(home, "projB", "mcp.json")
	writeFile(t, pathA, `{"mcpServers":{"github":{"command":"npx","env":{"GITHUB_TOKEN":"token-from-a"}}}}`)
	writeFile(t, pathB, `{"mcpServers":{"github":{"command":"npx","env":{"GITHUB_TOKEN":"token-from-b"}}}}`)

	resultA, err := ApplyMCPConfig(v, pathA)
	if err != nil {
		t.Fatalf("ApplyMCPConfig(A): %v", err)
	}
	if resultA.Servers[0].ProfileName != "mcp-github" || resultA.Servers[0].NamespaceMovedFrom != "" {
		t.Fatalf("A: (ProfileName, NamespaceMovedFrom) = (%q, %q), want (mcp-github, \"\")", resultA.Servers[0].ProfileName, resultA.Servers[0].NamespaceMovedFrom)
	}

	resultB, err := ApplyMCPConfig(v, pathB)
	if err != nil {
		t.Fatalf("ApplyMCPConfig(B): %v", err)
	}
	smB := resultB.Servers[0]
	if smB.ProfileName != "mcp-github-2" {
		t.Errorf("B ProfileName = %q, want mcp-github-2, a different config's server must never claim the first one's namespace", smB.ProfileName)
	}
	if smB.NamespaceMovedFrom != "mcp-github" {
		t.Errorf("B NamespaceMovedFrom = %q, want mcp-github", smB.NamespaceMovedFrom)
	}

	// The point of the mechanism: A's live token survives B's migration.
	if got, err := v.Get("mcp-github/GITHUB_TOKEN"); err != nil || string(got) != "token-from-a" {
		t.Errorf("mcp-github/GITHUB_TOKEN = (%q, %v), want (token-from-a, nil)", got, err)
	}
	if got, err := v.Get("mcp-github-2/GITHUB_TOKEN"); err != nil || string(got) != "token-from-b" {
		t.Errorf("mcp-github-2/GITHUB_TOKEN = (%q, %v), want (token-from-b, nil)", got, err)
	}
	// And B's rewritten config launches with ITS profile, not A's.
	rawB, err := os.ReadFile(pathB) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading rewritten B: %v", err)
	}
	if !strings.Contains(string(rawB), "mcp-github-2") {
		t.Errorf("B's rewritten config must reference mcp-github-2, got:\n%s", rawB)
	}
}

// A re-run from the SAME config file (the undo-then-remigrate flow) must
// refresh its own namespace in place — the .source sidecar is what
// distinguishes it from the foreign-config case above.
func TestApplyMCPConfigReRunSameConfigRefreshes(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	v := newTestVault(t)

	path := filepath.Join(home, "mcp.json")
	original := `{"mcpServers":{"github":{"command":"npx","env":{"GITHUB_TOKEN":"token-v1"}}}}`
	writeFile(t, path, original)
	if _, err := ApplyMCPConfig(v, path); err != nil {
		t.Fatalf("first ApplyMCPConfig: %v", err)
	}

	// Put the original config back (what `jit migrate undo` does) with an
	// updated token, then migrate again.
	writeFile(t, path, strings.ReplaceAll(original, "token-v1", "token-v2"))
	result, err := ApplyMCPConfig(v, path)
	if err != nil {
		t.Fatalf("second ApplyMCPConfig: %v", err)
	}
	sm := result.Servers[0]
	if sm.ProfileName != "mcp-github" || sm.NamespaceMovedFrom != "" {
		t.Errorf("re-run: (ProfileName, NamespaceMovedFrom) = (%q, %q), want (mcp-github, \"\"), a re-run refreshes, never forks", sm.ProfileName, sm.NamespaceMovedFrom)
	}
	if got, err := v.Get("mcp-github/GITHUB_TOKEN"); err != nil || string(got) != "token-v2" {
		t.Errorf("after re-run, token = (%q, %v), want (token-v2, nil)", got, err)
	}
}

// A profile migrated before the .source sidecar existed has no recorded
// owner. Identical values → adopt it (and stamp it); any difference → the
// exact silent overwrite #56 describes → bump.
func TestApplyMCPConfigLegacyUnstampedProfile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	v := newTestVault(t)

	// Simulate a pre-#56 migration by hand: manifest + secret, NO sidecar.
	profilePath, err := profile.Path(home, "mcp-github")
	if err != nil {
		t.Fatalf("profile.Path: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(profilePath), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	writeFile(t, profilePath, "GITHUB_TOKEN: mcp-github/GITHUB_TOKEN\n")
	if err := v.Set("mcp-github/GITHUB_TOKEN", []byte("same-token")); err != nil {
		t.Fatalf("v.Set: %v", err)
	}

	// Same value → adopt: same namespace, and now stamped.
	pathSame := filepath.Join(home, "same", "mcp.json")
	writeFile(t, pathSame, `{"mcpServers":{"github":{"command":"npx","env":{"GITHUB_TOKEN":"same-token"}}}}`)
	resultSame, err := ApplyMCPConfig(v, pathSame)
	if err != nil {
		t.Fatalf("ApplyMCPConfig(same value): %v", err)
	}
	if resultSame.Servers[0].ProfileName != "mcp-github" {
		t.Errorf("identical-value legacy profile should be adopted, got %q", resultSame.Servers[0].ProfileName)
	}
	if _, err := os.Stat(profileSourceSidecarPath(profilePath)); err != nil {
		t.Errorf("adoption must stamp the .source sidecar: %v", err)
	}

	// A DIFFERENT config with a different value must now bump (the sidecar
	// names pathSame), never overwrite.
	pathDiff := filepath.Join(home, "diff", "mcp.json")
	writeFile(t, pathDiff, `{"mcpServers":{"github":{"command":"npx","env":{"GITHUB_TOKEN":"different-token"}}}}`)
	resultDiff, err := ApplyMCPConfig(v, pathDiff)
	if err != nil {
		t.Fatalf("ApplyMCPConfig(different value): %v", err)
	}
	if resultDiff.Servers[0].ProfileName != "mcp-github-2" {
		t.Errorf("different config must bump, got %q", resultDiff.Servers[0].ProfileName)
	}
	if got, err := v.Get("mcp-github/GITHUB_TOKEN"); err != nil || string(got) != "same-token" {
		t.Errorf("legacy secret = (%q, %v), want (same-token, nil), must survive the different config's migration", got, err)
	}
}

func TestUnwrapMCPConfigRestoresWrappedServer(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, "mcp.json")
	writeFile(t, path, `{
		"mcpServers": {
			"stripe": {
				"command": "node",
				"args": ["server.js", "--verbose"],
				"cwd": "/opt/stripe-mcp",
				"env": {"STRIPE_KEY": "sk_live_secret"}
			}
		}
	}`)

	v := newTestVault(t)
	applied, err := ApplyMCPConfig(v, path)
	if err != nil {
		t.Fatalf("ApplyMCPConfig: %v", err)
	}
	sm := applied.Servers[0]

	if owner := ProfileOwnerConfig(sm.ProfilePath); owner != path {
		t.Fatalf("ProfileOwnerConfig = %q, want %q", owner, path)
	}
	if wrapped := WrappedMCPProfiles(path); !wrapped[sm.ProfileName] {
		t.Fatalf("WrappedMCPProfiles = %v, want %q wrapped", wrapped, sm.ProfileName)
	}

	// Edit the vault value after migration — unwrap must write back the
	// CURRENT value (unmount's semantics), not the original.
	if err := v.Set(sm.ProfileName+"/STRIPE_KEY", []byte("sk_live_rotated")); err != nil {
		t.Fatalf("vault set: %v", err)
	}

	restored, err := UnwrapMCPConfig(v, path, map[string]string{sm.ProfileName: sm.ProfilePath})
	if err != nil {
		t.Fatalf("UnwrapMCPConfig: %v", err)
	}
	if len(restored) != 1 || restored[0].ServerName != "stripe" {
		t.Fatalf("restored = %+v, want the stripe server", restored)
	}

	raw, err := os.ReadFile(path) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var rewritten struct {
		MCPServers map[string]struct {
			Command string            `json:"command"`
			Args    []string          `json:"args"`
			Cwd     string            `json:"cwd"`
			Env     map[string]string `json:"env"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(raw, &rewritten); err != nil {
		t.Fatalf("rewritten file is not valid JSON: %v", err)
	}
	entry := rewritten.MCPServers["stripe"]
	if entry.Command != "node" {
		t.Errorf("Command = %q, want the original node", entry.Command)
	}
	if len(entry.Args) != 2 || entry.Args[0] != "server.js" || entry.Args[1] != "--verbose" {
		t.Errorf("Args = %v, want the original [server.js --verbose]", entry.Args)
	}
	if entry.Env["STRIPE_KEY"] != "sk_live_rotated" {
		t.Errorf("Env = %v, want the CURRENT vault value sk_live_rotated", entry.Env)
	}
	if entry.Cwd != "/opt/stripe-mcp" {
		t.Errorf("Cwd = %q, want the original field preserved untouched", entry.Cwd)
	}
}

func TestUnwrapMCPConfigLeavesForeignWrappersAlone(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, "mcp.json")
	writeFile(t, path, `{
		"mcpServers": {
			"other": {
				"command": "/usr/local/bin/jit",
				"args": ["run", "--profile", "mcp-other", "--", "node", "s.js"]
			}
		}
	}`)
	before, err := os.ReadFile(path) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	v := newTestVault(t)
	restored, err := UnwrapMCPConfig(v, path, map[string]string{"mcp-mine": "/nonexistent.yaml"})
	if err != nil {
		t.Fatalf("UnwrapMCPConfig: %v", err)
	}
	if len(restored) != 0 {
		t.Fatalf("restored = %+v, want nothing, mcp-other is not in the owned set", restored)
	}
	after, err := os.ReadFile(path) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(after) != string(before) {
		t.Error("config rewritten even though nothing was restored")
	}
}

func TestRemoveOwnedProfileDeletesManifestAndSidecar(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "mcp-x.yaml")
	writeFile(t, manifest, "K: mcp-x/K\n")
	writeFile(t, profileSourceSidecarPath(manifest), "/some/mcp.json\n")

	if err := RemoveOwnedProfile(manifest); err != nil {
		t.Fatalf("RemoveOwnedProfile: %v", err)
	}
	if _, err := os.Stat(manifest); !os.IsNotExist(err) {
		t.Error("manifest still exists")
	}
	if _, err := os.Stat(profileSourceSidecarPath(manifest)); !os.IsNotExist(err) {
		t.Error(".source sidecar still exists")
	}
	if err := RemoveOwnedProfile(manifest); err != nil {
		t.Errorf("second RemoveOwnedProfile must be idempotent, got %v", err)
	}
}
