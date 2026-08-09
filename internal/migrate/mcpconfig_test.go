// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sort"
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

func TestDiscoverWrappedMCPEntriesReportsWrapperFields(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	path := filepath.Join(cwd, ".mcp.json")
	writeFile(t, path, `{"mcpServers":{
		"wrapped":{"command":"/opt/jit","args":["run","--profile","mcp-wrapped","--","uv","run","srv"]},
		"plain":{"command":"npx","args":["-y","srv"],"env":{"API_KEY":"abc"}}
	}}`)

	entries, err := DiscoverWrappedMCPEntries(home, cwd, false)
	if err != nil {
		t.Fatalf("DiscoverWrappedMCPEntries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %+v, want exactly the wrapped server", entries)
	}
	got := entries[0]
	want := WrappedMCPEntry{
		ConfigPath:  path,
		ServerName:  "wrapped",
		JitPath:     "/opt/jit",
		ProfileName: "mcp-wrapped",
		Command:     "uv",
	}
	if got != want {
		t.Errorf("entry = %+v, want %+v", got, want)
	}
}

// A wrapper with nothing after the "--" is legal (migrateMCPServer writes it
// for a server that had an env block and no command of its own), and must
// report an empty Command rather than panicking on args[4].
func TestDiscoverWrappedMCPEntriesEmptyWrappedCommand(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	writeFile(t, filepath.Join(cwd, ".mcp.json"),
		`{"mcpServers":{"bare":{"command":"/opt/jit","args":["run","--profile","mcp-bare","--"]}}}`)

	entries, err := DiscoverWrappedMCPEntries(home, cwd, false)
	if err != nil {
		t.Fatalf("DiscoverWrappedMCPEntries: %v", err)
	}
	if len(entries) != 1 || entries[0].Command != "" {
		t.Fatalf("entries = %+v, want one entry with an empty Command", entries)
	}
}

// The migrate-side discovery predicate and this one must not bleed into each
// other: a file with only wrapped servers has nothing left to migrate, and a
// file with only plaintext env blocks has nothing wrapped to check.
func TestDiscoverMCPConfigsAndWrappedEntriesSelectDifferentFiles(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	wrappedOnly := filepath.Join(cwd, ".mcp.json")
	writeFile(t, wrappedOnly, `{"mcpServers":{"w":{"command":"/opt/jit","args":["run","--profile","p","--","srv"]}}}`)
	plainOnly := filepath.Join(cwd, "mcp.json")
	writeFile(t, plainOnly, `{"mcpServers":{"p":{"command":"npx","args":["srv"],"env":{"K":"v"}}}}`)

	migratable, err := DiscoverMCPConfigs(home, cwd, false)
	if err != nil {
		t.Fatalf("DiscoverMCPConfigs: %v", err)
	}
	if len(migratable) != 1 || migratable[0] != plainOnly {
		t.Errorf("DiscoverMCPConfigs = %v, want only %s", migratable, plainOnly)
	}

	entries, err := DiscoverWrappedMCPEntries(home, cwd, false)
	if err != nil {
		t.Fatalf("DiscoverWrappedMCPEntries: %v", err)
	}
	if len(entries) != 1 || entries[0].ConfigPath != wrappedOnly {
		t.Errorf("DiscoverWrappedMCPEntries = %+v, want only %s", entries, wrappedOnly)
	}
}

func TestApplyMCPConfigMigratesEnvFileServer(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	envPath := filepath.Join(home, "secrets.env")
	writeFile(t, envPath, "OKTA_ORG_URL=https://x.okta.com\nOKTA_TOKEN=00tGx7Kw2LpQ4vRs9XmZb3\n")
	path := filepath.Join(home, ".mcp.json")
	writeFile(t, path, `{"mcpServers":{"okta":{
		"command":"uv",
		"args":["run","--env-file","`+envPath+`","--directory","/srv","okta-mcp-server"],
		"alwaysAllow":["list_users"]}}}`)

	v := newTestVault(t)
	result, err := ApplyMCPConfig(v, path)
	if err != nil {
		t.Fatalf("ApplyMCPConfig: %v", err)
	}
	if len(result.Servers) != 1 {
		t.Fatalf("Servers = %+v, want the --env-file server migrated", result.Servers)
	}
	sm := result.Servers[0]
	if len(sm.EnvFiles) != 1 || sm.EnvFiles[0] != envPath {
		t.Errorf("EnvFiles = %v, want [%s]", sm.EnvFiles, envPath)
	}

	// Both variables reached the vault under the server's own profile.
	for _, name := range []string{"OKTA_ORG_URL", "OKTA_TOKEN"} {
		if _, err := v.Get("mcp-okta/" + name); err != nil {
			t.Errorf("v.Get(mcp-okta/%s): %v", name, err)
		}
	}

	// The flag goes with the file: leaving it would point uv at the pointer
	// file and set every credential to a literal "jit://vault/..." string.
	_, blocks, _, err := loadMCPFile(path)
	if err != nil {
		t.Fatalf("loadMCPFile: %v", err)
	}
	if len(blocks) != 1 {
		t.Fatalf("blocks = %d, want 1", len(blocks))
	}
	servers := blocks[0].servers
	var args []string
	if err := json.Unmarshal(servers["okta"]["args"], &args); err != nil {
		t.Fatalf("args: %v", err)
	}
	for i, a := range args {
		if a == "--env-file" || strings.HasPrefix(a, "--env-file=") {
			t.Errorf("args still carry --env-file at %d: %v", i, args)
		}
	}
	want := []string{"run", "--profile", "mcp-okta", "--", "uv", "run", "--directory", "/srv", "okta-mcp-server"}
	if !slices.Equal(args, want) {
		t.Errorf("args = %v, want %v", args, want)
	}
	if _, ok := servers["okta"]["alwaysAllow"]; !ok {
		t.Error("an unknown field was dropped from the rewritten entry")
	}

	// The source file is neutralized, not left in plaintext.
	body, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("reading %s: %v", envPath, err)
	}
	if strings.Contains(string(body), "00tGx7Kw2LpQ4vRs9XmZb3") {
		t.Error("the credential is still on disk in the --env-file target")
	}
	if !strings.Contains(string(body), "jit://vault/mcp-okta/OKTA_TOKEN") {
		t.Errorf("target was not replaced with a pointer file:\n%s", body)
	}
}

// A name in both places must resolve to the env block: the host sets that on
// the child process directly, and silently preferring the file would change
// what the server sees.
func TestApplyMCPConfigEnvBlockWinsOverEnvFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	envPath := filepath.Join(home, "s.env")
	writeFile(t, envPath, "TOKEN=from-the-file\n")
	path := filepath.Join(home, ".mcp.json")
	writeFile(t, path, `{"mcpServers":{"srv":{"command":"uv",
		"args":["run","--env-file","`+envPath+`","srv"],
		"env":{"TOKEN":"from-the-block"}}}}`)

	v := newTestVault(t)
	if _, err := ApplyMCPConfig(v, path); err != nil {
		t.Fatalf("ApplyMCPConfig: %v", err)
	}
	got, err := v.Get("mcp-srv/TOKEN")
	if err != nil {
		t.Fatalf("v.Get: %v", err)
	}
	if string(got) != "from-the-block" {
		t.Errorf("TOKEN = %q, want the env block's value", got)
	}
}

// The same hard stop ApplyEnvFile takes, for the same reason: the next step
// rewrites this file, so a silently dropped line is a variable the server
// loses with nothing saying why.
func TestApplyMCPConfigEnvFileUnparsedLineStops(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	envPath := filepath.Join(home, "s.env")
	writeFile(t, envPath, "GOOD=1\nthis is not a KEY=value line at all &&&\n")
	path := filepath.Join(home, ".mcp.json")
	writeFile(t, path, `{"mcpServers":{"srv":{"command":"uv","args":["run","--env-file","`+envPath+`","srv"]}}}`)

	v := newTestVault(t)
	_, err := ApplyMCPConfig(v, path)
	if err == nil {
		t.Fatal("ApplyMCPConfig succeeded on an unparseable --env-file target, want a hard stop")
	}
	if !strings.Contains(err.Error(), "could not be parsed") {
		t.Errorf("error = %v, want it to name the parse failure", err)
	}
	// Nothing was touched: the stop happens before any rewrite.
	body, _ := os.ReadFile(envPath)
	if !strings.Contains(string(body), "GOOD=1") {
		t.Error("the source file was modified despite the hard stop")
	}
}

// A pointer at a file that isn't there is not migratable: there is nothing to
// read, and stripping the flag would remove something the user still needs
// once they fix the path.
func TestDiscoverMCPConfigsSkipsDanglingEnvFile(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	writeFile(t, filepath.Join(cwd, ".mcp.json"),
		`{"mcpServers":{"srv":{"command":"uv","args":["run","--env-file","/nonexistent/x.env","srv"]}}}`)

	found, err := DiscoverMCPConfigs(home, cwd, false)
	if err != nil {
		t.Fatalf("DiscoverMCPConfigs: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("found = %v, want none: the target doesn't exist", found)
	}
}

func TestMCPEnvFilePreviewNamesTheSecondFile(t *testing.T) {
	home := t.TempDir()
	envPath := filepath.Join(home, "s.env")
	writeFile(t, envPath, "TOKEN=x\n")
	path := filepath.Join(home, ".mcp.json")
	writeFile(t, path, `{"mcpServers":{"srv":{"command":"uv","args":["run","--env-file","`+envPath+`","srv"]}}}`)

	got := MCPEnvFilePreview(path)
	if len(got) != 1 || got[0] != envPath {
		t.Errorf("MCPEnvFilePreview = %v, want [%s]", got, envPath)
	}
}

// Undoing the config alone would re-add --env-file aimed at a pointer file.
func TestApplyMCPConfigLinksEnvFileForUndo(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	envPath := filepath.Join(home, "s.env")
	writeFile(t, envPath, "TOKEN=00tGx7Kw2LpQ4vRs9XmZb3\n")
	path := filepath.Join(home, ".mcp.json")
	writeFile(t, path, `{"mcpServers":{"srv":{"command":"uv","args":["run","--env-file","`+envPath+`","srv"]}}}`)

	v := newTestVault(t)
	if _, err := ApplyMCPConfig(v, path); err != nil {
		t.Fatalf("ApplyMCPConfig: %v", err)
	}
	records, err := LoadBackupRecords(v.Root)
	if err != nil {
		t.Fatalf("LoadBackupRecords: %v", err)
	}
	var linked []string
	for _, r := range records {
		if r.OriginalPath == path {
			linked = r.RestoreWith
		}
	}
	if len(linked) != 1 || linked[0] != envPath {
		t.Errorf("RestoreWith = %v, want [%s]: undo must bring both files back together", linked, envPath)
	}
}

func TestStripEnvFileArgs(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []string
		want []string
	}{
		{"separate", []string{"run", "--env-file", "a.env", "srv"}, []string{"run", "srv"}},
		{"joined", []string{"run", "--env-file=a.env", "srv"}, []string{"run", "srv"}},
		{"trailing with no value", []string{"run", "--env-file"}, []string{"run"}},
		{"repeated", []string{"--env-file", "a", "--env-file=b", "srv"}, []string{"srv"}},
		{"untouched", []string{"run", "--directory", "/srv", "srv"}, []string{"run", "--directory", "/srv", "srv"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := stripEnvFileArgs(tc.in); !slices.Equal(got, tc.want) {
				t.Errorf("stripEnvFileArgs(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// Two servers reading ONE --env-file. Neutralizing inside the per-server loop
// made the first server vault the real values and rewrite the file to a
// pointer, after which the second parsed that pointer and stored
// "jit://vault/mcp-alpha/TOKEN" as its own credential -- silently, so its
// server would have received that string as a token.
func TestApplyMCPConfigSharedEnvFileGivesBothServersTheRealValue(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	envPath := filepath.Join(home, "common.env")
	const real = "00tGx7Kw2LpQ4vRs9XmZb3NcJdF6Yh1Wq8"
	writeFile(t, envPath, "SHARED_TOKEN="+real+"\n")
	path := filepath.Join(home, ".mcp.json")
	writeFile(t, path, `{"mcpServers":{
		"alpha":{"command":"uv","args":["run","--env-file","`+envPath+`","alpha"]},
		"beta":{"command":"uv","args":["run","--env-file","`+envPath+`","beta"]}}}`)

	v := newTestVault(t)
	if _, err := ApplyMCPConfig(v, path); err != nil {
		t.Fatalf("ApplyMCPConfig: %v", err)
	}
	for _, profileName := range []string{"mcp-alpha", "mcp-beta"} {
		got, err := v.Get(profileName + "/SHARED_TOKEN")
		if err != nil {
			t.Fatalf("v.Get(%s/SHARED_TOKEN): %v", profileName, err)
		}
		if string(got) != real {
			t.Errorf("%s/SHARED_TOKEN = %q, want the real value, not a pointer", profileName, got)
		}
	}
	// One file, one rewrite, however many servers read it.
	body, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("reading %s: %v", envPath, err)
	}
	if strings.Count(string(body), "SHARED_TOKEN=") != 1 {
		t.Errorf("pointer file names SHARED_TOKEN more than once:\n%s", body)
	}
	if strings.Contains(string(body), real) {
		t.Error("the credential is still on disk")
	}
}

// A target another config already converted holds vault paths, not values.
// Migrating it again would store "jit://vault/..." as a credential.
func TestApplyMCPConfigSkipsAnAlreadyNeutralizedEnvFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	envPath := filepath.Join(home, "done.env")
	writeFile(t, envPath, "# jit pointer file, no secret values here, only vault paths.\nTOKEN=jit://vault/mcp-other/TOKEN\n")
	path := filepath.Join(home, ".mcp.json")
	writeFile(t, path, `{"mcpServers":{"srv":{"command":"uv","args":["run","--env-file","`+envPath+`","srv"]}}}`)

	if got := migratableEnvFiles(path, mcpServerRaw{
		"args": json.RawMessage(`["run","--env-file","` + envPath + `","srv"]`),
	}); len(got) != 0 {
		t.Errorf("migratableEnvFiles = %v, want none: the target is already a pointer file", got)
	}

	v := newTestVault(t)
	if _, err := ApplyMCPConfig(v, path); err == nil {
		t.Error("ApplyMCPConfig succeeded, want it to find nothing to migrate")
	}
	if _, err := v.Get("mcp-srv/TOKEN"); err == nil {
		t.Error("a pointer line was stored as a credential")
	}
}

// The hard stop must land before ANY file is touched, not partway through the
// server loop, so one bad file cannot leave a config half-migrated.
func TestApplyMCPConfigUnparsedEnvFileLeavesEverythingUntouched(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	goodPath := filepath.Join(home, "good.env")
	badPath := filepath.Join(home, "bad.env")
	writeFile(t, goodPath, "GOOD_TOKEN=00tGx7Kw2LpQ4vRs9XmZb3\n")
	writeFile(t, badPath, "this is not a KEY=value line at all &&&\n")
	path := filepath.Join(home, ".mcp.json")
	// "alpha" sorts first and would migrate cleanly; "beta" carries the bad
	// file. Alphabetical order is what makes this a regression test.
	writeFile(t, path, `{"mcpServers":{
		"alpha":{"command":"uv","args":["run","--env-file","`+goodPath+`","alpha"]},
		"beta":{"command":"uv","args":["run","--env-file","`+badPath+`","beta"]}}}`)

	v := newTestVault(t)
	if _, err := ApplyMCPConfig(v, path); err == nil {
		t.Fatal("ApplyMCPConfig succeeded despite an unparseable --env-file target")
	}
	body, err := os.ReadFile(goodPath)
	if err != nil {
		t.Fatalf("reading %s: %v", goodPath, err)
	}
	if !strings.Contains(string(body), "GOOD_TOKEN=00tGx7Kw2LpQ4vRs9XmZb3") {
		t.Errorf("a healthy server's env file was rewritten before the run failed:\n%s", body)
	}
	if _, err := v.Get("mcp-alpha/GOOD_TOKEN"); err == nil {
		t.Error("a secret was vaulted before the run failed on another server")
	}
}

// claudeCodeStoreFixture is the shape of a real ~/.claude.json: application
// state (numprompts, history) around a top-level mcpServers block AND a
// projects map keying a second set of server definitions by project directory
// — each project carrying its own non-MCP state that a rewrite must not touch.
// Both projects deliberately define a server named "github": that is the
// collision that used to overwrite vault values (see the overwrite test).
const claudeCodeStoreFixture = `{
  "numStartups": 42,
  "mcpServers": {
    "jira": {"command": "node", "args": ["jira.js"], "env": {"JIRA_TOKEN": "jira-secret-1"}}
  },
  "projects": {
    "/Users/x/proj-a": {
      "allowedTools": ["Bash"],
      "history": ["do the thing"],
      "mcpServers": {
        "github": {"command": "node", "args": ["gh.js"], "env": {"GITHUB_TOKEN": "gh-secret-a"}}
      }
    },
    "/Users/x/proj-b": {
      "allowedTools": [],
      "mcpServers": {
        "github": {"command": "node", "args": ["gh.js"], "env": {"GITHUB_TOKEN": "gh-secret-b"}}
      }
    }
  }
}`

// TestApplyMCPConfigMigratesClaudeCodeProjects is the fix-path half of the
// ~/.claude.json gap: audit has scanned this file's projects map since MCP
// scanning existed, so its findings were real — and migrate's rewriter only
// knew the top-level block, so `jit migrate ~/.claude.json` either said
// "nothing to do" or, wired naively, would have rewritten only part of a file
// holding live credentials.
func TestApplyMCPConfigMigratesClaudeCodeProjects(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, ".claude.json")
	writeFile(t, path, claudeCodeStoreFixture)
	v := newTestVault(t)

	result, err := ApplyMCPConfig(v, path)
	if err != nil {
		t.Fatalf("ApplyMCPConfig: %v", err)
	}
	if len(result.Servers) != 3 {
		t.Fatalf("migrated %d servers, want 3 (top-level jira + one github per project): %+v", len(result.Servers), result.Servers)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)

	// Every credential is out of the file...
	for _, secret := range []string{"jira-secret-1", "gh-secret-a", "gh-secret-b"} {
		if strings.Contains(body, secret) {
			t.Errorf("credential %q still in the rewritten file", secret)
		}
	}
	// ...while the application state around the blocks survives, top-level and
	// per-project alike. This is the "teach the rewriter Projects first"
	// pitfall: a rewriter that round-trips only the servers key would drop
	// numStartups/allowedTools/history and corrupt Claude Code's own store.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		t.Fatalf("rewritten file is not valid JSON: %v", err)
	}
	if string(top["numStartups"]) != "42" {
		t.Errorf("numStartups = %s, want 42 (top-level state must survive)", top["numStartups"])
	}
	var projects map[string]map[string]json.RawMessage
	if err := json.Unmarshal(top["projects"], &projects); err != nil {
		t.Fatalf("projects block: %v", err)
	}
	if got := string(projects["/Users/x/proj-a"]["history"]); !strings.Contains(got, "do the thing") {
		t.Errorf("proj-a history = %s; per-project state must survive a rewrite", got)
	}
	if got := string(projects["/Users/x/proj-b"]["allowedTools"]); got != "[]" {
		t.Errorf("proj-b allowedTools = %s, want []", got)
	}
	// And each project's server now launches through jit.
	for _, dir := range []string{"/Users/x/proj-a", "/Users/x/proj-b"} {
		var servers map[string]mcpServerRaw
		if err := json.Unmarshal(projects[dir]["mcpServers"], &servers); err != nil {
			t.Fatalf("%s mcpServers: %v", dir, err)
		}
		if p := mcpWrapperProfile(servers["github"]); p == "" {
			t.Errorf("%s's github server was not rewritten to launch through jit", dir)
		}
	}
}

// TestClaudeCodeProjectsSameServerNameKeepsBothCredentials pins the overwrite
// hazard scoping exists for. The namespace base is "mcp-"+server, and
// claimMCPNamespace bumps to -2 only when the .source sidecar names a
// DIFFERENT source. Two projects in one ~/.claude.json defining the same
// server name resolve to the same FILE — so before block scoping, the second
// project reused the first's namespace, saw its own env key already recorded
// there, and OVERWROTE the first project's vault value. Silently: the file
// rewrite succeeded, and the first project's server now resolved the second's
// credential.
func TestClaudeCodeProjectsSameServerNameKeepsBothCredentials(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, ".claude.json")
	writeFile(t, path, claudeCodeStoreFixture)
	v := newTestVault(t)

	if _, err := ApplyMCPConfig(v, path); err != nil {
		t.Fatalf("ApplyMCPConfig: %v", err)
	}

	// BOTH secrets must be in the vault, under distinct namespaces.
	var found []string
	for _, ns := range []string{"mcp-github", "mcp-github-2"} {
		got, err := v.Get(ns + "/GITHUB_TOKEN")
		if err != nil {
			continue
		}
		found = append(found, string(got))
	}
	sort.Strings(found)
	if len(found) != 2 || found[0] != "gh-secret-a" || found[1] != "gh-secret-b" {
		t.Fatalf("vault holds %v, want both gh-secret-a and gh-secret-b under distinct namespaces; "+
			"a shared namespace means the second project overwrote the first's credential", found)
	}

	// And each project's rewritten entry names the namespace holding ITS value.
	data, _ := os.ReadFile(path)
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		t.Fatal(err)
	}
	var projects map[string]map[string]json.RawMessage
	if err := json.Unmarshal(top["projects"], &projects); err != nil {
		t.Fatal(err)
	}
	profiles := map[string]string{}
	for dir := range projects {
		var servers map[string]mcpServerRaw
		if err := json.Unmarshal(projects[dir]["mcpServers"], &servers); err != nil {
			t.Fatal(err)
		}
		profiles[dir] = mcpWrapperProfile(servers["github"])
	}
	if profiles["/Users/x/proj-a"] == profiles["/Users/x/proj-b"] {
		t.Errorf("both projects launch through profile %q; they must be distinct or they resolve one credential", profiles["/Users/x/proj-a"])
	}
	for dir, prof := range profiles {
		wantSecret := "gh-secret-a"
		if dir == "/Users/x/proj-b" {
			wantSecret = "gh-secret-b"
		}
		got, err := v.Get(prof + "/GITHUB_TOKEN")
		if err != nil {
			t.Errorf("%s's profile %q resolves nothing: %v", dir, prof, err)
			continue
		}
		if string(got) != wantSecret {
			t.Errorf("%s resolves %q, want %q — the projects swapped or shared credentials", dir, got, wantSecret)
		}
	}
}

// TestUnwrapMCPConfigRestoresClaudeCodeProjects closes the loop the handoff
// insisted on: migrating ~/.claude.json is only safe if undo/remove
// understands project blocks too, or the migration is un-undoable — worse
// than the dead end it replaces.
func TestUnwrapMCPConfigRestoresClaudeCodeProjects(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, ".claude.json")
	writeFile(t, path, claudeCodeStoreFixture)
	v := newTestVault(t)

	if _, err := ApplyMCPConfig(v, path); err != nil {
		t.Fatalf("ApplyMCPConfig: %v", err)
	}

	// remove's real flow: every profile whose sidecar names this config.
	owned := map[string]string{}
	globalRoot, err := profile.GlobalRoot()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"mcp-jira", "mcp-github", "mcp-github-2"} {
		p, err := profile.Path(globalRoot, name)
		if err != nil {
			t.Fatal(err)
		}
		if ProfileOwnerConfig(p) != path {
			t.Fatalf("profile %s's owner = %q, want %q (ProfileOwnerConfig must strip the block scope)", name, ProfileOwnerConfig(p), path)
		}
		owned[name] = p
	}

	restored, err := UnwrapMCPConfig(v, path, owned)
	if err != nil {
		t.Fatalf("UnwrapMCPConfig: %v", err)
	}
	if len(restored) != 3 {
		t.Fatalf("restored %d servers, want 3: %+v", len(restored), restored)
	}

	data, _ := os.ReadFile(path)
	body := string(data)
	for _, secret := range []string{"jira-secret-1", "gh-secret-a", "gh-secret-b"} {
		if !strings.Contains(body, secret) {
			t.Errorf("credential %q not restored to the file", secret)
		}
	}
	if strings.Contains(body, "--profile") {
		t.Error("a jit wrapper survived the unwrap")
	}
	// Application state still intact after the round trip.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		t.Fatalf("restored file is not valid JSON: %v", err)
	}
	if string(top["numStartups"]) != "42" {
		t.Errorf("numStartups = %s after round trip, want 42", top["numStartups"])
	}
}

// TestClaudeCodeStoreDegradesSafelyOnMangledProjects pins the two review
// findings on the projects support (2026-08-06): an empty-string project key
// must not alias the TOP-LEVEL block (its rewrite would clobber real
// top-level servers while the project's own plaintext stayed put), and an
// unparseable project block must be REPORTED, not silently walked past —
// silence recreates the finding-with-no-fix-path gap one level down.
func TestClaudeCodeStoreDegradesSafelyOnMangledProjects(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, ".claude.json")
	writeFile(t, path, `{
	  "mcpServers": {"top": {"command": "node", "args": ["t.js"], "env": {"TOP_TOKEN": "top-secret-1"}}},
	  "projects": {
	    "": {"mcpServers": {"evil": {"command": "node", "env": {"X": "clobber-me"}}}},
	    "/Users/x/broken": {"mcpServers": "not an object"},
	    "/Users/x/fine": {"mcpServers": {"ok": {"command": "node", "env": {"K": "fine-secret"}}}}
	  }
	}`)
	v := newTestVault(t)

	result, err := ApplyMCPConfig(v, path)
	if err != nil {
		t.Fatalf("ApplyMCPConfig: %v", err)
	}

	// Both mangled blocks are reported, in a stable order.
	if len(result.SkippedProjects) != 2 {
		t.Fatalf("SkippedProjects = %v, want the empty-key and broken blocks", result.SkippedProjects)
	}

	// The real blocks migrated: the top-level server and the healthy project.
	migrated := map[string]bool{}
	for _, sm := range result.Servers {
		migrated[sm.ServerName] = true
	}
	if !migrated["top"] || !migrated["ok"] || len(migrated) != 2 {
		t.Errorf("migrated %v, want exactly top and ok", migrated)
	}

	data, _ := os.ReadFile(path)
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		t.Fatalf("rewritten file: %v", err)
	}
	// The top-level block was rewritten to launch through jit — NOT replaced
	// by the empty-key project's servers, which is what projectDir=="" used
	// to do to it.
	var topServers map[string]mcpServerRaw
	if err := json.Unmarshal(top["mcpServers"], &topServers); err != nil {
		t.Fatal(err)
	}
	if _, clobbered := topServers["evil"]; clobbered {
		t.Error(`the projects[""] block clobbered the top-level servers`)
	}
	if p := mcpWrapperProfile(topServers["top"]); p == "" {
		t.Error("the real top-level server was not migrated")
	}
	// The mangled blocks' own bytes are untouched.
	var projects map[string]json.RawMessage
	if err := json.Unmarshal(top["projects"], &projects); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(projects[""]), "clobber-me") {
		t.Error(`projects[""] was modified; a skipped block must be left byte-exact`)
	}
	if !strings.Contains(string(projects["/Users/x/broken"]), "not an object") {
		t.Error("the unparseable block was modified")
	}
}

// TestVolatileExecutablePath pins the location test behind resolveJitExecutable.
func TestVolatileExecutablePath(t *testing.T) {
	volatile := []string{
		"/tmp/jit",
		"/private/tmp/build/jit",
		"/var/folders/xy/T/go-build123/b001/exe/jit",
		"/Volumes/jit-0.82.0/jit",
	}
	for _, p := range volatile {
		if !volatileExecutablePath(p) {
			t.Errorf("%q was treated as a durable install location", p)
		}
	}
	durable := []string{
		"/usr/local/bin/jit",
		"/opt/homebrew/bin/jit",
		"/opt/homebrew/Caskroom/jitpass/0.82.0/jit",
		"/Users/alex/go/bin/jit",
	}
	for _, p := range durable {
		if volatileExecutablePath(p) {
			t.Errorf("%q was treated as temporary", p)
		}
	}
	// A prefix must not match across a name boundary: /tmpfoo is not /tmp.
	if volatileExecutablePath("/tmpfoo/jit") {
		t.Error("/tmpfoo/jit matched the /tmp root on a bare string prefix")
	}
}

// TestResolveJitExecutableNeverReturnsAVolatilePath is the guard that matters:
// the path this returns is written into an MCP host's config and outlives the
// process, so it must name a binary that will still exist.
//
// The test binary itself runs from /var/folders, so this exercises the
// fallback for free — os.Executable() is volatile here by construction.
func TestResolveJitExecutableNeverReturnsAVolatilePath(t *testing.T) {
	got, err := resolveJitExecutable()
	if err != nil {
		// Refusing is the correct outcome when nothing durable exists, and
		// the message has to say why rather than surfacing a bare failure.
		for _, want := range []string{"temporary location", "install jit first"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("refusal does not explain itself (%q missing): %v", want, err)
			}
		}
		return
	}
	if volatileExecutablePath(got) {
		t.Errorf("returned %q, which is inside a directory whose contents disappear", got)
	}
}
