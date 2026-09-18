// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// readServerEntry pulls one server's command and args back out of a rewritten
// config, so these tests assert on the launch line the host will actually run
// rather than on a substring of the file.
func readServerEntry(t *testing.T, path, server string) (command string, args []string) {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var doc struct {
		MCPServers map[string]struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
			Env     map[string]string
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parsing %s: %v\n%s", path, err, data)
	}
	entry, ok := doc.MCPServers[server]
	if !ok {
		t.Fatalf("server %q missing from %s:\n%s", server, path, data)
	}
	if len(entry.Env) != 0 {
		t.Errorf("server %q kept an env block after migration: %v", server, entry.Env)
	}
	return entry.Command, entry.Args
}

// countWrapperLayers counts how many `run --profile <name> --` prefixes are
// stacked in a launch line. Exactly one is correct; more than one is the
// nesting bug.
func countWrapperLayers(command string, args []string) int {
	_, _, profiles := unwrapJitWrappers(command, args)
	return len(profiles)
}

// TestUnwrapJitWrappersLeavesNonJitLaunchersAlone: the argument shape alone
// does not make something jit's wrapper. `uv run --profile x -- y` is a real
// command line for a different tool, and peeling it would rewrite an
// unrelated launcher into oblivion.
func TestUnwrapJitWrappersLeavesNonJitLaunchersAlone(t *testing.T) {
	args := []string{"run", "--profile", "x", "--", "server"}
	gotCmd, gotArgs, profiles := unwrapJitWrappers("uv", args)
	if gotCmd != "uv" || !reflect.DeepEqual(gotArgs, args) || len(profiles) != 0 {
		t.Errorf("unwrapJitWrappers(uv, %v) = (%q, %v, %v); want it left untouched", args, gotCmd, gotArgs, profiles)
	}
}

// TestUnwrapJitWrappersPeelsEveryLayer covers the shape found in the field:
// an entry migrated twice, the inner jit being a path that no longer exists.
// Peeling ONE layer would leave the stale inner path in place, so doctor
// would keep reporting it and `jit migrate` would never be able to fix it.
func TestUnwrapJitWrappersPeelsEveryLayer(t *testing.T) {
	command := "/opt/homebrew/bin/jit"
	args := []string{
		"run", "--profile", "mcp-caido-2", "--",
		"/usr/local/bin/jit", "run", "--profile", "mcp-caido", "--",
		"/opt/tools/caido-mcp-server", "serve",
	}

	gotCmd, gotArgs, profiles := unwrapJitWrappers(command, args)
	if gotCmd != "/opt/tools/caido-mcp-server" {
		t.Errorf("command = %q, want the real tool underneath both wrappers", gotCmd)
	}
	if want := []string{"serve"}; !reflect.DeepEqual(gotArgs, want) {
		t.Errorf("args = %v, want %v", gotArgs, want)
	}
	if want := []string{"mcp-caido-2", "mcp-caido"}; !reflect.DeepEqual(profiles, want) {
		t.Errorf("profiles = %v, want %v (outermost first)", profiles, want)
	}
}

// TestApplyMCPConfigNeverNestsItsOwnWrapper is the regression test for the
// field bug: an entry jit already migrated, which then had a stray env var
// added back, was wrapped a SECOND time — with jit's own wrapper treated as
// the command to wrap. The re-migration must land back on the same profile,
// fold the new variable in, and leave exactly one wrapper.
func TestApplyMCPConfigNeverNestsItsOwnWrapper(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	v := newTestVault(t)

	path := filepath.Join(home, "proj", "mcp.json")
	writeFile(t, path, `{"mcpServers":{"caido":{"command":"caido-server","args":["serve"],"env":{"CAIDO_KEY":"key-v1"}}}}`)

	if _, err := ApplyMCPConfig(v, path); err != nil {
		t.Fatalf("first ApplyMCPConfig: %v", err)
	}
	command, args := readServerEntry(t, path, "caido")
	if n := countWrapperLayers(command, args); n != 1 {
		t.Fatalf("after the first migration there are %d wrapper layers, want 1", n)
	}

	// The field shape: someone adds a variable back to the already-wrapped
	// entry, so the next scan finds a secret in it again.
	data, err := os.ReadFile(path) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	var doc map[string]map[string]map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parsing: %v", err)
	}
	doc["mcpServers"]["caido"]["env"] = map[string]string{"CAIDO_URL": "http://127.0.0.1:8080"}
	rewritten, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	writeFile(t, path, string(rewritten))

	result, err := ApplyMCPConfig(v, path)
	if err != nil {
		t.Fatalf("second ApplyMCPConfig: %v", err)
	}

	sm := result.Servers[0]
	if sm.ProfileName != "mcp-caido" || sm.NamespaceMovedFrom != "" {
		t.Errorf("(ProfileName, NamespaceMovedFrom) = (%q, %q), want (mcp-caido, \"\") — re-migrating its own entry must refresh, never fork",
			sm.ProfileName, sm.NamespaceMovedFrom)
	}
	if want := []string{"mcp-caido"}; !reflect.DeepEqual(sm.RewrappedFrom, want) {
		t.Errorf("RewrappedFrom = %v, want %v", sm.RewrappedFrom, want)
	}

	command, args = readServerEntry(t, path, "caido")
	if n := countWrapperLayers(command, args); n != 1 {
		t.Fatalf("after re-migration there are %d wrapper layers, want 1:\n  command=%q\n  args=%v", n, command, args)
	}
	realCmd, realArgs, _ := unwrapJitWrappers(command, args)
	if realCmd != "caido-server" || !reflect.DeepEqual(realArgs, []string{"serve"}) {
		t.Errorf("the real command was mangled: (%q, %v), want (caido-server, [serve])", realCmd, realArgs)
	}

	// Both the original and the newly added variable resolve from one profile.
	for name, want := range map[string]string{
		"CAIDO_KEY": "key-v1",
		"CAIDO_URL": "http://127.0.0.1:8080",
	} {
		got, err := v.Get("mcp-caido/" + name)
		if err != nil || string(got) != want {
			t.Errorf("mcp-caido/%s = (%q, %v), want (%s, nil)", name, got, err, want)
		}
	}
}

// TestApplyMCPConfigHealsAnAlreadyNestedEntry: a config carrying the damage
// the old code produced must come back to a single wrapper the next time it
// is migrated. Without this, `jit doctor`'s "→ jit migrate <file>" advice
// cannot actually fix what doctor is reporting.
func TestApplyMCPConfigHealsAnAlreadyNestedEntry(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	v := newTestVault(t)

	path := filepath.Join(home, "proj", "mcp.json")
	writeFile(t, path, `{"mcpServers":{"caido":{
		"command":"/opt/homebrew/Caskroom/jitpass/0.84.0/jit",
		"args":["run","--profile","mcp-caido-2","--",
		        "/usr/local/bin/jit","run","--profile","mcp-caido","--",
		        "caido-server","serve"],
		"env":{"CAIDO_KEY":"key-v1"}}}}`)

	if _, err := ApplyMCPConfig(v, path); err != nil {
		t.Fatalf("ApplyMCPConfig: %v", err)
	}

	command, args := readServerEntry(t, path, "caido")
	if n := countWrapperLayers(command, args); n != 1 {
		t.Fatalf("nesting survived: %d wrapper layers, want 1:\n  command=%q\n  args=%v", n, command, args)
	}
	realCmd, realArgs, _ := unwrapJitWrappers(command, args)
	if realCmd != "caido-server" || !reflect.DeepEqual(realArgs, []string{"serve"}) {
		t.Errorf("real command = (%q, %v), want (caido-server, [serve])", realCmd, realArgs)
	}
	// Every stale jit path is gone, including the buried one nothing used to
	// revalidate.
	if command != "/usr/local/bin/jit" { // the test stub's stable path
		t.Errorf("command = %q, want the current jit binary", command)
	}
	for _, arg := range args {
		if arg == "/usr/local/bin/jit" || arg == "/opt/homebrew/Caskroom/jitpass/0.84.0/jit" {
			t.Errorf("a jit path is still buried in args: %v", args)
		}
	}
}

// TestApplyMCPConfigRewrapCarriesForeignProfileVars is the case that makes
// unwrapping safe. A config file can hold a wrapper naming a profile that
// belongs to a DIFFERENT config — copy a migrated workspace and both trees
// have one. The namespace must still bump (the other file's secrets are not
// this one's to overwrite), and because it bumps, whatever the old wrapper
// injected has to be carried across or the server silently loses it.
func TestApplyMCPConfigRewrapCarriesForeignProfileVars(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	v := newTestVault(t)

	pathA := filepath.Join(home, "projA", "mcp.json")
	writeFile(t, pathA, `{"mcpServers":{"caido":{"command":"caido-server","args":["serve"],
		"env":{"CAIDO_URL":"url-a","CAIDO_KEY":"key-a"}}}}`)
	if _, err := ApplyMCPConfig(v, pathA); err != nil {
		t.Fatalf("ApplyMCPConfig(A): %v", err)
	}

	// B is a copy of A taken AFTER A was migrated, so it carries A's wrapper
	// and profile name, plus a variable of its own added since.
	pathB := filepath.Join(home, "projB", "mcp.json")
	writeFile(t, pathB, `{"mcpServers":{"caido":{
		"command":"/usr/local/bin/jit",
		"args":["run","--profile","mcp-caido","--","caido-server","serve"],
		"env":{"CAIDO_URL":"url-b"}}}}`)

	result, err := ApplyMCPConfig(v, pathB)
	if err != nil {
		t.Fatalf("ApplyMCPConfig(B): %v", err)
	}
	sm := result.Servers[0]
	if sm.ProfileName != "mcp-caido-2" || sm.NamespaceMovedFrom != "mcp-caido" {
		t.Fatalf("(ProfileName, NamespaceMovedFrom) = (%q, %q), want (mcp-caido-2, mcp-caido)", sm.ProfileName, sm.NamespaceMovedFrom)
	}

	command, args := readServerEntry(t, pathB, "caido")
	if n := countWrapperLayers(command, args); n != 1 {
		t.Errorf("B has %d wrapper layers, want 1", n)
	}

	// B's own value wins; A's variable is carried so unwrapping dropped
	// nothing the server used to receive.
	for name, want := range map[string]string{
		"CAIDO_URL": "url-b",
		"CAIDO_KEY": "key-a",
	} {
		got, gerr := v.Get("mcp-caido-2/" + name)
		if gerr != nil || string(got) != want {
			t.Errorf("mcp-caido-2/%s = (%q, %v), want (%s, nil)", name, got, gerr, want)
		}
	}
	// A is untouched.
	if got, gerr := v.Get("mcp-caido/CAIDO_URL"); gerr != nil || string(got) != "url-a" {
		t.Errorf("mcp-caido/CAIDO_URL = (%q, %v), want (url-a, nil) — A's secrets are not B's to overwrite", got, gerr)
	}
}

// TestApplyMCPConfigHealsANestedEntryWithNoEnv is the field shape of
// 2026-09-18: nested by an old jit, fully migrated since, so there is no env
// block left to trip the credentials gate. It used to be unreachable —
// ApplyMCPConfig answered "no server with secrets to migrate" and the file
// stayed nested forever.
func TestApplyMCPConfigHealsANestedEntryWithNoEnv(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	v := newTestVault(t)

	path := filepath.Join(home, "proj", "mcp.json")
	writeFile(t, path, `{"mcpServers":{"caido":{"command":"caido-server","args":["serve"],"env":{"CAIDO_URL":"url-v1"}}}}`)
	if _, err := ApplyMCPConfig(v, path); err != nil {
		t.Fatalf("first ApplyMCPConfig: %v", err)
	}

	writeFile(t, path, `{"mcpServers":{"caido":{
		"command":"/opt/homebrew/bin/jit",
		"args":["run","--profile","mcp-caido","--",
		        "/opt/homebrew/bin/jit","run","--profile","mcp-caido","--",
		        "caido-server","serve"],
		"type":"stdio"}}}`)

	configs, err := DiscoverMCPConfigs(home, filepath.Dir(path), false)
	if err != nil {
		t.Fatalf("DiscoverMCPConfigs: %v", err)
	}
	if !reflect.DeepEqual(configs, []string{path}) {
		t.Errorf("DiscoverMCPConfigs = %v, want the nested config found", configs)
	}

	result, err := ApplyMCPConfig(v, path)
	if err != nil {
		t.Fatalf("ApplyMCPConfig on a nested entry with no env: %v", err)
	}
	if got := result.Servers[0].ProfileName; got != "mcp-caido" {
		t.Errorf("ProfileName = %q, want mcp-caido (its own profile, no bump)", got)
	}
	command, args := readServerEntry(t, path, "caido")
	if n := countWrapperLayers(command, args); n != 1 {
		t.Fatalf("nesting survived: %d wrapper layers, want 1: %v", n, args)
	}
	if got, gerr := v.Get("mcp-caido/CAIDO_URL"); gerr != nil || string(got) != "url-v1" {
		t.Errorf("mcp-caido/CAIDO_URL = (%q, %v), want (url-v1, nil)", got, gerr)
	}
}

// TestApplyMCPConfigHealCarriesInnerProfileVars: layers naming DIFFERENT
// profiles each injected their own variables. Collapsing onto the outer
// profile used to carry nothing, so the inner profile's credentials left the
// launch line with no error anywhere — the server just started without them.
func TestApplyMCPConfigHealCarriesInnerProfileVars(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	v := newTestVault(t)

	path := filepath.Join(home, "proj", "mcp.json")
	writeFile(t, path, `{"mcpServers":{
		"okta":{"command":"okta-server","env":{"OKTA_PRIVATE_KEY":"pk-inner","OKTA_ORG_URL":"url-inner"}},
		"okta-mcp-server":{"command":"okta-server","env":{"OKTA_ORG_URL":"url-outer"}}}}`)
	if _, err := ApplyMCPConfig(v, path); err != nil {
		t.Fatalf("first ApplyMCPConfig: %v", err)
	}

	writeFile(t, path, `{"mcpServers":{"okta-mcp-server":{
		"command":"/opt/homebrew/bin/jit",
		"args":["run","--profile","mcp-okta-mcp-server","--",
		        "/opt/homebrew/bin/jit","run","--profile","mcp-okta","--",
		        "okta-server"],
		"type":"stdio"}}}`)

	result, err := ApplyMCPConfig(v, path)
	if err != nil {
		t.Fatalf("ApplyMCPConfig: %v", err)
	}
	if got := result.Servers[0].ProfileName; got != "mcp-okta-mcp-server" {
		t.Fatalf("ProfileName = %q, want mcp-okta-mcp-server", got)
	}
	command, args := readServerEntry(t, path, "okta-mcp-server")
	if n := countWrapperLayers(command, args); n != 1 {
		t.Fatalf("nesting survived: %d wrapper layers, want 1: %v", n, args)
	}

	// The inner profile's variable is carried; the outer profile keeps its
	// own value for the name both hold (outermost wins).
	for name, want := range map[string]string{
		"OKTA_PRIVATE_KEY": "pk-inner",
		"OKTA_ORG_URL":     "url-outer",
	} {
		got, gerr := v.Get("mcp-okta-mcp-server/" + name)
		if gerr != nil || string(got) != want {
			t.Errorf("mcp-okta-mcp-server/%s = (%q, %v), want (%s, nil)", name, got, gerr, want)
		}
	}
	// The inner profile is read, never written.
	if got, gerr := v.Get("mcp-okta/OKTA_ORG_URL"); gerr != nil || string(got) != "url-inner" {
		t.Errorf("mcp-okta/OKTA_ORG_URL = (%q, %v), want (url-inner, nil)", got, gerr)
	}
}

// TestDiscoverMCPConfigsIgnoresAHealthyWrapper: one wrapper and no env is a
// finished migration. Admitting it would put every migrated config back in
// every plan and rewrite it on every run.
func TestDiscoverMCPConfigsIgnoresAHealthyWrapper(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	path := filepath.Join(home, "proj", "mcp.json")
	writeFile(t, path, `{"mcpServers":{"caido":{
		"command":"/opt/homebrew/bin/jit",
		"args":["run","--profile","mcp-caido","--","caido-server","serve"]}}}`)

	configs, err := DiscoverMCPConfigs(home, filepath.Dir(path), false)
	if err != nil {
		t.Fatalf("DiscoverMCPConfigs: %v", err)
	}
	if len(configs) != 0 {
		t.Errorf("DiscoverMCPConfigs = %v, want a healthy single wrapper left alone", configs)
	}
}
