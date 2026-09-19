// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

// mcpProfilePaths returns the global-store manifest and .source sidecar paths
// for name, the two files a server migration writes beside its vault secrets.
func mcpProfilePaths(t *testing.T, home, name string) (manifest, sidecar string) {
	t.Helper()
	manifest, err := profile.Path(home, name)
	if err != nil {
		t.Fatalf("profile.Path(%s): %v", name, err)
	}
	return manifest, profileSourceSidecarPath(manifest)
}

func assertAbsent(t *testing.T, path, why string) {
	t.Helper()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%s exists after a failed run (stat err = %v): %s", path, err, why)
	}
}

func readBytes(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return data
}

// TestApplyMCPConfigFailingServerWritesNothing is the regression test for a
// field report against ~/Security-Ops/.mcp.json: ApplyMCPConfig migrated
// servers one at a time, each writing its vault secrets, profile manifest and
// .source sidecar before the next was even looked at. A later server failing
// — here in carriedProfileValues, because a profile its nested wrapper names
// references a secret that is no longer in the vault, an error by design —
// aborted the run with the config left as it was, and with the earlier
// servers' fresh profiles and secrets stranded: nothing launches through them,
// and the next run bumps past them to a -2/-3 namespace. "alpha" sorts first
// and would migrate cleanly on its own, which is what makes this a regression
// test rather than a single-server one.
func TestApplyMCPConfigFailingServerWritesNothing(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	v := newTestVault(t)

	// A profile an old jit wrote, whose secret has since left the vault.
	staleManifest, _ := mcpProfilePaths(t, home, "mcp-beta-old")
	writeFile(t, staleManifest, "BETA_KEY: mcp-beta-old/BETA_KEY\n")

	path := filepath.Join(home, "proj", ".mcp.json")
	config := `{"mcpServers":{
		"alpha":{"command":"alpha-server","env":{"ALPHA_TOKEN":"alpha-secret"}},
		"beta":{"command":"/usr/local/bin/jit",
		        "args":["run","--profile","mcp-beta","--",
		                "/usr/local/bin/jit","run","--profile","mcp-beta-old","--","beta-server"],
		        "env":{"BETA_URL":"https://beta.example"}}}}`
	writeFile(t, path, config)

	_, err := ApplyMCPConfig(v, path)
	if err == nil {
		t.Fatal("ApplyMCPConfig succeeded although beta's wrapper names a secret missing from the vault")
	}
	if !strings.Contains(err.Error(), `server "beta"`) || !strings.Contains(err.Error(), "mcp-beta-old/BETA_KEY") {
		t.Fatalf("err = %v, want beta's carried-value failure", err)
	}

	if paths, lerr := v.List(); lerr != nil || len(paths) != 0 {
		t.Errorf("vault holds %v (err %v) after a failed run, want nothing: alpha's secret was written before beta failed", paths, lerr)
	}
	for _, name := range []string{"mcp-alpha", "mcp-beta"} {
		manifest, sidecar := mcpProfilePaths(t, home, name)
		assertAbsent(t, manifest, "a failing server must leave no profile behind")
		assertAbsent(t, sidecar, "a failing server must leave no ownership stamp behind")
	}
	if got := string(readBytes(t, path)); got != config {
		t.Errorf("config rewritten by a failed run:\n%s", got)
	}
	if got := string(readBytes(t, staleManifest)); got != "BETA_KEY: mcp-beta-old/BETA_KEY\n" {
		t.Errorf("the profile carriedProfileValues read was modified: %q", got)
	}
}

// failAfterKeyWrapper is fakeKeyWrapper that starts refusing WrapKey once
// armed and allowed more wraps have happened — the shape of a Touch ID prompt
// canceled partway through a migration's writes.
type failAfterKeyWrapper struct {
	*fakeKeyWrapper
	armed   bool
	allowed int
}

func (f *failAfterKeyWrapper) WrapKey(dek []byte) ([]byte, error) {
	if f.armed {
		if f.allowed == 0 {
			return nil, errors.New("authentication canceled")
		}
		f.allowed--
	}
	return f.fakeKeyWrapper.WrapKey(dek)
}

// TestApplyMCPConfigCommitFailureRollsBack covers the other half of the
// guarantee: every server PLANNED fine, and a write failed partway through
// committing them. The writes this run already made must be undone — a
// secret that is new removed, and one that existed (alpha's, from an earlier
// run of the same config) put back to its previous value, together with its
// previous manifest and sidecar.
func TestApplyMCPConfigCommitFailureRollsBack(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	kw := &failAfterKeyWrapper{fakeKeyWrapper: newFakeKeyWrapper()}
	v := &vault.Vault{Root: t.TempDir(), KeyWrapper: kw, RecipientID: "test-device"}

	path := filepath.Join(home, "proj", ".mcp.json")
	writeFile(t, path, `{"mcpServers":{"alpha":{"command":"alpha-server","env":{"ALPHA_TOKEN":"alpha-v1"}}}}`)
	if _, err := ApplyMCPConfig(v, path); err != nil {
		t.Fatalf("first ApplyMCPConfig: %v", err)
	}
	alphaManifest, alphaSidecar := mcpProfilePaths(t, home, "mcp-alpha")
	manifestBefore := readBytes(t, alphaManifest)
	sidecarBefore := readBytes(t, alphaSidecar)

	// The config came back with plaintext (an undo, a hand edit): alpha's
	// token rotated and a second server added.
	config := `{"mcpServers":{
		"alpha":{"command":"alpha-server","env":{"ALPHA_TOKEN":"alpha-v2","ALPHA_URL":"https://alpha.example"}},
		"beta":{"command":"beta-server","env":{"BETA_TOKEN":"beta-secret"}}}}`
	writeFile(t, path, config)

	// alpha's two secrets land; beta's is refused.
	kw.armed, kw.allowed = true, 2
	if _, err := ApplyMCPConfig(v, path); err == nil {
		t.Fatal("ApplyMCPConfig succeeded although a vault write was refused")
	} else if !strings.Contains(err.Error(), `server "beta"`) || !strings.Contains(err.Error(), "storing BETA_TOKEN in vault") {
		t.Fatalf("err = %v, want beta's refused vault write", err)
	}
	kw.armed = false

	if got, err := v.Get("mcp-alpha/ALPHA_TOKEN"); err != nil || string(got) != "alpha-v1" {
		t.Errorf("mcp-alpha/ALPHA_TOKEN = (%q, %v), want its pre-run value (alpha-v1, nil)", got, err)
	}
	for _, p := range []string{"mcp-alpha/ALPHA_URL", "mcp-beta/BETA_TOKEN"} {
		if exists, err := v.Exists(p); err != nil || exists {
			t.Errorf("%s exists = (%v, %v) after a rolled-back run, want false", p, exists, err)
		}
	}
	if got := readBytes(t, alphaManifest); !bytes.Equal(got, manifestBefore) {
		t.Errorf("alpha's manifest = %q, want its pre-run content %q", got, manifestBefore)
	}
	if got := readBytes(t, alphaSidecar); !bytes.Equal(got, sidecarBefore) {
		t.Errorf("alpha's sidecar = %q, want its pre-run content %q", got, sidecarBefore)
	}
	betaManifest, betaSidecar := mcpProfilePaths(t, home, "mcp-beta")
	assertAbsent(t, betaManifest, "beta's commit failed")
	assertAbsent(t, betaSidecar, "beta's commit failed")
	if got := string(readBytes(t, path)); got != config {
		t.Errorf("config rewritten by a failed run:\n%s", got)
	}

	// Nothing about the rollback gets in the way of simply running again.
	result, err := ApplyMCPConfig(v, path)
	if err != nil {
		t.Fatalf("re-run after the rollback: %v", err)
	}
	for _, sm := range result.Servers {
		if sm.NamespaceMovedFrom != "" {
			t.Errorf("server %q bumped to %q after a rollback; the failed run left something behind", sm.ServerName, sm.ProfileName)
		}
	}
	if got, err := v.Get("mcp-alpha/ALPHA_TOKEN"); err != nil || string(got) != "alpha-v2" {
		t.Errorf("after the re-run, mcp-alpha/ALPHA_TOKEN = (%q, %v), want (alpha-v2, nil)", got, err)
	}
}

// TestApplyMCPConfigSameNameInOneFileClaimsDistinctNamespaces pins exactly
// which namespace each same-named server in ONE file lands on. The claims are
// made while planning, before anything is written, so the second server's
// claim can only see the first one's through the plan's pending writes — if
// it looked at disk alone it would find mcp-github free and both projects
// would share one credential.
func TestApplyMCPConfigSameNameInOneFileClaimsDistinctNamespaces(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, ".claude.json")
	writeFile(t, path, claudeCodeStoreFixture)
	v := newTestVault(t)

	result, err := ApplyMCPConfig(v, path)
	if err != nil {
		t.Fatalf("ApplyMCPConfig: %v", err)
	}
	type landing struct{ profile, movedFrom string }
	got := map[string]landing{}
	for _, sm := range result.Servers {
		if sm.ServerName == "github" {
			got[sm.ProfileName] = landing{sm.ProfileName, sm.NamespaceMovedFrom}
		}
	}
	want := map[string]landing{
		"mcp-github":   {"mcp-github", ""},
		"mcp-github-2": {"mcp-github-2", "mcp-github"},
	}
	if len(got) != len(want) || got["mcp-github"] != want["mcp-github"] || got["mcp-github-2"] != want["mcp-github-2"] {
		t.Fatalf("github servers landed on %v, want %v", got, want)
	}

	// Projects are claimed in sorted order: proj-a first.
	for name, wantScope := range map[string]string{
		"mcp-github":   path + "#/Users/x/proj-a",
		"mcp-github-2": path + "#/Users/x/proj-b",
	} {
		_, sidecar := mcpProfilePaths(t, home, name)
		if got := strings.TrimSpace(string(readBytes(t, sidecar))); got != wantScope {
			t.Errorf("%s sidecar = %q, want %q", name, got, wantScope)
		}
	}
	for ns, want := range map[string]string{"mcp-github": "gh-secret-a", "mcp-github-2": "gh-secret-b"} {
		if got, err := v.Get(ns + "/GITHUB_TOKEN"); err != nil || string(got) != want {
			t.Errorf("%s/GITHUB_TOKEN = (%q, %v), want (%s, nil)", ns, got, err, want)
		}
	}
}
