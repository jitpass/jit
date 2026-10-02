// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/sealstore"
	"github.com/jitpass/jit/internal/wrap"
)

// plantAzureLogin writes a logged-in Azure CLI config dir under home.
func plantAzureLogin(t *testing.T, home, rt string) string {
	t.Helper()
	dir := migrate.AzureConfigDir(home)
	for name, body := range map[string]string{
		"msal_token_cache.json":          `{"RefreshToken":{"dev-rt":{"secret":"` + rt + `"}}}`,
		"service_principal_entries.json": `[{"client_id":"app-1","tenant":"t","client_secret":"sp-secret"}]`,
		"azureProfile.json":              `{"subscriptions":[]}`,
		"config":                         "[core]\ninstance_discovery = false\n",
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// `jit wrap az` shims az and seals its two secret files; settings stay;
// undo writes the login back and removes the shim.
func TestWrapAzSealsTheStoreAndUndoPutsItBack(t *testing.T) {
	home := withFixtureHome(t)
	withTestKeystore(t)
	t.Setenv("SHELL", "/bin/zsh")
	t.Setenv("PATH", "/usr/bin:/bin")
	putToolOnPath(t, "az")
	dir := plantAzureLogin(t, home, "rt-FIRST")

	out, err := execWrap(t, "az")
	if err != nil {
		t.Fatalf("jit wrap az: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Wrapped az") || !strings.Contains(out, "2 files moved to the vault") {
		t.Errorf("summary:\n%s", out)
	}
	if _, err := os.Lstat(filepath.Join(wrap.ShimDir(home), "az")); err != nil {
		t.Errorf("no az shim: %v", err)
	}
	if m, _ := wrap.LoadManifest(home); m.Tools["az"].Store != "az" {
		t.Errorf("manifest %+v, want a store-wrap on az", m.Tools)
	}
	if left, _ := sealstore.Azure.Plaintext(dir); len(left) != 0 {
		t.Fatalf("plaintext left after the wrap: %q", left)
	}
	for _, kept := range []string{"azureProfile.json", "config"} {
		if _, err := os.Stat(filepath.Join(dir, kept)); err != nil {
			t.Errorf("the wrap took the setting %s: %v", kept, err)
		}
	}

	out, err = execWrap(t, "undo", "az")
	if err != nil {
		t.Fatalf("jit wrap undo az: %v\n%s", err, out)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "msal_token_cache.json")); err != nil || !strings.Contains(string(b), "rt-FIRST") { // #nosec G304 -- test path
		t.Fatalf("undo left the token cache %q, %v", b, err)
	}
	if _, err := os.Lstat(filepath.Join(wrap.ShimDir(home), "az")); err == nil {
		t.Error("undo left the az shim")
	}
}

// fakeAz is a stand-in Azure CLI: it reads and rewrites the store it was
// pointed at the way az does, and reports what it saw to $OUT.
const fakeAz = `#!/bin/sh
case "$1" in
  peek)    cat "$AZURE_CONFIG_DIR/msal_token_cache.json" > "$OUT" ;;
  refresh) printf '{"RefreshToken":{"dev-rt":{"secret":"rt-ROTATED"}}}' > "$AZURE_CONFIG_DIR/msal_token_cache.json" ;;
  setting) echo work >> "$AZURE_CONFIG_DIR/config" ;;
  clear)   rm -f "$AZURE_CONFIG_DIR/msal_token_cache.json" "$AZURE_CONFIG_DIR/service_principal_entries.json" ;;
esac
`

func azRunForTest(t *testing.T, args ...string) (string, string) {
	t.Helper()
	home := withFixtureHome(t)
	withTestKeystore(t)
	t.Setenv("AZURE_CONFIG_DIR", "")
	plantAzureLogin(t, home, "rt-FIRST")
	v, err := openVault()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := migrate.AzureStore.Seal(v, home); err != nil {
		t.Fatal(err)
	}
	tool := filepath.Join(t.TempDir(), "az")
	if err := os.WriteFile(tool, []byte(fakeAz), 0o755); err != nil { // #nosec G306 -- a test stub must be executable
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "out")
	t.Setenv("OUT", out)
	var stderr bytes.Buffer
	for _, a := range args {
		cmd := &cobra.Command{}
		cmd.SetErr(&stderr)
		if code, err := runStoreRun(cmd, migrate.AzureStore, tool, []string{a}); err != nil || code != 0 {
			t.Fatalf("az-run %s: %d, %v\n%s", a, code, err, stderr.String())
		}
	}
	got, _ := os.ReadFile(out) // #nosec G304 -- test path
	return home, string(got) + stderr.String()
}

// The run sees the unsealed login through AZURE_CONFIG_DIR, a refresh is
// sealed back silently, a settings write lands in ~/.azure, and nothing
// is left in plaintext.
func TestAzRunUnsealsRefreshesAndLeavesNothing(t *testing.T) {
	home, seen := azRunForTest(t, "peek", "refresh", "setting")
	if !strings.Contains(seen, "rt-FIRST") {
		t.Fatalf("the run did not see the sealed login: %q", seen)
	}
	if strings.Contains(seen, "sealed") {
		t.Fatalf("a routine refresh announced itself: %q", seen)
	}
	dir := migrate.AzureConfigDir(home)
	if left, _ := sealstore.Azure.Plaintext(dir); len(left) != 0 {
		t.Fatalf("plaintext left: %q", left)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "config")); !strings.Contains(string(b), "work") { // #nosec G304 -- test path
		t.Fatalf("the settings write did not reach ~/.azure: %q", b)
	}
	v, _ := openVault()
	blob, _, err := migrate.AzureStore.ReadSealed(v)
	if err != nil {
		t.Fatal(err)
	}
	files, _ := sealstore.Files(blob)
	if !bytes.Contains(files["msal_token_cache.json"], []byte("rt-ROTATED")) || !bytes.Contains(files["service_principal_entries.json"], []byte("sp-secret")) {
		t.Fatalf("sealed after the refresh: %q", files)
	}
}

// A sign-out empties the sealed store, and says so.
func TestAzRunSignOut(t *testing.T) {
	_, seen := azRunForTest(t, "clear")
	if !strings.Contains(seen, "Azure CLI is signed out") {
		t.Fatalf("sign-out said %q", seen)
	}
}
