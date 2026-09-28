// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// A profile in a project folder the listing does not run from was never
// seen by `vault list`, so the Vault window said "set by hand" of secrets
// an MCP server used every day. --users finds it, and says where it is.
func TestVaultListUsersFindsAProjectOutsideTheCurrentFolder(t *testing.T) {
	home := withFixtureHome(t)
	vaultListFormat = "text"
	t.Cleanup(func() { vaultListFormat = "text"; vaultListUsers = false })
	seedFixtureVault(t, "mcp-tickets/TICKETS_TOKEN")

	project := filepath.Join(home, "work", "ops")
	manifests := filepath.Join(project, ".jit", "profiles")
	if err := os.MkdirAll(manifests, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(manifests, "mcp-tickets.yaml"), []byte("TICKETS_TOKEN: mcp-tickets/TICKETS_TOKEN\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	list := func(args ...string) []vaultSecretJSON {
		t.Helper()
		var buf bytes.Buffer
		rootCmd.SetOut(&buf)
		rootCmd.SetErr(&buf)
		rootCmd.SetArgs(append([]string{"vault", "list", "--format", "json"}, args...))
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("jit vault list: %v\n%s", err, buf.String())
		}
		var res vaultListResult
		if err := json.Unmarshal(buf.Bytes(), &res); err != nil {
			t.Fatalf("parsing: %v\n%s", err, buf.String())
		}
		return res.Secrets
	}

	if got := list(); len(got) != 1 || len(got[0].UsedBy) != 0 {
		t.Fatalf("without --users the listing stays narrow and cheap: %+v", got)
	}
	got := list("--users")
	if len(got) != 1 || len(got[0].Users) != 1 {
		t.Fatalf("--users: %+v", got)
	}
	u := got[0].Users[0]
	resolved, _ := filepath.EvalSymlinks(project)
	if u.Profile != "mcp-tickets" || (u.Project != project && u.Project != resolved) {
		t.Fatalf("user = %+v, want mcp-tickets in %s", u, project)
	}
	if len(got[0].UsedBy) != 1 || got[0].UsedBy[0] != "mcp-tickets" {
		t.Fatalf("used_by = %v, want [mcp-tickets]", got[0].UsedBy)
	}
}
