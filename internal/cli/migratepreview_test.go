// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The Protect sheet's input: where each variable goes, the settings' values
// and never a secret's, and an MCP config reading the same run's .env shown
// as covered.
func TestMigratePreviewSplitsAndCoversTheMCPConfig(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	dir := filepath.Join(home, "code", "billing-sync")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := strings.Join([]string{"Qx7vK2", "mP9wLs", "4Rt8Yn", "3Bz6Hc"}, "")
	env := filepath.Join(dir, ".env")
	if err := os.WriteFile(env, []byte("BILLING_URL=https://billing.example.com\nBILLING_CLIENT_SECRET="+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mcp := filepath.Join(home, "code", ".mcp.json")
	if err := os.WriteFile(mcp, []byte(`{"mcpServers":{"billing":{"command":"uv","args":["run","--env-file","`+env+`","billing"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := execMigrate(t, "preview", env, mcp, "--format", "json")
	if err != nil {
		t.Fatalf("migrate preview: %v\n%s", err, out)
	}
	if strings.Contains(out, secret) {
		t.Fatalf("the preview carries a secret's value:\n%s", out)
	}
	var res migratePreviewResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if len(res.Files) != 2 || res.Files[0].Kind != "env" || res.Files[1].Kind != "mcp" {
		t.Fatalf("files = %+v", res.Files)
	}
	vars := map[string]migratePreviewVar{}
	for _, v := range res.Files[0].Vars {
		vars[v.Name] = v
	}
	if v := vars["BILLING_URL"]; v.InVault || v.Value != "https://billing.example.com" {
		t.Errorf("BILLING_URL = %+v, want a setting with its value", v)
	}
	if v := vars["BILLING_CLIENT_SECRET"]; !v.InVault || v.Class != "secret" || v.Value != "" {
		t.Errorf("BILLING_CLIENT_SECRET = %+v, want a secret without its value", v)
	}
	if m := res.Files[1].MCP; m == nil || !m.Covered || len(m.Reads) != 1 {
		t.Errorf("mcp = %+v, want covered by the .env", m)
	}

	// Named alone, the config is not covered: its .env is not in this run.
	out, err = execMigrate(t, "preview", mcp, "--format", "json")
	if err != nil {
		t.Fatalf("migrate preview: %v", err)
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err)
	}
	if m := res.Files[0].MCP; m == nil || m.Covered {
		t.Errorf("mcp alone = %+v, want not covered", m)
	}
}
