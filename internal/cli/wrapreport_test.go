// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/keystore"
	"github.com/jitpass/jit/internal/wrap"
)

// `jit wrap <tool> --format json` is what the JitPass app's Wrapped sheet
// reads: one document, nothing ahead of it, and never the key's value.
func decodeWrapReport(t *testing.T, out string) wrapReport {
	t.Helper()
	if !strings.HasPrefix(out, "{") {
		t.Fatalf("text ahead of the document:\n%s", out)
	}
	var r wrapReport
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("not one JSON document: %v\n%s", err, out)
	}
	return r
}

func TestWrapJSONKeyAlreadyInTheVault(t *testing.T) {
	home := withFixtureHome(t)
	putToolOnPath(t, "openai")
	plantVaultSecret(t, home, "wrap-openai/OPENAI_API_KEY")
	out, err := execWrap(t, "openai", "--format", "json")
	if err != nil {
		t.Fatalf("jit wrap openai --format json: %v\n%s", err, out)
	}
	r := decodeWrapReport(t, out)
	if !r.Wrapped || r.Kind != "shim" || r.Profile != "wrap-openai" || r.Shim != "~/.jit/shims/openai" {
		t.Errorf("report = %+v", r)
	}
	if r.Key == nil || r.Key.From != "vault" || r.Key.VaultPath != "wrap-openai/OPENAI_API_KEY" || r.Key.Scrubbed {
		t.Errorf("key = %+v, want already in the vault, nothing scrubbed", r.Key)
	}
	if !strings.Contains(r.Report, "Wrapped openai") {
		t.Errorf("report text lacks the wrap's own words:\n%s", r.Report)
	}
}

// A key read from the tool's file moves into the vault and the file is
// scrubbed; the row says where it came from.
func TestWrapJSONKeyFromItsFile(t *testing.T) {
	home := withFixtureHome(t)
	origOpen := openKeyStore
	t.Cleanup(func() { openKeyStore = origOpen })
	key := countingKeychainKey{kw: newFakeKeyWrapper(), uses: new(int)}
	openKeyStore = func(r string) keystore.Store { return keystore.OpenTesting(r, key) }
	withFakeLaunchd(t)
	putToolOnPath(t, "hf")
	const token = "hf_FIXTUREwrapToken0123456789abcdef" // gitleaks:allow
	src := filepath.Join(home, ".cache", "huggingface", "token")
	if err := os.MkdirAll(filepath.Dir(src), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := execWrap(t, "hf", "--format", "json")
	if err != nil {
		t.Fatalf("jit wrap hf --format json: %v\n%s", err, out)
	}
	if strings.Contains(out, token) {
		t.Fatal("the document carries the key's value")
	}
	r := decodeWrapReport(t, out)
	if !r.Wrapped || r.Key == nil || r.Key.From != "file" || r.Key.Source != "~/.cache/huggingface/token" || !r.Key.Scrubbed || r.Key.Var != "HF_TOKEN" {
		t.Errorf("report = %+v, key = %+v", r, r.Key)
	}
	if b, _ := os.ReadFile(src); strings.Contains(string(b), token) {
		t.Error("the token is still in its file")
	}
}

func TestWrapJSONGrantSaysTheMountIsNotMigrated(t *testing.T) {
	withFixtureHome(t)
	putToolOnPath(t, "sops")
	out, err := execWrap(t, "sops", "--format", "json")
	if err != nil {
		t.Fatalf("jit wrap sops --format json: %v\n%s", err, out)
	}
	r := decodeWrapReport(t, out)
	if !r.Wrapped || r.Kind != "grant" || r.Grant != "sops" || r.GrantMigrated == nil || *r.GrantMigrated {
		t.Errorf("report = %+v, want a grant wrap whose mount isn't migrated", r)
	}
}

func TestWrapJSONRefusals(t *testing.T) {
	withFixtureHome(t)
	if _, err := execWrap(t, "aws", "--format", "json"); err == nil || !strings.Contains(err.Error(), "needs --yes") {
		t.Errorf("native without --yes: err = %v", err)
	}
	if _, err := execWrap(t, "openai", "--format", "json", "--dry-run"); err == nil || !strings.Contains(err.Error(), "drop --dry-run") {
		t.Errorf("--dry-run: err = %v", err)
	}
}

// A native tool's wrap is its migration: runNativeWrapJSON runs the
// delegated command with --yes --format json and embeds the document.
// The test binary can't re-exec itself as jit, so a stub stands in for
// it and records its arguments.
func TestNativeWrapJSONEmbedsTheMigration(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	stub := filepath.Join(dir, "jit")
	doc := `{"targets":["/h/.aws/credentials"],"applied":true,"vaulted":["aws_secret_access_key"],"settings":[],"caches":{"removed":[],"left":[]},"errors":[],"report":"Migrated."}`
	script := "#!/bin/sh\necho \"$@\" > " + argsFile + "\ncat <<'DOC'\n" + doc + "\nDOC\n"
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil { // #nosec G306 -- a test stub must be executable
		t.Fatal(err)
	}
	entry, _ := wrap.Lookup("aws")
	d, err := wrap.Delegation(entry, []string{"/h/.aws/credentials"})
	if err != nil {
		t.Fatal(err)
	}
	cmd := &cobra.Command{}
	cmd.SetErr(&bytes.Buffer{})
	rep := &wrapReport{Tool: "aws", Kind: "native"}
	if err := runNativeWrapJSON(cmd, stub, d, rep); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(argsFile)
	if strings.TrimSpace(string(got)) != "migrate /h/.aws/credentials --only aws --yes --format json" {
		t.Errorf("delegated args = %q", got)
	}
	if !rep.Wrapped || rep.Migrate == nil || strings.Join(rep.Migrate.Vaulted, ",") != "aws_secret_access_key" {
		t.Errorf("report = %+v, migrate = %+v", rep, rep.Migrate)
	}
}

// `jit wrap add --format json` is Wrap Another Tool's result: each
// variable with whether its vault path holds a secret yet.
func TestWrapAddJSON(t *testing.T) {
	home := withFixtureHome(t)
	plantVaultSecret(t, home, "wrap-acme/ACME_TOKEN")
	out, err := execWrap(t, "add", "acme", "--env", "ACME_TOKEN=wrap-acme/ACME_TOKEN", "--env", "ACME_ORG=wrap-acme/ACME_ORG", "--format", "json")
	if err != nil {
		t.Fatalf("jit wrap add --format json: %v\n%s", err, out)
	}
	r := decodeWrapReport(t, out)
	if !r.Wrapped || r.Kind != "shim" || r.Profile != "wrap-acme" || r.Shim != "~/.jit/shims/acme" {
		t.Errorf("report = %+v", r)
	}
	stored := map[string]bool{}
	for _, in := range r.Injects {
		stored[in.Var] = in.Stored
	}
	if len(r.Injects) != 2 || !stored["ACME_TOKEN"] || stored["ACME_ORG"] {
		t.Errorf("injects = %+v, want ACME_TOKEN stored and ACME_ORG not", r.Injects)
	}

	out, err = execWrap(t, "add", "gsutil", "--grant", "gcp", "--format", "json")
	if err != nil {
		t.Fatalf("jit wrap add --grant --format json: %v\n%s", err, out)
	}
	if g := decodeWrapReport(t, out); g.Kind != "grant" || g.Grant != "gcp" || g.GrantMigrated == nil || *g.GrantMigrated {
		t.Errorf("grant report = %+v", g)
	}
}
