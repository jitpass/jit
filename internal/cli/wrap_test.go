// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/wrap"
)

func execWrap(t *testing.T, args ...string) (stdout string, err error) {
	t.Helper()
	// Package-level flag vars persist across Execute calls in one test
	// binary (cobra re-parses into the same variable), so an --env from a
	// previous test would leak into a call that passes none.
	wrapAddEnv = nil
	wrapAddGrant = ""
	wrapDryRun = false
	wrapListFormat = "text"
	wrapListAll = false
	wrapListDiscover = false
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs(append([]string{"wrap"}, args...))
	err = rootCmd.Execute()
	return buf.String(), err
}

// putToolOnPath plants an executable stub named tool in a temp dir and
// prepends that dir to PATH, so the wrap flow's is-it-installed check
// passes without the real tool.
func putToolOnPath(t *testing.T, tool string) {
	t.Helper()
	dir := t.TempDir()
	stub := filepath.Join(dir, tool)
	if err := os.WriteFile(stub, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { // #nosec G306 -- a test stub must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// A no-source tool whose secret is ALREADY in the vault must not be told to
// "store it first" — the docs for every such tool say to `jit vault set`
// before wrapping, so that message told a user who had just followed the
// instructions that they hadn't (observed on a real wrap 2026-08-09). The
// check must also never prompt: it runs on a bare read-only Vault, one
// os.Stat, no agent.
func TestWrapUsesTheSecretAlreadyInTheVault(t *testing.T) {
	home := withFixtureHome(t)
	putToolOnPath(t, "openai")
	plantVaultSecret(t, home, "wrap-openai/OPENAI_API_KEY")

	out, err := execWrap(t, "openai")
	if err != nil {
		t.Fatalf("jit wrap openai: %v", err)
	}
	if strings.Contains(out, "store it first") {
		t.Errorf("wrap told the user to store a secret the vault already holds:\n%s", out)
	}
	if !strings.Contains(out, "already in the vault at wrap-openai/OPENAI_API_KEY") {
		t.Errorf("wrap didn't acknowledge the existing secret:\n%s", out)
	}
	if !strings.Contains(out, "Wrapped openai") {
		t.Errorf("wrap didn't install the shim:\n%s", out)
	}
}

// With nothing on disk AND nothing in the vault, the store-it-first guidance
// is exactly right and must stay.
func TestWrapStillAsksWhenNothingIsVaulted(t *testing.T) {
	withFixtureHome(t)
	putToolOnPath(t, "openai")

	out, err := execWrap(t, "openai")
	if err != nil {
		t.Fatalf("jit wrap openai: %v", err)
	}
	// Two substrings, not one: wrapBody may line-wrap between the command
	// and its argument at narrow test widths.
	if !strings.Contains(out, "store it first") || !strings.Contains(out, "wrap-openai/OPENAI_API_KEY") {
		t.Errorf("empty-vault wrap lost the store-it-first guidance:\n%s", out)
	}
}

func TestWrapAddListUndoRoundTrip(t *testing.T) {
	home := withFixtureHome(t)

	out, err := execWrap(t, "add", "faketool", "--env", "FAKE_TOKEN=wrap-faketool/FAKE_TOKEN")
	if err != nil {
		t.Fatalf("jit wrap add: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Wrapped faketool") {
		t.Errorf("expected a wrapped summary, got:\n%s", out)
	}

	link := filepath.Join(wrap.ShimDir(home), "faketool")
	if _, err := os.Lstat(link); err != nil {
		t.Errorf("shim not installed at %s: %v", link, err)
	}
	profilePath := filepath.Join(home, ".jit", "profiles", "wrap-faketool.yaml")
	if _, err := os.Stat(profilePath); err != nil {
		t.Errorf("profile not written at %s: %v", profilePath, err)
	}
	rc := wrap.RcFile(home, os.Getenv("SHELL"))
	if data, err := os.ReadFile(rc); err != nil || !strings.Contains(string(data), ".jit/shims") {
		t.Errorf("PATH line not ensured in %s (err=%v):\n%s", rc, err, data)
	}

	out, err = execWrap(t, "list")
	if err != nil {
		t.Fatalf("jit wrap list: %v", err)
	}
	if !strings.Contains(out, "faketool") || !strings.Contains(out, "env") || !strings.Contains(out, "FAKE_TOKEN") || !strings.Contains(out, "ok") {
		t.Errorf("list missing the wrapped tool row:\n%s", out)
	}

	out, err = execWrap(t, "undo", "faketool")
	if err != nil {
		t.Fatalf("jit wrap undo: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Unwrapped faketool") {
		t.Errorf("expected an unwrapped summary, got:\n%s", out)
	}
	if !strings.Contains(out, "wrap-faketool/FAKE_TOKEN") {
		t.Errorf("expected the kept vault path named, got:\n%s", out)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Errorf("shim survived undo: %v", err)
	}
	// Last tool gone -> the PATH line is cleaned up too.
	if data, _ := os.ReadFile(rc); strings.Contains(string(data), ".jit/shims") {
		t.Errorf("PATH line survived the last undo:\n%s", data)
	}
}

// TestWrapUndoKeepsPathLineWhileHelpersRemain pins the #77 fix end to end:
// undoing the last wrapped tool must NOT remove the shim PATH line while a
// docker/git credential helper still lives in the shim dir — docker and git
// find those helpers strictly by $PATH lookup, and yanking the line silently
// broke their credential lookup in the next shell.
func TestWrapUndoKeepsPathLineWhileHelpersRemain(t *testing.T) {
	home := withFixtureHome(t)
	if _, err := execWrap(t, "add", "faketool", "--env", "FAKE_TOKEN=wrap-faketool/FAKE_TOKEN"); err != nil {
		t.Fatalf("jit wrap add: %v", err)
	}
	helper := filepath.Join(wrap.ShimDir(home), "docker-credential-jit")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexec jit dockercred \"$@\"\n"), 0o700); err != nil { // #nosec G306 -- an executable helper script needs the execute bit
		t.Fatal(err)
	}
	rc := wrap.RcFile(home, os.Getenv("SHELL"))

	// The preview must promise what the real run does: the line stays.
	out, err := execWrap(t, "undo", "faketool", "--dry-run")
	if err != nil {
		t.Fatalf("jit wrap undo --dry-run: %v", err)
	}
	if !strings.Contains(out, "stays") || !strings.Contains(out, "docker-credential-jit") {
		t.Errorf("dry-run should say the PATH line stays and name the helper, got:\n%s", out)
	}

	out, err = execWrap(t, "undo", "faketool")
	if err != nil {
		t.Fatalf("jit wrap undo: %v\n%s", err, out)
	}
	if !strings.Contains(out, "stays") || !strings.Contains(out, "docker-credential-jit") {
		t.Errorf("undo should say the PATH line stays and name the helper, got:\n%s", out)
	}
	if data, err := os.ReadFile(rc); err != nil || !strings.Contains(string(data), ".jit/shims") {
		t.Errorf("PATH line must survive the undo while the helper needs it (err=%v):\n%s", err, data)
	}
}

func TestWrapAddRequiresEnv(t *testing.T) {
	withFixtureHome(t)
	if _, err := execWrap(t, "add", "faketool"); err == nil {
		t.Fatal("expected jit wrap add without --env to fail")
	}
}

func TestWrapListEmpty(t *testing.T) {
	withFixtureHome(t)
	out, err := execWrap(t, "list")
	if err != nil {
		t.Fatalf("jit wrap list: %v", err)
	}
	if !strings.Contains(out, "No wrapped tools") {
		t.Errorf("expected the empty-state message, got:\n%s", out)
	}
}

func TestWrapUnknownToolListsCatalogAndEscapeHatch(t *testing.T) {
	withFixtureHome(t)
	_, err := execWrap(t, "sometool")
	if err == nil {
		t.Fatal("expected an error for an uncataloged tool")
	}
	if !strings.Contains(err.Error(), "gh") || !strings.Contains(err.Error(), "aws") {
		t.Errorf("error should list the catalog, got: %v", err)
	}
	if !strings.Contains(err.Error(), "jit wrap add sometool") {
		t.Errorf("error should point at the manual escape hatch, got: %v", err)
	}
}

func TestParseWrapEnv(t *testing.T) {
	env, order, err := parseWrapEnv([]string{"B=vault/b", "A=vault/a", "B=vault/b2"})
	if err != nil {
		t.Fatal(err)
	}
	if env["A"] != "vault/a" || env["B"] != "vault/b2" {
		t.Errorf("env = %v, want last-flag-wins for B", env)
	}
	if strings.Join(order, ",") != "B,A" {
		t.Errorf("order = %v, want first-appearance order [B A]", order)
	}
	for _, bad := range [][]string{nil, {"NOVALUE"}, {"=path"}, {"VAR="}} {
		if _, _, err := parseWrapEnv(bad); err == nil {
			t.Errorf("parseWrapEnv(%v): expected an error", bad)
		}
	}
}

// TestWrapAddGrantRoundTrip covers the grant-wrap path: `jit wrap add
// <tool> --grant <name>` installs a shim that grants a global mount (no
// profile), list shows it as a grant, doctor is happy, undo removes it.
func TestWrapAddGrantRoundTrip(t *testing.T) {
	withFixtureHome(t)

	out, err := execWrap(t, "add", "gcloud", "--grant", "gcp")
	if err != nil {
		t.Fatalf("jit wrap add --grant: %v", err)
	}
	if !strings.Contains(out, "Grant-wrapped gcloud") || !strings.Contains(out, "--with gcp") {
		t.Errorf("add --grant output missing the grant note:\n%s", out)
	}

	out, err = execWrap(t, "list")
	if err != nil {
		t.Fatalf("jit wrap list: %v", err)
	}
	if !strings.Contains(out, "gcloud") || !strings.Contains(out, "grant") || !strings.Contains(out, "--with gcp") {
		t.Errorf("list missing the grant-wrap row:\n%s", out)
	}

	// --env and --grant are mutually exclusive.
	if _, err := execWrap(t, "add", "x", "--env", "A=p", "--grant", "gcp"); err == nil {
		t.Error("expected an error when --env and --grant are combined")
	}

	if _, err := execWrap(t, "undo", "gcloud"); err != nil {
		t.Fatalf("jit wrap undo: %v", err)
	}
}

// TestWrapDryRunPreviewsWithoutChanging: `jit wrap <tool> --dry-run`
// renders the same frame + [CLI wrap] plan row migrate's plan uses
// (design/dry-run-refactor.md D6) and touches nothing — no shim dir, no
// rc edit, no vault.
func TestWrapDryRunPreviewsWithoutChanging(t *testing.T) {
	home := withFixtureHome(t)

	out, err := execWrap(t, "gh", "--dry-run")
	if err != nil {
		t.Fatalf("jit wrap gh --dry-run: %v", err)
	}
	if got := strings.Count(out, "[DRY RUN]"); got != 2 {
		t.Errorf("expected exactly 2 [DRY RUN] markers, got %d:\n%s", got, out)
	}
	for _, want := range []string{"[CLI wrap] 1", "gh", "Apply this plan: jit wrap gh"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in the preview, got:\n%s", want, out)
		}
	}
	if _, err := os.Stat(wrap.ShimDir(home)); !os.IsNotExist(err) {
		t.Errorf("dry-run must not create the shim dir (stat err=%v)", err)
	}
}

// TestWrapUndoDryRunPreviewsWithoutChanging: the undo preview names the
// shim (and rc PATH-line removal for the last tool) and leaves the
// manifest, shim, and rc untouched.
func TestWrapUndoDryRunPreviewsWithoutChanging(t *testing.T) {
	home := withFixtureHome(t)
	putToolOnPath(t, "openai")
	plantVaultSecret(t, home, "wrap-openai/OPENAI_API_KEY")
	if _, err := execWrap(t, "openai"); err != nil {
		t.Fatalf("jit wrap openai: %v", err)
	}
	shim := filepath.Join(wrap.ShimDir(home), "openai")
	if _, err := os.Lstat(shim); err != nil {
		t.Fatalf("expected the shim installed before the undo preview: %v", err)
	}

	out, err := execWrap(t, "undo", "openai", "--dry-run")
	if err != nil {
		t.Fatalf("jit wrap undo openai --dry-run: %v", err)
	}
	if got := strings.Count(out, "[DRY RUN]"); got != 2 {
		t.Errorf("expected exactly 2 [DRY RUN] markers, got %d:\n%s", got, out)
	}
	for _, want := range []string{"Unwrap openai:", "shim removed:", "last wrapped tool", "Apply this plan: jit wrap undo openai"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in the undo preview, got:\n%s", want, out)
		}
	}
	if _, err := os.Lstat(shim); err != nil {
		t.Errorf("dry-run must leave the shim in place: %v", err)
	}
}

// `jit wrap list --format json` is what the JitPass app's Tools window reads,
// so the shape is a contract: a wrapped tool carries its shim verdict, the
// vars it injects with their vault paths and whether each is stored, and
// with --all the catalog joins in with where each tool is installed.
func TestWrapListJSON(t *testing.T) {
	home := withFixtureHome(t)
	putToolOnPath(t, "faketool")
	if _, err := execWrap(t, "add", "faketool", "--env", "FAKE_TOKEN=wrap-faketool/FAKE_TOKEN"); err != nil {
		t.Fatalf("jit wrap add: %v", err)
	}
	plantVaultSecret(t, home, "wrap-faketool/FAKE_TOKEN")

	out, err := execWrap(t, "list", "--format", "json")
	if err != nil {
		t.Fatalf("jit wrap list --format json: %v\n%s", err, out)
	}
	var res wrapListResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if !res.RcHasPathLine {
		t.Error("rc_has_path_line = false after a wrap add that wrote the PATH line")
	}
	if len(res.Tools) != 1 {
		t.Fatalf("got %d tools, want the one wrapped: %+v", len(res.Tools), res.Tools)
	}
	row := res.Tools[0]
	if row.Tool != "faketool" || !row.Wrapped || row.Kind != "shim" || row.Catalog {
		t.Errorf("row = %+v, want faketool, wrapped, kind shim, not in the catalog", row)
	}
	if row.Shim != wrap.ShimOK || row.ShimDetail != "" {
		t.Errorf("shim = %q (%q), want ok with no detail", row.Shim, row.ShimDetail)
	}
	if row.InstalledPath == "" {
		t.Error("installed_path empty for a tool the test put on PATH")
	}
	if len(row.Injects) != 1 || row.Injects[0].Var != "FAKE_TOKEN" ||
		row.Injects[0].VaultPath != "wrap-faketool/FAKE_TOKEN" || !row.Injects[0].Stored {
		t.Errorf("injects = %+v, want FAKE_TOKEN from wrap-faketool/FAKE_TOKEN, stored", row.Injects)
	}

	// Break the shim: the verdict must say so, in doctor's words.
	if err := os.Remove(filepath.Join(wrap.ShimDir(home), "faketool")); err != nil {
		t.Fatal(err)
	}
	out, err = execWrap(t, "list", "--format", "json")
	if err != nil {
		t.Fatalf("jit wrap list --format json: %v", err)
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err)
	}
	if res.Tools[0].Shim != wrap.ShimMissing || !strings.Contains(res.Tools[0].ShimDetail, "symlink missing") {
		t.Errorf("after removing the shim: %q (%q)", res.Tools[0].Shim, res.Tools[0].ShimDetail)
	}
}

func TestWrapListJSONAllAddsTheCatalog(t *testing.T) {
	withFixtureHome(t)
	putToolOnPath(t, "gh")
	out, err := execWrap(t, "list", "--format", "json", "--all")
	if err != nil {
		t.Fatalf("jit wrap list --format json --all: %v", err)
	}
	var res wrapListResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if len(res.Tools) != len(wrap.CatalogTools()) {
		t.Fatalf("got %d tools, want the whole catalog (%d)", len(res.Tools), len(wrap.CatalogTools()))
	}
	byName := map[string]wrapToolJSON{}
	for _, r := range res.Tools {
		byName[r.Tool] = r
	}
	gh := byName["gh"]
	if gh.Wrapped || !gh.Catalog || gh.Kind != "shim" || gh.InstalledPath == "" || gh.Shim != "" {
		t.Errorf("gh = %+v, want catalog, not wrapped, kind shim, installed, no shim verdict", gh)
	}
	if len(gh.Injects) != 1 || gh.Injects[0].VaultPath != "wrap-gh/GH_TOKEN" || gh.Injects[0].Stored {
		t.Errorf("gh injects = %+v, want the catalog's vault path, not stored", gh.Injects)
	}
	if gh.TokenCommand != "gh auth token" || len(gh.Sources) == 0 {
		t.Errorf("gh discovery = sources %v, token_command %q", gh.Sources, gh.TokenCommand)
	}
	// The real PATH stays behind the stub dir, so whether aws is installed
	// is the machine's business; the kind and category are the contract.
	if aws := byName["aws"]; aws.Kind != "native" || aws.NativeCategory != "aws" || aws.Shim != "" {
		t.Errorf("aws = %+v, want native/aws with no shim verdict", aws)
	}
	if clisso := byName["clisso"]; clisso.Kind != "capture" {
		t.Errorf("clisso kind = %q, want capture", clisso.Kind)
	}

	// Text mode has no --all view (it would need a rendered table nobody
	// has designed), so the flag says so rather than printing the same table.
	if _, err := execWrap(t, "list", "--all"); err == nil || !strings.Contains(err.Error(), "--format json") {
		t.Errorf("--all without --format json: err = %v, want a pointer at the JSON view", err)
	}
	// An empty manifest is an empty list in JSON, not the text hint.
	out, err = execWrap(t, "list", "--format", "json")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"tools": []`) {
		t.Errorf("empty listing = %s, want an empty tools array", out)
	}
}

// --discover answers "is there anything to wrap": the same discovery the
// wrap flow runs, reporting where the key is and never what it is.
func TestWrapListJSONDiscoverReportsWhereTheKeyIs(t *testing.T) {
	home := withFixtureHome(t)
	putToolOnPath(t, "gh")
	hosts, err := os.ReadFile(filepath.Join("..", "wrap", "testdata", "gh", "hosts.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".config", "gh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".config", "gh", "hosts.yml"), hosts, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := execWrap(t, "list", "--format", "json", "--all", "--discover")
	if err != nil {
		t.Fatalf("jit wrap list --discover: %v", err)
	}
	var res wrapListResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err)
	}
	var gh, stripe wrapToolJSON
	for _, r := range res.Tools {
		switch r.Tool {
		case "gh":
			gh = r
		case "stripe":
			stripe = r
		}
	}
	if gh.KeyFound == nil || !*gh.KeyFound || gh.KeySource != "~/.config/gh/hosts.yml" {
		t.Errorf("gh discovery = found %v at %q, want found at ~/.config/gh/hosts.yml", gh.KeyFound, gh.KeySource)
	}
	if strings.Contains(out, "gho_") {
		t.Fatalf("the listing must never carry a token value:\n%s", out)
	}
	if stripe.KeyFound != nil {
		t.Errorf("stripe is not installed in the fixture PATH, so discovery must not run for it: %+v", stripe)
	}
	if _, err := execWrap(t, "list", "--format", "json", "--discover"); err == nil {
		t.Error("--discover without --all must be refused")
	}
}

// A grant-kind catalog tool installs the `--with` shim by its own name and
// says when the mount's file has not been migrated yet, instead of
// silently installing a shim that grants nothing.
func TestWrapGrantToolInstallsShimAndSaysMigrateFirst(t *testing.T) {
	home := withFixtureHome(t)
	putToolOnPath(t, "sops")
	out, err := execWrap(t, "sops")
	if err != nil {
		t.Fatalf("jit wrap sops: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Wrapped sops") || !strings.Contains(out, "jit run --with sops") {
		t.Errorf("expected a grant-wrap summary, got:\n%s", out)
	}
	if !strings.Contains(out, "not migrated yet") {
		t.Errorf("with nothing of class sops in the vault, the wrap must say to migrate first:\n%s", out)
	}
	if _, err := os.Lstat(filepath.Join(wrap.ShimDir(home), "sops")); err != nil {
		t.Errorf("shim not installed: %v", err)
	}
	m, err := wrap.LoadManifest(home)
	if err != nil || m.Tools["sops"].With != "sops" {
		t.Errorf("manifest entry = %+v (err %v), want a grant-wrap on the sops mount", m.Tools["sops"], err)
	}
	out, err = execWrap(t, "list", "--format", "json", "--all")
	if err != nil {
		t.Fatal(err)
	}
	var res wrapListResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err)
	}
	for _, r := range res.Tools {
		if r.Tool == "sops" && (r.Kind != "grant" || !r.Wrapped || r.With != "sops" || !r.Catalog) {
			t.Errorf("sops row = %+v, want catalog grant kind, wrapped, with sops", r)
		}
		if r.Tool == "gcloud" && (r.Kind != "grant" || r.With != "gcp") {
			t.Errorf("gcloud row = %+v, want catalog grant kind with gcp", r)
		}
	}
}
