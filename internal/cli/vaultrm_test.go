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

	"github.com/jitpass/jit/internal/auditlog"
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/vault"
)

// rmHarness drives `jit vault rm` through rootCmd with a counting
// user-presence stub, so a test can assert both what was printed and that
// a refusal never reached Touch ID.
type rmHarness struct {
	t        *testing.T
	gestures int
	reasons  []string
}

func newRmHarness(t *testing.T) *rmHarness {
	t.Helper()
	h := &rmHarness{t: t}
	prev := requireUserPresence
	requireUserPresence = func(reason string) error {
		h.gestures++
		h.reasons = append(h.reasons, reason)
		return nil
	}
	reset := func() {
		vaultRmYes, vaultRmForce, vaultRmBreakProfiles, vaultRmDryRun = false, false, false, false
		vaultRmFormat = "text"
		invocationDeleted, invocationBroke = nil, nil
	}
	reset()
	t.Cleanup(func() { requireUserPresence = prev; reset() })
	return h
}

// run executes `jit <args>` and returns stdout+stderr as the terminal would
// show them: the command's output, then main's rendering of any error.
func (h *rmHarness) run(args ...string) (string, error) {
	h.t.Helper()
	vaultRmYes, vaultRmForce, vaultRmBreakProfiles, vaultRmDryRun = false, false, false, false
	vaultRmFormat = "text"
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	// Another test may have set the subcommand's own writers, which would
	// win over the root's; clear them so output lands in buf.
	vaultRmCmd.SetOut(nil)
	vaultRmCmd.SetErr(nil)
	rootCmd.SetArgs(args)
	err := rootCmd.Execute()
	if err != nil {
		buf.WriteString(FormatError(err) + "\n")
	}
	return buf.String(), err
}

func writeFileAt(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func seedSecrets(t *testing.T, paths ...string) *vault.Vault {
	t.Helper()
	root, err := vaultRootDir()
	if err != nil {
		t.Fatalf("vaultRootDir: %v", err)
	}
	v := &vault.Vault{Root: root, KeyWrapper: newFakeKeyWrapper(), RecipientID: "test-device"}
	for _, p := range paths {
		if err := v.Set(p, []byte("value")); err != nil {
			t.Fatalf("seeding %s: %v", p, err)
		}
	}
	return v
}

func assertStored(t *testing.T, v *vault.Vault, want bool, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if ok, _ := v.Exists(p); ok != want {
			t.Errorf("%s stored = %v, want %v", p, ok, want)
		}
	}
}

// The incident, reproduced: the global profile an MCP config launches, with
// rm run from home itself (where the global store and cwd's store are the
// same directory, which the old lookup labelled "project"). -y and the
// hidden -f skip only the typed confirmation; neither may delete a secret
// something uses, and a refusal must never reach Touch ID.
func TestVaultRmRefusesGlobalProfileFromHome(t *testing.T) {
	home := withFixtureHome(t)
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(home); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })
	h := newRmHarness(t)
	v := seedSecrets(t, "mcp-okta-mcp-server/OKTA_ORG_URL", "mcp-okta-mcp-server/OKTA_SCOPES")
	writeFileAt(t, filepath.Join(home, ".jit", "profiles", "mcp-okta-mcp-server.yaml"),
		"OKTA_ORG_URL: mcp-okta-mcp-server/OKTA_ORG_URL\nOKTA_SCOPES: mcp-okta-mcp-server/OKTA_SCOPES\n")
	writeFileAt(t, filepath.Join(home, "Security-Ops", ".mcp.json"), `{"mcpServers":{"okta":{
		"command":"/opt/jit","args":["run","--profile","mcp-okta-mcp-server","--","npx","okta"]}}}`)

	for _, flag := range []string{"-y", "-f", "--yes"} {
		out, err := h.run("vault", "rm", flag, "mcp-okta-mcp-server")
		if err == nil {
			t.Fatalf("rm %s of an in-use group succeeded, want a refusal:\n%s", flag, out)
		}
		for _, want := range []string{
			"mcp-okta-mcp-server is a group of 2 secrets.",
			"profile mcp-okta-mcp-server (global) uses both",
			"tool okta in ~/Security-Ops/.mcp.json",
			"a profile missing a secret can't start its tool",
			"jit vault rm: nothing deleted, 2 secrets are in use",
			glyphAction + " jit vault rm --break-profiles mcp-okta-mcp-server",
			"to delete them anyway",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("rm %s output missing %q, got:\n%s", flag, want, out)
			}
		}
		if strings.Contains(out, "(project") {
			t.Errorf("a global profile must be labelled global from home, got:\n%s", out)
		}
	}
	if h.gestures != 0 {
		t.Errorf("a refusal reached Touch ID %d times", h.gestures)
	}
	assertStored(t, v, true, "mcp-okta-mcp-server/OKTA_ORG_URL", "mcp-okta-mcp-server/OKTA_SCOPES")
	t.Logf("refusal, global profile:\n%s", mustRun(t, h, "vault", "rm", "mcp-okta-mcp-server"))
}

func mustRun(t *testing.T, h *rmHarness, args ...string) string {
	t.Helper()
	out, _ := h.run(args...)
	return out
}

// A project store outside cwd, under home: invisible to the old cwd-only
// lookup, so its secrets looked unused from anywhere else.
func TestVaultRmRefusesProjectStoreOutsideCwd(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	h := newRmHarness(t)
	v := seedSecrets(t, "custom_scripts-wiz/WIZ_TOKEN")
	writeFixtureProfile(t, filepath.Join(home, "Security-Ops"), "custom_scripts-wiz", "WIZ_TOKEN: custom_scripts-wiz/WIZ_TOKEN\n")

	out, err := h.run("vault", "rm", "-y", "custom_scripts-wiz/WIZ_TOKEN")
	if err == nil {
		t.Fatalf("rm of a project-store secret succeeded, want a refusal:\n%s", out)
	}
	for _, want := range []string{
		"profile custom_scripts-wiz (project ~/Security-Ops) uses it",
		"jit vault rm: nothing deleted, 1 secret is in use",
		glyphAction + " jit vault rm --break-profiles custom_scripts-wiz/WIZ_TOKEN",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q, got:\n%s", want, out)
		}
	}
	if strings.Contains(out, "anyway") || strings.Contains(out, "can't start its tool") {
		t.Errorf("single secret, no known tool: no note lines, got:\n%s", out)
	}
	if h.gestures != 0 {
		t.Errorf("a refusal reached Touch ID")
	}
	assertStored(t, v, true, "custom_scripts-wiz/WIZ_TOKEN")
	t.Logf("refusal, project store:\n%s", out)
}

// ~/.clisso.yaml's jit://vault pointer is a user no profile names: the
// capture shim resolves it on every clisso run.
func TestVaultRmRefusesPointerFile(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	h := newRmHarness(t)
	v := seedSecrets(t, "wrap-clisso/blockaid-client-secret")
	writeFileAt(t, migrate.ClissoConfigPath(home),
		"providers:\n  blockaid:\n    client-id: abc\n    client-secret: jit://vault/wrap-clisso/blockaid-client-secret\n")

	out, err := h.run("vault", "rm", "-y", "wrap-clisso/blockaid-client-secret")
	if err == nil {
		t.Fatalf("rm of a pointed-at secret succeeded, want a refusal:\n%s", out)
	}
	for _, want := range []string{
		"~/.clisso.yaml points at it (jit://)",
		"jit vault rm: nothing deleted, 1 secret is in use",
		glyphAction + " jit vault rm --break-profiles wrap-clisso/blockaid-client-secret",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q, got:\n%s", want, out)
		}
	}
	if h.gestures != 0 {
		t.Errorf("a refusal reached Touch ID")
	}
	assertStored(t, v, true, "wrap-clisso/blockaid-client-secret")
	t.Logf("refusal, pointer file:\n%s", out)
}

// --break-profiles is the explicit override: same warnings, then the usual
// confirmation and Touch ID, whose reason names what breaks. The audit
// record gets the expanded paths and the broken profile.
func TestVaultRmBreakProfilesProceeds(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	h := newRmHarness(t)
	v := seedSecrets(t, "mcp-okta-mcp-server/OKTA_ORG_URL", "mcp-okta-mcp-server/OKTA_SCOPES", "free/KEY")
	writeFixtureProfile(t, home, "mcp-okta-mcp-server",
		"OKTA_ORG_URL: mcp-okta-mcp-server/OKTA_ORG_URL\nOKTA_SCOPES: mcp-okta-mcp-server/OKTA_SCOPES\n")

	out, err := h.run("vault", "rm", "-y", "--break-profiles", "mcp-okta-mcp-server")
	if err != nil {
		t.Fatalf("rm --break-profiles: %v\n%s", err, out)
	}
	if !strings.Contains(out, "profile mcp-okta-mcp-server (global) uses both") {
		t.Errorf("--break-profiles must still print the warning, got:\n%s", out)
	}
	if h.gestures != 1 {
		t.Fatalf("gestures = %d, want 1", h.gestures)
	}
	if want := "delete 2 secrets from the vault, breaking profile mcp-okta-mcp-server"; h.reasons[0] != want {
		t.Errorf("Touch ID reason = %q, want %q", h.reasons[0], want)
	}
	assertStored(t, v, false, "mcp-okta-mcp-server/OKTA_ORG_URL", "mcp-okta-mcp-server/OKTA_SCOPES")
	if strings.Join(invocationDeleted, ",") != "mcp-okta-mcp-server/OKTA_ORG_URL,mcp-okta-mcp-server/OKTA_SCOPES" {
		t.Errorf("audit deleted = %v", invocationDeleted)
	}
	if strings.Join(invocationBroke, ",") != "mcp-okta-mcp-server" {
		t.Errorf("audit broke = %v", invocationBroke)
	}

	// An unused secret needs no flag, and its dialog names no breakage.
	h.reasons = nil
	if out, err := h.run("vault", "rm", "-y", "free/KEY"); err != nil {
		t.Fatalf("rm of an unused secret: %v\n%s", err, out)
	}
	if len(h.reasons) != 1 || strings.Contains(h.reasons[0], "breaking") {
		t.Errorf("unused-secret reason = %v, want no breakage named", h.reasons)
	}
	assertStored(t, v, false, "free/KEY")
}

// A manifest jit can't read means it can't tell what uses the secret: that
// refuses too, unless --break-profiles says to delete regardless.
func TestVaultRmRefusesWhenItCantTell(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	h := newRmHarness(t)
	v := seedSecrets(t, "free/KEY")
	writeFixtureProfile(t, filepath.Join(home, "proj"), "broken", ":\tnot yaml")

	out, err := h.run("vault", "rm", "-y", "free/KEY")
	if err == nil {
		t.Fatalf("rm succeeded with an unreadable manifest, want a refusal:\n%s", out)
	}
	if !strings.Contains(out, "can't tell whether free/KEY is in use") ||
		!strings.Contains(out, "jit vault rm --break-profiles free/KEY") {
		t.Errorf("refusal must say it can't tell and name the override, got:\n%s", out)
	}
	if h.gestures != 0 {
		t.Errorf("a refusal reached Touch ID")
	}
	assertStored(t, v, true, "free/KEY")

	if out, err := h.run("vault", "rm", "-y", "--break-profiles", "free/KEY"); err != nil {
		t.Fatalf("rm --break-profiles past an unreadable manifest: %v\n%s", err, out)
	}
	assertStored(t, v, false, "free/KEY")
}

// --dry-run writes nothing and asks nothing; --format json is the shape
// the menu bar app confirms against.
func TestVaultRmDryRun(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	h := newRmHarness(t)
	v := seedSecrets(t, "mcp-okta-mcp-server/OKTA_ORG_URL", "mcp-okta-mcp-server/OKTA_SCOPES")
	writeFixtureProfile(t, home, "mcp-okta-mcp-server",
		"OKTA_ORG_URL: mcp-okta-mcp-server/OKTA_ORG_URL\nOKTA_SCOPES: mcp-okta-mcp-server/OKTA_SCOPES\n")
	cfg := filepath.Join(home, "Security-Ops", ".mcp.json")
	writeFileAt(t, cfg, `{"mcpServers":{"okta":{
		"command":"/opt/jit","args":["run","--profile","mcp-okta-mcp-server","--","npx","okta"]}}}`)

	out, err := h.run("vault", "rm", "--dry-run", "mcp-okta-mcp-server")
	if err != nil {
		t.Fatalf("dry run: %v\n%s", err, out)
	}
	want := "would delete 2 secrets:\n" +
		"  mcp-okta-mcp-server/OKTA_ORG_URL\n" +
		"  mcp-okta-mcp-server/OKTA_SCOPES\n" +
		glyphMark + " profile mcp-okta-mcp-server (global) uses both\n" +
		"  " + glyphBranch + " tool okta in ~/Security-Ops/.mcp.json\n" +
		"refused without --break-profiles\n"
	if out != want {
		t.Errorf("dry-run text =\n%s\nwant\n%s", out, want)
	}
	t.Logf("dry run:\n%s", out)

	out, err = h.run("vault", "rm", "--dry-run", "--format", "json", "mcp-okta-mcp-server", "gone/KEY")
	if err != nil {
		t.Fatalf("dry run json: %v\n%s", err, out)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("dry-run json does not parse: %v\n%s", err, out)
	}
	var res rmDryRunJSON
	_ = json.Unmarshal([]byte(out), &res)
	if strings.Join(res.Paths, ",") != "mcp-okta-mcp-server/OKTA_ORG_URL,mcp-okta-mcp-server/OKTA_SCOPES" ||
		strings.Join(res.Missing, ",") != "gone/KEY" || !res.Refused || len(res.InUse) != 2 {
		t.Fatalf("dry-run json = %s", out)
	}
	row := res.InUse[0]
	if row.Path != "mcp-okta-mcp-server/OKTA_ORG_URL" || row.Profile != "mcp-okta-mcp-server" ||
		row.Scope != "global" || row.Project != "" || len(row.LaunchedBy) != 1 || row.LaunchedBy[0] != cfg ||
		len(row.Tools) != 1 || row.Tools[0] != (toolUse{Name: "okta", Config: cfg}) {
		t.Errorf("in_use row = %+v", row)
	}
	inUse := got["in_use"].([]any)[0].(map[string]any)
	for _, absent := range []string{"project", "mount", "pointer_file"} {
		if _, ok := inUse[absent]; ok {
			t.Errorf("empty field %q must be omitted, got %s", absent, out)
		}
	}
	if _, ok := got["error"]; ok {
		t.Errorf("no error field when the lookup worked, got %s", out)
	}

	if h.gestures != 0 {
		t.Errorf("a dry run reached Touch ID")
	}
	assertStored(t, v, true, "mcp-okta-mcp-server/OKTA_ORG_URL", "mcp-okta-mcp-server/OKTA_SCOPES")

	if _, err := h.run("vault", "rm", "--format", "json", "mcp-okta-mcp-server"); err == nil ||
		!strings.Contains(err.Error(), "--format json needs --dry-run") {
		t.Errorf("--format json without --dry-run must be rejected, got %v", err)
	}
	assertStored(t, v, true, "mcp-okta-mcp-server/OKTA_ORG_URL")
}

// orphans --prune deletes only what nothing uses: a project store outside
// cwd, a jit pointer file found by the home walk, one found through the
// undo index, and ~/.clisso.yaml all count as users now.
func TestVaultOrphansSparesProjectStoresAndPointerFiles(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	stubUserPresence(t)
	t.Cleanup(func() { vaultOrphansPrune = false; vaultOrphansYes = false })

	v := seedSecrets(t, "proj/API_KEY", "bak/KEY", "loose/TOKEN", "wrap-clisso/p-client-secret", "orphan/KEY")
	writeFixtureProfile(t, filepath.Join(home, "proj"), "proj", "API_KEY: proj/API_KEY\n")
	header := "# jit pointer file, no secret values here, only vault paths.\n"
	writeFileAt(t, filepath.Join(home, "other", ".env.bak"), header+"KEY=jit://vault/bak/KEY\n")
	loose := filepath.Join(home, "tok", "token.txt")
	writeFileAt(t, loose, header+"TOKEN=jit://vault/loose/TOKEN\n")
	writeFileAt(t, migrate.BackupIndexPath(v.Root),
		"backups:\n    - {original_path: "+loose+", vault_path: _backups/tok/token.txt.jit-bak-1, unix_ts: 1}\n")
	writeFileAt(t, migrate.ClissoConfigPath(home),
		"providers:\n  p:\n    client-secret: jit://vault/wrap-clisso/p-client-secret\n")

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"vault", "orphans", "--prune", "--yes"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("orphans --prune: %v\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), "Deleted 1 orphaned secret") {
		t.Errorf("want exactly the one orphan deleted, got:\n%s", buf.String())
	}
	assertStored(t, v, false, "orphan/KEY")
	assertStored(t, v, true, "proj/API_KEY", "bak/KEY", "loose/TOKEN", "wrap-clisso/p-client-secret")
}

// migrate remove keeps a secret another project's store uses, even though
// that project is nowhere near cwd.
func TestBuildProjectRemovalPlanKeepsAnotherProjectsSecret(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)
	writeFixtureProfile(t, cwd, "myapp", "SHARED: root/SHARED\nMINE: myapp/MINE\n")
	writeFixtureProfile(t, filepath.Join(home, "elsewhere"), "other", "SHARED: root/SHARED\n")

	vaultRoot := filepath.Join(home, "Library", "Application Support", "jitpass")
	plan, err := buildProjectRemovalPlan(vaultRoot, home, cwd, &vault.Vault{Root: vaultRoot})
	if err != nil {
		t.Fatalf("buildProjectRemovalPlan: %v", err)
	}
	if strings.Join(plan.deletePaths, ",") != "myapp/MINE" {
		t.Errorf("deletePaths = %v, want [myapp/MINE]", plan.deletePaths)
	}
	if strings.Join(plan.keptShared, ",") != "root/SHARED" {
		t.Errorf("keptShared = %v, want [root/SHARED]: ~/elsewhere's profile uses it", plan.keptShared)
	}
}

// A live copy is offered to `jit migrate remove` only when that removal
// takes every user with it. Here an MCP config in another folder launches
// the copy's profile: removing its origin's project would delete a profile
// that config still starts, so there is no pick.
func TestDuplicatesWithholdMigrateRemoveWhenLaunchedElsewhere(t *testing.T) {
	home := withFixtureHome(t)
	ws := filepath.Join(home, "Desktop", "ws")
	if err := os.MkdirAll(ws, 0o700); err != nil {
		t.Fatal(err)
	}
	a := dupTestGroup("mcp-caido", "~/Documents/ws/.mcp.json", true, []string{"mcp-caido"}, map[string]string{"CAIDO_URL": "u"})
	b := dupTestGroup("mcp-caido-2", "~/Desktop/ws/.mcp.json", true, []string{"mcp-caido-2"}, map[string]string{"CAIDO_URL": "u"})
	b.uses = []secretUse{{
		ProfileName: "mcp-caido-2", ProfilePath: filepath.Join(home, ".jit", "profiles", "mcp-caido-2.yaml"),
		Scope: "global", OwnerConfig: "~/Desktop/ws/.mcp.json",
		LaunchedBy: []string{filepath.Join(home, "Security-Ops", ".mcp.json")},
	}}
	fs := sameFileFindings(map[string]*dupGroup{"mcp-caido": a, "mcp-caido-2": b})
	if len(fs) != 1 || fs[0].RemoveCommand != "" || fs[0].InUseGroup != "mcp-caido-2" {
		t.Fatalf("a copy launched from elsewhere must get no pick, got %+v", fs)
	}

	// Launched only by its own config: migrate remove retires it cleanly.
	b.uses[0].LaunchedBy = []string{filepath.Join(ws, ".mcp.json")}
	fs = sameFileFindings(map[string]*dupGroup{"mcp-caido": a, "mcp-caido-2": b})
	if len(fs) != 1 || fs[0].RemoveCommand != "jit migrate remove ~/Desktop/ws/.mcp.json" {
		t.Errorf("a copy only its own config launches retires via migrate remove, got %+v", fs)
	}
}

// A successful delete's audit line names what went, after group expansion,
// and what lost a secret: paths and names only.
func TestAuditCommandEntryNamesDeletedAndBroken(t *testing.T) {
	e := commandEntry(auditlog.Record{
		UnixNano: 1, Command: "jit vault rm", Success: true,
		Args:    []string{"vault", "rm", "--break-profiles", "grp"},
		Deleted: []string{"grp/A", "grp/B"},
		Broke:   []string{"grp-profile"},
	})
	if !strings.Contains(e.match, "deleted=grp/A,grp/B broke=grp-profile") {
		t.Errorf("audit line = %q, want deleted= and broke= fields", e.match)
	}
	if e := commandEntry(auditlog.Record{UnixNano: 1, Command: "jit vault list", Success: true}); strings.Contains(e.match, "deleted=") {
		t.Errorf("a command that deleted nothing must carry no deleted= field: %q", e.match)
	}
}
