// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/launchers"
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/pointerfile"
	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/wrap"
)

// launchFromShellRC gives each named global profile a known launcher: a
// `jit export --profile` line in ~/.zshrc, the one launcher kind that pulls
// no other doctor section in with it.
func launchFromShellRC(t *testing.T, home string, names ...string) {
	t.Helper()
	var b strings.Builder
	for _, n := range names {
		b.WriteString(`eval "$(jit export --profile ` + n + `)"` + "\n")
	}
	writeProfileAt(t, filepath.Join(home, ".zshrc"), b.String())
}

// testJitPath is an executable named jit, outside home, that stands in for
// jit in a launcher: the jit-path checks ([mcp], [jit path]) stay quiet
// about it, and a nested MCP entry's inner layer is recognized by name.
func testJitPath(t *testing.T) string {
	t.Helper()
	exe := filepath.Join(t.TempDir(), "bin", "jit")
	if err := os.MkdirAll(filepath.Dir(exe), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o700); err != nil { // #nosec G306 -- a test stand-in that must be executable
		t.Fatal(err)
	}
	return exe
}

// mcpServerJSON is one wrapped MCP server entry: `jit run --profile` once per
// profile, outermost first, then the tool.
func mcpServerJSON(jit string, profiles ...string) string {
	var args []string
	for i, p := range profiles {
		if i > 0 {
			args = append(args, jit)
		}
		args = append(args, "run", "--profile", p, "--")
	}
	args = append(args, "npx", "server")
	a, _ := json.Marshal(args)
	c, _ := json.Marshal(jit)
	return `{"command":` + string(c) + `,"args":` + string(a) + `}`
}

func writeMCPConfig(t *testing.T, path string, servers map[string]string) {
	t.Helper()
	var parts []string
	for name, entry := range servers {
		parts = append(parts, `"`+name+`":`+entry)
	}
	writeProfileAt(t, path, `{"mcpServers":{`+strings.Join(parts, ",")+`}}`)
}

func writeOwners(t *testing.T, home, name string, owners ...string) {
	t.Helper()
	manifest := filepath.Join(home, ".jit", "profiles", name+".yaml")
	if err := migrate.WriteProfileOwners(manifest, owners); err != nil {
		t.Fatalf("WriteProfileOwners: %v", err)
	}
}

// ownershipFixture is this Mac's state on 2026-09-19, the one the approved
// preview was built from: two AWS sections naming profiles that don't
// exist, a clisso pointer at a missing secret, five MCP profiles whose owner
// config is gone and two with no owner, all launched by one live config,
// and two global profiles nothing launches.
func ownershipFixture(t *testing.T) string {
	t.Helper()
	home := withFixtureHome(t)
	chdirForTest(t, home)
	jit := testJitPath(t)

	writeProfileAt(t, migrate.AWSConfigPath(home), "[profile dev]\n"+
		"credential_process = "+jit+" aws-credential-process --profile aws-dev\n"+
		"[profile admin]\n"+
		"credential_process = "+jit+" aws-credential-process --profile aws-admin\n")
	writeProfileAt(t, migrate.ClissoConfigPath(home),
		"providers:\n  acme:\n    client-secret: "+pointerfile.Value("wrap-clisso/acme-client-secret")+"\n")

	gone := filepath.Join(home, "Documents", "ai_security_workspace", ".mcp.json")
	for _, name := range []string{
		"mcp-caido", "mcp-google-workspace-investigate", "mcp-jamf", "mcp-okta",
		"mcp-okta-mcp-server", "mcp-google-workspace", "mcp-urlscan",
	} {
		writeFixtureProfile(t, home, name, "KEY: "+name+"/KEY\n")
		plantVaultSecret(t, home, name+"/KEY")
	}
	for _, name := range []string{"mcp-caido", "mcp-google-workspace-investigate", "mcp-jamf", "mcp-okta", "mcp-okta-mcp-server"} {
		writeOwners(t, home, name, gone)
	}
	writeMCPConfig(t, filepath.Join(home, "Security-Ops", ".mcp.json"), map[string]string{
		"caido":                        mcpServerJSON(jit, "mcp-caido"),
		"google-workspace-investigate": mcpServerJSON(jit, "mcp-google-workspace-investigate", "mcp-google-workspace"),
		"jamf":                         mcpServerJSON(jit, "mcp-jamf"),
		"okta-mcp-server":              mcpServerJSON(jit, "mcp-okta-mcp-server", "mcp-okta"),
		"urlscan":                      mcpServerJSON(jit, "mcp-urlscan"),
	})

	writeFixtureProfile(t, home, "k8s-docker-desktop",
		"CLIENT_CERTIFICATE_DATA: k8s-docker-desktop/CLIENT_CERTIFICATE_DATA\nCLIENT_KEY_DATA: k8s-docker-desktop/CLIENT_KEY_DATA\n")
	writeFixtureProfile(t, home, "token", "JSON_WEB_TOKEN_JWT: token/JSON_WEB_TOKEN_JWT\n")
	plantOriginSecret(t, home, "token/JSON_WEB_TOKEN_JWT", "~/token.txt")
	// Credentials redacted out of shell history: an archive nothing
	// launches, and the vault's copy is the only one, so it is never
	// offered for deletion.
	writeFixtureProfile(t, home, "zsh_history", "NOTION_TOKEN: zsh_history/NOTION_TOKEN\n")
	writeVaultEnc(t, home, "zsh_history/NOTION_TOKEN",
		`{"version":3,"origin":"~/.zsh_history","class":"shell_history","recipients":{"test":"00"},"payload":"00"}`)
	if err := os.WriteFile(filepath.Join(home, ".zsh_history"), nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return home
}

// TestDoctorOwnershipRendersTheApprovedShape pins every Phase 2 section the
// preview approved, byte for byte at 80 columns with no color.
func TestDoctorOwnershipRendersTheApprovedShape(t *testing.T) {
	ownershipFixture(t)
	out, err := execDoctor(t)
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != doctorProblemsExitCode {
		t.Fatalf("broken launchers and a missing pointer are problems: err = %v", err)
	}
	for _, block := range []string{
		"[profile missing]  2\n" +
			"  ✗ aws-dev · ~/.aws/config [profile dev] names it\n" +
			"  ✗ aws-admin · ~/.aws/config [profile admin] names it\n" +
			"  no such jit profiles, so aws fails for those profiles\n" +
			"  mint them again, or delete those [profile] blocks\n\n",
		"[pointer missing]\n" +
			"  ✗ ~/.clisso.yaml · wrap-clisso/acme-client-secret\n" +
			"  → jit vault set wrap-clisso/acme-client-secret\n\n",
		"[config deleted]  5\n" +
			"  recorded config ~/Documents/ai_security_workspace/.mcp.json is deleted\n" +
			"  now started by ~/Security-Ops/.mcp.json\n" +
			"  ○ mcp-caido · tool caido\n" +
			"  ○ mcp-google-workspace-investigate · tool google-workspace-investigate\n" +
			"  ○ mcp-jamf · tool jamf\n" +
			"  ○ mcp-okta · tool okta-mcp-server\n" +
			"  ○ mcp-okta-mcp-server · tool okta-mcp-server\n" +
			"  → jit profile attach ~/Security-Ops/.mcp.json\n\n",
		"[config not recorded]  2\n" +
			"  started by ~/Security-Ops/.mcp.json\n" +
			"  ○ mcp-google-workspace · tool google-workspace-investigate\n" +
			"  ○ mcp-urlscan · tool urlscan\n" +
			"  → jit profile attach ~/Security-Ops/.mcp.json\n\n",
		"[no known tool]  2\n" +
			"  ○ k8s-docker-desktop · 2 secrets, both missing\n" +
			"  ○ token · 1 secret\n" +
			"    └ made from ~/token.txt, now gone\n" +
			"  a script or alias may still use them; jit can't see those\n" +
			"  → jit profile rm <name> for any you no longer use\n",
	} {
		if !strings.Contains(out, block) {
			t.Errorf("expected the approved block:\n%s\ngot:\n%s", block, out)
		}
	}
	// Order: problems first, then config deleted, config not recorded, no
	// known tool.
	order := []string{"[profile missing]", "[pointer missing]", "[config deleted]", "[config not recorded]", "[no known tool]"}
	last := -1
	for _, h := range order {
		i := strings.Index(out, h)
		if i < last {
			t.Errorf("%s is out of order in:\n%s", h, out)
		}
		last = i
	}
	// Correlation (a): the unlaunched profile's missing secrets are on its
	// row, not repeated under [missing].
	if strings.Contains(out, "[missing]") {
		t.Errorf("k8s-docker-desktop's missing secrets belong to its [no known tool] row, got:\n%s", out)
	}
	// Correlation (b): token is reported once, not also under [origin gone].
	if strings.Contains(out, "[origin gone]") {
		t.Errorf("an unlaunched profile's gone origin is its └ line, got:\n%s", out)
	}
	// No wrap or aws profile is an MCP profile.
	if strings.Contains(out, "○ token\n") || strings.Contains(out, "aws-prod") {
		t.Errorf("only MCP profiles get owner findings, got:\n%s", out)
	}
}

// Correlation (c): a config_deleted profile IS launched, so a secret it lacks is
// still a [missing] problem, which a launched profile's missing secret
// always is.
func TestDoctorOwnerGoneProfileStillReportsMissing(t *testing.T) {
	home := withFixtureHome(t)
	chdirForTest(t, home)
	writeFixtureProfile(t, home, "mcp-okta", "OKTA_API_TOKEN: mcp-okta/OKTA_API_TOKEN\n")
	writeOwners(t, home, "mcp-okta", filepath.Join(home, "gone", ".mcp.json"))
	writeMCPConfig(t, filepath.Join(home, "Security-Ops", ".mcp.json"),
		map[string]string{"okta": mcpServerJSON(testJitPath(t), "mcp-okta")})

	out, err := execDoctor(t)
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != doctorProblemsExitCode {
		t.Fatalf("a launched profile's missing secret is a problem: err = %v", err)
	}
	for _, want := range []string{
		"[missing]\n  ✗ profile \"mcp-okta\" (global): OKTA_API_TOKEN",
		"[config deleted]\n  recorded config ~/gone/.mcp.json is deleted\n  now started by ~/Security-Ops/.mcp.json\n  ○ mcp-okta · tool okta\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "[no known tool]") {
		t.Errorf("an MCP-launched profile has a tool, got:\n%s", out)
	}
}

// Correlation (b), the other half: origin_gone keeps the launched profiles
// of a group and drops only the unlaunched one, so each profile is in one
// section.
func TestDoctorUnlaunchedLeavesOriginGone(t *testing.T) {
	home := withFixtureHome(t)
	chdirForTest(t, home)
	gone := filepath.Join(home, "old", ".env")
	writeFixtureProfile(t, home, "used", "A: shared/A\n")
	writeFixtureProfile(t, home, "idle", "B: shared/B\n")
	launchFromShellRC(t, home, "used")
	plantOriginSecret(t, home, "shared/A", gone)
	plantOriginSecret(t, home, "shared/B", gone)

	out, err := execDoctor(t)
	if err != nil {
		t.Fatalf("nothing here is a problem: %v\n%s", err, out)
	}
	if !strings.Contains(out, "  "+glyphBranch+" used by profile used\n") {
		t.Errorf("the launched profile keeps its [origin gone] line, got:\n%s", out)
	}
	if strings.Contains(out, "used by profiles") || strings.Contains(out, "idle, used") {
		t.Errorf("the unlaunched profile must leave [origin gone], got:\n%s", out)
	}
	want := "[no known tool]\n" +
		"  ○ idle · 1 secret\n" +
		"    └ made from ~/old/.env, now gone\n" +
		"  a script or alias may still use it; jit can't see those\n" +
		"  → jit profile rm idle if you no longer use it\n"
	if !strings.Contains(out, want) {
		t.Errorf("expected the single-row shape:\n%s\ngot:\n%s", want, out)
	}
}

// An unlaunched profile's missing secrets are counted on its row, and the
// run no longer fails for them: they are a warning's detail now.
func TestDoctorUnlaunchedMissingIsNotAProblem(t *testing.T) {
	home := withFixtureHome(t)
	chdirForTest(t, home)
	writeFixtureProfile(t, home, "old", "A: old/A\nB: old/B\nC: old/C\n")
	plantVaultSecret(t, home, "old/A")

	out, err := execDoctor(t)
	if err != nil {
		t.Fatalf("an unlaunched profile's missing secrets are advisory: %v\n%s", err, out)
	}
	if !strings.Contains(out, "  ○ old · 3 secrets, 2 missing\n") {
		t.Errorf("expected the missing count on the row, got:\n%s", out)
	}
	if strings.Contains(out, "[missing]") {
		t.Errorf("no [missing] section for an unlaunched profile, got:\n%s", out)
	}
	if !strings.Contains(out, "1 profile, 1 secret reference resolve cleanly") {
		t.Errorf("the verdict counts only what it verified, got:\n%s", out)
	}
	if _, err := execDoctor(t, "--strict"); err == nil {
		t.Error("--strict makes the [no known tool] warning count")
	}
}

// "No known tool" is only said about places jit looked: a directory the
// walk couldn't enter might hold the launcher, so the section goes quiet.
func TestDoctorUnlaunchedNeedsCompleteCoverage(t *testing.T) {
	home := withFixtureHome(t)
	chdirForTest(t, home)
	writeFixtureProfile(t, home, "token", "T: token/T\n")
	plantVaultSecret(t, home, "token/T")
	locked := filepath.Join(home, "Private")
	writeProfileAt(t, filepath.Join(locked, "x.txt"), "x")
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })

	out, _ := execDoctor(t)
	if strings.Contains(out, "[no known tool]") {
		t.Errorf("an incomplete walk must not say no known tool, got:\n%s", out)
	}

	// Same for a launcher source that failed to read.
	_ = os.Chmod(locked, 0o700)
	writeProfileAt(t, filepath.Join(home, "ws", ".mcp.json"), "{not json")
	out, _ = execDoctor(t)
	if strings.Contains(out, "[no known tool]") {
		t.Errorf("an unreadable MCP config might launch it, got:\n%s", out)
	}
}

// A project profile is launched by `jit run` inside its project, which
// nothing on disk records: never unlaunched, from inside or outside it.
func TestDoctorProjectProfileNeverUnlaunched(t *testing.T) {
	home := withFixtureHome(t)
	project := filepath.Join(home, "Security-Ops")
	writeFixtureProfile(t, project, "custom_scripts-wiz", "WIZ: wiz/WIZ\n")
	plantVaultSecret(t, home, "wiz/WIZ")

	for _, dir := range []string{home, project} {
		chdirForTest(t, dir)
		out, err := execDoctor(t)
		if err != nil {
			t.Fatalf("from %s: %v\n%s", dir, err, out)
		}
		if strings.Contains(out, "[no known tool]") {
			t.Errorf("from %s, a project profile was called unlaunched:\n%s", dir, out)
		}
	}
}

// A nested MCP entry's inner layer naming a gone profile is [profile
// missing]; the outer layer's is [mcp]'s, reported there once.
func TestDoctorBrokenInnerMCPLayer(t *testing.T) {
	home := withFixtureHome(t)
	chdirForTest(t, home)
	jit := testJitPath(t)
	writeFixtureProfile(t, home, "mcp-outer", "K: mcp-outer/K\n")
	plantVaultSecret(t, home, "mcp-outer/K")
	writeMCPConfig(t, filepath.Join(home, "ws", ".mcp.json"), map[string]string{
		"inner-gone": mcpServerJSON(jit, "mcp-outer", "mcp-inner"),
		"outer-gone": mcpServerJSON(jit, "mcp-ghost"),
	})

	out, err := execDoctor(t)
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != doctorProblemsExitCode {
		t.Fatalf("a broken launcher is a problem: err = %v", err)
	}
	want := "[profile missing]\n" +
		"  ✗ mcp-inner · ~/ws/.mcp.json inner-gone names it\n" +
		"  no such jit profile, so that MCP server fails to start\n" +
		"  undo that migration, or drop that jit run layer\n"
	if !strings.Contains(out, want) {
		t.Errorf("expected the inner layer's row:\n%s\ngot:\n%s", want, out)
	}
	if !strings.Contains(out, "[mcp]\n  ✗ MCP server \"outer-gone\"") {
		t.Errorf("[mcp] reports the outer layer, got:\n%s", out)
	}
	if strings.Contains(out, "mcp-ghost · ") {
		t.Errorf("the outer layer is [mcp]'s, not reported twice, got:\n%s", out)
	}
}

// The closing notes for the other by-name launchers, one run per kind.
func TestDoctorBrokenLauncherNotesPerKind(t *testing.T) {
	home := withFixtureHome(t)
	chdirForTest(t, home)
	writeProfileAt(t, migrate.KubeconfigPath(home), "users:\n- name: dd\n  user:\n    exec:\n      command: "+
		testJitPath(t)+"\n      args: [k8s-exec-credential, --profile, k8s-dd]\n")
	launchFromShellRC(t, home, "gone-rc")

	out, _ := execDoctor(t)
	want := "[profile missing]  2\n" +
		"  ✗ k8s-dd · ~/.kube/config user dd names it\n" +
		"  no such jit profile, so kubectl fails as that user\n" +
		"  undo that migration, or delete that user entry\n" +
		"  ✗ gone-rc · ~/.zshrc line 1 names it\n" +
		"  no such jit profile, so that line fails in every new shell\n" +
		"  undo that migration, or delete that line\n"
	if !strings.Contains(out, want) {
		t.Errorf("expected per-kind notes:\n%s\ngot:\n%s", want, out)
	}
}

// Only a problem fails the run: warnings alone exit 0, and --strict counts
// them.
func TestDoctorOwnershipExitCodes(t *testing.T) {
	home := withFixtureHome(t)
	chdirForTest(t, home)
	writeFixtureProfile(t, home, "mcp-urlscan", "K: mcp-urlscan/K\n")
	plantVaultSecret(t, home, "mcp-urlscan/K")
	writeMCPConfig(t, filepath.Join(home, "ws", ".mcp.json"),
		map[string]string{"urlscan": mcpServerJSON(testJitPath(t), "mcp-urlscan")})

	out, err := execDoctor(t)
	if err != nil {
		t.Fatalf("[config not recorded] is advisory: %v\n%s", err, out)
	}
	if !strings.Contains(out, "[config not recorded]") {
		t.Fatalf("expected a [config not recorded] warning, got:\n%s", out)
	}
	if _, err := execDoctor(t, "--strict"); err == nil {
		t.Error("--strict must count the ownership warnings")
	}

	writeProfileAt(t, migrate.ClissoConfigPath(home),
		"providers:\n  a:\n    client-secret: "+pointerfile.Value("wrap-clisso/a")+"\n")
	_, err = execDoctor(t)
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != doctorProblemsExitCode {
		t.Errorf("a missing pointer target is a problem: err = %v", err)
	}
}

// --format json carries each new kind with its structured fields, and fixes
// from the prose action: `vault set` asks for presence, and a `profile`
// command this build doesn't have classifies as destructive until it does.
func TestDoctorOwnershipJSON(t *testing.T) {
	home := ownershipFixture(t)
	out, _ := execDoctor(t, "--format", "json")
	var result doctorResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, out)
	}
	byKind := map[checkKind][]checkFinding{}
	for _, f := range append(result.Problems, result.Warnings...) {
		byKind[f.Kind] = append(byKind[f.Kind], f)
	}
	if result.OK {
		t.Error("ok must be false with broken launchers")
	}

	broken := byKind[kindProfileMissing]
	if len(broken) != 2 || broken[0].Profile != "aws-dev" || broken[0].File != migrate.AWSConfigPath(home) ||
		len(broken[0].Launchers) != 1 || broken[0].Launchers[0].Kind != launchers.KindAWS ||
		broken[0].Launchers[0].Detail != "[profile dev]" || len(broken[0].Fixes) != 0 {
		t.Errorf("profile_missing = %+v", broken)
	}

	ptr := byKind[kindPointerMissing]
	if len(ptr) != 1 || ptr[0].File != migrate.ClissoConfigPath(home) || ptr[0].Path != "wrap-clisso/acme-client-secret" ||
		len(ptr[0].Fixes) != 1 || ptr[0].Fixes[0].Destructive || !ptr[0].Fixes[0].Presence ||
		strings.Join(ptr[0].Fixes[0].Argv, " ") != "vault set wrap-clisso/acme-client-secret" {
		t.Errorf("pointer_missing = %+v", ptr)
	}

	config := filepath.Join(home, "Security-Ops", ".mcp.json")
	gone := byKind[kindConfigDeleted]
	if len(gone) != 5 {
		t.Fatalf("config_deleted = %d findings, want 5", len(gone))
	}
	okta := gone[3]
	if okta.Profile != "mcp-okta" || okta.Config != config || len(okta.Configs) != 1 ||
		len(okta.Owners) != 1 || okta.Owners[0] != filepath.Join(home, "Documents", "ai_security_workspace", ".mcp.json") ||
		len(okta.Launchers) != 1 || okta.Launchers[0].Layer != 1 || okta.Launchers[0].Detail != "okta-mcp-server" {
		t.Errorf("config_deleted mcp-okta = %+v", okta)
	}
	if len(okta.Fixes) != 1 || okta.Fixes[0].Destructive || okta.Fixes[0].Presence ||
		strings.Join(okta.Fixes[0].Argv, " ") != "profile attach "+config {
		t.Errorf("config_deleted fixes = %+v, want attach: records only, no Touch ID", okta.Fixes)
	}

	if no := byKind[kindConfigNotRecorded]; len(no) != 2 || no[0].Profile != "mcp-google-workspace" || no[0].Config != config || len(no[0].Owners) != 0 {
		t.Errorf("config_not_recorded = %+v", no)
	}

	un := byKind[kindNoKnownTool]
	if len(un) != 2 {
		t.Fatalf("unlaunched = %+v", un)
	}
	k8s, token := un[0], un[1]
	if k8s.Profile != "k8s-docker-desktop" || k8s.Scope != "global" || k8s.Secrets != 2 || k8s.SecretsMissing != 2 ||
		k8s.Origin != "" {
		t.Errorf("unlaunched k8s = %+v", k8s)
	}
	if token.Secrets != 1 || token.SecretsMissing != 0 || token.Origin != filepath.Join(home, "token.txt") ||
		len(token.Fixes) != 1 || strings.Join(token.Fixes[0].Argv, " ") != "profile rm token" || !token.Fixes[0].Destructive {
		t.Errorf("unlaunched token = %+v", token)
	}
	if len(byKind[kindMissing]) != 0 {
		t.Errorf("an unlaunched profile's missing secrets are not [missing]: %+v", byKind[kindMissing])
	}
}

// --profile is a one-profile question: none of the whole-machine ownership
// sections run.
func TestDoctorProfileFlagSkipsOwnership(t *testing.T) {
	ownershipFixture(t)
	out, _ := execDoctor(t, "--profile", "token")
	for _, h := range []string{"[profile missing]", "[pointer missing]", "[config deleted]", "[config not recorded]", "[no known tool]"} {
		if strings.Contains(out, h) {
			t.Errorf("--profile must skip %s, got:\n%s", h, out)
		}
	}
}

func TestSecretsPhrase(t *testing.T) {
	for _, c := range []struct {
		n, missing int
		want       string
	}{
		{0, 0, "no secrets"},
		{1, 0, "1 secret"},
		{1, 1, "1 secret, missing"},
		{2, 2, "2 secrets, both missing"},
		{3, 3, "3 secrets, all missing"},
		{5, 2, "5 secrets, 2 missing"},
	} {
		if got := secretsPhrase(c.n, c.missing); got != c.want {
			t.Errorf("secretsPhrase(%d, %d) = %q, want %q", c.n, c.missing, got, c.want)
		}
	}
}

func TestAWSProfileCommand(t *testing.T) {
	for section, want := range map[string]string{
		"[profile dev]": "aws --profile dev",
		"[default]":     "aws",
		"":              "that aws profile",
	} {
		if got := awsProfileCommand(section); got != want {
			t.Errorf("awsProfileCommand(%q) = %q, want %q", section, got, want)
		}
	}
}

// Several gone owners and several launching configs are counted on the
// sub-group's header lines.
func TestDoctorOwnerGroupHeaderCountsExtras(t *testing.T) {
	home := withFixtureHome(t)
	chdirForTest(t, home)
	jit := testJitPath(t)
	writeFixtureProfile(t, home, "mcp-okta", "K: mcp-okta/K\n")
	plantVaultSecret(t, home, "mcp-okta/K")
	writeOwners(t, home, "mcp-okta", filepath.Join(home, "gone1", ".mcp.json"), filepath.Join(home, "gone2", ".mcp.json"))
	for _, dir := range []string{"a", "b", "c"} {
		writeMCPConfig(t, filepath.Join(home, dir, ".mcp.json"), map[string]string{"okta": mcpServerJSON(jit, "mcp-okta")})
	}

	out, _ := execDoctor(t)
	want := "[config deleted]\n" +
		"  recorded config ~/gone1/.mcp.json and 1 more are deleted\n" +
		"  now started by ~/a/.mcp.json and 2 more\n" +
		"  ○ mcp-okta · tool okta\n" +
		"  → jit profile attach ~/a/.mcp.json\n"
	if !strings.Contains(out, want) {
		t.Errorf("expected:\n%s\ngot:\n%s", want, out)
	}
}

// installClissoCapture wraps clisso the way `jit wrap clisso` does: a
// capture entry in ~/.jit/wrap.json and a shim symlink to an executable.
func installClissoCapture(t *testing.T, home string) {
	t.Helper()
	m := wrap.Manifest{Tools: map[string]wrap.Entry{"clisso": {Capture: "clisso"}}}
	if err := m.Save(home); err != nil {
		t.Fatalf("Save: %v", err)
	}
	dir := wrap.ShimDir(home)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(testJitPath(t), filepath.Join(dir, "clisso")); err != nil {
		t.Fatal(err)
	}
	// The rc PATH line, so [wrap] has no damage to report: the only wrap
	// rows left are about this test process's own PATH.
	t.Setenv("SHELL", "/bin/zsh")
	writeProfileAt(t, filepath.Join(home, ".zshrc"), wrap.PathLine()+"\n")
}

// notLoggedInFixture is ~/.aws/config naming aws-dev, aws-admin and aws-qa,
// with dev and admin apps in ~/.clisso.yaml and no profile for any of them.
func notLoggedInFixture(t *testing.T) string {
	t.Helper()
	home := withFixtureHome(t)
	chdirForTest(t, home)
	jit := testJitPath(t)
	var b strings.Builder
	for _, name := range []string{"dev", "admin", "qa"} {
		b.WriteString("[profile " + name + "]\ncredential_process = " + jit + " aws-credential-process --profile aws-" + name + "\n")
	}
	writeProfileAt(t, migrate.AWSConfigPath(home), b.String())
	writeProfileAt(t, migrate.ClissoConfigPath(home), "apps:\n  dev:\n    principal-arn: x\n  admin:\n    principal-arn: y\n")
	return home
}

// A profile clisso makes at the first login is a state, not breakage — but
// only when the capture wrap is there to make it, and only for an app
// clisso knows.
func TestDoctorNotLoggedIn(t *testing.T) {
	cases := []struct {
		name        string
		wrapped     bool
		notLoggedIn []string
		missing     []string
	}{
		{name: "capture wrap installed", wrapped: true, notLoggedIn: []string{"aws-dev", "aws-admin"}, missing: []string{"aws-qa"}},
		{name: "no capture wrap", wrapped: false, missing: []string{"aws-dev", "aws-admin", "aws-qa"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := notLoggedInFixture(t)
			if tc.wrapped {
				installClissoCapture(t, home)
			}
			out, _ := execDoctor(t, "--format", "json")
			var result doctorResult
			if err := json.Unmarshal([]byte(out), &result); err != nil {
				t.Fatalf("unmarshal: %v\n%s", err, out)
			}
			var gotNLI, gotMissing []string
			for _, f := range result.Warnings {
				if f.Kind == kindNotLoggedIn {
					gotNLI = append(gotNLI, f.Profile)
					if len(f.Fixes) != 1 || strings.Join(f.Fixes[0].Argv, " ") != "clisso get "+strings.TrimPrefix(f.Profile, "aws-") ||
						!f.Fixes[0].External || f.Fixes[0].Destructive {
						t.Errorf("not_logged_in fixes = %+v", f.Fixes)
					}
				}
			}
			for _, f := range result.Problems {
				if f.Kind == kindProfileMissing {
					gotMissing = append(gotMissing, f.Profile)
				}
				if f.Kind == kindNotLoggedIn {
					t.Errorf("not_logged_in is advisory, found under problems: %+v", f)
				}
			}
			if strings.Join(gotNLI, ",") != strings.Join(tc.notLoggedIn, ",") {
				t.Errorf("not_logged_in = %v, want %v", gotNLI, tc.notLoggedIn)
			}
			if strings.Join(gotMissing, ",") != strings.Join(tc.missing, ",") {
				t.Errorf("profile_missing = %v, want %v", gotMissing, tc.missing)
			}
		})
	}
}

// The approved [not logged in] block, byte for byte at 80 columns.
func TestDoctorNotLoggedInRendersTheApprovedShape(t *testing.T) {
	home := notLoggedInFixture(t)
	installClissoCapture(t, home)
	out, _ := execDoctor(t)
	want := "[not logged in]  2\n" +
		"  clisso makes these profiles the first time you log in\n" +
		"  ○ aws --profile dev · ~/.aws/config [profile dev]\n" +
		"  → clisso get dev\n" +
		"  ○ aws --profile admin · ~/.aws/config [profile admin]\n" +
		"  → clisso get admin\n"
	if !strings.Contains(out, want) {
		t.Errorf("expected:\n%s\ngot:\n%s", want, out)
	}
	if !strings.Contains(out, "[profile missing]\n  ✗ aws-qa · ~/.aws/config [profile qa] names it\n") {
		t.Errorf("aws-qa has no clisso app and stays a problem, got:\n%s", out)
	}
}

// TestMissingPointerFindingsReportsCompanions: a `.pointers` companion is
// the one record of what a mount served, and on a machine whose mounts were
// never re-registered nothing else in doctor names its secrets. It was
// skipped entirely by discovery, so a companion naming a vault group that
// does not exist — the state that silently blocks the server beside it —
// produced no finding at all.
func TestMissingPointerFindingsReportsCompanions(t *testing.T) {
	m := &launchers.Map{
		MissingPointers: []launchers.Launcher{
			{Kind: launchers.KindPointerFile, File: "/h/.clisso.yaml", VaultPath: "wrap-clisso/secret"},
		},
		MissingCompanions: []launchers.Launcher{
			{Kind: launchers.KindPointerFile, File: "/h/okta-mcp-server/.env.pointers", VaultPath: "okta-mcp-server-2/OKTA_ORG_URL"},
			{Kind: launchers.KindPointerFile, File: "/h/okta-mcp-server/.env.pointers", VaultPath: "okta-mcp-server-2/OKTA_SCOPES"},
			// The same value named twice must not inflate the count.
			{Kind: launchers.KindPointerFile, File: "/h/okta-mcp-server/.env.pointers", VaultPath: "okta-mcp-server-2/OKTA_SCOPES"},
		},
	}
	got := missingPointerFindings(m, map[string]bool{"other": true})
	if len(got) != 2 {
		t.Fatalf("findings = %+v, want the pointer and ONE row for the companion's group", got)
	}
	if got[0].Path != "wrap-clisso/secret" {
		t.Errorf("the real pointer must still be reported first, got %+v", got[0])
	}
	c := got[1]
	if c.Kind != kindStalePointers || c.Path != "okta-mcp-server-2" {
		t.Errorf("companion finding = %+v, want the GROUP as its path", c)
	}
	if !strings.Contains(c.Detail, "okta-mcp-server-2/") || !strings.Contains(c.Detail, "2 values") {
		t.Errorf("detail %q must name the group and how many values it records", c.Detail)
	}
	// The offered fix deletes the record, so it must be marked destructive:
	// that is what makes the app confirm before it runs, and what keeps it
	// out of any "apply everything" path.
	fixes := fixesFor(c.Kind, c.Action)
	if len(fixes) != 1 || !strings.HasPrefix(fixes[0].Command, "jit migrate forget ") {
		t.Fatalf("fixes = %+v, want the one command that removes a stale record", fixes)
	}
	if !fixes[0].Destructive {
		t.Error("deleting a file must be marked destructive so the app confirms")
	}
	if fixes[0].Presence {
		t.Error("no secret is read or removed, so it must not demand Touch ID")
	}
	// An empty vault makes every companion on the disk look stale.
	if got := missingCompanionFindings(m, nil); got != nil {
		t.Errorf("companions = %+v, want none when the vault holds nothing", got)
	}
}

// TestRegistryEmptyDroppedWhenProfilesLiveElsewhere: the finding claims the
// MACHINE has no profile registry, while the check that raises it looked only
// in cwd and the global store. A project-scoped setup read from anywhere else
// — which is every run the JitPass app makes, since it starts from home — is
// not the state this warns about.
func TestRegistryEmptyDroppedWhenProfilesLiveElsewhere(t *testing.T) {
	home := withFixtureHome(t)
	m := &launchers.Map{Profiles: []*launchers.Profile{
		{Name: "a", Scope: profile.ScopeProject, Project: filepath.Join(home, "Security-Ops")},
	}}
	in := []checkFinding{
		{Kind: kindRegistryEmpty, Detail: "69 secrets stored"},
		{Kind: kindBackup, Detail: "keep me"},
	}
	got := dropRegistryEmptyWhenProfilesExist(in, m, home)
	if len(got) != 1 || got[0].Kind != kindBackup {
		t.Errorf("findings = %+v, want only the unrelated one", got)
	}
}

// With no profile manifest anywhere, the registry really is gone and the
// finding stands — the incident it was written for.
func TestRegistryEmptyKeptWhenNoProfilesAnywhere(t *testing.T) {
	home := withFixtureHome(t)
	in := []checkFinding{{Kind: kindRegistryEmpty, Detail: "69 secrets stored"}}
	if got := dropRegistryEmptyWhenProfilesExist(in, &launchers.Map{}, home); len(got) != 1 {
		t.Errorf("findings = %+v, want the finding kept", got)
	}
}

// TestStalePointersIsAProblemNotAWarning: a companion names the variables a
// program in that directory needs. A group that is gone means that program
// cannot get its secrets, which is breakage — the same verdict jit gives any
// other reference to a secret the vault does not hold.
func TestStalePointersIsAProblemNotAWarning(t *testing.T) {
	if kindStalePointers.warning() {
		t.Error("a tool whose secrets are not in the vault is broken, not untidy")
	}
	if kindPointerMissing.warning() || kindMissing.warning() {
		t.Error("the kinds this one matches must stay hard problems too")
	}
}

// TestCompanionSilentWhenItsGroupPartlyExists: a migrate that stored some of
// a companion's values leaves the rest to the profile or mount that names
// them, each with its own `jit vault set`. Claiming the vault "has nothing"
// under a group holding two secrets was false, and it buried four better
// findings under one wrong one.
func TestCompanionSilentWhenItsGroupPartlyExists(t *testing.T) {
	m := &launchers.Map{MissingCompanions: []launchers.Launcher{
		{File: "/h/hibob/.env.pointers", VaultPath: "hibob/HIBOB_BASE_URL"},
		{File: "/h/hibob/.env.pointers", VaultPath: "hibob/OUTPUT_FILE"},
		{File: "/h/wiz/.env.pointers", VaultPath: "wiz/WIZ_CLIENT_ID"},
	}}
	// hibob exists (migrate stored two of its values); wiz does not.
	got := missingCompanionFindings(m, map[string]bool{"hibob": true})
	if len(got) != 1 {
		t.Fatalf("findings = %+v, want only the group that is wholly absent", got)
	}
	if got[0].Path != "wiz" {
		t.Errorf("finding = %+v, want the wiz group", got[0])
	}
}
