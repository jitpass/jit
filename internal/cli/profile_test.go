// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/launchers"
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/pointerfile"
	"github.com/jitpass/jit/internal/vault"
)

// profileHarness drives `jit profile ...` through rootCmd with a counting
// user-presence stub and the Touch ID wait line captured in the same
// buffer, so a test reads exactly what the terminal would show.
type profileHarness struct {
	t        *testing.T
	home     string
	gestures int
	reasons  []string
}

func newProfileHarness(t *testing.T) *profileHarness {
	t.Helper()
	h := &profileHarness{t: t, home: withFixtureHome(t)}
	withFixtureCwd(t)
	prev := requireUserPresence
	requireUserPresence = func(reason string) error {
		h.gestures++
		h.reasons = append(h.reasons, reason)
		return nil
	}
	touchIDNotice.mu.Lock()
	prevOut, prevShown := touchIDNotice.out, touchIDNotice.shown
	touchIDNotice.mu.Unlock()
	t.Cleanup(func() {
		requireUserPresence = prev
		resetProfileFlags()
		touchIDNotice.mu.Lock()
		touchIDNotice.out, touchIDNotice.shown = prevOut, prevShown
		touchIDNotice.mu.Unlock()
		rootCmd.SetIn(nil)
	})
	return h
}

func resetProfileFlags() {
	profileAttachYes, profileAttachDryRun, profileAttachFormat = false, false, "text"
	profileRmYes, profileRmDryRun, profileRmFormat = false, false, "text"
	invocationDeleted, invocationBroke, invocationAuth = nil, nil, ""
}

// run executes `jit <args>` with stdin answering the y/N, returning stdout,
// stderr and main's rendering of any error, interleaved as a terminal shows
// them.
func (h *profileHarness) run(stdin string, args ...string) (string, error) {
	h.t.Helper()
	resetProfileFlags()
	var buf bytes.Buffer
	touchIDNotice.mu.Lock()
	touchIDNotice.out, touchIDNotice.shown = &buf, false
	touchIDNotice.mu.Unlock()
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetIn(strings.NewReader(stdin))
	profileAttachCmd.SetOut(nil)
	profileAttachCmd.SetErr(nil)
	profileRmCmd.SetOut(nil)
	profileRmCmd.SetErr(nil)
	rootCmd.SetArgs(args)
	err := rootCmd.Execute()
	if err != nil {
		buf.WriteString(FormatError(err) + "\n")
	}
	return buf.String(), err
}

func (h *profileHarness) globalManifest(name string) string {
	return filepath.Join(h.home, ".jit", "profiles", name+".yaml")
}

func (h *profileHarness) writeGlobal(name, content string, owners ...string) {
	h.t.Helper()
	writeFileAt(h.t, h.globalManifest(name), content)
	if len(owners) > 0 {
		writeFileAt(h.t, migrate.ProfileSourcePath(h.globalManifest(name)), strings.Join(owners, "\n")+"\n")
	}
}

func (h *profileHarness) owners(name string) []string {
	h.t.Helper()
	owners, err := migrate.ReadProfileOwners(h.globalManifest(name))
	if err != nil {
		h.t.Fatalf("reading owners of %s: %v", name, err)
	}
	return owners
}

// seedWithOrigin stores secrets whose recorded Origin is origin.
func (h *profileHarness) seedWithOrigin(origin string, paths ...string) *vault.Vault {
	h.t.Helper()
	v := seedSecrets(h.t)
	for _, p := range paths {
		if err := v.SetWithMeta(p, []byte("value"), vault.Meta{Origin: origin}); err != nil {
			h.t.Fatalf("seeding %s: %v", p, err)
		}
	}
	return v
}

// mcpEntry is a server entry launching through every profile given, the
// first outermost, the way an old jit nested them.
func mcpEntry(profiles ...string) string {
	var args []string
	for i, p := range profiles {
		if i > 0 {
			args = append(args, "/old/bin/jit")
		}
		args = append(args, "run", "--profile", p, "--")
	}
	args = append(args, "npx", "tool")
	data, _ := json.Marshal(map[string]any{"command": "/opt/homebrew/bin/jit", "args": args})
	return string(data)
}

func assertContainsAll(t *testing.T, out string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("output missing %q, got:\n%s", w, out)
		}
	}
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// The approved preview, from the incident Mac: five profiles whose
// recorded config was deleted and two that record no config, all used by
// tools in ~/Security-Ops/.mcp.json (mcp-okta only as the inner layer).
func securityOpsFixture(h *profileHarness) string {
	h.t.Helper()
	config := filepath.Join(h.home, "Security-Ops", ".mcp.json")
	gone := filepath.Join(h.home, "Documents", "ai_security_workspace", ".mcp.json")
	for _, name := range []string{"mcp-caido", "mcp-google-workspace-investigate", "mcp-jamf", "mcp-okta", "mcp-okta-mcp-server"} {
		h.writeGlobal(name, "KEY: "+name+"/KEY\n", gone)
	}
	h.writeGlobal("mcp-google-workspace", "KEY: mcp-google-workspace/KEY\n")
	h.writeGlobal("mcp-urlscan", "KEY: mcp-urlscan/KEY\n")
	writeFileAt(h.t, config, `{"mcpServers":{
		"caido":`+mcpEntry("mcp-caido")+`,
		"google-workspace":`+mcpEntry("mcp-google-workspace")+`,
		"google-workspace-investigate":`+mcpEntry("mcp-google-workspace-investigate")+`,
		"jamf":`+mcpEntry("mcp-jamf")+`,
		"okta-mcp-server":`+mcpEntry("mcp-okta-mcp-server", "mcp-okta")+`,
		"urlscan":`+mcpEntry("mcp-urlscan")+`}}`)
	if err := os.MkdirAll(filepath.Join(h.home, "Security-Ops", ".jit"), 0o700); err != nil {
		h.t.Fatal(err)
	}
	return config
}

func TestProfileAttachPreview(t *testing.T) {
	h := newProfileHarness(t)
	config := securityOpsFixture(h)

	out, err := h.run("y\n", "profile", "attach", "~/Security-Ops/.mcp.json")
	if err != nil {
		t.Fatalf("attach: %v\n%s", err, out)
	}
	assertContainsAll(t, out,
		"~/Security-Ops/.mcp.json uses 7 profiles that don't record it:\n"+
			"  mcp-caido                          records a deleted config\n"+
			"  mcp-google-workspace-investigate   records a deleted config\n"+
			"  mcp-jamf                           records a deleted config\n"+
			"  mcp-okta                           records a deleted config\n"+
			"  mcp-okta-mcp-server                records a deleted config\n"+
			"  mcp-google-workspace               records no config\n"+
			"  mcp-urlscan                        records no config\n"+
			"jit migrate remove ~/Security-Ops will then take them too.\n"+
			"Record it on all 7? [y/N] ",
		glyphDone+" 7 profiles now record ~/Security-Ops/.mcp.json\n")
	for _, name := range []string{"mcp-caido", "mcp-okta", "mcp-urlscan", "mcp-google-workspace"} {
		if got := h.owners(name); !reflect.DeepEqual(got, []string{config}) {
			t.Errorf("%s owners = %v, want only %s (the gone owner dropped)", name, got, config)
		}
	}
	if h.gestures != 0 {
		t.Errorf("attach reached Touch ID %d times, want none", h.gestures)
	}
	t.Logf("attach:\n%s", out)

	// Everything recorded now: nothing to attach, exit 0.
	out, err = h.run("", "profile", "attach", config)
	if err != nil || out != "~/Security-Ops/.mcp.json uses no profile that doesn't record it\n" {
		t.Errorf("second attach = (%v) %q, want the nothing-to-attach line", err, out)
	}
	t.Logf("nothing to attach:\n%s", out)
}

func TestProfileAttachDeclinedWritesNothing(t *testing.T) {
	h := newProfileHarness(t)
	securityOpsFixture(h)
	out, err := h.run("n\n", "profile", "attach", "~/Security-Ops/.mcp.json")
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	assertContainsAll(t, out, "Record it on all 7? [y/N] ", "Aborted.")
	if got := h.owners("mcp-urlscan"); got != nil {
		t.Errorf("declined attach wrote owners %v", got)
	}
}

// A live owner that isn't this config keeps its place; this config is
// added beside it. `jit migrate remove` goes by the first owner, so the
// migrate line is left out when only such profiles are attached.
func TestProfileAttachOwnedElsewhereAddsOwner(t *testing.T) {
	h := newProfileHarness(t)
	other := filepath.Join(h.home, "other", ".mcp.json")
	writeFileAt(t, other, `{"mcpServers":{"x":`+mcpEntry("mcp-shared")+`}}`)
	config := filepath.Join(h.home, "copy", ".mcp.json")
	writeFileAt(t, config, `{"mcpServers":{"x":`+mcpEntry("mcp-shared")+`}}`)
	h.writeGlobal("mcp-shared", "KEY: mcp-shared/KEY\n", other, filepath.Join(h.home, "gone", ".mcp.json"))

	out, err := h.run("", "profile", "attach", "--yes", config)
	if err != nil {
		t.Fatalf("attach: %v\n%s", err, out)
	}
	assertContainsAll(t, out, "  mcp-shared   records ~/other/.mcp.json\n", glyphDone+" 1 profile now records ~/copy/.mcp.json")
	if strings.Contains(out, "migrate remove") || strings.Contains(out, "[y/N]") {
		t.Errorf("owned elsewhere: no migrate line, and --yes skips the question:\n%s", out)
	}
	if got := h.owners("mcp-shared"); !reflect.DeepEqual(got, []string{other, config}) {
		t.Errorf("owners = %v, want the live owner kept first, this config added, the gone one dropped", got)
	}
	t.Logf("owned elsewhere:\n%s", out)
}

// One profile: the question names it, and the result is singular.
func TestProfileAttachOneProfile(t *testing.T) {
	h := newProfileHarness(t)
	securityOpsFixture(h)
	out, err := h.run("y\n", "profile", "attach", "~/Security-Ops/.mcp.json", "mcp-urlscan")
	if err != nil {
		t.Fatalf("attach: %v\n%s", err, out)
	}
	assertContainsAll(t, out,
		"~/Security-Ops/.mcp.json uses 1 profile that doesn't record it:\n"+
			"  mcp-urlscan   records no config\n",
		"Record it on mcp-urlscan? [y/N] ",
		glyphDone+" 1 profile now records ~/Security-Ops/.mcp.json\n")
}

func TestProfileAttachNamedSubset(t *testing.T) {
	h := newProfileHarness(t)
	config := securityOpsFixture(h)

	out, err := h.run("", "profile", "attach", "-y", config, "mcp-okta", "mcp-urlscan")
	if err != nil {
		t.Fatalf("attach: %v\n%s", err, out)
	}
	assertContainsAll(t, out, "uses 2 profiles that don't record it:", glyphDone+" 2 profiles now record ~/Security-Ops/.mcp.json")
	if got := h.owners("mcp-caido"); len(got) != 1 || got[0] == config {
		t.Errorf("an unnamed profile was attached: %v", got)
	}
	if got := h.owners("mcp-okta"); !reflect.DeepEqual(got, []string{config}) {
		t.Errorf("mcp-okta owners = %v", got)
	}

	out, err = h.run("", "profile", "attach", config, "mcp-nope")
	if err == nil || !strings.Contains(out, "no tool in ~/Security-Ops/.mcp.json uses mcp-nope") {
		t.Errorf("naming an unlaunched profile = (%v) %s", err, out)
	}
}

// ~/.claude.json's project blocks own their profiles as "path#projectDir":
// the same profile launched from two blocks is two owners, and a config at
// home is never a `jit migrate remove` target.
func TestProfileAttachClaudeJSONScopedOwners(t *testing.T) {
	h := newProfileHarness(t)
	config := filepath.Join(h.home, ".claude.json")
	projA, projB := filepath.Join(h.home, "projA"), filepath.Join(h.home, "projB")
	data, _ := json.Marshal(map[string]any{
		"mcpServers": map[string]json.RawMessage{"top": json.RawMessage(mcpEntry("mcp-top"))},
		"projects": map[string]any{
			projA: map[string]any{"mcpServers": map[string]json.RawMessage{"github": json.RawMessage(mcpEntry("mcp-github"))}},
			projB: map[string]any{"mcpServers": map[string]json.RawMessage{"github": json.RawMessage(mcpEntry("mcp-github"))}},
		},
	})
	writeFileAt(t, config, string(data))
	ownerA, ownerB := config+"#"+projA, config+"#"+projB
	h.writeGlobal("mcp-github", "KEY: mcp-github/KEY\n", ownerA)
	h.writeGlobal("mcp-top", "KEY: mcp-top/KEY\n")

	out, err := h.run("", "profile", "attach", "--dry-run", "--format", "json", "~/.claude.json")
	if err != nil {
		t.Fatalf("dry run: %v\n%s", err, out)
	}
	var res attachDryRunJSON
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("dry run JSON: %v\n%s", err, out)
	}
	want := attachDryRunJSON{Config: config, Profiles: []attachProfileJSON{
		{Name: "mcp-top", Status: attachNoConfig, Owners: []string{}, Adds: []string{config}},
		{Name: "mcp-github", Status: attachRecordedElsewhere, Owners: []string{ownerA}, Adds: []string{ownerB}},
	}}
	if !reflect.DeepEqual(res, want) {
		t.Errorf("dry run = %+v\nwant %+v", res, want)
	}
	if h.owners("mcp-top") != nil {
		t.Error("a dry run wrote an owner list")
	}

	out, err = h.run("y\n", "profile", "attach", config)
	if err != nil {
		t.Fatalf("attach: %v\n%s", err, out)
	}
	assertContainsAll(t, out, "  mcp-github   records ~/.claude.json (~/projA)\n")
	if strings.Contains(out, "migrate remove") {
		t.Errorf("a config at home names no migrate remove target:\n%s", out)
	}
	if got := h.owners("mcp-github"); !reflect.DeepEqual(got, []string{ownerA, ownerB}) {
		t.Errorf("mcp-github owners = %v, want both blocks", got)
	}
	if got := h.owners("mcp-top"); !reflect.DeepEqual(got, []string{config}) {
		t.Errorf("mcp-top owners = %v, want the unscoped file", got)
	}
	t.Logf("claude.json:\n%s", out)
}

func TestProfileAttachRejects(t *testing.T) {
	h := newProfileHarness(t)
	plain := filepath.Join(h.home, "plain", ".mcp.json")
	writeFileAt(t, plain, `{"mcpServers":{"x":{"command":"npx","env":{"K":"v"}}}}`)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{plain}, "jit profile attach: no jit-wrapped MCP server in ~/plain/.mcp.json"},
		{[]string{"~/nope.json"}, "jit profile attach: ~/nope.json does not exist"},
		{[]string{"--format", "json", plain}, "--format json needs --dry-run"},
	} {
		out, err := h.run("", append([]string{"profile", "attach"}, tc.args...)...)
		if err == nil || !strings.Contains(out, tc.want) {
			t.Errorf("attach %v = (%v) %s, want %q", tc.args, err, out, tc.want)
		}
	}
}

// ---- jit profile rm ----

// Missing secrets only: the profile goes, no secret to delete, so no
// Touch ID.
func TestProfileRmMissingSecretsOnly(t *testing.T) {
	h := newProfileHarness(t)
	h.writeGlobal("k8s-docker-desktop", "CLIENT_CERTIFICATE_DATA: k8s-docker-desktop/CLIENT_CERTIFICATE_DATA\nCLIENT_KEY_DATA: k8s-docker-desktop/CLIENT_KEY_DATA\n",
		filepath.Join(h.home, ".kube", "gone"))

	out, err := h.run("y\n", "profile", "rm", "k8s-docker-desktop")
	if err != nil {
		t.Fatalf("rm: %v\n%s", err, out)
	}
	assertContainsAll(t, out,
		"profile k8s-docker-desktop (global)\n"+
			"  "+glyphBranch+" no known tool\n"+
			"deletes the profile; its 2 secrets are already gone\n"+
			"Delete it? [y/N] ",
		glyphDone+" deleted profile k8s-docker-desktop\n")
	if h.gestures != 0 || strings.Contains(out, "Touch ID") {
		t.Errorf("no secret to delete must mean no Touch ID (%d):\n%s", h.gestures, out)
	}
	if exists(h.globalManifest("k8s-docker-desktop")) || exists(migrate.ProfileSourcePath(h.globalManifest("k8s-docker-desktop"))) {
		t.Error("manifest or sidecar survived")
	}
	if !reflect.DeepEqual(invocationDeleted, []string{"profile:k8s-docker-desktop"}) {
		t.Errorf("audit deleted = %v", invocationDeleted)
	}
	t.Logf("rm k8s-docker-desktop:\n%s", out)
}

func TestProfileRmDeletesUnsharedSecretsWithTouchID(t *testing.T) {
	h := newProfileHarness(t)
	v := h.seedWithOrigin("~/token.txt", "token/JSON_WEB_TOKEN_JWT")
	h.writeGlobal("token", "JSON_WEB_TOKEN_JWT: token/JSON_WEB_TOKEN_JWT\n")

	out, err := h.run("y\n", "profile", "rm", "token")
	if err != nil {
		t.Fatalf("rm: %v\n%s", err, out)
	}
	assertContainsAll(t, out,
		"profile token (global)\n"+
			"  "+glyphBranch+" made from ~/token.txt, now gone\n"+
			"  "+glyphBranch+" no known tool\n"+
			"deletes the profile and 1 secret nothing else uses:\n"+
			"  token/JSON_WEB_TOKEN_JWT\n"+
			"Delete both? [y/N] ",
		glyphLock+" Touch ID required",
		glyphDone+" deleted profile token and 1 secret\n")
	if h.gestures != 1 || h.reasons[0] != "delete profile token and 1 secret" {
		t.Errorf("gestures = %d %v, want one naming the profile and count", h.gestures, h.reasons)
	}
	assertStored(t, v, false, "token/JSON_WEB_TOKEN_JWT")
	if exists(h.globalManifest("token")) {
		t.Error("manifest survived")
	}
	if !reflect.DeepEqual(invocationDeleted, []string{"token/JSON_WEB_TOKEN_JWT", "profile:token"}) || invocationBroke != nil {
		t.Errorf("audit deleted = %v broke = %v", invocationDeleted, invocationBroke)
	}
	if invocationAuth != freshUserPresenceMethod {
		t.Errorf("audit auth = %q", invocationAuth)
	}
	t.Logf("rm token:\n%s", out)
}

// --yes skips only the typed question, never the fingerprint.
func TestProfileRmYesSkipsPromptNotTouchID(t *testing.T) {
	h := newProfileHarness(t)
	h.seedWithOrigin("", "token/K")
	h.writeGlobal("token", "K: token/K\n")
	out, err := h.run("", "profile", "rm", "--yes", "token")
	if err != nil {
		t.Fatalf("rm: %v\n%s", err, out)
	}
	if strings.Contains(out, "[y/N]") || h.gestures != 1 {
		t.Errorf("--yes: prompt shown or Touch ID skipped (%d):\n%s", h.gestures, out)
	}
	if strings.Contains(out, "made from") {
		t.Errorf("no recorded origin, no made-from line:\n%s", out)
	}
}

func TestProfileRmDeclinedDeletesNothing(t *testing.T) {
	h := newProfileHarness(t)
	v := h.seedWithOrigin("", "token/K")
	h.writeGlobal("token", "K: token/K\n")
	out, err := h.run("n\n", "profile", "rm", "token")
	if err != nil || !strings.Contains(out, "Aborted.") {
		t.Fatalf("declined rm = (%v) %s", err, out)
	}
	if h.gestures != 0 || !exists(h.globalManifest("token")) {
		t.Error("a declined rm reached Touch ID or deleted the manifest")
	}
	assertStored(t, v, true, "token/K")
}

// A secret another profile or a pointer file uses is kept.
func TestProfileRmKeepsSharedSecrets(t *testing.T) {
	h := newProfileHarness(t)
	v := h.seedWithOrigin("", "shared/K", "own/K", "clisso/K")
	h.writeGlobal("alpha", "A: own/K\nB: shared/K\nC: clisso/K\nD: gone/K\n")
	h.writeGlobal("beta", "B: shared/K\n")
	writeFileAt(t, migrate.ClissoConfigPath(h.home), "providers:\n  x:\n    client-secret: "+pointerfile.Value("clisso/K")+"\n")

	out, err := h.run("y\n", "profile", "rm", "alpha")
	if err != nil {
		t.Fatalf("rm: %v\n%s", err, out)
	}
	assertContainsAll(t, out,
		"deletes the profile and 1 secret nothing else uses:\n  own/K\n"+
			"keeps 2 secrets something else uses:\n  clisso/K\n  shared/K\n"+
			"1 secret is already gone\n"+
			"Delete both? [y/N] ",
		glyphDone+" deleted profile alpha and 1 secret\n")
	assertStored(t, v, false, "own/K")
	assertStored(t, v, true, "shared/K", "clisso/K")
	t.Logf("rm with shared secrets:\n%s", out)
}

func TestProfileRmRefusesMCPLauncher(t *testing.T) {
	h := newProfileHarness(t)
	securityOpsFixture(h)
	v := h.seedWithOrigin("", "mcp-okta/KEY")

	for _, flags := range [][]string{nil, {"--yes"}} {
		out, err := h.run("y\n", append(append([]string{"profile", "rm"}, flags...), "mcp-okta")...)
		if err == nil {
			t.Fatalf("rm %v of a launched profile succeeded:\n%s", flags, out)
		}
		want := glyphMark + " tool okta-mcp-server uses it (~/Security-Ops/.mcp.json)\n" +
			"jit profile rm: nothing deleted, mcp-okta is in use\n" +
			"  remove okta-mcp-server from that file first\n"
		if out != want {
			t.Errorf("refusal %v =\n%s\nwant\n%s", flags, out, want)
		}
	}
	if h.gestures != 0 {
		t.Errorf("a refusal reached Touch ID")
	}
	assertStored(t, v, true, "mcp-okta/KEY")
	if !exists(h.globalManifest("mcp-okta")) {
		t.Error("refused rm deleted the manifest")
	}
	out, _ := h.run("", "profile", "rm", "mcp-okta")
	t.Logf("rm mcp-okta (refused):\n%s", out)
}

// Every launcher kind refuses, each with its own line and way out.
func TestProfileRmRefusesEveryLauncherKind(t *testing.T) {
	h := newProfileHarness(t)
	root, err := vaultRootDir()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"aws-prod", "k8s-lab", "wrap-gh", "zshrc", "docker-ghcr.io", "mounted"} {
		h.writeGlobal(name, "K: "+name+"/K\n")
	}
	writeFileAt(t, migrate.AWSConfigPath(h.home), "[profile prod]\ncredential_process = /opt/homebrew/bin/jit aws-credential-process --profile aws-prod\n")
	writeFileAt(t, migrate.KubeconfigPath(h.home), "users:\n- name: lab\n  user:\n    exec:\n      command: /opt/homebrew/bin/jit\n      args: [k8s-exec-credential, --profile, k8s-lab]\n")
	writeFileAt(t, filepath.Join(h.home, ".jit", "wrap.json"), `{"tools":{"gh":{"profile":"wrap-gh","added_at":"2026-01-01T00:00:00Z"}}}`)
	writeFileAt(t, filepath.Join(h.home, ".zshrc"), "# jit\neval \"$(jit export --profile zshrc)\"\n")
	writeFileAt(t, migrate.DockerHelperPath(h.home), "#!/bin/sh\nexec /opt/homebrew/bin/jit docker-credential \"$@\"\n")
	mountPath := filepath.Join(h.home, "app", ".env")
	if err := mount.AddMount(mount.RegistryPath(root), mount.Entry{MountPath: mountPath, ProfilePath: h.globalManifest("mounted")}); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		want []string
	}{
		{"aws-prod", []string{glyphMark + " tool aws uses it (~/.aws/config [profile prod])", "  remove the [profile prod] section from that file first"}},
		{"k8s-lab", []string{glyphMark + " tool kubectl uses it (~/.kube/config user lab)", "  remove user lab from that file first"}},
		{"wrap-gh", []string{glyphMark + " tool gh uses it (wrapped)", glyphAction + " jit wrap undo gh", "unwraps the tool and removes this profile with it"}},
		{"zshrc", []string{glyphMark + " your shell uses it (~/.zshrc line 2)", "  remove its jit export line (line 2) first"}},
		{"docker-ghcr.io", []string{glyphMark + " tool docker uses it (credential helper)", "  the docker helper may ask for it; undo that migration first"}},
		{"mounted", []string{glyphMark + " the mount at ~/app/.env uses it", glyphAction + " jit migrate remove ~/app/.env", "restores the file and removes the profile with it"}},
	} {
		out, err := h.run("y\n", "profile", "rm", "--yes", tc.name)
		if err == nil {
			t.Errorf("rm %s succeeded, want a refusal:\n%s", tc.name, out)
			continue
		}
		assertContainsAll(t, out, append(tc.want, "jit profile rm: nothing deleted, "+tc.name+" is in use")...)
		if !exists(h.globalManifest(tc.name)) {
			t.Errorf("refused rm of %s deleted its manifest", tc.name)
		}
		t.Logf("rm %s (refused):\n%s", tc.name, out)
	}
	if h.gestures != 0 {
		t.Errorf("a refusal reached Touch ID")
	}
}

func TestProfileRmProjectScopeAndMissing(t *testing.T) {
	h := newProfileHarness(t)
	proj := filepath.Join(h.home, "Security-Ops")
	writeFixtureProfile(t, proj, "custom_scripts-wiz", "WIZ: custom_scripts-wiz/WIZ\n")

	out, err := h.run("", "profile", "rm", "custom_scripts-wiz")
	if err == nil {
		t.Fatalf("rm of a project profile succeeded:\n%s", out)
	}
	assertContainsAll(t, out,
		"jit profile rm: custom_scripts-wiz is a project profile in ~/Security-Ops; it goes with its project",
		glyphAction+" jit migrate remove ~/Security-Ops")
	t.Logf("project scope:\n%s", out)

	out, err = h.run("", "profile", "rm", "nope")
	if err == nil || !strings.Contains(out, "jit profile rm: no global profile named nope") {
		t.Errorf("rm of a missing profile = (%v) %s", err, out)
	}
	t.Logf("not found:\n%s", out)
}

// A file jit can't read might be the launcher: strict discovery refuses,
// before any prompt and before Touch ID.
func TestProfileRmStrictFailureRefuses(t *testing.T) {
	h := newProfileHarness(t)
	v := h.seedWithOrigin("", "token/K")
	h.writeGlobal("token", "K: token/K\n")
	writeFileAt(t, filepath.Join(h.home, "proj", ".mcp.json"), "{not json")

	out, err := h.run("y\n", "profile", "rm", "--yes", "token")
	if err == nil || !strings.Contains(out, "jit profile rm: nothing deleted, can't tell whether token is in use: reading MCP config") {
		t.Fatalf("strict failure = (%v) %s", err, out)
	}
	if h.gestures != 0 || strings.Contains(out, "[y/N]") {
		t.Errorf("a can't-tell refusal prompted (%d gestures):\n%s", h.gestures, out)
	}
	assertStored(t, v, true, "token/K")
	t.Logf("strict failure:\n%s", out)

	out, err = h.run("", "profile", "rm", "--dry-run", "--format", "json", "token")
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	var res profileRmJSON
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("JSON: %v\n%s", err, out)
	}
	if !res.Refused || !strings.Contains(res.Error, "reading MCP config") || res.Launchers == nil {
		t.Errorf("dry run on a strict failure = %+v", res)
	}
	t.Logf("strict failure, dry run:\n%s", out)
}

// A directory the walk can't enter makes "no known tool" unsayable.
func TestProfileRmIncompleteCoverage(t *testing.T) {
	h := newProfileHarness(t)
	h.writeGlobal("token", "K: token/K\n")
	locked := filepath.Join(h.home, "Private")
	writeFileAt(t, filepath.Join(locked, "x"), "x")
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })

	out, err := h.run("n\n", "profile", "rm", "token")
	if err != nil {
		t.Fatalf("rm: %v\n%s", err, out)
	}
	assertContainsAll(t, out, "  "+glyphBranch+" jit could not see all of ~\n", "Delete it? [y/N] ", "Aborted.")
	if strings.Contains(out, "no known tool") {
		t.Errorf("incomplete coverage claimed no known tool:\n%s", out)
	}
}

func TestProfileRmDryRunJSON(t *testing.T) {
	h := newProfileHarness(t)
	securityOpsFixture(h)
	h.seedWithOrigin("~/token.txt", "token/K", "shared/K")
	h.writeGlobal("token", "K: token/K\nS: shared/K\nG: token/GONE\n")
	h.writeGlobal("other", "S: shared/K\n")

	out, err := h.run("", "profile", "rm", "--dry-run", "--format", "json", "token")
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	var res profileRmJSON
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("JSON: %v\n%s", err, out)
	}
	want := profileRmJSON{Profile: "token", Scope: "global", Launchers: []launchers.Launcher{}, DeleteSecrets: []string{"token/K"},
		KeepSecrets: []string{"shared/K"}, MissingSecrets: []string{"token/GONE"}, CoverageComplete: true}
	if !reflect.DeepEqual(res, want) {
		t.Errorf("dry run =\n%+v\nwant\n%+v", res, want)
	}
	if !strings.Contains(out, `"launchers": []`) {
		t.Errorf("empty lists must be [], not null:\n%s", out)
	}

	out, err = h.run("", "profile", "rm", "--dry-run", "--format", "json", "mcp-okta")
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	res = profileRmJSON{}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("JSON: %v\n%s", err, out)
	}
	if !res.Refused || len(res.Launchers) != 1 || res.Launchers[0].Detail != "okta-mcp-server" || res.Launchers[0].Layer != 1 {
		t.Errorf("refused dry run = %+v", res)
	}
	if h.gestures != 0 || !exists(h.globalManifest("token")) {
		t.Error("a dry run changed something")
	}

	out, err = h.run("", "profile", "rm", "--dry-run", "mcp-okta")
	if err != nil {
		t.Fatalf("text dry run of a refusal must exit 0: %v", err)
	}
	assertContainsAll(t, out, glyphMark+" tool okta-mcp-server uses it (~/Security-Ops/.mcp.json)", "refused: nothing would be deleted")

	out, err = h.run("", "profile", "rm", "--format", "json", "token")
	if err == nil || !strings.Contains(out, "--format json needs --dry-run") {
		t.Errorf("--format json without --dry-run = (%v) %s", err, out)
	}
}
