// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package launchers

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/pointerfile"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func manifest(t *testing.T, storeRoot, name, content string) string {
	t.Helper()
	p := filepath.Join(storeRoot, ".jit", "profiles", name+".yaml")
	write(t, p, content)
	return p
}

func wrapperArgs(profiles []string, tail ...string) string {
	var args []string
	for i, p := range profiles {
		if i > 0 {
			args = append(args, "/old/bin/jit")
		}
		args = append(args, "run", "--profile", p, "--")
	}
	args = append(args, tail...)
	return `["` + strings.Join(args, `","`) + `"]`
}

// fixture is a home holding one of every launcher kind, plus a broken
// launcher and a pointer at a missing secret.
type fixture struct {
	home, root string
	project    string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	base := t.TempDir()
	f := fixture{
		home:    filepath.Join(base, "home"),
		root:    filepath.Join(base, "jitroot"),
		project: filepath.Join(base, "home", "Security-Ops"),
	}
	t.Setenv("HOME", f.home)
	t.Setenv("GOMODCACHE", filepath.Join(base, "gomodcache"))

	// Global profiles.
	for _, name := range []string{"mcp-okta", "mcp-okta-mcp-server", "mcp-urlscan", "aws-prod", "k8s-docker-desktop", "wrap-gh", "zshrc", "docker-ghcr.io", "token", "vscode-server", "windsurf-server"} {
		manifest(t, f.home, name, fmt.Sprintf("KEY: %s/KEY\n", name))
	}
	// A project store and its own profiles, one of them mounted.
	manifest(t, f.project, "custom_scripts-wiz", "WIZ: custom_scripts-wiz/WIZ\n")
	envManifest := manifest(t, f.project, "security-ops", "API: security-ops/API\n")

	// MCP: a nested entry (inner layer mcp-okta), a plain one, and one
	// naming a profile that exists nowhere.
	write(t, filepath.Join(f.project, ".mcp.json"), `{"mcpServers":{
		"okta-mcp-server":{"command":"/opt/homebrew/bin/jit","args":`+wrapperArgs([]string{"mcp-okta-mcp-server", "mcp-okta"}, "npx", "okta")+`},
		"urlscan":{"command":"/opt/homebrew/bin/jit","args":`+wrapperArgs([]string{"mcp-urlscan"}, "uvx", "urlscan")+`},
		"ghost":{"command":"/opt/homebrew/bin/jit","args":`+wrapperArgs([]string{"mcp-ghost"}, "npx", "ghost")+`},
		"plain":{"command":"npx","env":{"X":"y"}}}}`)
	// VS Code's user config ("servers") and Windsurf's, both fixed files.
	write(t, filepath.Join(f.home, "Library", "Application Support", "Code", "User", "mcp.json"),
		`{"servers":{"vs":{"command":"/opt/homebrew/bin/jit","args":`+wrapperArgs([]string{"vscode-server"}, "npx", "vs")+`}},"inputs":[]}`)
	write(t, filepath.Join(f.home, ".codeium", "windsurf", "mcp_config.json"),
		`{"mcpServers":{"ws":{"command":"/opt/homebrew/bin/jit","args":`+wrapperArgs([]string{"windsurf-server"}, "npx", "ws")+`}}}`)
	// A trashed project's config launches nothing.
	write(t, filepath.Join(f.home, ".Trash", "old", ".mcp.json"),
		`{"mcpServers":{"t":{"command":"/opt/homebrew/bin/jit","args":`+wrapperArgs([]string{"token"}, "npx", "t")+`}}}`)

	write(t, migrate.AWSConfigPath(f.home), `[profile prod]
credential_process = /opt/homebrew/bin/jit aws-credential-process --profile aws-prod
[profile dev]
credential_process = /opt/homebrew/bin/jit aws-credential-process --profile aws-dev
`)
	write(t, migrate.KubeconfigPath(f.home), `users:
- name: docker-desktop
  user:
    exec:
      command: /opt/homebrew/bin/jit
      args: [k8s-exec-credential, --profile, k8s-docker-desktop]
`)
	write(t, filepath.Join(f.home, ".jit", "wrap.json"), `{"tools":{
		"gh":{"profile":"wrap-gh","added_at":"2026-01-01T00:00:00Z"},
		"clisso":{"capture":"clisso","added_at":"2026-01-01T00:00:00Z"},
		"gcloud":{"with":"gcp","added_at":"2026-01-01T00:00:00Z"}}}`)
	write(t, filepath.Join(f.home, ".zshrc"), "# jit migrate moved...\neval \"$(jit export --profile zshrc)\"\n")
	write(t, migrate.DockerHelperPath(f.home), "#!/bin/sh\nexec /opt/homebrew/bin/jit docker-credential \"$@\"\n")

	// A mount feeding the project's env profile.
	if err := mount.AddMount(mount.RegistryPath(f.root), mount.Entry{MountPath: filepath.Join(f.project, ".env"), ProfilePath: envManifest}); err != nil {
		t.Fatal(err)
	}
	// Pointer files: an in-place .env-family one found by the walk, and
	// ~/.clisso.yaml, one of whose targets is gone.
	write(t, filepath.Join(f.project, "scripts", ".env.bak"), pointerfile.Header+"\nAPI="+pointerfile.Value("security-ops/API")+"\n")
	write(t, migrate.ClissoConfigPath(f.home), "providers:\n  acme:\n    client-secret: "+pointerfile.Value("wrap-clisso/acme-client-secret")+"\n")

	// Owners: one live, one gone.
	write(t, migrate.ProfileSourcePath(filepath.Join(f.home, ".jit", "profiles", "mcp-okta.yaml")),
		filepath.Join(f.home, "gone", ".mcp.json")+"\n"+filepath.Join(f.project, ".mcp.json")+"\n")
	return f
}

func (f fixture) discover(t *testing.T, opts Options) *Map {
	t.Helper()
	if opts.Home == "" {
		opts.Home = f.home
	}
	if opts.Root == "" {
		opts.Root = f.root
	}
	m, err := Discover(opts)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	return m
}

func only(t *testing.T, m *Map, name string) *Profile {
	t.Helper()
	ps := m.ProfilesNamed(name)
	if len(ps) != 1 {
		t.Fatalf("profiles named %s = %d, want 1", name, len(ps))
	}
	return ps[0]
}

func describe(ls []Launcher) string {
	var parts []string
	for _, l := range ls {
		s := string(l.Kind) + ":" + filepath.Base(l.File)
		if l.Detail != "" {
			s += "[" + l.Detail + "]"
		}
		if l.Layer > 0 {
			s += fmt.Sprintf("@%d", l.Layer)
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, " ")
}

func TestDiscoverEveryLauncherKind(t *testing.T) {
	f := newFixture(t)
	m := f.discover(t, Options{})
	if len(m.Errors) != 0 {
		t.Fatalf("errors: %v", m.Errors)
	}
	if !m.Coverage.Walked || !m.Coverage.Complete() || m.Coverage.Root != f.home {
		t.Errorf("coverage = %+v, want a complete walk of home", m.Coverage)
	}

	for name, want := range map[string]string{
		// The outer layer and, just as much, the inner one.
		"mcp-okta-mcp-server": "mcp:.mcp.json[okta-mcp-server]",
		"mcp-okta":            "mcp:.mcp.json[okta-mcp-server]@1",
		"mcp-urlscan":         "mcp:.mcp.json[urlscan]",
		"vscode-server":       "mcp:mcp.json[vs]",
		"windsurf-server":     "mcp:mcp_config.json[ws]",
		"aws-prod":            "aws:config[[profile prod]]",
		"k8s-docker-desktop":  "kube:config[user docker-desktop]",
		"wrap-gh":             "wrap:wrap.json[gh]",
		"zshrc":               "shell_rc:.zshrc[line 2]",
		"docker-ghcr.io":      "helper:docker-credential-jit[docker]",
		"custom_scripts-wiz":  "project_store:Security-Ops",
		"security-ops":        "mount:mounts.yaml[" + filepath.Join(f.project, ".env") + "] project_store:Security-Ops",
		// Only launched from the Trash, which launches nothing.
		"token": "",
	} {
		if got := describe(only(t, m, name).Launchers); got != want {
			t.Errorf("%s launchers = %q, want %q", name, got, want)
		}
	}

	var broken []string
	for _, l := range m.Broken {
		broken = append(broken, string(l.Kind)+":"+l.Profile)
	}
	sort.Strings(broken)
	if strings.Join(broken, ",") != "aws:aws-dev,mcp:mcp-ghost" {
		t.Errorf("broken = %v, want the aws-dev section and the ghost server", broken)
	}

	var pointers []string
	for _, l := range m.Pointers {
		pointers = append(pointers, filepath.Base(l.File)+"->"+l.VaultPath)
	}
	if strings.Join(pointers, ",") != ".env.bak->security-ops/API,.clisso.yaml->wrap-clisso/acme-client-secret" {
		t.Errorf("pointers = %v", pointers)
	}
	if m.PointersChecked || len(m.MissingPointers) != 0 {
		t.Errorf("pointer targets are only checked when SecretExists is given")
	}

	okta := only(t, m, "mcp-okta")
	if len(okta.Owners) != 2 || len(okta.LiveOwners) != 1 || okta.LiveOwners[0] != filepath.Join(f.project, ".mcp.json") {
		t.Errorf("mcp-okta owners = %v, live = %v, want the gone owner filtered", okta.Owners, okta.LiveOwners)
	}
	if okta.Values["KEY"] != "mcp-okta/KEY" {
		t.Errorf("mcp-okta values = %v", okta.Values)
	}
	if got := only(t, m, "security-ops"); got.Scope != "project" || got.Project != f.project || len(got.Mounts) != 1 {
		t.Errorf("security-ops = %+v", got)
	}
	if len(m.MCPEntries) != 5 {
		t.Errorf("MCP entries = %d, want 5 (3 project, VS Code, Windsurf; none from the Trash)", len(m.MCPEntries))
	}
}

func TestDiscoverMissingPointerTarget(t *testing.T) {
	f := newFixture(t)
	stored := map[string]bool{"security-ops/API": true}
	m := f.discover(t, Options{SecretExists: func(p string) (bool, error) { return stored[p], nil }})
	if !m.PointersChecked || len(m.MissingPointers) != 1 ||
		m.MissingPointers[0].VaultPath != "wrap-clisso/acme-client-secret" ||
		m.MissingPointers[0].File != migrate.ClissoConfigPath(f.home) {
		t.Errorf("missing pointers = %+v, want only clisso's", m.MissingPointers)
	}
}

// A launcher names a profile the way `jit run` resolves one: a project
// profile only takes launchers inside its own project.
func TestDiscoverProjectResolution(t *testing.T) {
	f := newFixture(t)
	other := filepath.Join(f.home, "elsewhere")
	manifest(t, other, "custom_scripts-wiz", "WIZ: elsewhere/WIZ\n")
	write(t, filepath.Join(other, ".mcp.json"), `{"mcpServers":{"wiz":{"command":"/opt/homebrew/bin/jit","args":`+wrapperArgs([]string{"custom_scripts-wiz"}, "wiz")+`}}}`)
	m := f.discover(t, Options{})
	for _, p := range m.ProfilesNamed("custom_scripts-wiz") {
		mcp := p.LaunchersOf(KindMCP)
		switch p.Project {
		case other:
			if len(mcp) != 1 {
				t.Errorf("elsewhere's profile MCP launchers = %v, want its own config", mcp)
			}
		case f.project:
			if len(mcp) != 0 {
				t.Errorf("Security-Ops' profile took a launcher from another project: %v", mcp)
			}
		}
	}
}

// cwd's own store is read too, and one profile reached twice (cwd and the
// walk) is one entry.
func TestDiscoverCwdStoreDeduped(t *testing.T) {
	f := newFixture(t)
	m := f.discover(t, Options{Cwd: f.project})
	if n := len(m.ProfilesNamed("custom_scripts-wiz")); n != 1 {
		t.Errorf("custom_scripts-wiz entries = %d, want 1", n)
	}
	outside := t.TempDir()
	manifest(t, outside, "local", "K: local/K\n")
	m = f.discover(t, Options{Cwd: outside})
	if p := only(t, m, "local"); p.Scope != "project" || p.Project != outside {
		t.Errorf("cwd profile outside home = %+v", p)
	}
}

func TestDiscoverStrictFailsOnUnreadableSource(t *testing.T) {
	f := newFixture(t)
	bad := filepath.Join(f.home, ".jit", "profiles", "token.yaml")
	if err := os.Chmod(bad, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(bad, 0o600) })

	m := f.discover(t, Options{})
	if err := m.Err(SourceProfiles); err == nil || !strings.Contains(err.Error(), "loading profile "+bad) {
		t.Errorf("lenient: profiles error = %v, want the unreadable manifest", err)
	}
	if m.Err(SourceMCP) != nil {
		t.Errorf("an unrelated source must not report it: %v", m.Err(SourceMCP))
	}
	if m, err := Discover(Options{Home: f.home, Root: f.root, Strict: true}); err == nil || m != nil {
		t.Errorf("strict = (%v, %v), want an error and no map", m, err)
	}

	// A malformed MCP config is a source error too, strict or not.
	_ = os.Chmod(bad, 0o600)
	write(t, filepath.Join(f.project, "broken", "mcp.json"), "{not json")
	m = f.discover(t, Options{})
	if err := m.Err(SourceMCP); err == nil || !strings.Contains(err.Error(), filepath.Join(f.project, "broken", "mcp.json")) {
		t.Errorf("malformed MCP config error = %v", err)
	}
	if _, err := Discover(Options{Home: f.home, Root: f.root, Strict: true}); err == nil {
		t.Error("strict discovery must fail on a malformed MCP config")
	}
}

func TestDiscoverRecordsUnreadableDirectories(t *testing.T) {
	f := newFixture(t)
	locked := filepath.Join(f.home, "Private")
	write(t, filepath.Join(locked, "x.txt"), "x")
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	m := f.discover(t, Options{})
	if !m.Coverage.Walked || m.Coverage.Complete() || len(m.Coverage.Unreadable) != 1 || m.Coverage.Unreadable[0] != locked {
		t.Errorf("coverage = %+v, want %s recorded and the walk incomplete", m.Coverage, locked)
	}
	if len(m.Errors) != 0 {
		t.Errorf("an unenterable directory is coverage, not a source error: %v", m.Errors)
	}
}

// Discovery starts at home and never at the filesystem root, whatever
// home claims to be.
func TestDiscoverNeverWalksRoot(t *testing.T) {
	for _, home := range []string{"/", "", "relative/home", "//"} {
		if m, err := Discover(Options{Home: home}); err == nil || m != nil {
			t.Errorf("Discover(Home: %q) = (%v, %v), want a refusal", home, m, err)
		}
	}
	// And a cwd of / moves nothing: the walk is still home's.
	f := newFixture(t)
	m := f.discover(t, Options{Cwd: "/"})
	if m.Coverage.Root != f.home {
		t.Errorf("walk root = %s, want home", m.Coverage.Root)
	}
}

func TestFixedMCPConfigPathsIncludeEditors(t *testing.T) {
	home := t.TempDir()
	write(t, filepath.Join(home, "Library", "Application Support", "Code", "User", "profiles", "abc", "mcp.json"), "{}")
	got := strings.Join(FixedMCPConfigPaths(home), "\n")
	for _, want := range []string{
		filepath.Join(home, ".claude.json"),
		filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
		filepath.Join(home, "Library", "Application Support", "Code", "User", "mcp.json"),
		filepath.Join(home, "Library", "Application Support", "Code", "User", "profiles", "abc", "mcp.json"),
		filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"),
	} {
		if !strings.Contains(got, want) {
			t.Errorf("fixed MCP paths miss %s:\n%s", want, got)
		}
	}
}
