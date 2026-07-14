// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/profile"
)

func TestEnvLayerRank(t *testing.T) {
	cases := []struct {
		file, mode string
		rank       int
		ok         bool
	}{
		{".env", "", 0, true},
		{".env.local", "", 2, true},
		{".env.development", "", 0, false},           // mode layer excluded without --mode
		{".env", "development", 0, true},
		{".env.development", "development", 1, true},
		{".env.local", "development", 2, true},
		{".env.development.local", "development", 3, true},
		{".env.production", "development", 0, false}, // other modes never ride along
		{".env.production.local", "development", 0, false},
		{".env.bak", "", 0, false},      // backups are never mounted anyway, but rank must not admit them
		{".env.pointers", "", 0, false}, // jit artifact
		{"config.env", "", 0, false},    // not .env-family at all
	}
	for _, c := range cases {
		rank, ok := envLayerRank(c.file, c.mode)
		if ok != c.ok || (ok && rank != c.rank) {
			t.Errorf("envLayerRank(%q, mode=%q) = (%d, %v), want (%d, %v)", c.file, c.mode, rank, ok, c.rank, c.ok)
		}
	}
}

func TestValidateEnvMode(t *testing.T) {
	if err := validateEnvMode(""); err != nil {
		t.Errorf("empty mode should be valid (means: no mode): %v", err)
	}
	if err := validateEnvMode("production"); err != nil {
		t.Errorf("plain mode should be valid: %v", err)
	}
	for _, bad := range []string{"local", "a/b", `a\b`, ".."} {
		if err := validateEnvMode(bad); err == nil {
			t.Errorf("validateEnvMode(%q) should be rejected", bad)
		}
	}
}

func TestDirEnvLayersOrdersAndFilters(t *testing.T) {
	entries := []mount.Entry{
		{MountPath: "/p/app/.env.local", ProfilePath: "/p/app/.jit/profiles/root-local.yaml"},
		{MountPath: "/p/app/.env", ProfilePath: "/p/app/.jit/profiles/root.yaml"},
		{MountPath: "/p/app/.npmrc", ProfilePath: "/p/app/.jit/profiles/npmrc.yaml", TemplatePath: "/t/npmrc.tmpl"}, // template mount: excluded
		{MountPath: "/p/other/.env", ProfilePath: "/p/other/.jit/profiles/root.yaml"},                              // other dir: excluded
		{MountPath: "/p/app/.env.production", ProfilePath: "/p/app/.jit/profiles/root-production.yaml"},            // mode layer, no mode: excluded
	}

	layers := dirEnvLayers(entries, "/p/app", "")
	if len(layers) != 2 {
		t.Fatalf("dirEnvLayers = %+v, want exactly .env and .env.local", layers)
	}
	if layers[0].fileName != ".env" || layers[1].fileName != ".env.local" {
		t.Errorf("layer order = [%s, %s], want [.env, .env.local] (ascending precedence)", layers[0].fileName, layers[1].fileName)
	}
	if layers[0].profileName != "root" || layers[1].profileName != "root-local" {
		t.Errorf("profile names = [%s, %s], want [root, root-local]", layers[0].profileName, layers[1].profileName)
	}

	withMode := dirEnvLayers(entries, "/p/app", "production")
	if len(withMode) != 3 || withMode[1].fileName != ".env.production" {
		t.Errorf("with mode: layers = %+v, want .env < .env.production < .env.local", withMode)
	}
}

func TestFindEnvLayersWalksUpAndStopsAtHome(t *testing.T) {
	entries := []mount.Entry{
		{MountPath: "/home/u/code/app/.env", ProfilePath: "/home/u/code/app/.jit/profiles/root.yaml"},
		{MountPath: "/home/u/.env", ProfilePath: "/home/u/.jit/profiles/root.yaml"},
	}

	// From a nested subdirectory: finds the nearest ancestor with layers.
	dir, layers := findEnvLayers(entries, "/home/u/code/app/services/api", "/home/u", "")
	if dir != "/home/u/code/app" || len(layers) != 1 {
		t.Errorf("walk-up: dir=%q layers=%d, want /home/u/code/app with 1 layer", dir, len(layers))
	}

	// $HOME itself is checked (a migrated ~/.env), then the walk stops.
	dir, layers = findEnvLayers(entries, "/home/u/unrelated", "/home/u", "")
	if dir != "/home/u" || len(layers) != 1 {
		t.Errorf("home fallthrough: dir=%q layers=%d, want /home/u with 1 layer", dir, len(layers))
	}

	// Never scans ABOVE $HOME: an entry at /home is invisible from within.
	above := []mount.Entry{{MountPath: "/home/.env", ProfilePath: "/home/.jit/profiles/root.yaml"}}
	if dir, layers := findEnvLayers(above, "/home/u/code", "/home/u", ""); len(layers) != 0 {
		t.Errorf("scanned above home: found %d layer(s) in %q", len(layers), dir)
	}

	// A cwd outside $HOME entirely stops at the filesystem root, no hang.
	if _, layers := findEnvLayers(entries, "/tmp/elsewhere", "/home/u", ""); len(layers) != 0 {
		t.Errorf("outside-home walk found %d layer(s), want none", len(layers))
	}
}

// writeLayerFixture builds a real project + registry under a fixture $HOME:
// a project dir with per-layer profile manifests, and a mounts.yaml
// registering each given .env-family filename. Returns the project dir.
func writeLayerFixture(t *testing.T, home string, layerFiles map[string]string) string {
	t.Helper()
	proj := filepath.Join(home, "code", "app")
	root, err := vaultRootDir()
	if err != nil {
		t.Fatalf("vaultRootDir: %v", err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	for file, manifest := range layerFiles {
		name := strings.TrimPrefix(strings.TrimPrefix(file, ".env"), ".")
		if name == "" {
			name = "root"
		} else {
			name = "root-" + strings.ReplaceAll(name, ".", "-")
		}
		writeFixtureProfile(t, proj, name, manifest)
		profilePath, err := profile.Path(proj, name)
		if err != nil {
			t.Fatalf("profile.Path: %v", err)
		}
		if err := mount.AddMount(mount.RegistryPath(root), mount.Entry{
			MountPath:   filepath.Join(proj, file),
			ProfilePath: profilePath,
		}); err != nil {
			t.Fatalf("AddMount: %v", err)
		}
	}
	return proj
}

func TestResolveInjectionProfileMergesLayers(t *testing.T) {
	home := withFixtureHome(t)
	proj := writeLayerFixture(t, home, map[string]string{
		".env":       "API_KEY: root/API_KEY\nDB_URL: root/DB_URL\n",
		".env.local": "API_KEY: root-local/API_KEY\n",
	})

	var buf bytes.Buffer
	p, err := resolveInjectionProfile("jit run", proj, "", "", &buf)
	if err != nil {
		t.Fatalf("resolveInjectionProfile: %v", err)
	}
	if p["API_KEY"] != "root-local/API_KEY" {
		t.Errorf("API_KEY = %q, want root-local/API_KEY (.env.local wins)", p["API_KEY"])
	}
	if p["DB_URL"] != "root/DB_URL" {
		t.Errorf("DB_URL = %q, want root/DB_URL (base survives)", p["DB_URL"])
	}
	out := buf.String()
	if !strings.Contains(out, "merging .env, .env.local") || !strings.Contains(out, "root, root-local") {
		t.Errorf("announce should name layers and profiles, got: %q", out)
	}
}

func TestResolveInjectionProfileWalksUpFromSubdir(t *testing.T) {
	home := withFixtureHome(t)
	proj := writeLayerFixture(t, home, map[string]string{
		".env": "API_KEY: root/API_KEY\n",
	})
	sub := filepath.Join(proj, "services", "api")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	var buf bytes.Buffer
	p, err := resolveInjectionProfile("jit run", sub, "", "", &buf)
	if err != nil {
		t.Fatalf("resolveInjectionProfile from subdir: %v", err)
	}
	if p["API_KEY"] != "root/API_KEY" {
		t.Errorf("API_KEY = %q, want root/API_KEY", p["API_KEY"])
	}
	if !strings.Contains(buf.String(), "in ") {
		t.Errorf("announce should say which directory won after walking up, got: %q", buf.String())
	}
}

func TestResolveInjectionProfileModeLayers(t *testing.T) {
	home := withFixtureHome(t)
	proj := writeLayerFixture(t, home, map[string]string{
		".env":            "API_KEY: root/API_KEY\nDB_URL: root/DB_URL\n",
		".env.production": "DB_URL: root-production/DB_URL\n",
		".env.local":      "API_KEY: root-local/API_KEY\n",
	})

	// Without --mode: production must NOT ride along.
	var buf bytes.Buffer
	p, err := resolveInjectionProfile("jit run", proj, "", "", &buf)
	if err != nil {
		t.Fatalf("no mode: %v", err)
	}
	if p["DB_URL"] != "root/DB_URL" {
		t.Errorf("no mode: DB_URL = %q, want root/DB_URL (production never merged by default)", p["DB_URL"])
	}

	// With --mode production: layered in between .env and .env.local.
	buf.Reset()
	p, err = resolveInjectionProfile("jit run", proj, "", "production", &buf)
	if err != nil {
		t.Fatalf("mode production: %v", err)
	}
	if p["DB_URL"] != "root-production/DB_URL" {
		t.Errorf("mode: DB_URL = %q, want root-production/DB_URL", p["DB_URL"])
	}
	if p["API_KEY"] != "root-local/API_KEY" {
		t.Errorf("mode: API_KEY = %q, want root-local/API_KEY (.env.local still beats .env.<mode>)", p["API_KEY"])
	}

	// A mode with no matching layer is a hard error (typo protection).
	if _, err := resolveInjectionProfile("jit run", proj, "", "staging", &buf); err == nil {
		t.Error("mode with no matching layer should be a hard error")
	}
}

func TestResolveInjectionProfileExplicitProfile(t *testing.T) {
	home := withFixtureHome(t)
	proj := writeLayerFixture(t, home, map[string]string{
		".env":       "API_KEY: root/API_KEY\n",
		".env.local": "API_KEY: root-local/API_KEY\n",
	})

	// Explicit --profile: exactly that one layer, no merge, no announce.
	var buf bytes.Buffer
	p, err := resolveInjectionProfile("jit run", proj, "root", "", &buf)
	if err != nil {
		t.Fatalf("explicit: %v", err)
	}
	if p["API_KEY"] != "root/API_KEY" {
		t.Errorf("explicit root: API_KEY = %q, want root/API_KEY (no merge)", p["API_KEY"])
	}
	if buf.Len() != 0 {
		t.Errorf("explicit --profile should be silent, got: %q", buf.String())
	}

	// --profile + --mode is a hard error.
	if _, err := resolveInjectionProfile("jit run", proj, "root", "production", &buf); err == nil {
		t.Error("--profile with --mode should be a hard error")
	}
}

func TestResolveInjectionProfileFallsBackToSingleProjectProfile(t *testing.T) {
	home := withFixtureHome(t)
	// A profile exists but nothing is registered in the mount registry —
	// e.g. a backup-suffixed .env migration (pointer file, never mounted).
	proj := filepath.Join(home, "code", "app")
	writeFixtureProfile(t, proj, "root-bak", "API_KEY: root-bak/API_KEY\n")

	var buf bytes.Buffer
	p, err := resolveInjectionProfile("jit run", proj, "", "", &buf)
	if err != nil {
		t.Fatalf("fallback: %v", err)
	}
	if p["API_KEY"] != "root-bak/API_KEY" {
		t.Errorf("fallback: API_KEY = %q, want root-bak/API_KEY", p["API_KEY"])
	}
	if !strings.Contains(buf.String(), `using profile "root-bak"`) {
		t.Errorf("fallback should announce the auto-selected profile, got: %q", buf.String())
	}

	// Several profiles, no layers: still refuses to guess.
	writeFixtureProfile(t, proj, "other", "B: other/B\n")
	if _, err := resolveInjectionProfile("jit run", proj, "", "", &buf); err == nil {
		t.Error("several project profiles with no layers should be a hard error")
	}
}

func TestResolveInjectionProfileWarnsOnUnmigratedSibling(t *testing.T) {
	home := withFixtureHome(t)
	proj := writeLayerFixture(t, home, map[string]string{
		".env": "API_KEY: root/API_KEY\n",
	})
	// A plaintext .env.local sits on disk but was never migrated.
	if err := os.WriteFile(filepath.Join(proj, ".env.local"), []byte("API_KEY=plaintext\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var buf bytes.Buffer
	if _, err := resolveInjectionProfile("jit run", proj, "", "", &buf); err != nil {
		t.Fatalf("resolveInjectionProfile: %v", err)
	}
	if !strings.Contains(buf.String(), ".env.local") || !strings.Contains(buf.String(), "not migrated") {
		t.Errorf("expected an unmigrated-sibling heads-up naming .env.local, got: %q", buf.String())
	}
}
