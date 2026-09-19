// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/vault"
)

// migrateThenDelete migrates a config and then deletes it, leaving behind
// exactly what a config that has since been removed leaves: profiles and
// secrets whose .source sidecar names a file that no longer exists.
func migrateThenDelete(t *testing.T, v *vault.Vault, path, content string) {
	t.Helper()
	writeFile(t, path, content)
	if _, err := ApplyMCPConfig(v, path); err != nil {
		t.Fatalf("ApplyMCPConfig(%s): %v", path, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("removing %s: %v", path, err)
	}
}

func assertSecret(t *testing.T, v *vault.Vault, path, want string) {
	t.Helper()
	got, err := v.Get(path)
	if err != nil || string(got) != want {
		t.Errorf("%s = (%q, %v), want (%q, nil)", path, got, err, want)
	}
}

func assertOwners(t *testing.T, home, profileName string, want ...string) {
	t.Helper()
	manifest, _ := mcpProfilePaths(t, home, profileName)
	if got := ProfileOwners(manifest); !reflect.DeepEqual(got, want) {
		t.Errorf("owners of %s = %q, want %q", profileName, got, want)
	}
}

func assertNoProfile(t *testing.T, home, profileName, why string) {
	t.Helper()
	manifest, _ := mcpProfilePaths(t, home, profileName)
	assertAbsent(t, manifest, why)
}

// TestApplyMCPConfigAdoptsNestedProfilesOfAGoneConfig is the field shape from
// design/doctor-repair.md ("What re-migrating would do today"):
// ~/Security-Ops/.mcp.json was copied from a config since deleted, its entries
// still nested by an old jit, and every profile they launch names the deleted
// config as its only owner. Re-migrating bumped each server past the
// originals to a -2 (and on the next run a -3) copy. Now each entry collapses
// onto the outer profile it already launches, which becomes the copy's own,
// and the inner layer's variables are carried in.
func TestApplyMCPConfigAdoptsNestedProfilesOfAGoneConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	v := newTestVault(t)

	gone := filepath.Join(home, "Documents", "ai_security_workspace", ".mcp.json")
	migrateThenDelete(t, v, gone, `{"mcpServers":{
		"okta":{"command":"okta-server","env":{"OKTA_PRIVATE_KEY":"pk-inner","OKTA_ORG_URL":"url-inner"}},
		"okta-mcp-server":{"command":"okta-server","env":{"OKTA_ORG_URL":"url-outer","OKTA_SCOPES":"scopes"}},
		"caido":{"command":"caido-server","env":{"CAIDO_KEY":"caido-inner"}},
		"caido-mcp":{"command":"caido-server","env":{"CAIDO_URL":"caido-url"}}}}`)

	copied := filepath.Join(home, "Security-Ops", ".mcp.json")
	writeFile(t, copied, `{"mcpServers":{
		"okta-mcp-server":{"command":"/opt/homebrew/bin/jit",
			"args":["run","--profile","mcp-okta-mcp-server","--",
			        "/usr/local/bin/jit","run","--profile","mcp-okta","--","okta-server"]},
		"caido":{"command":"/opt/homebrew/bin/jit",
			"args":["run","--profile","mcp-caido-mcp","--",
			        "/usr/local/bin/jit","run","--profile","mcp-caido","--","caido-server","serve"]}}}`)

	result, err := ApplyMCPConfig(v, copied)
	if err != nil {
		t.Fatalf("ApplyMCPConfig(copied): %v", err)
	}
	landed := map[string]MCPServerMigration{}
	for _, sm := range result.Servers {
		landed[sm.ServerName] = sm
	}
	for server, want := range map[string][]string{
		"okta-mcp-server": {"mcp-okta-mcp-server", "mcp-okta"},
		"caido":           {"mcp-caido-mcp", "mcp-caido"},
	} {
		sm, ok := landed[server]
		if !ok {
			t.Fatalf("server %q not migrated: %+v", server, result.Servers)
		}
		if sm.ProfileName != want[0] || sm.NamespaceMovedFrom != "" {
			t.Errorf("%s: (ProfileName, NamespaceMovedFrom) = (%q, %q), want (%q, \"\"): a gone owner's profile is adopted, not bumped past",
				server, sm.ProfileName, sm.NamespaceMovedFrom, want[0])
		}
		if !reflect.DeepEqual(sm.RewrappedFrom, want) {
			t.Errorf("%s: RewrappedFrom = %v, want %v", server, sm.RewrappedFrom, want)
		}
		command, args := readServerEntry(t, copied, server)
		if n := countWrapperLayers(command, args); n != 1 || args[2] != want[0] {
			t.Errorf("%s: launch line %q %v, want ONE wrapper naming %s", server, command, args, want[0])
		}
		for _, suffix := range []string{"-2", "-3"} {
			assertNoProfile(t, home, want[0]+suffix, "adoption must not leave a bumped copy")
		}
		assertOwners(t, home, want[0], copied)
		// The inner profile is left for the orphan path: untouched, still
		// naming the gone config.
		assertOwners(t, home, want[1], gone)
	}

	// Outermost wins a shared name; the inner layer's other variables are
	// carried in, so the collapsed launch line drops nothing.
	assertSecret(t, v, "mcp-okta-mcp-server/OKTA_ORG_URL", "url-outer")
	assertSecret(t, v, "mcp-okta-mcp-server/OKTA_SCOPES", "scopes")
	assertSecret(t, v, "mcp-okta-mcp-server/OKTA_PRIVATE_KEY", "pk-inner")
	assertSecret(t, v, "mcp-caido-mcp/CAIDO_URL", "caido-url")
	assertSecret(t, v, "mcp-caido-mcp/CAIDO_KEY", "caido-inner")
	// Inner profiles are read, never written.
	assertSecret(t, v, "mcp-okta/OKTA_ORG_URL", "url-inner")
	assertSecret(t, v, "mcp-caido/CAIDO_KEY", "caido-inner")
}

// A gone owner alone is not enough to adopt: the entry must launch the
// profile. A plain entry that merely derives the same name, with a different
// value, is a different server and bumps as it always did.
func TestApplyMCPConfigGoneOwnerNotLaunchedStillBumps(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	v := newTestVault(t)

	gone := filepath.Join(home, "old", ".mcp.json")
	migrateThenDelete(t, v, gone, `{"mcpServers":{"github":{"command":"npx","env":{"GITHUB_TOKEN":"tok-old"}}}}`)

	fresh := filepath.Join(home, "new", ".mcp.json")
	writeFile(t, fresh, `{"mcpServers":{"github":{"command":"npx","env":{"GITHUB_TOKEN":"tok-new"}}}}`)
	result, err := ApplyMCPConfig(v, fresh)
	if err != nil {
		t.Fatalf("ApplyMCPConfig: %v", err)
	}
	if sm := result.Servers[0]; sm.ProfileName != "mcp-github-2" || sm.NamespaceMovedFrom != "mcp-github" {
		t.Errorf("(ProfileName, NamespaceMovedFrom) = (%q, %q), want (mcp-github-2, mcp-github)", sm.ProfileName, sm.NamespaceMovedFrom)
	}
	assertSecret(t, v, "mcp-github/GITHUB_TOKEN", "tok-old")
	assertOwners(t, home, "mcp-github", gone)
}

// One profile, several configs, when the values are the same: the second
// config is added to the owner list instead of getting a copy, so a rotation
// happens once. Values that differ, or a variable the profile doesn't hold,
// are a different server and bump without touching the first.
func TestApplyMCPConfigLiveOwnerSharesOnlyIdenticalValues(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	v := newTestVault(t)

	first := filepath.Join(home, "projA", ".mcp.json")
	writeFile(t, first, `{"mcpServers":{"github":{"command":"npx","env":{"GITHUB_TOKEN":"tok"}}}}`)
	if _, err := ApplyMCPConfig(v, first); err != nil {
		t.Fatalf("ApplyMCPConfig(first): %v", err)
	}

	same := filepath.Join(home, "projB", ".mcp.json")
	writeFile(t, same, `{"mcpServers":{"github":{"command":"npx","env":{"GITHUB_TOKEN":"tok"}}}}`)
	result, err := ApplyMCPConfig(v, same)
	if err != nil {
		t.Fatalf("ApplyMCPConfig(same): %v", err)
	}
	if sm := result.Servers[0]; sm.ProfileName != "mcp-github" || sm.NamespaceMovedFrom != "" {
		t.Errorf("identical values: (ProfileName, NamespaceMovedFrom) = (%q, %q), want (mcp-github, \"\")", sm.ProfileName, sm.NamespaceMovedFrom)
	}
	assertOwners(t, home, "mcp-github", first, same)
	assertNoProfile(t, home, "mcp-github-2", "identical values share one profile")

	for _, tc := range []struct {
		name, dir, config string
	}{
		{"different value", "projC", `{"mcpServers":{"github":{"command":"npx","env":{"GITHUB_TOKEN":"other"}}}}`},
		{"extra variable", "projD", `{"mcpServers":{"github":{"command":"npx","env":{"GITHUB_TOKEN":"tok","GITHUB_HOST":"ghe"}}}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(home, tc.dir, ".mcp.json")
			writeFile(t, path, tc.config)
			res, err := ApplyMCPConfig(v, path)
			if err != nil {
				t.Fatalf("ApplyMCPConfig: %v", err)
			}
			if sm := res.Servers[0]; sm.ProfileName == "mcp-github" {
				t.Errorf("ProfileName = %q: a different server must never land on the shared profile", sm.ProfileName)
			}
			assertSecret(t, v, "mcp-github/GITHUB_TOKEN", "tok")
			assertOwners(t, home, "mcp-github", first, same)
		})
	}
}

// A different server in another live config whose name only SANITIZES to the
// same profile name, with its own value, gets its own profile.
func TestApplyMCPConfigSameSanitizedNameDifferentServerBumps(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	v := newTestVault(t)

	first := filepath.Join(home, "projA", ".mcp.json")
	writeFile(t, first, `{"mcpServers":{"my-server":{"command":"a-server","env":{"TOKEN":"tok-a"}}}}`)
	if _, err := ApplyMCPConfig(v, first); err != nil {
		t.Fatalf("ApplyMCPConfig(first): %v", err)
	}
	other := filepath.Join(home, "projB", ".mcp.json")
	writeFile(t, other, `{"mcpServers":{"my server":{"command":"b-server","env":{"TOKEN":"tok-b"}}}}`)
	result, err := ApplyMCPConfig(v, other)
	if err != nil {
		t.Fatalf("ApplyMCPConfig(other): %v", err)
	}
	if sm := result.Servers[0]; sm.ProfileName != "mcp-my-server-2" || sm.NamespaceMovedFrom != "mcp-my-server" {
		t.Errorf("(ProfileName, NamespaceMovedFrom) = (%q, %q), want (mcp-my-server-2, mcp-my-server)", sm.ProfileName, sm.NamespaceMovedFrom)
	}
	assertSecret(t, v, "mcp-my-server/TOKEN", "tok-a")
	assertOwners(t, home, "mcp-my-server", first)
}

// The same rule for a server that launches the live owner's profile itself: a
// config copied from a LIVE one carries its wrapper, and a differing value
// added back to it still bumps. Adoption needs every owner gone.
func TestApplyMCPConfigLaunchedLiveOwnerProfileBumpsOnDifferentValues(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	v := newTestVault(t)

	first := filepath.Join(home, "projA", ".mcp.json")
	writeFile(t, first, `{"mcpServers":{"caido":{"command":"caido-server","env":{"CAIDO_KEY":"key-a"}}}}`)
	if _, err := ApplyMCPConfig(v, first); err != nil {
		t.Fatalf("ApplyMCPConfig(first): %v", err)
	}

	copied := filepath.Join(home, "projB", ".mcp.json")
	writeFile(t, copied, `{"mcpServers":{"caido":{"command":"/usr/local/bin/jit",
		"args":["run","--profile","mcp-caido","--","caido-server"],
		"env":{"CAIDO_KEY":"key-b"}}}}`)
	result, err := ApplyMCPConfig(v, copied)
	if err != nil {
		t.Fatalf("ApplyMCPConfig(copied): %v", err)
	}
	if sm := result.Servers[0]; sm.ProfileName != "mcp-caido-2" || sm.NamespaceMovedFrom != "mcp-caido" {
		t.Errorf("(ProfileName, NamespaceMovedFrom) = (%q, %q), want (mcp-caido-2, mcp-caido)", sm.ProfileName, sm.NamespaceMovedFrom)
	}
	assertSecret(t, v, "mcp-caido/CAIDO_KEY", "key-a")
	assertOwners(t, home, "mcp-caido", first)
}

// Sharing must not smuggle a write in through the carry: a nested entry
// landing on a profile a live config owns would add the inner layer's
// variables to that config's server. Such an entry bumps, and the live
// owner's profile is left exactly as it was.
func TestApplyMCPConfigShareNeverCarriesIntoALiveOwnersProfile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	v := newTestVault(t)

	first := filepath.Join(home, "projA", ".mcp.json")
	writeFile(t, first, `{"mcpServers":{
		"okta":{"command":"okta-server","env":{"OKTA_PRIVATE_KEY":"pk"}},
		"okta-mcp-server":{"command":"okta-server","env":{"OKTA_ORG_URL":"url"}}}}`)
	if _, err := ApplyMCPConfig(v, first); err != nil {
		t.Fatalf("ApplyMCPConfig(first): %v", err)
	}
	outer, _ := mcpProfilePaths(t, home, "mcp-okta-mcp-server")
	before := string(readBytes(t, outer))

	copied := filepath.Join(home, "projB", ".mcp.json")
	writeFile(t, copied, `{"mcpServers":{"okta-mcp-server":{"command":"/usr/local/bin/jit",
		"args":["run","--profile","mcp-okta-mcp-server","--",
		        "/usr/local/bin/jit","run","--profile","mcp-okta","--","okta-server"]}}}`)
	result, err := ApplyMCPConfig(v, copied)
	if err != nil {
		t.Fatalf("ApplyMCPConfig(copied): %v", err)
	}
	if sm := result.Servers[0]; sm.ProfileName != "mcp-okta-mcp-server-2" {
		t.Errorf("ProfileName = %q, want mcp-okta-mcp-server-2", sm.ProfileName)
	}
	if after := string(readBytes(t, outer)); after != before {
		t.Errorf("the live owner's manifest changed:\nbefore %q\nafter  %q", before, after)
	}
	assertOwners(t, home, "mcp-okta-mcp-server", first)
	assertSecret(t, v, "mcp-okta-mcp-server-2/OKTA_PRIVATE_KEY", "pk")
	assertSecret(t, v, "mcp-okta-mcp-server-2/OKTA_ORG_URL", "url")
}

// A profile migrated before the .source sidecar existed, launched by this
// entry's own wrapper. A secret the manifest maps but the vault no longer
// holds (a `jit vault rm` of a wrapped profile's secret, then the value typed
// back into the config) is a hole, not someone else's value: adopt and fill
// it. A value that exists and differs still bumps, because without a sidecar
// nothing rules out a second config launching the same profile. A plain entry
// that only derives the name keeps the legacy rule and bumps on the hole.
func TestApplyMCPConfigLegacyProfileLaunchedByEntry(t *testing.T) {
	legacy := func(t *testing.T) (home string, v *vault.Vault) {
		t.Helper()
		home = t.TempDir()
		t.Setenv("HOME", home)
		v = newTestVault(t)
		manifest, sidecar := mcpProfilePaths(t, home, "mcp-okta")
		writeFile(t, manifest, "OKTA_ORG_URL: mcp-okta/OKTA_ORG_URL\nOKTA_SCOPES: mcp-okta/OKTA_SCOPES\n")
		if err := v.Set("mcp-okta/OKTA_SCOPES", []byte("scopes")); err != nil {
			t.Fatal(err)
		}
		assertAbsent(t, sidecar, "fixture: a legacy profile has no sidecar")
		return home, v
	}
	wrapped := func(value string) string {
		return `{"mcpServers":{"okta":{"command":"/usr/local/bin/jit",
			"args":["run","--profile","mcp-okta","--","okta-server"],
			"env":{"OKTA_ORG_URL":"` + value + `"}}}}`
	}

	t.Run("missing secret, launched: adopted", func(t *testing.T) {
		home, v := legacy(t)
		path := filepath.Join(home, "Security-Ops", ".mcp.json")
		writeFile(t, path, wrapped("url"))
		result, err := ApplyMCPConfig(v, path)
		if err != nil {
			t.Fatalf("ApplyMCPConfig: %v", err)
		}
		if sm := result.Servers[0]; sm.ProfileName != "mcp-okta" || sm.NamespaceMovedFrom != "" {
			t.Errorf("(ProfileName, NamespaceMovedFrom) = (%q, %q), want (mcp-okta, \"\")", sm.ProfileName, sm.NamespaceMovedFrom)
		}
		assertSecret(t, v, "mcp-okta/OKTA_ORG_URL", "url")
		assertSecret(t, v, "mcp-okta/OKTA_SCOPES", "scopes")
		assertOwners(t, home, "mcp-okta", path)
		assertNoProfile(t, home, "mcp-okta-2", "the launched legacy profile is adopted")
	})

	t.Run("different value, launched: bumps", func(t *testing.T) {
		home, v := legacy(t)
		if err := v.Set("mcp-okta/OKTA_ORG_URL", []byte("url-other")); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(home, "Security-Ops", ".mcp.json")
		writeFile(t, path, wrapped("url"))
		result, err := ApplyMCPConfig(v, path)
		if err != nil {
			t.Fatalf("ApplyMCPConfig: %v", err)
		}
		if sm := result.Servers[0]; sm.ProfileName != "mcp-okta-2" {
			t.Errorf("ProfileName = %q, want mcp-okta-2", sm.ProfileName)
		}
		assertSecret(t, v, "mcp-okta/OKTA_ORG_URL", "url-other")
	})

	t.Run("missing secret, not launched: bumps", func(t *testing.T) {
		home, v := legacy(t)
		path := filepath.Join(home, "Security-Ops", ".mcp.json")
		writeFile(t, path, `{"mcpServers":{"okta":{"command":"okta-server","env":{"OKTA_ORG_URL":"url"}}}}`)
		result, err := ApplyMCPConfig(v, path)
		if err != nil {
			t.Fatalf("ApplyMCPConfig: %v", err)
		}
		if sm := result.Servers[0]; sm.ProfileName != "mcp-okta-2" {
			t.Errorf("ProfileName = %q, want mcp-okta-2", sm.ProfileName)
		}
		_, sidecar := mcpProfilePaths(t, home, "mcp-okta")
		assertAbsent(t, sidecar, "a bumped-past legacy profile stays unstamped")
		if data, err := os.ReadFile(path); err != nil || !strings.Contains(string(data), "mcp-okta-2") {
			t.Errorf("config must launch mcp-okta-2: %s (%v)", data, err)
		}
	})
}
