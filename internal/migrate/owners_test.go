// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/profile"
)

func ownerFixture(t *testing.T) (home, manifest string) {
	t.Helper()
	home = t.TempDir()
	manifest, err := profile.Path(home, "mcp-okta")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, manifest, "OKTA_TOKEN: mcp-okta/OKTA_TOKEN\n")
	return home, manifest
}

// An owner list survives a write and a read unchanged, one owner per line,
// trimmed and deduplicated on the way in.
func TestProfileOwnersRoundTrip(t *testing.T) {
	home, manifest := ownerFixture(t)
	a := filepath.Join(home, "Security-Ops", ".mcp.json")
	b := filepath.Join(home, ".claude.json") + "#" + filepath.Join(home, "proj")
	if err := WriteProfileOwners(manifest, []string{a, " " + b + " ", a, ""}); err != nil {
		t.Fatalf("WriteProfileOwners: %v", err)
	}
	raw := string(readBytes(t, profileSourceSidecarPath(manifest)))
	if want := a + "\n" + b + "\n"; raw != want {
		t.Errorf("sidecar = %q, want %q", raw, want)
	}
	got := ProfileOwners(manifest)
	if strings.Join(got, "|") != a+"|"+b {
		t.Errorf("ProfileOwners = %q, want [%s %s]", got, a, b)
	}
	if first := ProfileOwnerConfig(manifest); first != a {
		t.Errorf("ProfileOwnerConfig = %q, want the first owner %q", first, a)
	}
	if OwnerFile(b) != filepath.Join(home, ".claude.json") {
		t.Errorf("OwnerFile(%q) = %q, want the scope stripped", b, OwnerFile(b))
	}
	info, err := os.Stat(profileSourceSidecarPath(manifest))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("sidecar mode = %v (%v), want 0600", info.Mode().Perm(), err)
	}

	// An empty list removes the sidecar: unstamped, never stamped-with-nobody.
	if err := WriteProfileOwners(manifest, nil); err != nil {
		t.Fatalf("WriteProfileOwners(nil): %v", err)
	}
	if _, err := os.Stat(profileSourceSidecarPath(manifest)); !os.IsNotExist(err) {
		t.Errorf("an empty owner list must remove the sidecar, stat err = %v", err)
	}
	if got, err := ReadProfileOwners(manifest); err != nil || got != nil {
		t.Errorf("ReadProfileOwners with no sidecar = (%q, %v), want (nil, nil)", got, err)
	}
}

// Every sidecar written before the owner list is one line, often with a
// block scope. It must read exactly as it always did.
func TestProfileOwnersSingleLineCompat(t *testing.T) {
	home, manifest := ownerFixture(t)
	cfg := filepath.Join(home, ".claude.json")
	scoped := cfg + "#" + filepath.Join(home, "proj")
	writeFile(t, profileSourceSidecarPath(manifest), scoped+"\n")
	if got := ProfileOwners(manifest); len(got) != 1 || got[0] != scoped {
		t.Errorf("ProfileOwners = %q, want [%s]", got, scoped)
	}
	if got := ProfileOwnerConfig(manifest); got != cfg {
		t.Errorf("ProfileOwnerConfig = %q, want %q", got, cfg)
	}
	// No trailing newline, as a hand edit might leave it.
	writeFile(t, profileSourceSidecarPath(manifest), cfg)
	if got := ProfileOwnerConfig(manifest); got != cfg {
		t.Errorf("ProfileOwnerConfig without a newline = %q, want %q", got, cfg)
	}
	// And a one-owner write is byte-identical to what claimMCPNamespace
	// always stamped.
	if err := WriteProfileOwners(manifest, []string{scoped}); err != nil {
		t.Fatal(err)
	}
	if raw := string(readBytes(t, profileSourceSidecarPath(manifest))); raw != scoped+"\n" {
		t.Errorf("one-owner sidecar = %q, want %q", raw, scoped+"\n")
	}
}

// An owner whose config file is gone launches nothing and must not count.
func TestLiveProfileOwnersDropsGoneOwners(t *testing.T) {
	home, manifest := ownerFixture(t)
	live := filepath.Join(home, "Security-Ops", ".mcp.json")
	writeFile(t, live, `{"mcpServers":{}}`)
	gone := filepath.Join(home, "Documents", "ai_security_workspace", ".mcp.json")
	liveScoped := filepath.Join(home, ".claude.json") + "#" + filepath.Join(home, "proj")
	writeFile(t, filepath.Join(home, ".claude.json"), `{}`)
	if err := WriteProfileOwners(manifest, []string{gone, live, liveScoped}); err != nil {
		t.Fatal(err)
	}
	got := LiveProfileOwners(manifest)
	if strings.Join(got, "|") != live+"|"+liveScoped {
		t.Errorf("LiveProfileOwners = %q, want [%s %s]", got, live, liveScoped)
	}
	if all := ProfileOwners(manifest); len(all) != 3 {
		t.Errorf("ProfileOwners must still list the gone owner, got %q", all)
	}
}

// claimMCPNamespace treats a multi-owner sidecar that NAMES this config as
// this config's own profile: a refresh in place, never a bump, and the other
// owners survive the refreshed stamp. A multi-owner sidecar that does not
// name it is still foreign, exactly like a one-line sidecar naming another
// file.
func TestClaimMCPNamespaceMultiOwnerSidecar(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	v := newTestVault(t)

	path := filepath.Join(home, "Security-Ops", ".mcp.json")
	original := `{"mcpServers":{"okta":{"command":"npx","env":{"OKTA_TOKEN":"t1"}}}}`
	writeFile(t, path, original)
	if _, err := ApplyMCPConfig(v, path); err != nil {
		t.Fatalf("first ApplyMCPConfig: %v", err)
	}
	manifest, sidecar := mcpProfilePaths(t, home, "mcp-okta")
	other := filepath.Join(home, "Documents", "copy", ".mcp.json")
	writeFile(t, sidecar, other+"\n"+path+"\n")

	// Re-migrate with a rotated value: this config co-owns mcp-okta.
	writeFile(t, path, strings.ReplaceAll(original, "t1", "t2"))
	res, err := ApplyMCPConfig(v, path)
	if err != nil {
		t.Fatalf("re-run ApplyMCPConfig: %v", err)
	}
	if sm := res.Servers[0]; sm.ProfileName != "mcp-okta" || sm.NamespaceMovedFrom != "" {
		t.Errorf("(ProfileName, NamespaceMovedFrom) = (%q, %q), want (mcp-okta, \"\"): an owner refreshes, never bumps", sm.ProfileName, sm.NamespaceMovedFrom)
	}
	if got, err := v.Get("mcp-okta/OKTA_TOKEN"); err != nil || string(got) != "t2" {
		t.Errorf("mcp-okta/OKTA_TOKEN = (%q, %v), want (t2, nil)", got, err)
	}
	if got := ProfileOwners(manifest); strings.Join(got, "|") != other+"|"+path {
		t.Errorf("owners after refresh = %q, want [%s %s]: a refresh keeps the other owners", got, other, path)
	}

	// A list naming only other configs is foreign: bump, touch nothing.
	third := filepath.Join(home, "third", ".mcp.json")
	writeFile(t, third, strings.ReplaceAll(original, "t1", "t3"))
	res, err = ApplyMCPConfig(v, third)
	if err != nil {
		t.Fatalf("third ApplyMCPConfig: %v", err)
	}
	if sm := res.Servers[0]; sm.ProfileName != "mcp-okta-2" {
		t.Errorf("third config ProfileName = %q, want mcp-okta-2", sm.ProfileName)
	}
	if got, err := v.Get("mcp-okta/OKTA_TOKEN"); err != nil || string(got) != "t2" {
		t.Errorf("mcp-okta/OKTA_TOKEN after a foreign run = (%q, %v), want (t2, nil)", got, err)
	}
	if got := ProfileOwners(manifest); strings.Join(got, "|") != other+"|"+path {
		t.Errorf("owners after a foreign run = %q, want them untouched", got)
	}
}

// The downgrade story in design/doctor-repair.md: a jit from before the
// owner list compares the whole sidecar as one string. A multi-owner
// sidecar therefore never equals its source and it bumps, which copies and
// never overwrites. Pinned here as the string compare it was.
func TestOlderStringCompareBumpsOnMultiOwnerSidecar(t *testing.T) {
	source := "/Users/x/Security-Ops/.mcp.json"
	sidecar := "/Users/x/copy/.mcp.json\n" + source + "\n"
	if strings.TrimSpace(sidecar) == source {
		t.Fatal("the pre-list compare would treat a multi-owner sidecar as its own; a downgrade would overwrite")
	}
	if !ownersInclude(parseOwnerLines([]byte(sidecar)), source) {
		t.Error("the list-aware compare must see its own line")
	}
}
