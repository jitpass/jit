// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const cargoCredsFixture = `[registry]
token = "cioFirstPartyTokenQmPl4TzWhu"

[registries.work]
token = "cioWorkRegistryTokenu2qcwnu9"

[http]
timeout = 30
`

func TestDiscoverCargoRegistries(t *testing.T) {
	home := t.TempDir()
	writeFile(t, CargoCredentialPaths(home)[0], cargoCredsFixture)

	regs, err := DiscoverCargoRegistries(home)
	if err != nil {
		t.Fatalf("DiscoverCargoRegistries: %v", err)
	}
	if len(regs) != 2 || regs[0] != "crates-io" || regs[1] != "work" {
		t.Errorf("registries = %v, want [crates-io work]", regs)
	}
}

func TestDiscoverCargoRegistriesQuietCases(t *testing.T) {
	t.Run("no file", func(t *testing.T) {
		regs, err := DiscoverCargoRegistries(t.TempDir())
		if err != nil || len(regs) != 0 {
			t.Errorf("got (%v, %v), want (nil, nil)", regs, err)
		}
	})
	t.Run("no tokens", func(t *testing.T) {
		home := t.TempDir()
		writeFile(t, CargoCredentialPaths(home)[0], "[http]\ntimeout = 30\n")
		regs, err := DiscoverCargoRegistries(home)
		if err != nil || len(regs) != 0 {
			t.Errorf("got (%v, %v), want (nil, nil)", regs, err)
		}
	})
	t.Run("legacy bare credentials file counts too", func(t *testing.T) {
		home := t.TempDir()
		writeFile(t, CargoCredentialPaths(home)[1], "[registry]\ntoken = \"cioLegacyFileTokenQmPl4Tz\"\n")
		regs, err := DiscoverCargoRegistries(home)
		if err != nil || len(regs) != 1 || regs[0] != "crates-io" {
			t.Errorf("got (%v, %v), want ([crates-io], nil)", regs, err)
		}
	})
}

func TestFindCargoTokensIgnoresOtherTables(t *testing.T) {
	tokens, err := findCargoTokens(writeTempCargo(t, "[http]\ntoken = \"not-a-registry-token\"\n\n[registry]\ntoken = \"cioRealTokenQmPl4TzWhu\"\n"))
	if err != nil {
		t.Fatalf("findCargoTokens: %v", err)
	}
	if len(tokens) != 1 || tokens[0].Registry != "crates-io" || tokens[0].Token != "cioRealTokenQmPl4TzWhu" {
		t.Errorf("tokens = %+v, want only [registry]'s token as crates-io", tokens)
	}
}

func writeTempCargo(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credentials.toml")
	writeFile(t, path, content)
	return path
}

func TestApplyCargoRegistryEndToEnd(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home) // upsertCargoProfile writes the global store under $HOME
	credPath := CargoCredentialPaths(home)[0]
	writeFile(t, credPath, cargoCredsFixture)

	v := newTestVault(t)
	tracker := NewBackupTracker()
	result, err := ApplyCargoRegistry(v, home, "work", tracker)
	if err != nil {
		t.Fatalf("ApplyCargoRegistry: %v", err)
	}
	if result.VaultProfileName != "cargo-work" {
		t.Errorf("VaultProfileName = %q, want cargo-work", result.VaultProfileName)
	}

	got, err := v.Get("cargo-work/TOKEN")
	if err != nil || string(got) != "cioWorkRegistryTokenu2qcwnu9" {
		t.Errorf("vault token = (%q, %v), want the work registry token", got, err)
	}

	// The token line is gone; every other line survives byte-oriented —
	// including crates-io's token, which was NOT migrated in this call.
	after, err := os.ReadFile(credPath) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading credentials after: %v", err)
	}
	if strings.Contains(string(after), "cioWorkRegistryTokenu2qcwnu9") {
		t.Error("migrated token still present in credentials.toml")
	}
	for _, keep := range []string{"cioFirstPartyTokenQmPl4TzWhu", "[registries.work]", "[http]", "timeout = 30"} {
		if !strings.Contains(string(after), keep) {
			t.Errorf("credentials.toml lost %q:\n%s", keep, after)
		}
	}

	// The wrapper exists, is executable, and execs jit's cargo-credential.
	helper, err := os.ReadFile(result.HelperPath) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading helper: %v", err)
	}
	if !strings.Contains(string(helper), "cargo-credential") {
		t.Errorf("helper does not invoke jit cargo-credential:\n%s", helper)
	}
	if info, err := os.Stat(result.HelperPath); err != nil || info.Mode()&0o100 == 0 {
		t.Errorf("helper must be executable, got %v (err=%v)", info, err)
	}

	// config.toml registers cargo:token FIRST (unmigrated registries keep
	// working via fallback) and jit LAST (later wins).
	config, err := os.ReadFile(result.ConfigPath) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading config.toml: %v", err)
	}
	line := ""
	for _, l := range strings.Split(string(config), "\n") {
		if strings.Contains(l, "global-credential-providers") {
			line = l
		}
	}
	if line == "" {
		t.Fatalf("config.toml has no global-credential-providers line:\n%s", config)
	}
	tokenIdx := strings.Index(line, "cargo:token")
	jitIdx := strings.Index(line, result.HelperPath)
	if tokenIdx < 0 || jitIdx < 0 || tokenIdx > jitIdx {
		t.Errorf("provider order must be [cargo:token, jit-helper], got %q", line)
	}

	// Second registry through the same tracker: config already carries
	// jit's line (alreadyInstalled) and must not be duplicated.
	if _, err := ApplyCargoRegistry(v, home, "crates-io", tracker); err != nil {
		t.Fatalf("ApplyCargoRegistry(crates-io): %v", err)
	}
	config2, _ := os.ReadFile(result.ConfigPath) // #nosec G304 -- test-controlled path
	if n := strings.Count(string(config2), "global-credential-providers"); n != 1 {
		t.Errorf("provider line appears %d times after two migrations, want 1:\n%s", n, config2)
	}
	after2, _ := os.ReadFile(credPath) // #nosec G304 -- test-controlled path
	if strings.Contains(string(after2), "cio") {
		t.Errorf("all tokens should be gone after migrating both registries:\n%s", after2)
	}
}

// TestApplyCargoRegistryStripsStaleLegacyCopy pins that a token duplicated
// in the pre-1.39 bare `credentials` file is stripped too: cargo only
// reads the first file that exists, but the stale copy is the same
// plaintext credential.
func TestApplyCargoRegistryStripsStaleLegacyCopy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeFile(t, CargoCredentialPaths(home)[0], "[registry]\ntoken = \"cioLiveTokenQmPl4TzWhu\"\n")
	writeFile(t, CargoCredentialPaths(home)[1], "[registry]\ntoken = \"cioStaleCopyTokenu2qcwn\"\n")

	v := newTestVault(t)
	if _, err := ApplyCargoRegistry(v, home, "crates-io", NewBackupTracker()); err != nil {
		t.Fatalf("ApplyCargoRegistry: %v", err)
	}
	// The FIRST file's value is the one cargo reads, so it's what vaults.
	got, err := v.Get("cargo-crates-io/TOKEN")
	if err != nil || string(got) != "cioLiveTokenQmPl4TzWhu" {
		t.Errorf("vault token = (%q, %v), want the first file's value", got, err)
	}
	for i, path := range CargoCredentialPaths(home) {
		data, err := os.ReadFile(path) // #nosec G304 -- test-controlled path
		if err != nil {
			t.Fatalf("reading file %d: %v", i, err)
		}
		if strings.Contains(string(data), "cio") {
			t.Errorf("file %d still holds a token after migration:\n%s", i, data)
		}
	}
}

// TestApplyCargoRegistryConflict pins the fail-loud rule: a
// global-credential-providers list jit didn't write is the user's own
// deliberate configuration, and merging into a hand-written TOML array by
// string surgery can't be done provably right — so nothing is mutated.
func TestApplyCargoRegistryConflict(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	credPath := CargoCredentialPaths(home)[0]
	writeFile(t, credPath, cargoCredsFixture)
	writeFile(t, CargoConfigPath(home), "[registry]\nglobal-credential-providers = [\"cargo:macos-keychain\"]\n")

	v := newTestVault(t)
	_, err := ApplyCargoRegistry(v, home, "work", NewBackupTracker())
	if err == nil {
		t.Fatal("expected a conflict error for a foreign provider list, got nil")
	}
	if !strings.Contains(err.Error(), "global-credential-providers") {
		t.Errorf("error should name the conflicting key, got %v", err)
	}
	after, _ := os.ReadFile(credPath) // #nosec G304 -- test-controlled path
	if string(after) != cargoCredsFixture {
		t.Error("a refused migration must leave credentials.toml untouched")
	}
}

// TestAppendCargoProvidersMergesIntoExistingRegistryTable pins the config
// surgery: an existing [registry] table (holding, say, default = "…")
// gets the key inserted under its header rather than a second [registry]
// table appended — two tables with one name is invalid TOML.
func TestAppendCargoProvidersMergesIntoExistingRegistryTable(t *testing.T) {
	home := t.TempDir()
	configPath := CargoConfigPath(home)
	writeFile(t, configPath, "[build]\njobs = 4\n\n[registry]\ndefault = \"work\"\n")

	if err := appendCargoProviders(configPath, "/usr/local/bin/cargo-credential-jit"); err != nil {
		t.Fatalf("appendCargoProviders: %v", err)
	}
	data, _ := os.ReadFile(configPath) // #nosec G304 -- test-controlled path
	content := string(data)
	if strings.Count(content, "[registry]") != 1 {
		t.Errorf("config must keep exactly one [registry] table:\n%s", content)
	}
	for _, keep := range []string{"[build]", "jobs = 4", "default = \"work\"", "global-credential-providers"} {
		if !strings.Contains(content, keep) {
			t.Errorf("config lost %q:\n%s", keep, content)
		}
	}
	// The key must sit inside [registry], i.e. after its header and before
	// any subsequent table header.
	regIdx := strings.Index(content, "[registry]")
	keyIdx := strings.Index(content, "global-credential-providers")
	if keyIdx < regIdx {
		t.Errorf("key inserted outside the [registry] table:\n%s", content)
	}
}

func TestStoreAndForgetCargoToken(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	v := newTestVault(t)

	if err := StoreCargoToken(v, "crates-io", "cioFreshLoginTokenQmPl4Tz"); err != nil {
		t.Fatalf("StoreCargoToken: %v", err)
	}
	got, err := v.Get("cargo-crates-io/TOKEN")
	if err != nil || string(got) != "cioFreshLoginTokenQmPl4Tz" {
		t.Errorf("vault token = (%q, %v), want the stored login token", got, err)
	}

	if err := ForgetCargoToken(v, "crates-io"); err != nil {
		t.Fatalf("ForgetCargoToken: %v", err)
	}
	if _, err := v.Get("cargo-crates-io/TOKEN"); err == nil {
		t.Error("token still readable after ForgetCargoToken")
	}
	// Idempotent: forgetting again is a no-op, matching cargo's own logout
	// with nothing saved.
	if err := ForgetCargoToken(v, "crates-io"); err != nil {
		t.Errorf("second ForgetCargoToken must be a no-op, got %v", err)
	}
}
