// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package migrate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/profile"
)

func writeDockerConfig(t *testing.T, home, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(home, ".docker"), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	writeFile(t, DockerConfigPath(home), content)
}

// Two plaintext auths: alice:s3cret-pass and bob:pa:ss:word (the second
// password contains colons, the split-on-first-colon case), plus an
// unrelated top-level key that must survive rewrites verbatim.
const dockerConfigTwoRegistries = `{
  "auths": {
    "registry.example.com": {
      "auth": "YWxpY2U6czNjcmV0LXBhc3M="
    },
    "ghcr.io": {
      "auth": "Ym9iOnBhOnNzOndvcmQ="
    }
  },
  "proxies": {
    "default": {
      "httpProxy": "http://proxy.example:3128"
    }
  }
}`

func TestDiscoverDockerRegistriesSortedPlaintextOnly(t *testing.T) {
	home := t.TempDir()
	writeDockerConfig(t, home, `{
  "auths": {
    "registry.example.com": {"auth": "YWxpY2U6czNjcmV0LXBhc3M="},
    "ghcr.io": {"auth": "Ym9iOnBhOnNzOndvcmQ="},
    "https://index.docker.io/v1/": {},
    "quay.io": {"email": "alice@example.com"},
    "helper.example.com": {"auth": "YWxpY2U6czNjcmV0LXBhc3M="}
  },
  "credHelpers": {"helper.example.com": "osxkeychain"}
}`)

	registries, err := DiscoverDockerRegistries(home)
	if err != nil {
		t.Fatalf("DiscoverDockerRegistries: %v", err)
	}
	// The {} marker (a store already holds it), the email-only entry, and
	// the registry routed to a foreign helper are all excluded.
	want := []string{"ghcr.io", "registry.example.com"}
	if len(registries) != len(want) {
		t.Fatalf("registries = %v, want %v", registries, want)
	}
	for i := range want {
		if registries[i] != want[i] {
			t.Errorf("registries[%d] = %q, want %q", i, registries[i], want[i])
		}
	}
}

func TestDiscoverDockerRegistriesMissingOrMalformed(t *testing.T) {
	if registries, err := DiscoverDockerRegistries(t.TempDir()); err != nil || len(registries) != 0 {
		t.Fatalf("missing file: registries=%v err=%v, want none", registries, err)
	}
	home := t.TempDir()
	writeDockerConfig(t, home, "not json at all")
	if registries, err := DiscoverDockerRegistries(home); err != nil || len(registries) != 0 {
		t.Fatalf("malformed file: registries=%v err=%v, want none", registries, err)
	}
}

func TestDockerProfileName(t *testing.T) {
	for in, want := range map[string]string{
		"https://index.docker.io/v1/": "docker-index.docker.io-v1",
		"registry.example.com":        "docker-registry.example.com",
		"registry.example.com:5000":   "docker-registry.example.com-5000",
		"http://insecure.example/":    "docker-insecure.example",
		"https://":                    "",
		"":                            "",
	} {
		if got := DockerProfileName(in); got != want {
			t.Errorf("DockerProfileName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestApplyDockerRegistryEndToEnd(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeDockerConfig(t, home, dockerConfigTwoRegistries)

	v := newTestVault(t)
	result, err := ApplyDockerRegistry(v, home, "registry.example.com")
	if err != nil {
		t.Fatalf("ApplyDockerRegistry: %v", err)
	}
	if result.VaultProfileName != "docker-registry.example.com" {
		t.Errorf("VaultProfileName = %q, want docker-registry.example.com", result.VaultProfileName)
	}
	if !result.ClaimedDefaultStore {
		t.Error("ClaimedDefaultStore = false, want true when the config had no credsStore")
	}

	for varName, want := range map[string]string{"USERNAME": "alice", "SECRET": "s3cret-pass"} {
		got, err := v.Get("docker-registry.example.com/" + varName)
		if err != nil || string(got) != want {
			t.Errorf("%s = (%q, %v), want %q", varName, got, err, want)
		}
	}

	p, err := profile.LoadFile(result.VaultProfilePath)
	if err != nil {
		t.Fatalf("loading written profile: %v", err)
	}
	if p["SECRET"] != "docker-registry.example.com/SECRET" {
		t.Errorf("profile SECRET = %q, want docker-registry.example.com/SECRET", p["SECRET"])
	}

	configRaw, err := os.ReadFile(DockerConfigPath(home)) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading rewritten config: %v", err)
	}
	if strings.Contains(string(configRaw), "YWxpY2U6czNjcmV0LXBhc3M=") {
		t.Error("rewritten config must not contain the migrated base64 credential")
	}
	var reparsed struct {
		Auths       map[string]map[string]string `json:"auths"`
		CredsStore  string                       `json:"credsStore"`
		CredHelpers map[string]string            `json:"credHelpers"`
		Proxies     map[string]map[string]string `json:"proxies"`
	}
	if err := json.Unmarshal(configRaw, &reparsed); err != nil {
		t.Fatalf("rewritten config is not valid JSON: %v", err)
	}
	// The migrated entry becomes docker's own empty marker; the other
	// registry's plaintext survives untouched until its own migration.
	if entry, ok := reparsed.Auths["registry.example.com"]; !ok || len(entry) != 0 {
		t.Errorf("migrated auths entry = %v, want the empty {} marker", entry)
	}
	if reparsed.Auths["ghcr.io"]["auth"] != "Ym9iOnBhOnNzOndvcmQ=" {
		t.Error("unrelated registry's credential was not preserved")
	}
	if reparsed.CredHelpers["registry.example.com"] != "jit" {
		t.Errorf("credHelpers = %v, want registry routed to jit", reparsed.CredHelpers)
	}
	if reparsed.CredsStore != "jit" {
		t.Errorf("credsStore = %q, want jit claimed as default when none existed", reparsed.CredsStore)
	}
	if reparsed.Proxies["default"]["httpProxy"] != "http://proxy.example:3128" {
		t.Error("unknown top-level key (proxies) was not preserved verbatim")
	}

	helperRaw, err := os.ReadFile(result.HelperPath) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading helper script: %v", err)
	}
	if !strings.Contains(string(helperRaw), "docker-credential \"$@\"") {
		t.Errorf("helper script = %q, want it to exec `jit docker-credential`", helperRaw)
	}
	info, err := os.Stat(result.HelperPath)
	if err != nil {
		t.Fatalf("stat helper: %v", err)
	}
	if info.Mode().Perm()&0o100 == 0 {
		t.Errorf("helper script mode = %v, want owner-executable, docker discovers helpers as executables on PATH", info.Mode())
	}
	if result.ConfigBackup == "" {
		t.Error("ConfigBackup is empty, the pre-rewrite backup must be recorded")
	}
}

// An existing default store (Docker Desktop's osxkeychain/desktop) is the
// user's own deliberate configuration: the migrated registry is routed via
// its per-registry credHelpers entry (which docker checks first), and the
// default store is never replaced.
func TestApplyDockerRegistryKeepsExistingCredsStore(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeDockerConfig(t, home, `{
  "auths": {"registry.example.com": {"auth": "YWxpY2U6czNjcmV0LXBhc3M="}},
  "credsStore": "osxkeychain"
}`)

	v := newTestVault(t)
	result, err := ApplyDockerRegistry(v, home, "registry.example.com")
	if err != nil {
		t.Fatalf("ApplyDockerRegistry: %v", err)
	}
	if result.ClaimedDefaultStore {
		t.Error("ClaimedDefaultStore = true, want false when a store was already configured")
	}
	configRaw, _ := os.ReadFile(DockerConfigPath(home)) // #nosec G304 -- test-controlled path
	var reparsed struct {
		CredsStore  string            `json:"credsStore"`
		CredHelpers map[string]string `json:"credHelpers"`
	}
	if err := json.Unmarshal(configRaw, &reparsed); err != nil {
		t.Fatalf("rewritten config is not valid JSON: %v", err)
	}
	if reparsed.CredsStore != "osxkeychain" {
		t.Errorf("credsStore = %q, the user's own store must never be replaced", reparsed.CredsStore)
	}
	if reparsed.CredHelpers["registry.example.com"] != "jit" {
		t.Errorf("credHelpers = %v, want the migrated registry routed to jit", reparsed.CredHelpers)
	}
}

// A registry already routed to a DIFFERENT helper is a hard stop before
// anything is mutated: the plaintext there is a stale leftover, and taking
// the registry over from the user's own helper choice is not jit's call.
func TestApplyDockerRegistryRefusesForeignHelper(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	original := `{
  "auths": {"registry.example.com": {"auth": "YWxpY2U6czNjcmV0LXBhc3M="}},
  "credHelpers": {"registry.example.com": "osxkeychain"}
}`
	writeDockerConfig(t, home, original)

	v := newTestVault(t)
	_, err := ApplyDockerRegistry(v, home, "registry.example.com")
	if err == nil || !strings.Contains(err.Error(), `credential helper "osxkeychain"`) {
		t.Fatalf("err = %v, want a foreign-helper refusal naming the helper", err)
	}
	got, _ := os.ReadFile(DockerConfigPath(home)) // #nosec G304 -- test-controlled path
	if string(got) != original {
		t.Error("config.json was mutated by a refused migration")
	}
}

func TestApplyDockerRegistryIdentityToken(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeDockerConfig(t, home, `{
  "auths": {
    "https://index.docker.io/v1/": {
      "auth": "YWxpY2U6czNjcmV0LXBhc3M=",
      "identitytoken": "eyJhbGciOi.example.token"
    }
  }
}`)

	v := newTestVault(t)
	result, err := ApplyDockerRegistry(v, home, "https://index.docker.io/v1/")
	if err != nil {
		t.Fatalf("ApplyDockerRegistry: %v", err)
	}
	// The identity token is the secret; the decoded username survives.
	if got, err := v.Get(result.VaultProfileName + "/SECRET"); err != nil || string(got) != "eyJhbGciOi.example.token" {
		t.Errorf("SECRET = (%q, %v), want the identity token", got, err)
	}
	if got, err := v.Get(result.VaultProfileName + "/USERNAME"); err != nil || string(got) != "alice" {
		t.Errorf("USERNAME = (%q, %v), want alice", got, err)
	}
}

// The docker sibling of the AWS/terraform multi-unit regression (GAPS.md
// #65): with a shared BackupTracker (as the CLI uses), migrating two
// registries out of one config.json and undoing restores the pristine
// file with BOTH credentials.
func TestApplyDockerMultiRegistryUndoRestoresPristine(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeDockerConfig(t, home, dockerConfigTwoRegistries)
	originalConfig, err := os.ReadFile(DockerConfigPath(home)) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading original config: %v", err)
	}

	v := newTestVault(t)
	tracker := NewBackupTracker() // one tracker for the run, exactly as the CLI does
	for _, registry := range []string{"ghcr.io", "registry.example.com"} {
		if _, err := ApplyDockerRegistry(v, home, registry, tracker); err != nil {
			t.Fatalf("ApplyDockerRegistry(%s): %v", registry, err)
		}
	}

	recs, err := LoadBackupRecords(v.Root)
	if err != nil {
		t.Fatalf("LoadBackupRecords: %v", err)
	}
	absConfig, _ := filepath.Abs(DockerConfigPath(home))
	configBackups := 0
	for _, r := range recs {
		if r.OriginalPath == absConfig && !r.RemoveOnRestore {
			configBackups++
		}
	}
	if configBackups != 1 {
		t.Errorf("expected exactly 1 pristine config backup for a 2-registry run, got %d", configBackups)
	}

	for _, rec := range LatestBackups(recs) {
		if err := RestoreFromBackup(v, rec); err != nil {
			t.Fatalf("RestoreFromBackup(%s): %v", rec.OriginalPath, err)
		}
	}
	gotConfig, _ := os.ReadFile(DockerConfigPath(home)) // #nosec G304 -- test-controlled path
	if string(gotConfig) != string(originalConfig) {
		t.Errorf("restored config not pristine:\n got: %q\nwant: %q", gotConfig, originalConfig)
	}
}

func TestStoreAndEraseDockerCredential(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	v := newTestVault(t)

	if err := StoreDockerCredential(v, "https://index.docker.io/v1/", "alice", "dckr_pat_example"); err != nil {
		t.Fatalf("StoreDockerCredential: %v", err)
	}
	if got, err := v.Get("docker-index.docker.io-v1/SECRET"); err != nil || string(got) != "dckr_pat_example" {
		t.Errorf("SECRET after store = (%q, %v), want the stored token", got, err)
	}
	// An identity-token login has no username; the protocol's own
	// placeholder fills it, docker treats an empty username as malformed.
	if err := StoreDockerCredential(v, "token.example.com", "", "eyJhbGciOi.example"); err != nil {
		t.Fatalf("StoreDockerCredential (no username): %v", err)
	}
	if got, err := v.Get("docker-token.example.com/USERNAME"); err != nil || string(got) != DockerTokenUsername {
		t.Errorf("USERNAME after tokenless store = (%q, %v), want %q", got, err, DockerTokenUsername)
	}
	if err := StoreDockerCredential(v, "x.example.com", "alice", ""); err == nil {
		t.Error("StoreDockerCredential with an empty secret must fail")
	}

	if err := EraseDockerCredential(v, "https://index.docker.io/v1/"); err != nil {
		t.Fatalf("EraseDockerCredential: %v", err)
	}
	globalRoot, _ := profile.GlobalRoot()
	manifestPath, _ := profile.Path(globalRoot, "docker-index.docker.io-v1")
	if _, err := os.Stat(manifestPath); !os.IsNotExist(err) {
		t.Errorf("profile manifest still present after erase, stat err = %v", err)
	}
	// Idempotent, like docker logout with nothing saved.
	if err := EraseDockerCredential(v, "https://index.docker.io/v1/"); err != nil {
		t.Errorf("second EraseDockerCredential: %v", err)
	}
	if err := EraseDockerCredential(v, "never-stored.example.com"); err != nil {
		t.Errorf("EraseDockerCredential for a never-stored registry: %v", err)
	}
}
