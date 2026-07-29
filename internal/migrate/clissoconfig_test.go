// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"os"
	"strings"
	"testing"
)

const clissoTestConfig = `apps:
    prod:
        app-id: "2181527"
        duration: "43200"
        provider: acme
global:
    output: ~/.aws/credentials
providers:
    acme:
        client-id: abc123exampleid
        client-secret: def456examplesecret
        region: US
        subdomain: acme
        type: onelogin
        username: alex@example.com
    backup:
        base-url: https://example.oktapreview.com
        type: okta
        username: alex@example.com
`

func TestApplyClissoConfigMovesSecretAndLeavesPointer(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeFile(t, ClissoConfigPath(home), clissoTestConfig)
	v := newTestVault(t)

	res, err := ApplyClissoConfig(v, home)
	if err != nil {
		t.Fatalf("ApplyClissoConfig: %v", err)
	}
	if len(res.Providers) != 1 || res.Providers[0] != "acme" {
		t.Fatalf("Providers = %v, want [acme] (the Okta provider has no secret here)", res.Providers)
	}
	if res.Backup == "" {
		t.Error("expected a backup before the rewrite")
	}

	got, err := v.Get("wrap-clisso/acme-client-secret")
	if err != nil || string(got) != "def456examplesecret" {
		t.Errorf("vaulted secret = (%q, %v), want the original", got, err)
	}

	raw, err := os.ReadFile(ClissoConfigPath(home)) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading rewritten config: %v", err)
	}
	content := string(raw)
	if strings.Contains(content, "def456examplesecret") {
		t.Errorf("plaintext secret survived the rewrite:\n%s", content)
	}
	if !strings.Contains(content, "client-secret: jit://vault/wrap-clisso/acme-client-secret") {
		t.Errorf("expected a jit://vault pointer in place of the secret:\n%s", content)
	}
	// Everything that isn't the secret must survive: apps, the Okta
	// provider, the client-id, global settings.
	for _, want := range []string{"app-id:", "abc123exampleid", "oktapreview", "output: ~/.aws/credentials"} {
		if !strings.Contains(content, want) {
			t.Errorf("rewrite lost %q:\n%s", want, content)
		}
	}
}

func TestApplyClissoConfigIdempotent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeFile(t, ClissoConfigPath(home), clissoTestConfig)
	v := newTestVault(t)

	if _, err := ApplyClissoConfig(v, home); err != nil {
		t.Fatalf("first ApplyClissoConfig: %v", err)
	}
	before, _ := os.ReadFile(ClissoConfigPath(home)) // #nosec G304 -- test-controlled path

	res, err := ApplyClissoConfig(v, home)
	if err != nil {
		t.Fatalf("second ApplyClissoConfig: %v", err)
	}
	if len(res.Providers) != 0 || res.Backup != "" {
		t.Errorf("second run moved %v (backup %q), want a no-op on an all-pointer file", res.Providers, res.Backup)
	}
	after, _ := os.ReadFile(ClissoConfigPath(home)) // #nosec G304 -- test-controlled path
	if string(before) != string(after) {
		t.Errorf("no-op run still rewrote the file:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

func TestApplyClissoConfigMissingFileIsNoop(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	v := newTestVault(t)
	res, err := ApplyClissoConfig(v, home)
	if err != nil || len(res.Providers) != 0 {
		t.Errorf("got (%+v, %v), want a clean no-op", res, err)
	}
}

func TestDiscoverClissoSecrets(t *testing.T) {
	home := t.TempDir()
	// Missing file: nothing to discover.
	if found, err := DiscoverClissoSecrets(home); err != nil || len(found) != 0 {
		t.Errorf("missing file: got (%v, %v), want (nil, nil)", found, err)
	}
	writeFile(t, ClissoConfigPath(home), clissoTestConfig)
	found, err := DiscoverClissoSecrets(home)
	if err != nil || len(found) != 1 || found[0] != "acme" {
		t.Errorf("got (%v, %v), want ([acme], nil)", found, err)
	}
	// A pointer is not a discovery.
	writeFile(t, ClissoConfigPath(home), "providers:\n    acme:\n        client-secret: jit://vault/wrap-clisso/acme-client-secret\n        type: onelogin\n")
	if found, err := DiscoverClissoSecrets(home); err != nil || len(found) != 0 {
		t.Errorf("pointer file: got (%v, %v), want (nil, nil)", found, err)
	}
}

func TestRenderClissoConfigResolvesPointers(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeFile(t, ClissoConfigPath(home), clissoTestConfig)
	v := newTestVault(t)
	if _, err := ApplyClissoConfig(v, home); err != nil {
		t.Fatalf("ApplyClissoConfig: %v", err)
	}
	decoy, err := os.ReadFile(ClissoConfigPath(home)) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading decoy: %v", err)
	}

	rendered, resolved, err := RenderClissoConfig(v, decoy)
	if err != nil {
		t.Fatalf("RenderClissoConfig: %v", err)
	}
	if !resolved {
		t.Fatal("expected the pointer resolved")
	}
	content := string(rendered)
	if !strings.Contains(content, "client-secret: def456examplesecret") {
		t.Errorf("rendered config missing the real secret:\n%s", content)
	}
	if strings.Contains(content, "jit://vault/") {
		t.Errorf("rendered config still holds a pointer:\n%s", content)
	}
}

func TestRenderClissoConfigNoPointersMeansNotResolved(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	v := newTestVault(t)
	_, resolved, err := RenderClissoConfig(v, []byte(clissoTestConfig))
	if err != nil {
		t.Fatalf("RenderClissoConfig: %v", err)
	}
	if resolved {
		t.Error("a never-wrapped config must not report resolved")
	}
}

func TestRenderClissoConfigMissingVaultSecretFailsLoudly(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	v := newTestVault(t)
	decoy := "providers:\n    acme:\n        client-secret: jit://vault/wrap-clisso/acme-client-secret\n        type: onelogin\n"
	_, _, err := RenderClissoConfig(v, []byte(decoy))
	if err == nil {
		t.Fatal("expected an error for a pointer with no vault secret behind it")
	}
	if !strings.Contains(err.Error(), "jit wrap clisso") {
		t.Errorf("the error must name the fix, got: %v", err)
	}
}
