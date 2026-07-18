// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/migrate"
)

func TestBuildDockerCredentialOutput(t *testing.T) {
	out, err := buildDockerCredentialOutput("https://index.docker.io/v1/", map[string]string{"USERNAME": "alice", "SECRET": "dckr_pat_fixture"})
	if err != nil {
		t.Fatalf("buildDockerCredentialOutput: %v", err)
	}
	if out.ServerURL != "https://index.docker.io/v1/" || out.Username != "alice" || out.Secret != "dckr_pat_fixture" {
		t.Errorf("output = %+v, want the resolved pair echoed with the server URL", out)
	}

	// A tokenless username gets the protocol's own placeholder — docker
	// treats an empty username in a get response as malformed.
	out, err = buildDockerCredentialOutput("x.example.com", map[string]string{"SECRET": "eyJhbGciOi.fixture"})
	if err != nil {
		t.Fatalf("buildDockerCredentialOutput (no username): %v", err)
	}
	if out.Username != migrate.DockerTokenUsername {
		t.Errorf("Username = %q, want %q", out.Username, migrate.DockerTokenUsername)
	}

	if _, err := buildDockerCredentialOutput("x.example.com", map[string]string{"USERNAME": "alice"}); err == nil {
		t.Error("expected an error for a profile with no SECRET, got nil")
	}
}

// The protocol's "no credentials" answer is the exact sentinel line on
// stdout plus a non-zero exit — docker queries the helper for ANY registry
// it talks to (public pulls included), matches that string, and falls
// through to anonymous access. This path returns before openVault(), so an
// unknown registry never costs a Touch ID prompt.
func TestDockerCredentialGetUnknownRegistryPrintsSentinel(t *testing.T) {
	withFixtureHome(t)
	withFixtureCwd(t)

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetIn(strings.NewReader("never-migrated.example.com\n"))
	rootCmd.SetArgs([]string{"docker-credential", "get"})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected a non-zero exit for an unknown registry, the protocol pairs the sentinel with a failure status")
	}
	if got := strings.TrimSpace(buf.String()); got != dockerCredentialsNotFoundMsg {
		t.Errorf("stdout = %q, want the protocol sentinel %q", got, dockerCredentialsNotFoundMsg)
	}
}

func TestDockerCredentialListPrintsEmptyObject(t *testing.T) {
	withFixtureHome(t)
	withFixtureCwd(t)

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetIn(strings.NewReader(""))
	rootCmd.SetArgs([]string{"docker-credential", "list"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("docker-credential list: %v", err)
	}
	if got := strings.TrimSpace(buf.String()); got != "{}" {
		t.Errorf("output = %q, want {}", got)
	}
}

func TestDockerCredentialStoreRejectsIncompletePayload(t *testing.T) {
	withFixtureHome(t)
	withFixtureCwd(t)

	for name, payload := range map[string]string{
		"no ServerURL": `{"Username": "alice", "Secret": "s3cret"}`,
		"no Secret":    `{"ServerURL": "registry.example.com", "Username": "alice"}`,
		"not JSON":     "registry.example.com",
	} {
		rootCmd.SetOut(&bytes.Buffer{})
		rootCmd.SetIn(strings.NewReader(payload))
		rootCmd.SetArgs([]string{"docker-credential", "store"})
		if err := rootCmd.Execute(); err == nil {
			t.Errorf("%s: expected an error, got nil", name)
		}
	}
}

func TestDockerCredentialUnknownVerbErrors(t *testing.T) {
	withFixtureHome(t)
	withFixtureCwd(t)

	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetIn(strings.NewReader(""))
	rootCmd.SetArgs([]string{"docker-credential", "forget"})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected an error for an unknown verb, got nil")
	}
}
