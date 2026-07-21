// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestBuildGitCredentialOutput(t *testing.T) {
	out, ok := buildGitCredentialOutput(map[string]string{"USERNAME": "octocat", "PASSWORD": "ghp_fixture"})
	if !ok {
		t.Fatal("buildGitCredentialOutput: ok=false for a complete pair")
	}
	if out != "username=octocat\npassword=ghp_fixture\n" {
		t.Errorf("output = %q, want the username/password lines", out)
	}

	// A password with no username is still valid: git only requires the
	// password, and the username came in on the request.
	out, ok = buildGitCredentialOutput(map[string]string{"PASSWORD": "ghp_fixture"})
	if !ok || out != "password=ghp_fixture\n" {
		t.Errorf("output = (%q, %v), want just the password line", out, ok)
	}

	// No password means no credential: the get verb stays silent so git
	// falls through, rather than emitting a malformed pair.
	if _, ok := buildGitCredentialOutput(map[string]string{"USERNAME": "octocat"}); ok {
		t.Error("expected ok=false for a profile with no PASSWORD")
	}
}

// A host jit holds nothing for must be silent success (empty stdout, zero
// exit): git reads empty output as "no credential" and moves on. This path
// returns before openVault(), so an unknown host never costs a Touch ID
// prompt.
func TestGitCredentialGetUnknownHostIsSilent(t *testing.T) {
	withFixtureHome(t)
	withFixtureCwd(t)

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetIn(strings.NewReader("protocol=https\nhost=never-migrated.example.com\n\n"))
	rootCmd.SetArgs([]string{"git-credential", "get"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("git-credential get for an unknown host must succeed silently, got %v", err)
	}
	if got := buf.String(); got != "" {
		t.Errorf("stdout = %q, want empty output for an unknown host", got)
	}
}

func TestGitCredentialStoreRejectsIncompleteRequest(t *testing.T) {
	withFixtureHome(t)
	withFixtureCwd(t)

	for name, payload := range map[string]string{
		"no host":     "protocol=https\nusername=alice\npassword=s3cret\n\n",
		"no password": "protocol=https\nhost=github.com\nusername=alice\n\n",
	} {
		rootCmd.SetOut(&bytes.Buffer{})
		rootCmd.SetIn(strings.NewReader(payload))
		rootCmd.SetArgs([]string{"git-credential", "store"})
		if err := rootCmd.Execute(); err == nil {
			t.Errorf("%s: expected an error, got nil", name)
		}
	}
}

func TestGitCredentialUnknownVerbErrors(t *testing.T) {
	withFixtureHome(t)
	withFixtureCwd(t)

	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetIn(strings.NewReader(""))
	rootCmd.SetArgs([]string{"git-credential", "list"})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected an error for an unknown verb, got nil")
	}
}
