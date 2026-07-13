// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestBuildTerraformCredentialOutput(t *testing.T) {
	out, err := buildTerraformCredentialOutput(map[string]string{"TOKEN": "atlasv1.fixture"})
	if err != nil {
		t.Fatalf("buildTerraformCredentialOutput: %v", err)
	}
	if out.Token != "atlasv1.fixture" {
		t.Errorf("Token = %q, want atlasv1.fixture", out.Token)
	}

	if _, err := buildTerraformCredentialOutput(map[string]string{}); err == nil {
		t.Error("expected an error for a profile with no TOKEN, got nil")
	}
}

// The protocol's "no credentials" answer is an empty JSON object, exit 0
// — terraform queries the helper for ANY host it talks to, so an unknown
// host must be a clean non-answer, never an error and never a Touch ID
// prompt (this path returns before openVault()), so it's fully
// automatable.
func TestTerraformCredentialsGetUnknownHostPrintsEmptyObject(t *testing.T) {
	withFixtureHome(t)
	withFixtureCwd(t)

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetArgs([]string{"terraform-credentials", "get", "never-migrated.example"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("terraform-credentials get (unknown host): %v", err)
	}
	if got := strings.TrimSpace(buf.String()); got != "{}" {
		t.Errorf("output = %q, want {} (the protocol's no-credentials answer)", got)
	}
}

func TestTerraformCredentialsUnknownVerbErrors(t *testing.T) {
	withFixtureHome(t)
	withFixtureCwd(t)

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetArgs([]string{"terraform-credentials", "delete", "app.terraform.io"})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected an error for an unknown verb, got nil")
	}
}
