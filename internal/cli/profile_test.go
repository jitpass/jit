// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

func execProfile(t *testing.T, args ...string) (stdout string, err error) {
	t.Helper()
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetArgs(append([]string{"profile"}, args...))
	err = rootCmd.Execute()
	return buf.String(), err
}

func TestProfileListNoProfiles(t *testing.T) {
	withFixtureHome(t)
	withFixtureCwd(t)

	out, err := execProfile(t, "list")
	if err != nil {
		t.Fatalf("jit profile list: %v", err)
	}
	if !strings.Contains(out, "No profiles found") {
		t.Errorf("expected a no-profiles message, got:\n%s", out)
	}
}

func TestProfileListShowsProjectAndGlobal(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)
	writeFixtureProfile(t, cwd, "aws-admin", "AWS_ACCESS_KEY_ID: aws/s3-access-key\n")
	writeFixtureProfile(t, home, "shell", "STRIPE_API_KEY: shell/STRIPE_API_KEY\n")

	out, err := execProfile(t, "list")
	if err != nil {
		t.Fatalf("jit profile list: %v", err)
	}
	// Columns are tabwriter-aligned (spaces, not raw tabs) — assert on the
	// row's fields, not an exact separator.
	if !regexp.MustCompile(`(?m)^aws-admin\s+project\s+`).MatchString(out) {
		t.Errorf("expected the project profile listed with its scope, got:\n%s", out)
	}
	if !regexp.MustCompile(`(?m)^shell\s+global\s+`).MatchString(out) {
		t.Errorf("expected the global profile listed with its scope, got:\n%s", out)
	}
}

func TestProfileShowPrintsMappingNotValues(t *testing.T) {
	withFixtureHome(t)
	cwd := withFixtureCwd(t)
	writeFixtureProfile(t, cwd, "aws-admin", "AWS_ACCESS_KEY_ID: aws/s3-access-key\n")

	out, err := execProfile(t, "show", "aws-admin")
	if err != nil {
		t.Fatalf("jit profile show: %v", err)
	}
	if !strings.Contains(out, "aws-admin (project:") {
		t.Errorf("expected a header naming the profile and its scope, got:\n%s", out)
	}
	if !strings.Contains(out, "AWS_ACCESS_KEY_ID -> aws/s3-access-key") {
		t.Errorf("expected the variable-to-path mapping, got:\n%s", out)
	}
}

func TestProfileShowMissingProfileFailsLoud(t *testing.T) {
	withFixtureHome(t)
	withFixtureCwd(t)

	if _, err := execProfile(t, "show", "nope"); err == nil {
		t.Fatal("expected an error showing a nonexistent profile, got nil")
	}
}
