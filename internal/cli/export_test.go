// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestShellQuote(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"simple", "'simple'"},
		{"", "''"},
		{"has spaces", "'has spaces'"},
		{"o'brien", `'o'\''brien'`},
		{"$(rm -rf /)", "'$(rm -rf /)'"},
		{"a'b'c", `'a'\''b'\''c'`},
	}
	for _, c := range cases {
		if got := shellQuote(c.in); got != c.want {
			t.Errorf("shellQuote(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// execExport drives `jit export` through rootCmd (see execAudit for why).
// Only pre-vault paths are automatable — anything past resolution reaches
// openVault() and needs a real Touch ID/passcode approval, per this
// package's testing discipline — so these tests cover exactly the
// resolution/flag-validation wiring and assert an error stops before any
// vault access.
func execExport(t *testing.T, args ...string) (output string, err error) {
	t.Helper()
	exportProfile = ""
	exportMode = ""
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs(append([]string{"export"}, args...))
	err = rootCmd.Execute()
	return buf.String(), err
}

func TestExportNoProfileNoLayersFailsBeforeVault(t *testing.T) {
	withFixtureHome(t)
	withFixtureCwd(t)

	_, err := execExport(t)
	if err == nil {
		t.Fatal("export with no profile and no layers should error, got nil")
	}
	if !strings.Contains(err.Error(), "--profile") {
		t.Errorf("error should point at --profile, got: %v", err)
	}
}

func TestExportProfileWithModeRejected(t *testing.T) {
	withFixtureHome(t)
	withFixtureCwd(t)

	_, err := execExport(t, "--profile", "root", "--mode", "production")
	if err == nil {
		t.Fatal("--profile with --mode should error, got nil")
	}
	if !strings.Contains(err.Error(), "--mode") {
		t.Errorf("error should explain the --mode/--profile conflict, got: %v", err)
	}
}
