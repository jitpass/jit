// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"errors"
	"strings"
	"testing"
)

func TestGuardCheckStdinFindsVendors(t *testing.T) {
	in := "curl -H 'Authorization: token ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'\n" +
		"export SLACK_TOKEN=xoxb" + "-1234567890-AbCdEfGhIjKlMnOpQrSt\n"
	vendors, err := guardCheckStdin(strings.NewReader(in))
	if err != nil {
		t.Fatalf("guardCheckStdin: %v", err)
	}
	if len(vendors) != 2 {
		t.Fatalf("vendors = %v, want two", vendors)
	}
	joined := strings.Join(vendors, ", ")
	if !strings.Contains(joined, "GitHub") || !strings.Contains(joined, "Slack") {
		t.Errorf("vendors = %v, want GitHub + Slack", vendors)
	}
	for _, v := range vendors {
		if strings.Contains(v, "ghp_") || strings.Contains(v, "xoxb") {
			t.Errorf("vendor name %q leaks the value", v)
		}
	}
}

func TestGuardCheckStdinCleanInput(t *testing.T) {
	vendors, err := guardCheckStdin(strings.NewReader("git status\nls -la\n"))
	if err != nil || len(vendors) != 0 {
		t.Errorf("guardCheckStdin = (%v, %v), want no vendors", vendors, err)
	}
}

// The exit-code contract the zsh hook branches on: found -> nil (exit 0)
// with vendors on stdout; clean -> errExitClean (exit 1) with NO output.
func TestGuardCheckCommandContract(t *testing.T) {
	var out strings.Builder
	guardCheckCmd.SetIn(strings.NewReader("export T=ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8\n"))
	guardCheckCmd.SetOut(&out)
	if err := guardCheckCmd.RunE(guardCheckCmd, nil); err != nil {
		t.Fatalf("credential input must exit 0, got %v", err)
	}
	if !strings.Contains(out.String(), "GitHub") {
		t.Errorf("stdout = %q, want the vendor name", out.String())
	}

	out.Reset()
	guardCheckCmd.SetIn(strings.NewReader("git status\n"))
	if err := guardCheckCmd.RunE(guardCheckCmd, nil); !errors.Is(err, errExitClean) {
		t.Fatalf("clean input must return errExitClean, got %v", err)
	}
	if out.String() != "" {
		t.Errorf("clean run printed %q, want silence", out.String())
	}
	if !guardCheckCmd.SilenceUsage || !guardCheckCmd.SilenceErrors {
		t.Error("clean run must silence cobra's usage/error printing")
	}
}

// The hook forks `jit guard check` constantly at the interactive prompt, so
// it must never reach the application audit log: an append there is latency
// on the user's keystrokes, and a timestamped record of when they typed
// credential-shaped commands is not what a secret-access trail is for.
func TestGuardCheckIsNotAuditLogged(t *testing.T) {
	if !auditExcludedPaths[guardCheckCmd.CommandPath()] {
		t.Errorf("%q is not audit-excluded; the guard hook would write a record per command line", guardCheckCmd.CommandPath())
	}
	// The visible half of the command tree stays audited: installing or
	// removing a guard changes the machine and belongs in the trail.
	if auditExcludedPaths[guardHistoryCmd.CommandPath()] || auditExcludedCommands[guardHistoryCmd.Name()] {
		t.Error("jit guard history must stay in the audit trail")
	}
}
