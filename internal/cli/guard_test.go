// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/auditlog"
	"github.com/jitpass/jit/internal/guard"
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

// A guard installed as part of bare `jit migrate` is a persistent change to
// the user's ~/.zshrc that they agreed to as one line in a plan. Recorded as
// only "jit migrate", it would be invisible to anyone later asking where the
// hook in their rc file came from.
func TestGuardInstallBySideEffectIsAudited(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	root, err := vaultRootDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}

	recordSideEffect("jit guard history", []string{"guard", "history"}, "jit migrate")

	recs := auditlog.New(root, io.Discard).Load(0)
	if len(recs) != 1 {
		t.Fatalf("got %d audit records, want 1", len(recs))
	}
	r := recs[0]
	if r.Command != "jit guard history" {
		t.Errorf("command = %q, want the equivalent command so --grep finds it", r.Command)
	}
	if !r.Success {
		t.Error("record marked failed")
	}
	// The rendered line must name who really did it: the user did not type
	// this command.
	joined := strings.Join(r.Args, " ")
	if !strings.Contains(joined, "by jit migrate") {
		t.Errorf("args = %q, want them to name the command that did it", joined)
	}
}

// execGuardHistory drives `jit guard history <args...>` through rootCmd,
// resetting the package-level flag vars first (same discipline as
// execMigrate/execWrap).
func execGuardHistory(t *testing.T, args ...string) (stdout string, err error) {
	t.Helper()
	guardHistoryRemove = false
	guardHistoryDryRun = false
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs(append([]string{"guard", "history"}, args...))
	err = rootCmd.Execute()
	return buf.String(), err
}

// TestGuardHistoryDryRun: install and remove previews carry the shared
// two-marker frame and change nothing on disk; the no-op answers
// (already installed / not installed) stay frameless.
func TestGuardHistoryDryRun(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	out, err := execGuardHistory(t, "--dry-run")
	if err != nil {
		t.Fatalf("jit guard history --dry-run: %v", err)
	}
	if got := strings.Count(out, "[DRY RUN]"); got != 2 {
		t.Errorf("expected exactly 2 [DRY RUN] markers, got %d:\n%s", got, out)
	}
	for _, want := range []string{"Install the history guard:", "guard.zsh", "Apply this plan: jit guard history"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in the install preview, got:\n%s", want, out)
		}
	}
	if _, statErr := os.Stat(guard.HookPath(home)); !os.IsNotExist(statErr) {
		t.Errorf("dry-run must not write the hook (stat err=%v)", statErr)
	}

	// --remove with nothing installed: a plain answer, no frame.
	out, err = execGuardHistory(t, "--remove", "--dry-run")
	if err != nil {
		t.Fatalf("jit guard history --remove --dry-run: %v", err)
	}
	if strings.Contains(out, "[DRY RUN]") || !strings.Contains(out, "not installed") {
		t.Errorf("expected a frameless not-installed answer, got:\n%s", out)
	}

	// Install for real, then preview the removal.
	if _, err := guard.Install(home); err != nil {
		t.Fatalf("guard.Install: %v", err)
	}
	out, err = execGuardHistory(t, "--remove", "--dry-run")
	if err != nil {
		t.Fatalf("jit guard history --remove --dry-run (installed): %v", err)
	}
	if got := strings.Count(out, "[DRY RUN]"); got != 2 {
		t.Errorf("expected exactly 2 [DRY RUN] markers on the remove preview, got %d:\n%s", got, out)
	}
	if !strings.Contains(out, "Remove the history guard:") || !strings.Contains(out, "Apply this plan: jit guard history --remove") {
		t.Errorf("expected the remove preview, got:\n%s", out)
	}
	if !guard.Installed(home) {
		t.Error("remove --dry-run must leave the guard installed")
	}
}
