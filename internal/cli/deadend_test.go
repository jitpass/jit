// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/agent"
)

// Errors are the one surface that printed its own backticks: they return
// through main.go, which never reached the highlighter every report line uses.
func TestFormatErrorRendersCommandSpans(t *testing.T) {
	got := FormatError(errors.New("no vault master key found, run `jit vault init` first"))
	if strings.Contains(got, "`") {
		t.Errorf("FormatError left literal backticks in %q", got)
	}
	if !strings.Contains(got, "jit vault init") {
		t.Errorf("FormatError dropped the command out of %q", got)
	}
	if FormatError(nil) != "" {
		t.Error("FormatError(nil) must be empty, not the string \"<nil>\"")
	}
}

// The remedy has to name a command. These were rejections with nowhere to go:
// the likeliest cause of each is a mistyped path, and the listing that settles
// it is one command away.
func TestNotFoundErrorsNameTheListing(t *testing.T) {
	withFixtureHome(t)
	seedFixtureVault(t, "stripe/dev-key")
	for _, args := range [][]string{
		{"vault", "get", "no-such-secret"},
		{"vault", "history", "no-such-secret"},
	} {
		var buf bytes.Buffer
		rootCmd.SetOut(&buf)
		rootCmd.SetErr(&buf)
		rootCmd.SetArgs(args)
		err := rootCmd.Execute()
		if err == nil {
			t.Fatalf("`jit %s` succeeded, want a not-found error", strings.Join(args, " "))
		}
		if !strings.Contains(err.Error(), "jit vault list") {
			t.Errorf("`jit %s` error = %q, want it to name `jit vault list`", strings.Join(args, " "), err)
		}
	}
}

// jit's own tab completion was reachable only through an optional README line:
// a Homebrew cask installs a binary and nothing else, so doctor is what
// notices. Skipped on a machine that already has a system-wide _jit, since
// there the finding correctly does not fire.
func TestCompletionCheckReportsAnUninstalledCompletion(t *testing.T) {
	for _, dir := range completionSearchDirs() {
		if _, err := os.Stat(filepath.Join(dir, "_jit")); err == nil {
			t.Skipf("this machine already has %s/_jit, so the finding correctly stays silent", dir)
		}
	}
	home := withFixtureHome(t)
	rc := filepath.Join(home, ".zshrc")
	if err := os.WriteFile(rc, []byte("# nothing about jit here\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	findings := completionFindings()
	if len(findings) != 1 {
		t.Fatalf("completionFindings() = %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.Kind != kindCompletion {
		t.Errorf("Kind = %q, want %q", f.Kind, kindCompletion)
	}
	if !f.Kind.warning() {
		t.Error("a missing completion must be advisory: nothing is unreadable and no command is blocked")
	}
	if !strings.Contains(f.Action, "jit completion zsh") {
		t.Errorf("Action = %q, want the source line to copy", f.Action)
	}

	// The two ways a machine can already have it, both silent.
	if err := os.WriteFile(rc, []byte("source <(jit completion zsh)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := completionFindings(); len(got) != 0 {
		t.Errorf("completionFindings() = %v with the source line present, want none", got)
	}
	if err := os.WriteFile(rc, []byte("# source <(jit completion zsh)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := completionFindings(); len(got) != 1 {
		t.Error("a COMMENTED-OUT source line must still report: it loads nothing")
	}
}

// An unreadable rc is not evidence, and a doctor line that might be wrong
// about the user's shell setup is worse than none.
func TestCompletionCheckStaysQuietWhenItCannotTell(t *testing.T) {
	if !completionInstalled(filepath.Join(t.TempDir(), "nonexistent-rc")) {
		t.Error("an rc that cannot be read must not produce a finding")
	}
}

// `jit grant` shipped with no on-ramp: outside its own command the string
// appeared in one error nobody reaches without already knowing the feature.
func TestStatusSurfacesGrants(t *testing.T) {
	var buf bytes.Buffer
	printGrantsSection(&buf, statusResult{
		Agent: statusAgent{Running: true},
		Vault: statusVault{SecretsStored: 3},
	})
	out := buf.String()
	if !strings.Contains(out, "none active") {
		t.Errorf("status with no grants = %q, want it to report none active", out)
	}
	if !strings.Contains(out, "--process") {
		t.Errorf("status with no grants = %q, want the create shape, the feature's only on-ramp", out)
	}

	// Nothing stored yet: advice for a feature the reader cannot use is noise,
	// and the dashboard reports state rather than advertising.
	buf.Reset()
	printGrantsSection(&buf, statusResult{Agent: statusAgent{Running: true}})
	if strings.Contains(buf.String(), "--process") {
		t.Errorf("status on an empty vault = %q, want no grant advice", buf.String())
	}

	buf.Reset()
	printGrantsSection(&buf, statusResult{
		Agent: statusAgent{Running: true, Grants: []agent.GrantStatus{
			{ID: "g1", Name: "claude", PID: 42, ExpiresUnix: 1 << 40},
		}},
		Vault: statusVault{SecretsStored: 3},
	})
	if out := buf.String(); !strings.Contains(out, "claude") || !strings.Contains(out, "1 active grant") {
		t.Errorf("status with one grant = %q, want the count and the program", out)
	}

	// A stopped service cannot be asked, and saying "none" would be a claim.
	buf.Reset()
	printGrantsSection(&buf, statusResult{})
	if !strings.Contains(buf.String(), "service is not running") {
		t.Errorf("status with no service = %q, want it to say why it cannot tell", buf.String())
	}
}

// Filters that match nothing was the only audit shape with no way forward, and
// it is the one reached by guessing.
func TestFilteredEmptyAuditNamesTheUnfilteredLog(t *testing.T) {
	var buf bytes.Buffer
	printAuditEmpty(&buf, true)
	if !strings.Contains(buf.String(), "jit audit") {
		t.Errorf("filtered-empty audit = %q, want it to name the unfiltered log", buf.String())
	}
}

// Three empty sections and nine lines to say jit has never stored a secret.
func TestSecretsDetailCollapsesWhenThereIsNothingToReconcile(t *testing.T) {
	var buf bytes.Buffer
	printSecretsDetail(&buf, secretsReconciliation{}, nil)
	out := buf.String()
	if strings.Contains(out, "Wired here") || strings.Contains(out, "Unreferenced here") {
		t.Errorf("empty reconciliation still prints its section headers:\n%s", out)
	}
	if !strings.Contains(out, "No secrets to reconcile yet") || !strings.Contains(out, "jit scan") {
		t.Errorf("empty reconciliation = %q, want one line and a next step", out)
	}
}

// The completion probe must land on "locked" for every state it cannot
// verify: the caller's fallback is the one path that can never raise a
// prompt, so uncertainty has to resolve there. (The unlocked half needs a
// live agent and is exercised by the agent package's own session tests.)
func TestSessionUnlockedIsFalseWithoutAService(t *testing.T) {
	withFixtureHome(t) // no socket under this root
	if SessionUnlocked() {
		t.Error("SessionUnlocked() = true with no service socket, want false")
	}
}
