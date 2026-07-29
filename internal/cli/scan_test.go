// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withFixtureHome points os.UserHomeDir() (which reads $HOME on Unix) at a
// throwaway fixture directory for the duration of the test, so a CLI-level
// test never touches — or reveals anything about — the real machine it
// runs on. Restores the real $HOME afterward.
func withFixtureHome(t *testing.T) string {
	t.Helper()
	fixture := t.TempDir()
	original, wasSet := os.LookupEnv("HOME")
	if err := os.Setenv("HOME", fixture); err != nil {
		t.Fatalf("os.Setenv(HOME): %v", err)
	}
	t.Cleanup(func() {
		if wasSet {
			_ = os.Setenv("HOME", original)
		} else {
			_ = os.Unsetenv("HOME")
		}
	})
	return fixture
}

// execScan drives execution through rootCmd, not scanCmd directly —
// Cobra's Execute() always redirects to the root command when called on a
// child ("if c.HasParent() { return c.Root().ExecuteC() }"), so args/output
// must be set on rootCmd with "scan" as the first argument for Find() to
// resolve to the scan subcommand at all.
//
// Resets every scan flag's backing package-level var before each call —
// Cobra does not reset flag values between Execute() calls within a
// process, so without this, a later test silently inherits whatever a
// previous test set --format or --output to. This bit twice while adding
// the markdown/--output feature (once for scanFormat, once for
// scanOutput) before being fixed here once, centrally, instead of requiring
// every test to remember to pass every flag explicitly forever.
func execScan(t *testing.T, args ...string) (stdout string, err error) {
	t.Helper()
	scanFormat = "text"
	scanOutput = ""
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetArgs(append([]string{"scan"}, args...))
	err = rootCmd.Execute()
	return buf.String(), err
}

func runScan(t *testing.T, args ...string) string {
	t.Helper()
	out, err := execScan(t, args...)
	if err != nil {
		t.Fatalf("jit scan %v: %v", args, err)
	}
	return out
}

func TestScanCommandTextFormat(t *testing.T) {
	home := withFixtureHome(t)
	if err := os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export STRIPE_API_KEY=sk_test_4eC39HqLyjWDarjtT1zdp7dc\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// The default text view is the coverage triage (2026-07-28 redesign):
	// secrets counted, the migrate manifest, no scanner vocabulary.
	out := runScan(t, "--format", "text")
	if !strings.Contains(out, "YOUR SECRETS:") {
		t.Errorf("expected the coverage ledger, got:\n%s", out)
	}
	if !strings.Contains(out, "jit will protect these") || !strings.Contains(out, ".zshrc") {
		t.Errorf("expected the migrate manifest naming the planted file, got:\n%s", out)
	}
	if strings.Contains(out, "RISK LEVEL:") {
		t.Errorf("the default view must not show the inventory banner (that's --full), got:\n%s", out)
	}
	// Must name the value this test actually planted, or the assertion is
	// vacuous — it would pass for any output at all.
	if strings.Contains(out, "sk_test_4eC39HqLyjWDarjtT1zdp7dc") {
		t.Fatal("CLI output must never contain the raw secret value")
	}

	// --full is the old detailed inventory, unchanged. The flag variable is
	// package-level and cobra does not reset it between executions in one
	// test process, so restore it for whoever runs next.
	t.Cleanup(func() { scanFull = false })
	full := runScan(t, "--format", "text", "--full")
	if !strings.Contains(full, "RISK LEVEL:") {
		t.Errorf("--full should show the risk level banner, got:\n%s", full)
	}
	if !strings.Contains(full, "Shell Configs") {
		t.Errorf("--full should show category sections, got:\n%s", full)
	}
	if strings.Contains(full, "sk_test_4eC39HqLyjWDarjtT1zdp7dc") {
		t.Fatal("--full output must never contain the raw secret value")
	}
}

func TestScanCommandNDJSONFormat(t *testing.T) {
	home := withFixtureHome(t)
	if err := os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export STRIPE_API_KEY=sk_test_4eC39HqLyjWDarjtT1zdp7dc\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out := runScan(t, "--format", "ndjson")

	if !strings.Contains(out, `"record_type":"finding"`) {
		t.Errorf("expected at least one finding record, got:\n%s", out)
	}
	if !strings.Contains(out, `"record_type":"scan_summary"`) {
		t.Errorf("expected a closing scan_summary record, got:\n%s", out)
	}
	if strings.Contains(out, "sk_test_fixture_value") {
		t.Fatal("CLI output must never contain the raw secret value")
	}
}

func TestScanCommandCleanFixture(t *testing.T) {
	withFixtureHome(t) // empty fixture, nothing planted
	out := runScan(t, "--format", "text")
	if !strings.Contains(out, "Nothing exposed") {
		t.Errorf("expected the clean-machine line on an empty fixture home, got:\n%s", out)
	}
	t.Cleanup(func() { scanFull = false })
	full := runScan(t, "--format", "text", "--full")
	if !strings.Contains(full, "RISK LEVEL: CLEAN") {
		t.Errorf("expected --full's clean banner on an empty fixture home, got:\n%s", full)
	}
}

func TestScanCommandMarkdownFormat(t *testing.T) {
	home := withFixtureHome(t)
	if err := os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export STRIPE_API_KEY=sk_test_4eC39HqLyjWDarjtT1zdp7dc\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out := runScan(t, "--format", "markdown")

	if !strings.Contains(out, "# jit scan report") {
		t.Errorf("expected a markdown title heading, got:\n%s", out)
	}
	if !strings.Contains(out, "### Shell Configs") {
		t.Errorf("expected a Shell Configs section heading, got:\n%s", out)
	}
	if strings.Contains(out, "sk_test_fixture_value") {
		t.Fatal("CLI output must never contain the raw secret value")
	}
}

func TestScanCommandOutputToFile(t *testing.T) {
	home := withFixtureHome(t)
	if err := os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export STRIPE_API_KEY=sk_test_4eC39HqLyjWDarjtT1zdp7dc\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	reportPath := filepath.Join(t.TempDir(), "report.md")
	stdout, err := execScan(t, "--format", "markdown", "--output", reportPath)
	if err != nil {
		t.Fatalf("jit scan --output: %v", err)
	}

	if !strings.Contains(stdout, "Report written to "+reportPath) {
		t.Errorf("expected a confirmation message on stdout, got:\n%s", stdout)
	}

	contents, err := os.ReadFile(reportPath) // #nosec G304 -- test-controlled path under t.TempDir()
	if err != nil {
		t.Fatalf("expected %s to exist: %v", reportPath, err)
	}
	if !strings.Contains(string(contents), "# jit scan report") {
		t.Errorf("expected the report file to contain markdown output, got:\n%s", contents)
	}
	if strings.Contains(string(contents), "\x1b[") {
		t.Error("report file must not contain raw ANSI escape codes")
	}
	if strings.Contains(string(contents), "sk_test_fixture_value") {
		t.Fatal("report file must never contain the raw secret value")
	}
}

func TestScanCommandRejectsUnknownFormat(t *testing.T) {
	withFixtureHome(t)
	_, err := execScan(t, "--format", "yaml")
	if err == nil {
		t.Fatal("expected an error for an unrecognized --format value, got nil")
	}
	if !strings.Contains(err.Error(), `unknown --format "yaml"`) {
		t.Errorf("expected the error to name the bad format value, got: %v", err)
	}
}

// TestScanCommandRejectsMissingPath: a path argument that doesn't exist is an
// error, not a silently empty scan — the same fail-loud choice `jit migrate
// <path>` makes, so a typo can't masquerade as a clean result.
func TestScanCommandRejectsMissingPath(t *testing.T) {
	withFixtureHome(t)
	_, err := execScan(t, "definitely-not-a-real-path.txt")
	if err == nil {
		t.Fatal("expected an error for a nonexistent path argument, got nil")
	}
	if !strings.Contains(err.Error(), "no such file or directory") {
		t.Errorf("expected the error to name the missing path, got: %v", err)
	}
}

// TestScanCommandScansNamedFile: pointing scan at a file classifies just that
// file. A bare JWT in a plainly-named file — invisible to the name-gated full
// scan — is caught as an Exposed Secret, and never printed in the clear.
func TestScanCommandScansNamedFile(t *testing.T) {
	withFixtureHome(t)
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20iLCJpZCI6MX0." +
		"i-Bx9F2fjO5nvvo_hlUFY6bvnAOeTs68BiTBa-1zfoE"
	tokenPath := filepath.Join(t.TempDir(), "token.txt")
	if err := os.WriteFile(tokenPath, []byte(jwt), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out := runScan(t, tokenPath)

	if !strings.Contains(out, "Exposed Secrets") {
		t.Errorf("expected an Exposed Secrets section, got:\n%s", out)
	}
	if !strings.Contains(out, "JSON Web Token (JWT)") {
		t.Errorf("expected the JWT to be identified, got:\n%s", out)
	}
	if strings.Contains(out, jwt) {
		t.Fatal("CLI output must never contain the raw token value")
	}
}
