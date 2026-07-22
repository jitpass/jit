// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

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
	if err := os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export STRIPE_API_KEY=sk_test_fixture_value\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out := runScan(t, "--format", "text")

	if !strings.Contains(out, "RISK LEVEL:") {
		t.Errorf("expected a risk level banner, got:\n%s", out)
	}
	if !strings.Contains(out, "Shell Configs") {
		t.Errorf("expected a Shell Configs section, got:\n%s", out)
	}
	if strings.Contains(out, "sk_test_fixture_value") {
		t.Fatal("CLI output must never contain the raw secret value")
	}
}

func TestScanCommandNDJSONFormat(t *testing.T) {
	home := withFixtureHome(t)
	if err := os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export STRIPE_API_KEY=sk_test_fixture_value\n"), 0600); err != nil {
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
	if !strings.Contains(out, "RISK LEVEL: CLEAN") {
		t.Errorf("expected a clean result on an empty fixture home, got:\n%s", out)
	}
}

func TestScanCommandMarkdownFormat(t *testing.T) {
	home := withFixtureHome(t)
	if err := os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export STRIPE_API_KEY=sk_test_fixture_value\n"), 0600); err != nil {
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
	if err := os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export STRIPE_API_KEY=sk_test_fixture_value\n"), 0600); err != nil {
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

// TestScanCommandRejectsUnexpectedPositionalArg is a real bug's regression
// test: scan had no Args validator at all (unlike every other subcommand
// in this package), so a stray positional argument — e.g. `jit scan
// help`, typed expecting help text — was silently accepted and ignored,
// running a real scan instead of erroring. cobra.NoArgs makes this fail
// loud like every other zero-argument command already does.
func TestScanCommandRejectsUnexpectedPositionalArg(t *testing.T) {
	withFixtureHome(t)
	_, err := execScan(t, "help")
	if err == nil {
		t.Fatal("expected an error for an unexpected positional argument, got nil")
	}
}
