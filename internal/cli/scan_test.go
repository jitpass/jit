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
	// Every scan flag, not just the two that caused a leak once: the point of
	// centralizing this is that adding a flag never requires remembering to
	// reset it in each test again.
	scanFormat = "text"
	scanOutput = ""
	scanScore = false
	scanUnfiltered = false
	scanFull = false
	scanFailOn = ""
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
	if !strings.Contains(full, "— exposure") {
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
	if !strings.Contains(full, "CLEAN — exposure 0/100") {
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

	// A saved report is an inventory of where this machine keeps its
	// credentials, so it gets the owner-only posture every other file jit
	// writes has — os.Create's 0666-minus-umask would leave it readable by
	// anyone with an account here.
	fi, err := os.Stat(reportPath)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("report file mode = %#o, want 0600", perm)
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

// TestScanFailOnDefaultAlwaysExitsZero pins the contract that matters most for
// backward compatibility: without --fail-on, a scan that finds critical
// secrets still exits 0. Anyone who already runs `jit scan` in a script must
// not start failing because the gate was added.
func TestScanFailOnDefaultAlwaysExitsZero(t *testing.T) {
	withFixtureHome(t)
	dir := t.TempDir()
	env := filepath.Join(dir, ".env")
	if err := os.WriteFile(env, []byte("STRIPE_LIVE=sk_live_4eC39HqLyjWDarjtT1zdp7dc\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := execScan(t, dir); err != nil {
		t.Fatalf("a scan with findings and no --fail-on must exit 0, got: %v", err)
	}
}

// TestScanFailOnTripsWithExitCode2: a tripped gate is a RESULT, so it carries
// exit 2 rather than the plain 1 a broken command returns — CI has to be able
// to tell "secrets found" from "the scan itself failed".
func TestScanFailOnTripsWithExitCode2(t *testing.T) {
	withFixtureHome(t)
	dir := t.TempDir()
	env := filepath.Join(dir, ".env")
	if err := os.WriteFile(env, []byte("STRIPE_LIVE=sk_live_4eC39HqLyjWDarjtT1zdp7dc\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := execScan(t, dir, "--fail-on", "any")
	if err == nil {
		t.Fatal("expected --fail-on any to trip on a scan with findings, got nil")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected an *ExitError so main() can set the status, got %T: %v", err, err)
	}
	if exitErr.Code != 2 {
		t.Errorf("expected exit code 2, got %d", exitErr.Code)
	}
}

// TestScanFailOnCleanScanPasses: the gate must not fire on a clean machine,
// otherwise it can never be left switched on in CI.
func TestScanFailOnCleanScanPasses(t *testing.T) {
	withFixtureHome(t)
	if _, err := execScan(t, t.TempDir(), "--fail-on", "any"); err != nil {
		t.Fatalf("a clean scan must pass --fail-on any, got: %v", err)
	}
}

// TestScanFailOnRespectsThreshold: a threshold ABOVE the scan's risk level
// passes. Without this the flag would collapse into a single "any findings"
// switch and the level vocabulary would be decorative.
func TestScanFailOnRespectsThreshold(t *testing.T) {
	withFixtureHome(t)
	dir := t.TempDir()
	env := filepath.Join(dir, ".env")
	// A single test key: enough to be a finding, not enough to reach CRITICAL.
	if err := os.WriteFile(env, []byte("STRIPE_KEY=sk_test_4eC39HqLyjWDarjtT1zdp7dc\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	out, err := execScan(t, dir, "--score", "--fail-on", "critical")
	if err != nil {
		t.Fatalf("--fail-on critical must not trip below CRITICAL (score line: %q), got: %v", out, err)
	}
	if !strings.Contains(out, "Exposure:") {
		t.Errorf("expected the score line to print, got: %q", out)
	}
}

// TestFailOnResultIncompleteScanTrips: a scan that couldn't read a category
// (DegradedScanners > 0) must not pass a --fail-on gate even when the readable
// categories came back clean — a partial scan cannot certify the machine is
// below the threshold, and a CI gate reading exit 0 would treat an incomplete
// scan as all-clear. The trip is on the incompleteness itself; without a gate
// (--fail-on unused) a degraded scan is still not an error.
func TestFailOnResultIncompleteScanTrips(t *testing.T) {
	tripped := func(err error) bool {
		var exitErr *ExitError
		return errors.As(err, &exitErr) && exitErr.Code == scanFailOnExitCode
	}

	// Degraded + clean risk + a gate: must trip on the incompleteness.
	if err := failOnResult("any", "clean", 0, 1); !tripped(err) {
		t.Errorf("an incomplete scan must trip --fail-on any even when clean, got: %v", err)
	}
	// Degraded + a threshold the readable findings didn't reach: still trips.
	if err := failOnResult("critical", "low", 10, 2); !tripped(err) {
		t.Errorf("an incomplete scan must trip regardless of the readable risk level, got: %v", err)
	}
	// The message names incompleteness, not a risk level, so the operator
	// knows why the gate fired.
	if err := failOnResult("any", "clean", 0, 1); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Errorf("the trip message should explain the scan was incomplete, got: %v", err)
	}
	// A complete clean scan under a gate still passes (regression guard).
	if err := failOnResult("any", "clean", 0, 0); err != nil {
		t.Errorf("a complete clean scan must still pass --fail-on any, got: %v", err)
	}
	// No gate: a degraded scan is a report, not a failure.
	if err := failOnResult("", "clean", 0, 3); err != nil {
		t.Errorf("without --fail-on, a degraded scan must not error, got: %v", err)
	}
}

// TestScanFailOnRejectsBadThreshold: a typo'd threshold is a usage error
// (exit 1), never a silently-disabled gate, and never mistaken for a trip.
// "clean" is rejected too — as a threshold it would read "fail when clean".
func TestScanFailOnRejectsBadThreshold(t *testing.T) {
	withFixtureHome(t)
	for _, level := range []string{"bogus", "clean", ""} {
		if level == "" {
			continue // empty means "flag unused", covered above
		}
		_, err := execScan(t, t.TempDir(), "--fail-on", level)
		if err == nil {
			t.Fatalf("--fail-on %q must be rejected, got nil", level)
		}
		var exitErr *ExitError
		if errors.As(err, &exitErr) {
			t.Errorf("--fail-on %q is a usage error (exit 1), not a gate trip (exit 2)", level)
		}
		if !strings.Contains(err.Error(), "--fail-on") {
			t.Errorf("expected the error to name the flag, got: %v", err)
		}
	}
}

// TestScanRefusedK8sManifestNotPromisedToMigrate: the wired
// K8sMigratable hook (design/dry-run-refactor.md D5) makes scan tell the
// truth about a Secret manifest migrate will refuse — a real dogfood run
// had scan promise Secret.yaml under "jit will protect these" (+3%),
// then migrate skip it as complex. The refused manifest must carry
// migrate's reason and no `jit migrate <path>` recommendation.
func TestScanRefusedK8sManifestNotPromisedToMigrate(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	dir := filepath.Join(home, "code", "k8s")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// data: mixed with stringData: in one document — migrate's classifier
	// refuses this shape (k8ssecret.go), so scan must not promise it.
	manifest := filepath.Join(dir, "Secret.yaml")
	if err := os.WriteFile(manifest, []byte(`apiVersion: v1
kind: Secret
metadata:
  name: my-secret
data:
  password: aHVudGVyMg==
stringData:
  token: vlt09zXcVbNm2qWe4rTy6uIo8p42
`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out := runScan(t, manifest)
	if !strings.Contains(out, "can't rewrite provably right") {
		t.Errorf("expected migrate's refusal reason in the report, got:\n%s", out)
	}
	if strings.Contains(out, "jit migrate "+manifest) || strings.Contains(out, "jit migrate ~/code/k8s/Secret.yaml") {
		t.Errorf("scan must not recommend migrating a manifest migrate refuses, got:\n%s", out)
	}
}
