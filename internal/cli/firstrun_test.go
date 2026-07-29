// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/audit"
)

// frRec records what the first-run flow did through its seams.
type frRec struct {
	scanRoots        []string
	steps            [][]string
	confirmCalled    bool
	confirmReturn    bool
	vaultReadyCalled bool
	vaultReadyReturn bool
}

// baseDeps is a fresh + interactive machine with nothing exposed and every
// prompt declined. Each test overrides only the seams it cares about.
func baseDeps() (*firstRunDeps, *frRec) {
	rec := &frRec{}
	d := &firstRunDeps{
		vaultReady: func() bool { rec.vaultReadyCalled = true; return rec.vaultReadyReturn },
		isTTY:      func() bool { return true },
		cwd:        func() (string, error) { return "/proj", nil },
		homeDir:    func() (string, error) { return "/home/u", nil },
		scan: func(root string) ([]audit.Finding, audit.ScanSummary, error) {
			rec.scanRoots = append(rec.scanRoots, root)
			return nil, audit.ScanSummary{}, nil
		},
		render:  func(io.Writer, []audit.Finding, audit.ScanSummary) {},
		confirm: func(string) bool { rec.confirmCalled = true; return rec.confirmReturn },
		runStep: func(args ...string) error { rec.steps = append(rec.steps, args); return nil },
	}
	return d, rec
}

// findingsFor makes a scan seam returning n findings for the given root, 0 for
// any other root, and recording every root scanned.
func findingsFor(rec *frRec, targetRoot string, n int) func(string) ([]audit.Finding, audit.ScanSummary, error) {
	return func(root string) ([]audit.Finding, audit.ScanSummary, error) {
		rec.scanRoots = append(rec.scanRoots, root)
		if root == targetRoot {
			return make([]audit.Finding, n), audit.ScanSummary{}, nil
		}
		return nil, audit.ScanSummary{}, nil
	}
}

func newCmd() (*cobra.Command, *bytes.Buffer) {
	var buf bytes.Buffer
	cmd := &cobra.Command{Use: "jit"}
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	return cmd, &buf
}

func runFR(t *testing.T, d *firstRunDeps) string {
	t.Helper()
	cmd, buf := newCmd()
	if err := firstRun(cmd, *d); err != nil {
		t.Fatalf("firstRun returned error: %v", err)
	}
	return buf.String()
}

// The two guard cases: an already-configured vault and a non-interactive
// shell both fall through to help with no scan, no prompt, no side effects.
func TestFirstRun_GuardsFallThroughToHelp(t *testing.T) {
	for _, tc := range []struct {
		name             string
		tweak            func(*firstRunDeps, *frRec)
		wantVaultChecked bool
	}{
		{"vault already set up", func(d *firstRunDeps, rec *frRec) { rec.vaultReadyReturn = true }, true},
		// Non-interactive must short-circuit BEFORE the keychain read, so a
		// piped or CI `jit` never triggers an OS keychain-permission prompt.
		{"not a TTY", func(d *firstRunDeps, rec *frRec) { d.isTTY = func() bool { return false } }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, rec := baseDeps()
			tc.tweak(d, rec)
			out := runFR(t, d)
			if strings.Contains(out, "Set up the vault now?") {
				t.Errorf("onboarding offered in guard case; output:\n%s", out)
			}
			if len(rec.scanRoots) != 0 {
				t.Errorf("scanned in guard case: %v", rec.scanRoots)
			}
			if rec.confirmCalled || len(rec.steps) != 0 {
				t.Errorf("side effects in guard case: confirm=%v steps=%v", rec.confirmCalled, rec.steps)
			}
			if rec.vaultReadyCalled != tc.wantVaultChecked {
				t.Errorf("vaultReady called = %v, want %v (non-interactive must not read the keychain)", rec.vaultReadyCalled, tc.wantVaultChecked)
			}
		})
	}
}

func TestFirstRun_NoFindingsCongratulates(t *testing.T) {
	d, rec := baseDeps() // scans return 0 everywhere
	out := runFR(t, d)
	if !strings.Contains(out, "No plaintext secrets found") {
		t.Errorf("missing the clean-machine message; output:\n%s", out)
	}
	if rec.confirmCalled {
		t.Error("prompted for setup with nothing to fix")
	}
	if len(rec.steps) != 0 {
		t.Errorf("ran setup steps with nothing to fix: %v", rec.steps)
	}
	if want := []string{"/proj", "/home/u"}; !reflect.DeepEqual(rec.scanRoots, want) {
		t.Errorf("scan order = %v, want %v (cwd probe then machine-wide)", rec.scanRoots, want)
	}
}

func TestFirstRun_ProjectFindingsScopeToLocal(t *testing.T) {
	d, rec := baseDeps()
	d.scan = findingsFor(rec, "/proj", 2)
	rec.confirmReturn = false
	out := runFR(t, d)
	if !strings.Contains(out, "this project") {
		t.Errorf("project-scoped copy missing; output:\n%s", out)
	}
	if !strings.Contains(out, "jit migrate .") {
		t.Errorf("should offer `jit migrate .` for a project; output:\n%s", out)
	}
	if !rec.confirmCalled {
		t.Error("did not reach the setup prompt")
	}
	if want := []string{"/proj"}; !reflect.DeepEqual(rec.scanRoots, want) {
		t.Errorf("scan roots = %v, want %v (no machine-wide fallback once the project has findings)", rec.scanRoots, want)
	}
	if len(rec.steps) != 0 {
		t.Errorf("ran steps after declining: %v", rec.steps)
	}
}

func TestFirstRun_MachineWideFallback(t *testing.T) {
	d, rec := baseDeps()
	d.scan = findingsFor(rec, "/home/u", 3) // nothing in cwd, findings machine-wide
	out := runFR(t, d)
	if !strings.Contains(out, "your machine") {
		t.Errorf("machine-scoped copy missing; output:\n%s", out)
	}
	if !strings.Contains(out, "jit migrate") {
		t.Errorf("should offer bare jit migrate for a machine-wide reveal; output:\n%s", out)
	}
	if want := []string{"/proj", "/home/u"}; !reflect.DeepEqual(rec.scanRoots, want) {
		t.Errorf("scan order = %v, want %v", rec.scanRoots, want)
	}
}

func TestFirstRun_ProjectFindingsScopedChain(t *testing.T) {
	d, rec := baseDeps()
	d.scan = findingsFor(rec, "/proj", 1)
	rec.confirmReturn = true
	out := runFR(t, d)
	if !strings.Contains(out, "exposed in this project") {
		t.Errorf("project-scoped banner missing; output:\n%s", out)
	}
	wantSteps := [][]string{{"vault", "init"}, {"migrate", "."}}
	if !reflect.DeepEqual(rec.steps, wantSteps) {
		t.Errorf("guided chain = %v, want %v", rec.steps, wantSteps)
	}
}

func TestFirstRun_YesRunsGuidedChainInOrder(t *testing.T) {
	d, rec := baseDeps()
	d.scan = findingsFor(rec, "/home/u", 2) // machine-wide → bare migrate
	rec.confirmReturn = true
	runFR(t, d)
	wantSteps := [][]string{{"vault", "init"}, {"migrate"}}
	if !reflect.DeepEqual(rec.steps, wantSteps) {
		t.Errorf("guided chain = %v, want %v", rec.steps, wantSteps)
	}
}
