// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/vault"
)

// stubKeychain replaces the two package vars gatherVaultIntegrityFindings
// reaches the outside world through. Both MUST be stubbed in any test that
// exercises the master-key probe: the real vaultHasMasterKey reads the
// PRODUCTION keychain, so an un-stubbed test asserts whatever the machine
// running it happens to hold (true on a developer's Mac, false on a CI
// runner), and the real interactiveTTY is false under `go test`, which would
// skip the probe entirely and make the test pass vacuously.
func stubKeychain(t *testing.T, hasKey, interactive bool) {
	t.Helper()
	origKey, origTTY := vaultHasMasterKey, interactiveTTY
	vaultHasMasterKey = func() bool { return hasKey }
	interactiveTTY = func() bool { return interactive }
	t.Cleanup(func() {
		vaultHasMasterKey = origKey
		interactiveTTY = origTTY
	})
}

// fixtureVault builds the read-only Vault the integrity checks take, rooted
// where withFixtureHome puts it.
func fixtureVault(home string) *vault.Vault {
	return &vault.Vault{Root: fixtureRoot(home), RecipientID: "test"}
}

func fixtureRoot(home string) string {
	return filepath.Join(home, "Library", "Application Support", "jitpass")
}

// TestVaultKeyMissingIsAHardProblem is the check doctor was most
// conspicuously missing: every envelope passes Verify (structure and
// recipient are intact) and not one of them can be decrypted, because the
// master key is gone from the keychain. Before this, doctor printed
// "all resolve cleanly" over a vault that had become unreadable.
func TestVaultKeyMissingIsAHardProblem(t *testing.T) {
	home := withFixtureHome(t)
	plantVaultSecret(t, home, "aws/s3-access-key")
	stubKeychain(t, false, true)

	findings := gatherVaultIntegrityFindings(fixtureRoot(home), fixtureVault(home))
	if len(findings) != 1 || findings[0].Kind != kindVaultKey {
		t.Fatalf("expected one vault_key finding, got %+v", findings)
	}
	if findings[0].Kind.warning() {
		t.Error("a missing master key must be a hard problem, not advisory")
	}
	if !strings.Contains(findings[0].Detail, "1 secret") {
		t.Errorf("expected the finding to say how much is at stake, got: %s", findings[0].Detail)
	}
}

// TestVaultKeyPresentIsSilent — a healthy vault says nothing.
func TestVaultKeyPresentIsSilent(t *testing.T) {
	home := withFixtureHome(t)
	plantVaultSecret(t, home, "aws/s3-access-key")
	stubKeychain(t, true, true)

	if findings := gatherVaultIntegrityFindings(fixtureRoot(home), fixtureVault(home)); len(findings) != 0 {
		t.Errorf("a healthy vault must be silent, got %+v", findings)
	}
}

// TestVaultKeyEmptyVaultIsSilent — no secrets and no key is a machine that
// hasn't run `jit vault init`. That's a state, not a fault, and `jit status`
// already reports it; doctor must not call it a problem.
func TestVaultKeyEmptyVaultIsSilent(t *testing.T) {
	home := withFixtureHome(t)
	stubKeychain(t, false, true)

	if findings := gatherVaultIntegrityFindings(fixtureRoot(home), fixtureVault(home)); len(findings) != 0 {
		t.Errorf("an empty vault with no key must be silent, got %+v", findings)
	}
}

// TestVaultKeyProbeSkippedWhenNotInteractive locks in the deliberate gate:
// reading a keychain item can raise the OS's own "allow access" dialog when
// the requesting binary's signature changed (a re-signed jit build does
// exactly that), so a piped or CI `jit doctor` must never risk blocking on a
// prompt nobody is there to dismiss. firstrun.go gates the same call on the
// same test for the same reason.
func TestVaultKeyProbeSkippedWhenNotInteractive(t *testing.T) {
	home := withFixtureHome(t)
	plantVaultSecret(t, home, "aws/s3-access-key")

	probed := false
	origKey, origTTY := vaultHasMasterKey, interactiveTTY
	vaultHasMasterKey = func() bool { probed = true; return false }
	interactiveTTY = func() bool { return false }
	t.Cleanup(func() { vaultHasMasterKey, interactiveTTY = origKey, origTTY })

	findings := gatherVaultIntegrityFindings(fixtureRoot(home), fixtureVault(home))
	if probed {
		t.Error("the keychain must not be read on a non-interactive run")
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings when the probe is skipped, got %+v", findings)
	}
}

// TestRekeyInProgressIsAHardProblem — while the marker exists every vault
// write is refused (errRekeyInProgress), and doctor used to report a clean
// bill of health, leaving the user to discover the state from whichever
// command failed next.
func TestRekeyInProgressIsAHardProblem(t *testing.T) {
	home := withFixtureHome(t)
	root := fixtureRoot(home)
	stubKeychain(t, true, true)
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(rekeyMarkerPath(root), []byte("started\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	findings := gatherVaultIntegrityFindings(root, fixtureVault(home))
	if len(findings) != 1 || findings[0].Kind != kindRekey {
		t.Fatalf("expected one rekey finding, got %+v", findings)
	}
	if findings[0].Kind.warning() {
		t.Error("an unfinished rekey must be a hard problem: it blocks every vault write")
	}
}

// TestAgentFindingsSurfaceUnreachableError pins the detail doctor used to
// throw away. gatherAgentStatus reports a hung or protocol-mismatched agent
// with Running=false plus an Error, which fell through to "installed but not
// running, it may have crashed" — the wrong fault, and without the one piece
// of information someone filing a bug needs.
func TestAgentFindingsSurfaceUnreachableError(t *testing.T) {
	st := statusAgent{Installed: true, Error: "protocol mismatch: unexpected frame"}

	findings := agentFindingsFrom(t.TempDir(), st)
	if len(findings) != 1 || findings[0].Kind != kindService {
		t.Fatalf("expected one service finding, got %+v", findings)
	}
	if !strings.Contains(findings[0].Detail, "protocol mismatch: unexpected frame") {
		t.Errorf("expected the agent's own error text in the finding, got: %s", findings[0].Detail)
	}
	if strings.Contains(findings[0].Detail, "may have crashed") {
		t.Errorf("an unreachable agent must not be reported as a plain crash, got: %s", findings[0].Detail)
	}
}

// TestWrapSeverityIsPerCheckNotPerCommand is the whole reason `jit wrap
// doctor` could be retired. The two commands used to disagree on identical
// facts — every failed check exited non-zero there and was advisory here —
// and the reasoning behind that split (a CI job that doesn't put the shim dir
// on PATH must not fail) was right about ONE check and wrong about the rest.
// Severity belongs on the check.
func TestWrapSeverityIsPerCheckNotPerCommand(t *testing.T) {
	home := withFixtureHome(t)
	if err := os.MkdirAll(filepath.Join(home, ".jit"), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, ".jit", "wrap.json"),
		[]byte(`{"tools":{"kubectl":{"profile":"wrap-kubectl"}}}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("SHELL", "/bin/zsh")
	t.Setenv("PATH", "/usr/bin") // shim dir absent -> the environmental case

	findings, _ := wrapFindings()
	var broken, environmental int
	for _, f := range findings {
		switch f.Kind {
		case kindWrap:
			broken++
		case kindWrapEnv:
			environmental++
		default:
			t.Errorf("unexpected kind %q from wrapFindings", f.Kind)
		}
	}
	if broken == 0 {
		t.Error("a missing shim dir and symlink are damage, and must be hard problems")
	}
	if environmental == 0 {
		t.Error("shim dir absent from THIS PATH must stay advisory, or CI fails for its own environment")
	}
	if kindWrap.warning() {
		t.Error("a damaged wrap installation must fail the run")
	}
	if !kindWrapEnv.warning() {
		t.Error("an environmental wrap complaint must never fail the run")
	}
}

// TestWrapFindingsReportPassingChecks: positive confirmation was the one
// thing the standalone command could say that the rollup couldn't. --verbose
// surfaces these, which is what makes `jit doctor --wrap` a full replacement.
func TestWrapFindingsReportPassingChecks(t *testing.T) {
	withFixtureHome(t) // no wrap.json at all
	_, ok := wrapFindings()
	if len(ok) == 0 {
		t.Error("expected at least one passing check to report on a machine with no wrapped tools")
	}
}

// TestAgentFindingsInstalledNotRunning confirms the unreachable case above
// didn't swallow the ordinary crashed/mid-restart one.
func TestAgentFindingsInstalledNotRunning(t *testing.T) {
	findings := agentFindingsFrom(t.TempDir(), statusAgent{Installed: true})
	if len(findings) != 1 || !strings.Contains(findings[0].Detail, "may have crashed") {
		t.Errorf("expected the installed-but-not-running advice, got %+v", findings)
	}
}
