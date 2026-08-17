// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/keychainwrap"
	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

// stubKeychain replaces the package var gatherVaultIntegrityFindings reaches
// the keychain through. It MUST be stubbed in any test that exercises the
// master-key probe: the real vaultMasterKeyPresence reads the PRODUCTION
// keychain, so an un-stubbed test would assert whatever the machine running it
// happens to hold (present on a developer's Mac, absent on a CI runner).
func stubKeychain(t *testing.T, presence keychainwrap.MEKPresence) {
	t.Helper()
	orig := vaultMasterKeyPresence
	vaultMasterKeyPresence = func() keychainwrap.MEKPresence { return presence }
	t.Cleanup(func() { vaultMasterKeyPresence = orig })
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
	stubKeychain(t, keychainwrap.MEKAbsent)

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
	stubKeychain(t, keychainwrap.MEKPresent)

	if findings := gatherVaultIntegrityFindings(fixtureRoot(home), fixtureVault(home)); len(findings) != 0 {
		t.Errorf("a healthy vault must be silent, got %+v", findings)
	}
}

// TestVaultKeyEmptyVaultIsSilent — no secrets and no key is a machine that
// hasn't run `jit vault init`. That's a state, not a fault, and `jit status`
// already reports it; doctor must not call it a problem.
func TestVaultKeyEmptyVaultIsSilent(t *testing.T) {
	home := withFixtureHome(t)
	stubKeychain(t, keychainwrap.MEKAbsent)

	if findings := gatherVaultIntegrityFindings(fixtureRoot(home), fixtureVault(home)); len(findings) != 0 {
		t.Errorf("an empty vault with no key must be silent, got %+v", findings)
	}
}

// TestVaultKeyMissingIsDetectedNonInteractively is the behavior the probe
// rework restored. Because MEKPresence reads only the item's presence and
// never prompts, doctor no longer skips the master-key check on a
// non-interactive run (a piped `jit doctor --format json`, a CI job) to avoid
// a possible dialog: a key that is genuinely gone is caught in every context,
// not just for a human at a TTY. There is no interactivity input any more —
// a stubbed MEKAbsent stands for "the real no-prompt probe found it gone".
func TestVaultKeyMissingIsDetectedNonInteractively(t *testing.T) {
	home := withFixtureHome(t)
	plantVaultSecret(t, home, "aws/s3-access-key")
	stubKeychain(t, keychainwrap.MEKAbsent)

	findings := gatherVaultIntegrityFindings(fixtureRoot(home), fixtureVault(home))
	if len(findings) != 1 || findings[0].Kind != kindVaultKey {
		t.Fatalf("a genuinely missing key must be reported in every context, got %+v", findings)
	}
}

// TestVaultKeyIndeterminateIsSilent: when presence can't be established
// without interaction (a keychain error, or a query MEKPresence refused rather
// than prompt), doctor reports neither present nor gone. Silence beats a false
// "your master key is missing" alarm over a vault that is actually fine.
func TestVaultKeyIndeterminateIsSilent(t *testing.T) {
	home := withFixtureHome(t)
	plantVaultSecret(t, home, "aws/s3-access-key")
	stubKeychain(t, keychainwrap.MEKIndeterminate)

	if findings := gatherVaultIntegrityFindings(fixtureRoot(home), fixtureVault(home)); len(findings) != 0 {
		t.Errorf("an indeterminate probe must stay silent, not raise a false alarm, got %+v", findings)
	}
}

// TestRekeyInProgressIsAHardProblem — while the marker exists every vault
// write is refused (errRekeyInProgress), and doctor used to report a clean
// bill of health, leaving the user to discover the state from whichever
// command failed next.
func TestRekeyInProgressIsAHardProblem(t *testing.T) {
	home := withFixtureHome(t)
	root := fixtureRoot(home)
	stubKeychain(t, keychainwrap.MEKPresent)
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
// didn't swallow the ordinary installed-but-not-running one, and that doctor
// derives its wording from installedNotRunningParts (which phrases the state
// from launchd's job record — faked here so the machine running the test
// can't change the expected variant).
func TestAgentFindingsInstalledNotRunning(t *testing.T) {
	restore := launchctlRun
	t.Cleanup(func() { launchctlRun = restore })
	launchctlRun = func(args ...string) ([]byte, error) {
		return []byte(`Could not find service "com.jitpass.agent" in domain for user gui: 501`), errors.New("exit status 113")
	}

	findings := agentFindingsFrom(t.TempDir(), statusAgent{Installed: true})
	if len(findings) != 1 || !strings.Contains(findings[0].Detail, "launchd has dropped it") {
		t.Errorf("expected the launchd-dropped-it advice for a not-loaded job, got %+v", findings)
	}
	if !strings.Contains(findings[0].Action, "jit service restart") {
		t.Errorf("the action must name the restart, got %q", findings[0].Action)
	}

	wantDetail, _ := installedNotRunningParts("the service")
	if findings[0].Detail != wantDetail {
		t.Errorf("doctor's detail must BE installedNotRunningParts's, not a copy: %q vs %q", findings[0].Detail, wantDetail)
	}
}

// mcpTestSetup builds a HOME with a global profile store and a project cwd
// holding one jit-wrapped .mcp.json, returning cwd. Both mcpFindings' own
// os.UserHomeDir and profile.GlobalRoot read $HOME, so setting it is what
// keeps the check off the developer's real machine.
func mcpTestSetup(t *testing.T, entry string) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	cwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(cwd, ".mcp.json"),
		[]byte(`{"mcpServers":{"srv":`+entry+`}}`), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	return cwd
}

func mcpTestJitBinary(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "jit")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil { // #nosec G306 -- a fake executable, by design
		t.Fatalf("writing fake jit: %v", err)
	}
	return path
}

func mcpTestProfile(t *testing.T, name string) {
	t.Helper()
	root, err := profile.GlobalRoot()
	if err != nil {
		t.Fatalf("GlobalRoot: %v", err)
	}
	path, err := profile.Path(root, name)
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte("API_KEY: "+name+"/API_KEY\n"), 0o600); err != nil {
		t.Fatalf("writing manifest: %v", err)
	}
}

func TestMCPFindingsReportsVanishedJitBinary(t *testing.T) {
	cwd := mcpTestSetup(t, `{"command":"/nonexistent/bin/jit","args":["run","--profile","mcp-srv","--","uv","run","srv"]}`)
	mcpTestProfile(t, "mcp-srv")

	findings := mcpFindings(cwd)
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want exactly one", findings)
	}
	if findings[0].Kind != kindMCP {
		t.Errorf("kind = %q, want %q", findings[0].Kind, kindMCP)
	}
	if findings[0].Kind.warning() {
		t.Error("a server that cannot launch is a hard problem, not a warning")
	}
	if !strings.Contains(findings[0].Detail, "/nonexistent/bin/jit") {
		t.Errorf("detail %q must name the missing binary", findings[0].Detail)
	}
}

func TestMCPFindingsHealthyEntryIsSilent(t *testing.T) {
	jit := mcpTestJitBinary(t)
	cwd := mcpTestSetup(t, `{"command":"`+jit+`","args":["run","--profile","mcp-srv","--","uv","run","srv"]}`)
	mcpTestProfile(t, "mcp-srv")

	if findings := mcpFindings(cwd); len(findings) != 0 {
		t.Errorf("findings = %+v, want none for a healthy entry", findings)
	}
}

func TestMCPFindingsReportsVanishedProfile(t *testing.T) {
	jit := mcpTestJitBinary(t)
	cwd := mcpTestSetup(t, `{"command":"`+jit+`","args":["run","--profile","mcp-gone","--","uv","run","srv"]}`)

	findings := mcpFindings(cwd)
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want exactly one", findings)
	}
	if !strings.Contains(findings[0].Detail, "mcp-gone") {
		t.Errorf("detail %q must name the missing profile", findings[0].Detail)
	}
}

// A vanished binary also implies a broken run; reporting both would put two
// lines on screen for one dead server.
func TestMCPFindingsReportsOneProblemPerServer(t *testing.T) {
	cwd := mcpTestSetup(t, `{"command":"/nonexistent/bin/jit","args":["run","--profile","mcp-gone","--","/nonexistent/uv"]}`)

	if findings := mcpFindings(cwd); len(findings) != 1 {
		t.Fatalf("findings = %+v, want exactly one for a single broken server", findings)
	}
}

// A bare "uv"/"npx" resolves against the PATH the MCP HOST gives the server,
// which this process cannot see. Reporting it would fail a healthy entry.
func TestMCPFindingsIgnoresBareWrappedCommand(t *testing.T) {
	jit := mcpTestJitBinary(t)
	cwd := mcpTestSetup(t, `{"command":"`+jit+`","args":["run","--profile","mcp-srv","--","definitely-not-on-path","serve"]}`)
	mcpTestProfile(t, "mcp-srv")

	if findings := mcpFindings(cwd); len(findings) != 0 {
		t.Errorf("findings = %+v, want none: a bare command is PATH-dependent", findings)
	}
}

func TestMCPFindingsReportsVanishedAbsoluteCommand(t *testing.T) {
	jit := mcpTestJitBinary(t)
	cwd := mcpTestSetup(t, `{"command":"`+jit+`","args":["run","--profile","mcp-srv","--","/nonexistent/caido-mcp-server","serve"]}`)
	mcpTestProfile(t, "mcp-srv")

	findings := mcpFindings(cwd)
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want exactly one", findings)
	}
	if !strings.Contains(findings[0].Detail, "/nonexistent/caido-mcp-server") {
		t.Errorf("detail %q must name the missing command", findings[0].Detail)
	}
}

// An unwrapped server is migrate's business, not doctor's.
func TestMCPFindingsIgnoresUnwrappedServers(t *testing.T) {
	cwd := mcpTestSetup(t, `{"command":"npx","args":["-y","srv"],"env":{"API_KEY":"abc"}}`)

	if findings := mcpFindings(cwd); len(findings) != 0 {
		t.Errorf("findings = %+v, want none: nothing here is jit's", findings)
	}
}

// plantLegacySecret writes a pre-AAD (v1) envelope, the shape every jit
// before v0.57.0 wrote. Structurally fine and readable forever — what makes
// it worth a doctor line is that its payload is bound to nothing.
func plantLegacySecret(t *testing.T, home, path string) {
	t.Helper()
	writeVaultEnc(t, home, path, `{"version":1,"recipients":{"test":"00"},"payload":"00"}`)
}

// A vault still holding pre-v0.57.0 envelopes gets one advisory line. It has
// to be advisory: nothing is broken, the secrets read exactly as they always
// have, and exploiting the unbound payload takes write access to the vault
// directory — an attacker who could read those files anyway. It has to be
// SAID because no other command reports it and it never heals on its own.
func TestLegacyEnvelopesAreReportedAsAdvisory(t *testing.T) {
	home := withFixtureHome(t)
	plantLegacySecret(t, home, "legacy/old-key")
	plantVaultSecret(t, home, "modern/current")
	stubKeychain(t, keychainwrap.MEKPresent)

	findings := gatherVaultIntegrityFindings(fixtureRoot(home), fixtureVault(home))
	if len(findings) != 1 || findings[0].Kind != kindLegacyEnvelope {
		t.Fatalf("expected one legacy_envelope finding, got %+v", findings)
	}
	if !findings[0].Kind.warning() {
		t.Error("a legacy envelope must be advisory: nothing is broken and the secret still reads")
	}
	if !strings.Contains(findings[0].Detail, "1 secret uses") {
		t.Errorf("expected the finding to count what is affected, got: %s", findings[0].Detail)
	}
	// The action has to name a remediation that actually works. Re-writing
	// the secret is the only thing that upgrades an envelope, and
	// export/import is how a whole vault does it at once — a rekey would
	// leave every one of these exactly as it found them.
	if !strings.Contains(findings[0].Action, "export") || !strings.Contains(findings[0].Action, "import") {
		t.Errorf("action must point at the round-trip that rewrites envelopes, got: %s", findings[0].Action)
	}
}

// A vault written by a current jit must stay silent, or every user carries a
// permanent doctor line urging an export/import round-trip that would
// rewrite every secret they own for nothing.
func TestCurrentEnvelopesAreSilent(t *testing.T) {
	home := withFixtureHome(t)
	plantVaultSecret(t, home, "modern/current")
	plantOriginSecret(t, home, "modern/other", "~/code/app/.env")
	stubKeychain(t, keychainwrap.MEKPresent)

	if findings := gatherVaultIntegrityFindings(fixtureRoot(home), fixtureVault(home)); len(findings) != 0 {
		t.Errorf("a current vault must be silent about envelope formats, got %+v", findings)
	}
}

// With the master key gone, the legacy-envelope line must not appear. Its
// remediation is an export, which decrypts every secret — unrunnable without
// the key. Printing it beside the vault-key finding would tell a user whose
// vault just became unreadable to go do something that cannot work.
func TestLegacyEnvelopesStaySilentWhenTheMasterKeyIsGone(t *testing.T) {
	home := withFixtureHome(t)
	plantLegacySecret(t, home, "legacy/old-key")
	stubKeychain(t, keychainwrap.MEKAbsent)

	findings := gatherVaultIntegrityFindings(fixtureRoot(home), fixtureVault(home))
	if len(findings) != 1 || findings[0].Kind != kindVaultKey {
		t.Fatalf("expected only the vault_key finding, got %+v", findings)
	}
}
