// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/mount"
)

// TestAnnotateRemedies pins the remedy taxonomy: "migrate"/"wrap" mean jit
// can act (FixCommand is runnable as-is), "manual" means only the user can.
// The manual membership is the design decision under the whole triage
// report, so each case documents why it belongs there.
func TestAnnotateRemedies(t *testing.T) {
	home := t.TempDir()
	str := func(s string) *string { return &s }
	// Real files where the remedy depends on content: a PURE token file
	// (every line is nothing but a token) is migratable; a file mixing a
	// token with other content is not something bare migrate touches.
	pure := filepath.Join(home, "token.txt")
	writeFile(t, pure, "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.Qm3xKq9ZmPq2LrTvWn5c\n")
	mixed := filepath.Join(home, "notes.txt")
	writeFile(t, mixed, "the deploy token is ghp_9fXk2QmPl4TzWhuCmu2qcwnu9PnWfMKNA1dT ok?\n")

	findings := []Finding{
		{FindingType: FindingTypeEnvFilePresent, FilePath: filepath.Join(home, "code/app/.env")},
		{FindingType: FindingTypePrivateKeyRisk, FilePath: filepath.Join(home, ".ssh/id_rsa")},
		{FindingType: FindingTypeCredentialFile, FilePath: filepath.Join(home, ".mcp-auth/v1/x_tokens.json")},
		{FindingType: FindingTypeIACVariableFile, FilePath: filepath.Join(home, "infra/secrets.yaml")},
		{FindingType: FindingTypeIACVariableFile, FilePath: filepath.Join(home, "infra/terraform.tfvars")},
		{FindingType: FindingTypeExposedSecret, FilePath: pure, ProductionIndicatorMatch: true},
		{FindingType: FindingTypeExposedSecret, FilePath: pure},
		{FindingType: FindingTypeExposedSecret, FilePath: mixed},
		// A wrappable arrives with both fields set by its scanner; annotate
		// must not overwrite them.
		{FindingType: FindingTypeWrappableCLIToken, FilePath: filepath.Join(home, ".config/gh/hosts.yml"),
			Remedy: RemedyWrap, FixCommand: "jit wrap gh", KeyName: str("oauth_token")},
	}
	annotateRemedies(findings, home, nil, nil)

	want := []struct {
		remedy, fixContains string
	}{
		{RemedyMigrate, "jit migrate ~/code/app/.env"},
		{RemedyManual, ""},  // private keys: migrate finds nothing to move
		{RemedyManual, ""},  // mcp-auth: mcp-remote rotates the file itself
		{RemedyManual, ""},  // k8s manifest: sealed-secrets territory
		{RemedyMigrate, ""}, // tfvars: migrate offers it
		{RemedyManual, ""},  // production credential: rotate, don't dress the wound
		{RemedyMigrate, "jit migrate ~/token.txt"},
		{RemedyManual, ""}, // mixed content: bare migrate skips it, don't promise it
		{RemedyWrap, "jit wrap gh"},
	}
	for i, w := range want {
		if findings[i].Remedy != w.remedy {
			t.Errorf("findings[%d] (%s) remedy = %q, want %q", i, findings[i].FilePath, findings[i].Remedy, w.remedy)
		}
		if w.fixContains != "" && findings[i].FixCommand != w.fixContains {
			t.Errorf("findings[%d] fix_command = %q, want %q", i, findings[i].FixCommand, w.fixContains)
		}
		if w.remedy == RemedyManual && findings[i].FixCommand != "" {
			t.Errorf("findings[%d] is manual but carries fix_command %q — a manual finding must not offer a command", i, findings[i].FixCommand)
		}
	}
}

// TestAnnotateCauseGroups pins the copy-collapsing identity: the FULL raw
// value's digest, never the 4-char preview — two different AWS keys share
// the "AKIA**********" preview but are two secrets needing two rotations
// (review finding, 2026-07-28). Findings without a digest (built outside
// ValueFinding) fall back to key+preview; no value at all means no group.
func TestAnnotateCauseGroups(t *testing.T) {
	str := func(s string) *string { return &s }
	findings := []Finding{
		// The same key copied into two files: one secret.
		{FilePath: "/a/dump1.html", KeyName: str("AWS Access Key ID"), ValuePreview: str("AKIA**********"), rawValueDigest: "digest-key-1"},
		{FilePath: "/b/dump2.html", KeyName: str("AWS Access Key ID"), ValuePreview: str("AKIA**********"), rawValueDigest: "digest-key-1"},
		// A DIFFERENT key with the identical preview: a second secret.
		{FilePath: "/c/other.txt", KeyName: str("AWS Access Key ID"), ValuePreview: str("AKIA**********"), rawValueDigest: "digest-key-2"},
		// No digest: preview fallback still groups copies.
		{FilePath: "/d/x.yml", KeyName: str("oauth_token"), ValuePreview: str("gho_**********")},
		{FilePath: "/e/y.yml", KeyName: str("oauth_token"), ValuePreview: str("gho_**********")},
		{FilePath: "/f/.env", RecordID: "r6"}, // no value: its own cause
	}
	annotateCauseGroups(findings)

	if findings[0].CauseGroup == "" || findings[0].CauseGroup != findings[1].CauseGroup {
		t.Errorf("copies of one value must share a cause group, got %q vs %q", findings[0].CauseGroup, findings[1].CauseGroup)
	}
	if findings[0].CauseGroup == findings[2].CauseGroup {
		t.Error("two different secrets sharing a vendor-prefix preview must NOT share a cause group")
	}
	if findings[3].CauseGroup == "" || findings[3].CauseGroup != findings[4].CauseGroup {
		t.Errorf("digest-less findings fall back to key+preview grouping, got %q vs %q", findings[3].CauseGroup, findings[4].CauseGroup)
	}
	if findings[5].CauseGroup != "" {
		t.Errorf("a valueless finding gets no group, got %q", findings[5].CauseGroup)
	}
}

// TestComputeCoverageOrderIndependent: a secret seen in an archived backup
// AND a live file is one exposed secret and IS migratable — bare `jit
// migrate` protects the live copy — regardless of which finding sorts
// first. An archived-only secret stays non-migratable.
func TestComputeCoverageOrderIndependent(t *testing.T) {
	str := func(s string) *string { return &s }
	mk := func(record, digest string, archived bool) Finding {
		return Finding{RecordID: record, Severity: SeverityHigh, Remedy: RemedyMigrate,
			Archived: archived, KeyName: str("K"), ValuePreview: str("xk92**********"), rawValueDigest: digest}
	}
	both := [][]Finding{
		{mk("arch", "d1", true), mk("live", "d1", false), mk("only-arch", "d2", true)},
		{mk("live", "d1", false), mk("arch", "d1", true), mk("only-arch", "d2", true)},
	}
	for i, findings := range both {
		annotateCauseGroups(findings)
		c := ComputeCoverage("", "", findings)
		if c.Exposed != 2 || c.Migratable != 1 {
			t.Errorf("order %d: Exposed/Migratable = %d/%d, want 2/1 (archived+live pair is migratable, archived-only is not)", i, c.Exposed, c.Migratable)
		}
	}
}

// TestComputeCoverage pins the ledger rules: distinct secrets not findings
// (copies collapse on cause group), Low/Info not counted, manual findings
// excluded from the migratable count.
func TestComputeCoverage(t *testing.T) {
	str := func(s string) *string { return &s }
	findings := []Finding{
		// One secret in two copies.
		{RecordID: "a", Severity: SeverityCritical, Remedy: RemedyManual,
			KeyName: str("k"), ValuePreview: str("sui_**********")},
		{RecordID: "b", Severity: SeverityCritical, Remedy: RemedyManual,
			KeyName: str("k"), ValuePreview: str("sui_**********")},
		// A migratable secret.
		{RecordID: "c", Severity: SeverityHigh, Remedy: RemedyMigrate},
		// A wrappable secret.
		{RecordID: "d", Severity: SeverityHigh, Remedy: RemedyWrap},
		// Low/Info sightings: jit does not stand behind them, so they are
		// not charged to the user's score.
		{RecordID: "e", Severity: SeverityLow, Remedy: RemedyMigrate},
		{RecordID: "f", Severity: SeverityInfo, Remedy: RemedyManual},
	}
	annotateCauseGroups(findings)
	c := ComputeCoverage("", "", findings)

	if c.Exposed != 3 {
		t.Errorf("Exposed = %d, want 3 (two copies collapse; Low/Info not counted)", c.Exposed)
	}
	if c.Migratable != 2 {
		t.Errorf("Migratable = %d, want 2 (the migrate + the wrap)", c.Migratable)
	}
	if c.Protected != 0 || c.Total() != 3 {
		t.Errorf("Protected/Total = %d/%d, want 0/3 with no registry", c.Protected, c.Total())
	}
	if c.Percent() != 0 || c.PercentAfterMigrate() != 66 {
		t.Errorf("Percent/After = %d/%d, want 0/66", c.Percent(), c.PercentAfterMigrate())
	}
}

// TestCoveragePercentCleanMachine: nothing known = 100%, not a division by
// zero and not a frightening 0%.
func TestCoveragePercentCleanMachine(t *testing.T) {
	c := Coverage{}
	if c.Percent() != 100 || c.PercentAfterMigrate() != 100 {
		t.Errorf("clean machine = %d%%/%d%%, want 100/100", c.Percent(), c.PercentAfterMigrate())
	}
}

// TestCountProtectedSecrets builds a real registry: one live mount whose
// profile manifest serves two secrets, one registry row whose pipe was
// replaced by a regular file (protects nothing — countProtectedMounts'
// rule), and one live mount with no readable manifest (floor of one).
func TestCountProtectedSecrets(t *testing.T) {
	dir := t.TempDir()
	registry := filepath.Join(dir, "mounts.yaml")

	live := filepath.Join(dir, "live.env")
	if err := mount.CreateFIFO(live); err != nil {
		t.Fatalf("CreateFIFO: %v", err)
	}
	manifest := filepath.Join(dir, "profile.yaml")
	writeFile(t, manifest, "A: prof/A\nB: prof/B\n")
	if err := mount.AddMount(registry, mount.Entry{MountPath: live, ProfilePath: manifest}); err != nil {
		t.Fatalf("AddMount: %v", err)
	}

	dead := filepath.Join(dir, "dead.env")
	writeFile(t, dead, "replaced by hand\n")
	if err := mount.AddMount(registry, mount.Entry{MountPath: dead, ProfilePath: manifest}); err != nil {
		t.Fatalf("AddMount: %v", err)
	}

	orphan := filepath.Join(dir, "orphan.env")
	if err := mount.CreateFIFO(orphan); err != nil {
		t.Fatalf("CreateFIFO: %v", err)
	}
	if err := mount.AddMount(registry, mount.Entry{MountPath: orphan, ProfilePath: filepath.Join(dir, "missing.yaml")}); err != nil {
		t.Fatalf("AddMount: %v", err)
	}

	if got := countProtectedSecrets(registry); got != 3 {
		t.Errorf("countProtectedSecrets = %d, want 3 (2 from the live manifest + 1 floor for the orphan; the dead mount contributes 0)", got)
	}
	if got := countProtectedSecrets(""); got != 0 {
		t.Errorf("no registry path should count 0, got %d", got)
	}
	_ = os.Remove(live)
	_ = os.Remove(orphan)
}

// A path is the one part of a jit command line an outsider can choose: scan
// walks whatever repos the user has checked out, and the output is both pasted
// into a shell by hand and published as NDJSON fix_command. So the property is
// not "looks tidy", it is that no filename can make the shell do a second
// thing — and the cases below are the ones the previous denylist let through.
func TestShellSafePathCannotExecuteAFilename(t *testing.T) {
	const home = "/Users/me"

	// Ordinary paths keep the pretty ~/ form, unquoted. This is the common
	// case and the reason quoting is conditional at all.
	bare := []struct{ path, want string }{
		{"/Users/me/.zsh_history", "~/.zsh_history"},
		{"/Users/me/proj/.env", "~/proj/.env"},
		{"/Users/me/.config/gh/hosts.yml", "~/.config/gh/hosts.yml"},
		{"/etc/ssl/private.pem", "/etc/ssl/private.pem"},
		// Non-ASCII carries no ASCII metacharacter, so it stays pretty.
		{"/Users/me/Résumé/.env", "~/Résumé/.env"},
		// Tilde expansion fires only at the start of a word; an Emacs backup
		// is common enough in a home directory to be worth not quoting.
		{"/Users/me/proj/.env~", "~/proj/.env~"},
	}
	for _, c := range bare {
		if got := shellSafePath(home, c.path); got != c.want {
			t.Errorf("shellSafePath(%q) = %q, want %q", c.path, got, c.want)
		}
	}

	// Anything else is single-quoted ABSOLUTE — absolute because "~" does not
	// expand inside quotes, single because nothing expands inside them.
	// Anything else is single-quoted, with the tilde left OUTSIDE the quotes so
	// the pretty form survives — the shell ends the tilde-prefix at the first
	// unquoted "/". A path outside $HOME has no prefix to keep and goes
	// quoted-absolute.
	quoted := []struct{ path, want string }{
		{"/Users/me/My Project/.env", `~/'My Project/.env'`},
		{"/Users/me/x$(id).env", `~/'x$(id).env'`},
		{"/Users/me/back`id`tick.env", "~/'back`id`tick.env'"},
		{"/Users/me/$HOME.env", `~/'$HOME.env'`},
		{"/Users/me/two\nlines.env", "~/'two\nlines.env'"},
		{"/Users/me/it's.env", `~/'it'\''s.env'`},
		{"/Users/me/a;rm -rf ~.env", `~/'a;rm -rf ~.env'`},
		{"/Users/me/glob*.env", `~/'glob*.env'`},
		// Outside $HOME: the deliberate residue.
		{"/opt/shared/keys (2 copies)/id_rsa", `'/opt/shared/keys (2 copies)/id_rsa'`},
	}
	for _, c := range quoted {
		if got := shellSafePath(home, c.path); got != c.want {
			t.Errorf("shellSafePath(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

// The claim above, checked by a real shell rather than by inspection: sh must
// see exactly one argument, byte-identical to the filename, for every path.
// Guards against the failure that made this a finding — %q looked like quoting
// and left $(...) and `...` live inside its double quotes.
func TestShellSafePathSurvivesARealShell(t *testing.T) {
	for _, path := range []string{
		"/Users/me/.zsh_history",
		"/Users/me/My Project/.env",
		"/Users/me/x$(exit 7).env",
		"/Users/me/back`exit 7`tick.env",
		"/Users/me/$HOME.env",
		"/Users/me/it's.env",
		"/Users/me/a;echo pwned.env",
		"/Users/me/glob*.env",
		"/Users/me/Résumé/.env",
		"/Users/me/.env~",
	} {
		// printf %s with one directive prints its FIRST argument only, so a
		// path that split into two words, or that ran a command, shows up as
		// output that differs from the input.
		script := "printf '%s' " + shellSafePath("", path)
		out, err := exec.Command("/bin/sh", "-c", script).Output()
		if err != nil {
			t.Errorf("%q: sh -c %q: %v", path, script, err)
			continue
		}
		if string(out) != path {
			t.Errorf("%q: sh saw %q (script: %s)", path, out, script)
		}
	}
}

// The tilde form's whole claim is about what a SHELL does with it, so it is
// checked by running one: sh must resolve ~/'we$ird…' to the real file on disk.
// Asserting the string would prove only that we can concatenate.
func TestShellSafePathTildeFormResolvesInARealShell(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "Documents", "we$ird dir")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	file := filepath.Join(dir, ".env")
	writeFile(t, file, "ghp_placeholder\n")

	rendered := shellSafePath(home, file)
	if !strings.HasPrefix(rendered, "~/") {
		t.Fatalf("a path under $HOME must keep the ~/ form, got %q", rendered)
	}
	for _, sh := range []string{"/bin/sh", "/bin/zsh"} {
		// printf %s with one directive prints its first argument only, so a
		// tilde that failed to expand, or a remainder that got re-parsed,
		// shows up as output that differs from the real path.
		cmd := exec.Command(sh, "-c", "printf '%s' "+rendered)
		cmd.Env = append(os.Environ(), "HOME="+home)
		out, err := cmd.Output()
		if err != nil {
			t.Errorf("%s: %v (rendered: %s)", sh, err, rendered)
			continue
		}
		if string(out) != file {
			t.Errorf("%s resolved %s to %q, want %q", sh, rendered, out, file)
		}
		// And the file it names is really there — the point of the hint.
		if _, err := os.Stat(string(out)); err != nil {
			t.Errorf("%s: resolved path does not exist: %v", sh, err)
		}
	}
}

// TestK8sMigratableHookFlipsRefusedManifests: Config.K8sMigratable is how
// scan stops promising a Secret manifest that migrate will refuse
// (design/dry-run-refactor.md D5). Refused: RemedyManual, migrate's
// reason in the evidence. ok or nil hook: RemedyMigrate with a
// FixCommand, the pre-hook behavior.
func TestK8sMigratableHookFlipsRefusedManifests(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "code", "k8s")
	mkdirAll(t, dir)
	manifest := filepath.Join(dir, "secrets.yaml")
	writeFile(t, manifest, `apiVersion: v1
kind: Secret
metadata:
  name: my-secret
data:
  password: aHVudGVyMg==
`)

	find := func(cfg Config) Finding {
		t.Helper()
		findings, _, err := TargetedScan(cfg, []string{manifest})
		if err != nil {
			t.Fatalf("TargetedScan: %v", err)
		}
		for _, f := range findings {
			if f.FindingType == FindingTypeIACVariableFile {
				return f
			}
		}
		t.Fatalf("no IAC finding for the manifest, got %d findings", len(findings))
		return Finding{}
	}

	refused := find(Config{HomeDir: home, K8sMigratable: func(path string) (string, bool) {
		if path != manifest {
			t.Errorf("hook asked about %q, want %q", path, manifest)
		}
		return "a Secret document uses both data: and stringData:", false
	}})
	if refused.Remedy != RemedyManual {
		t.Errorf("refused manifest remedy = %q, want %q", refused.Remedy, RemedyManual)
	}
	if !strings.Contains(refused.Evidence, "can't rewrite provably right") ||
		!strings.Contains(refused.Evidence, "both data: and stringData:") {
		t.Errorf("refused evidence should carry migrate's reason, got: %q", refused.Evidence)
	}
	if refused.FixCommand != "" {
		t.Errorf("refused manifest must not carry a FixCommand, got %q", refused.FixCommand)
	}

	okFinding := find(Config{HomeDir: home, K8sMigratable: func(string) (string, bool) { return "", true }})
	if okFinding.Remedy != RemedyMigrate || okFinding.FixCommand == "" {
		t.Errorf("ok verdict: remedy=%q fix=%q, want migrate with a FixCommand", okFinding.Remedy, okFinding.FixCommand)
	}

	nilHook := find(Config{HomeDir: home})
	if nilHook.Remedy != RemedyMigrate {
		t.Errorf("nil hook must keep the pre-hook optimistic remedy, got %q", nilHook.Remedy)
	}
}

// TestStreamlitMigratableHookFlipsUnrewritableFiles: Config.
// StreamlitMigratable is how scan stops promising a secrets.toml whose
// every flagged value falls outside migrate's stricter rewritable shape
// (single-line quoted string, no escapes) — the same D5 rule
// K8sMigratable enforces for Secret manifests.
func TestStreamlitMigratableHookFlipsUnrewritableFiles(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "proj", ".streamlit")
	mkdirAll(t, dir)
	secrets := filepath.Join(dir, "secrets.toml")
	writeFile(t, secrets, "db_password = \"Tr0ub4dor3xKq9ZmPq2Lr\"\n")

	find := func(cfg Config) Finding {
		t.Helper()
		findings, _, err := TargetedScan(cfg, []string{secrets})
		if err != nil {
			t.Fatalf("TargetedScan: %v", err)
		}
		for _, f := range findings {
			if f.FindingType == FindingTypeCredentialFile {
				return f
			}
		}
		t.Fatalf("no credential_file finding for the secrets file, got %d findings", len(findings))
		return Finding{}
	}

	refused := find(Config{HomeDir: home, StreamlitMigratable: func(path string) (string, bool) {
		if path != secrets {
			t.Errorf("hook asked about %q, want %q", path, secrets)
		}
		return "its values aren't single-line quoted strings", false
	}})
	if refused.Remedy != RemedyManual {
		t.Errorf("refused file remedy = %q, want %q", refused.Remedy, RemedyManual)
	}
	if !strings.Contains(refused.Evidence, "can't rewrite provably right") ||
		!strings.Contains(refused.Evidence, "single-line quoted strings") {
		t.Errorf("refused evidence should carry migrate's reason, got: %q", refused.Evidence)
	}
	if refused.FixCommand != "" {
		t.Errorf("refused file must not carry a FixCommand, got %q", refused.FixCommand)
	}

	okFinding := find(Config{HomeDir: home, StreamlitMigratable: func(string) (string, bool) { return "", true }})
	if okFinding.Remedy != RemedyMigrate || okFinding.FixCommand == "" {
		t.Errorf("ok verdict: remedy=%q fix=%q, want migrate with a FixCommand", okFinding.Remedy, okFinding.FixCommand)
	}

	nilHook := find(Config{HomeDir: home})
	if nilHook.Remedy != RemedyMigrate {
		t.Errorf("nil hook must keep the pre-hook optimistic remedy, got %q", nilHook.Remedy)
	}
}
