// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/jitpass/jit/internal/mount"
)

func findingOfType(ft string) Finding {
	return Finding{FindingType: ft, Severity: SeverityLow, Confidence: ConfidenceMedium}
}

func findingWithSeverity(ft, severity string) Finding {
	return Finding{FindingType: ft, Severity: severity, Confidence: ConfidenceMedium}
}

func TestComputeRiskLevel(t *testing.T) {
	ipStr := "8.8.8.8"

	cases := []struct {
		name     string
		findings []Finding
		want     string
	}{
		{"clean, zero findings", nil, RiskLevelClean},
		{"one low-signal finding", []Finding{findingOfType(FindingTypeEnvFilePresent)}, RiskLevelLow},
		{"two low-signal findings", []Finding{findingOfType(FindingTypeEnvFilePresent), findingOfType(FindingTypeIACVariableFile)}, RiskLevelLow},
		{"three findings -> medium", []Finding{
			findingOfType(FindingTypeEnvFilePresent),
			findingOfType(FindingTypeIACVariableFile),
			findingOfType(FindingTypeEnvFilePresent),
		}, RiskLevelMedium},
		{"five low-severity findings, none individually High -> high via count", []Finding{
			findingOfType(FindingTypeEnvFilePresent),
			findingOfType(FindingTypeEnvFilePresent),
			findingOfType(FindingTypeIACVariableFile),
			findingOfType(FindingTypeEnvFilePresent),
			findingOfType(FindingTypeIACVariableFile),
		}, RiskLevelHigh},
		{"single shell-config finding (Severity: High, as the real scanner produces) -> high regardless of count",
			[]Finding{findingWithSeverity(FindingTypeShellConfigSecret, SeverityHigh)}, RiskLevelHigh},
		{"single MCP finding (Severity: High) -> high regardless of count",
			[]Finding{findingWithSeverity(FindingTypeMCPEmbeddedSecret, SeverityHigh)}, RiskLevelHigh},
		{"single private-key finding (Severity: High) -> high regardless of count",
			[]Finding{findingWithSeverity(FindingTypePrivateKeyRisk, SeverityHigh)}, RiskLevelHigh},
		{"single credential-file finding (Severity: High) -> high regardless of count " +
			"— this is the real gap the Severity-based generalization fixed: credential_file " +
			"was missing from the old hardcoded FindingType switch entirely",
			[]Finding{findingWithSeverity(FindingTypeCredentialFile, SeverityHigh)}, RiskLevelHigh},
		{"production-indicator match anywhere -> critical, overrides everything", []Finding{
			{FindingType: FindingTypeEnvFilePresent, ProductionIndicatorMatch: true},
		}, RiskLevelCritical},
		{"public IP match anywhere -> critical, overrides everything", []Finding{
			{FindingType: FindingTypeEnvFilePresent, PublicIPMatch: &ipStr},
		}, RiskLevelCritical},
		{"critical overrides a high-trigger category too", []Finding{
			{FindingType: FindingTypeShellConfigSecret, Severity: SeverityHigh, ProductionIndicatorMatch: true},
		}, RiskLevelCritical},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ComputeRiskLevel(c.findings)
			if got != c.want {
				t.Errorf("ComputeRiskLevel() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestScanIntegration(t *testing.T) {
	home := t.TempDir()

	// Plant findings across several categories, including one that should
	// escalate the whole scan to Critical.
	// A realistically-shaped key, not "sk_test_example": LooksLikeNonSecretValue
	// now (correctly) reads all-lowercase filler containing "example" as an
	// unfilled placeholder, so the old fixture was quietly standing in for a
	// secret with a value no vendor would ever issue — the same trap tokenBody
	// exists to avoid in tokenpatterns_test.go.
	writeFile(t, filepath.Join(home, ".zshrc"), "export STRIPE_API_KEY=sk_test_4eC39HqLyjWDarjtT1zdp7dc\n")
	mkdirAll(t, filepath.Join(home, "code", "app"))
	writeFile(t, filepath.Join(home, "code", "app", ".env"), "PROD_DATABASE_URL=postgres://admin:x@db.internal/prod\n")

	findings, summary, err := Scan(Config{
		HomeDir:        home,
		RunID:          "test-run-id",
		ScannerVersion: "test",
		Endpoint:       Endpoint{Hostname: "test-host", OS: "darwin"},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if len(findings) != summary.TotalFindings {
		t.Errorf("len(findings) = %d, summary.TotalFindings = %d, want equal", len(findings), summary.TotalFindings)
	}
	if summary.TotalFindings < 2 {
		t.Fatalf("expected at least 2 findings (shell config + .env), got %d", summary.TotalFindings)
	}
	if summary.RiskLevel != RiskLevelCritical {
		t.Errorf("RiskLevel = %q, want %q (planted a production-indicator match)", summary.RiskLevel, RiskLevelCritical)
	}
	if summary.ProductionIndicatorCount < 1 {
		t.Errorf("ProductionIndicatorCount = %d, want >= 1", summary.ProductionIndicatorCount)
	}
	if summary.RecordType != RecordTypeScanSummary {
		t.Errorf("RecordType = %q, want %q", summary.RecordType, RecordTypeScanSummary)
	}
	if summary.RecordID != nil {
		t.Errorf("RecordID = %v, want nil (always null per RFC.md §4)", summary.RecordID)
	}
	if summary.RunID != "test-run-id" {
		t.Errorf("RunID = %q, want %q", summary.RunID, "test-run-id")
	}

	// All seven categories must always be present in the map, even at zero.
	if len(summary.FindingsByCategory) != len(AllFindingTypes) {
		t.Errorf("FindingsByCategory has %d keys, want %d (all categories always present)", len(summary.FindingsByCategory), len(AllFindingTypes))
	}
	for _, ft := range AllFindingTypes {
		if _, ok := summary.FindingsByCategory[ft]; !ok {
			t.Errorf("FindingsByCategory missing key %q", ft)
		}
	}
}

func TestScanCleanHomeDir(t *testing.T) {
	home := t.TempDir()
	findings, summary, err := Scan(Config{HomeDir: home, RunID: "r", ScannerVersion: "test"})
	if err != nil {
		t.Fatalf("Scan on empty home dir: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings on empty home dir, want 0", len(findings))
	}
	if summary.RiskLevel != RiskLevelClean {
		t.Errorf("RiskLevel = %q, want %q", summary.RiskLevel, RiskLevelClean)
	}
	if summary.TotalFindings != 0 {
		t.Errorf("TotalFindings = %d, want 0", summary.TotalFindings)
	}
}

// The protected count reports registered mounts whose path is currently a
// live pipe — and ONLY those: a registered path that is a regular file again
// holds plaintext at rest (scanners judge it normally), and a path that's
// gone protects nothing.
func TestScanCountsProtectedLiveMounts(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, "app"))
	fifoPath := filepath.Join(home, "app", ".env")
	mkfifo(t, fifoPath)
	regularPath := filepath.Join(home, "app", ".env.local")
	writeFile(t, regularPath, "API_KEY=stillplaintext123\n")

	registryPath := filepath.Join(t.TempDir(), "mounts.yaml")
	for _, p := range []string{fifoPath, regularPath, filepath.Join(home, "gone", ".env")} {
		if err := mount.AddMount(registryPath, mount.Entry{MountPath: p, ProfilePath: "/unused/profile.yaml"}); err != nil {
			t.Fatalf("AddMount(%q): %v", p, err)
		}
	}

	findings, summary, err := Scan(Config{
		HomeDir:           home,
		RunID:             "test-run-id",
		ScannerVersion:    "test",
		MountRegistryPath: registryPath,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if summary.JitProtectedCount != 1 {
		t.Errorf("JitProtectedCount = %d, want 1 (only the live FIFO counts)", summary.JitProtectedCount)
	}
	// The still-plaintext registered file must remain a normal finding.
	found := false
	for _, f := range findings {
		if f.FilePath == regularPath {
			found = true
		}
		if f.FilePath == fifoPath {
			t.Errorf("the live-mount FIFO produced a finding: %+v", f)
		}
	}
	if !found {
		t.Errorf("registered-but-regular %s produced no finding — plaintext at rest must still be reported", regularPath)
	}
}

// No registry path (the default for every test Config) and a missing
// registry file both mean a plain zero — a read-only scan must never fail
// because jit's own bookkeeping is absent.
func TestCountProtectedMountsBestEffort(t *testing.T) {
	if got := countProtectedMounts(""); got != 0 {
		t.Errorf("countProtectedMounts(\"\") = %d, want 0", got)
	}
	if got := countProtectedMounts(filepath.Join(t.TempDir(), "missing.yaml")); got != 0 {
		t.Errorf("countProtectedMounts(missing) = %d, want 0", got)
	}
}

// TestScanConcurrentWalkIsCompleteAndStable covers the two things a concurrent
// discovery walk can silently get wrong: dropping files (a merge that loses a
// goroutine's buckets, a race on the shared result) and reordering findings
// between runs (concurrent traversal has no inherent order, so discoverByWalk
// sorts). The fixture is deliberately wide and deep enough to saturate
// walkConcurrency, which is what exercises the inline-recursion fallback taken
// when every pool slot is busy — the branch a small fixture never reaches.
// Run this one under -race; it is the only test that would catch a regression
// there.
func TestScanConcurrentWalkIsCompleteAndStable(t *testing.T) {
	home := t.TempDir()
	const projects, subdirs = 40, 8
	for i := range projects {
		for j := range subdirs {
			dir := filepath.Join(home, fmt.Sprintf("proj%02d", i), fmt.Sprintf("sub%d", j), "deep")
			mkdirAll(t, dir)
			writeFile(t, filepath.Join(dir, ".env"), "API_KEY=ghp_1234567890123456789012345678901234ab\n")
			writeFile(t, filepath.Join(dir, ".npmrc"), "//registry.npmjs.org/:_authToken=npm_tok1234567890\n")
			writeFile(t, filepath.Join(dir, "noise.txt"), "nothing to find here")
		}
	}
	want := projects * subdirs

	var first []Finding
	for run := range 5 {
		findings, _, err := Scan(Config{HomeDir: home})
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		if got := countByType(findings, FindingTypeEnvFilePresent); got != want {
			t.Fatalf("run %d: env_file_present = %d, want %d — the walk lost files", run, got, want)
		}
		if got := countByType(findings, FindingTypeCredentialFile); got != want {
			t.Fatalf("run %d: credential_file = %d, want %d — the walk lost files", run, got, want)
		}
		if run == 0 {
			first = findings
			continue
		}
		if len(findings) != len(first) {
			t.Fatalf("run %d: %d findings, first run had %d", run, len(findings), len(first))
		}
		for i := range findings {
			if findings[i].RecordID != first[i].RecordID {
				t.Fatalf("run %d: order is not stable, index %d is %s but was %s",
					run, i, findings[i].FilePath, first[i].FilePath)
			}
		}
	}
}

// TestDropRedundantExposedSecrets is the regression test for a duplication
// introduced with classifyCredentialDump: "credential" is one of its filename
// hints, so it content-scanned ~/.aws/credentials — a file scanAWSCredentials
// already reports properly, per profile. Every machine with AWS keys got the
// same file twice, once with a fix path and once without. It would have hit 8
// of the 12 developer machines this feature was built from.
func TestDropRedundantExposedSecrets(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, ".aws"))
	// Exactly what `aws configure` writes: the AKIA id (a vendor pattern the
	// content sweep matches) alongside the secret.
	writeFile(t, filepath.Join(home, ".aws", "credentials"), `[default]
aws_access_key_id = AKIA3QK7BZWX2LMPD4TN
aws_secret_access_key = Xk92QmPl4TzWhuCmu2qcwnu9PnWfMKNA1dTr
`)

	findings, _, err := Scan(Config{HomeDir: home, RunID: "t", ScannerVersion: "t"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var credential, exposed int
	for _, f := range findings {
		switch f.FindingType {
		case FindingTypeCredentialFile:
			credential++
		case FindingTypeExposedSecret:
			exposed++
		}
	}
	if credential != 1 {
		t.Errorf("credential_file findings = %d, want 1 (the structured one, which names the profile and has a fix)", credential)
	}
	if exposed != 0 {
		t.Errorf("exposed_secret findings = %d, want 0 — the file is already claimed by a category that reports it better", exposed)
	}
}

// TestExposedSecretSurvivesWhenUnclaimed is the other half: the whole point of
// classifyCredentialDump is a credential dump NO category claims, so the
// redundancy filter must not swallow it.
func TestExposedSecretSurvivesWhenUnclaimed(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, "Downloads"))
	writeFile(t, filepath.Join(home, "Downloads", "acct-credentials.csv"),
		"User name,Access key ID,Secret access key\nv,AKIA3QK7BZWX2LMPD4TN,Xk92QmPl4TzWhuCmu2qcwnu9PnWfMKNA1dTr\n")

	findings, _, err := Scan(Config{HomeDir: home, RunID: "t", ScannerVersion: "t"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got := countByType(findings, FindingTypeExposedSecret); got != 1 {
		t.Errorf("exposed_secret findings = %d, want 1 (nothing else claims a .csv in Downloads)", got)
	}
}

// TestForeignTokenInClaimedFileSurvives is the other edge of
// dropRedundantExposedSecrets: the dedup must remove only what the claiming
// scanner already judged. A GitHub token pasted into ~/.aws/credentials is
// invisible to scanAWSCredentials (it parses only the AWS fields), so the
// content sweep's finding is the ONLY report of it — the path-keyed version
// of the dedup silently swallowed it (found in review, 2026-07-28).
func TestForeignTokenInClaimedFileSurvives(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, ".aws"))
	writeFile(t, filepath.Join(home, ".aws", "credentials"), `[default]
aws_access_key_id = AKIA3QK7BZWX2LMPD4TN
aws_secret_access_key = Xk92QmPl4TzWhuCmu2qcwnu9PnWfMKNA1dTr
# pasted during an incident, never cleaned up:
# ghp_9fXk2QmPl4TzWhuCmu2qcwnu9PnWfMKNA1dT
`)

	findings, _, err := Scan(Config{HomeDir: home, RunID: "t", ScannerVersion: "t"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var exposed []Finding
	for _, f := range findings {
		if f.FindingType == FindingTypeExposedSecret {
			exposed = append(exposed, f)
		}
	}
	if len(exposed) != 1 {
		t.Fatalf("exposed_secret findings = %d, want exactly 1 (the foreign GitHub token; the AKIA id stays claimed): %+v", len(exposed), exposed)
	}
	if *exposed[0].KeyName != "GitHub Personal Access Token" {
		t.Errorf("surviving exposed_secret = %q, want the GitHub token — the AWS id is already the claimed file's own credential", *exposed[0].KeyName)
	}
	if got := countByType(findings, FindingTypeCredentialFile); got != 1 {
		t.Errorf("credential_file findings = %d, want 1", got)
	}
}

// TestGitCredentialsNotDoubleReported: ~/.git-credentials is name-hinted
// ("credential"), and the content sweep's scheme-less connection-string
// pattern matches the "user:pass@host" span of each line — a DIFFERENT
// preview than the bare password the structured scanner reports. The
// scanner's ClaimedValuePreviews are what keep the value-keyed dedup from
// re-reporting the same credential under a second finding type.
func TestGitCredentialsNotDoubleReported(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".git-credentials"),
		"https://alice:Xk92QmPl4TzWhuCmu2qc@github.com\n")

	findings, _, err := Scan(Config{HomeDir: home, RunID: "t", ScannerVersion: "t"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got := countByType(findings, FindingTypeCredentialFile); got != 1 {
		t.Errorf("credential_file findings = %d, want 1", got)
	}
	if got := countByType(findings, FindingTypeExposedSecret); got != 0 {
		t.Errorf("exposed_secret findings = %d, want 0 — the connection-string span is the same credential the structured finding reports", got)
	}
}

// TestMCPAuthAccessTokenNotReReported: the MCP scanner deliberately reports
// only the refresh token (the access token lives minutes and would double the
// findings for less risk). The access token is typically a JWT the content
// sweep matches — "_tokens.json" passes the name gate — so the scanner claims
// it, and the sweep's re-discovery must not surface it as an exposed_secret.
func TestMCPAuthAccessTokenNotReReported(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".mcp-auth", "mcp-remote-0.1.29")
	mkdirAll(t, dir)
	writeFile(t, filepath.Join(dir, "3f9c2a_tokens.json"),
		`{"access_token":"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJtY3AtY2xpZW50In0.Qm3xKq9ZmPq2LrTvWn5c","refresh_token":"0.ARoAv4j5cvGGr0GRqy180BHbR6Qm3xKq9ZmPq2LrTvWn5cUd8eFg","expires_at":1753700000}`)

	findings, _, err := Scan(Config{HomeDir: home, RunID: "t", ScannerVersion: "t"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got := countByType(findings, FindingTypeCredentialFile); got != 1 {
		t.Errorf("credential_file findings = %d, want 1 (the refresh token)", got)
	}
	if got := countByType(findings, FindingTypeExposedSecret); got != 0 {
		t.Errorf("exposed_secret findings = %d, want 0 — the JWT access token is the scanner's own deliberate downgrade, not a foreign value", got)
	}
}

// TestCredentialDumpNameGateSkipsFalseStems pins the hint-stop list: an ML
// checkout's tokenizer_config.json (routinely megabytes) and an AUTHORS file
// contain "token"/"auth" without meaning it, and were being fully
// content-scanned on every walk. The gate must skip them — and still open a
// file whose remaining name genuinely hints.
func TestCredentialDumpNameGateSkipsFalseStems(t *testing.T) {
	home := t.TempDir()
	cfg := Config{HomeDir: home, RunID: "t", ScannerVersion: "t"}
	const body = "value = ghp_9fXk2QmPl4TzWhuCmu2qcwnu9PnWfMKNA1dT\n"

	cases := []struct {
		name string
		want int
	}{
		{"tokenizer_config.json", 0},  // "token" only via "tokenizer"
		{"AUTHORS", 0},                // "auth" only via "author"
		{"authorized_keys", 0},        // ditto
		{"token_dump.json", 1},        // a genuine hint still opens the file
		{"tokenizer_secrets.json", 1}, // removal, not rejection: "secret" remains
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(home, c.name)
			writeFile(t, path, body)
			got := classifyCredentialDump(cfg, path, c.name)
			if len(got) != c.want {
				t.Errorf("classifyCredentialDump(%q) = %d findings, want %d: %+v", c.name, len(got), c.want, got)
			}
		})
	}
}

// TestFindFileTokensSkipsBinary: a NUL in the first block marks a binary file
// (SQLite, docx, mach-o) the line-based sweep can't usefully read; the
// extension skip-list only covers the common formats, this covers the rest.
// The sniffed bytes must still be scanned when the file IS text — a token on
// line 1 sits inside the sniffed block.
func TestFindFileTokensSkipsBinary(t *testing.T) {
	dir := t.TempDir()

	binPath := filepath.Join(dir, "secrets.db")
	writeFile(t, binPath, "SQLite format 3\x00\x01\x02ghp_9fXk2QmPl4TzWhuCmu2qcwnu9PnWfMKNA1dT\n")
	tokens, err := FindFileTokens(binPath)
	if err != nil {
		t.Fatalf("FindFileTokens(binary): %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("binary file produced %d tokens, want 0: %+v", len(tokens), tokens)
	}

	textPath := filepath.Join(dir, "secrets.txt")
	writeFile(t, textPath, "ghp_9fXk2QmPl4TzWhuCmu2qcwnu9PnWfMKNA1dT\n")
	tokens, err = FindFileTokens(textPath)
	if err != nil {
		t.Fatalf("FindFileTokens(text): %v", err)
	}
	if len(tokens) != 1 {
		t.Errorf("text file produced %d tokens, want 1 — the sniffed head must be scanned, not discarded: %+v", len(tokens), tokens)
	}
}
