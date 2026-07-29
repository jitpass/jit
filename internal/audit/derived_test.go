// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFileIn is writeFile plus the parent directories, which every path in
// this file needs (~/.aws/cli/cache and friends never exist in a fresh home).
func writeFileIn(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	writeFile(t, path, content)
}

// A machine with nothing derived on it must produce no advisory at all — an
// advisory that always prints is a banner, and a banner is not read.
func TestNoDerivedCredentialsReportsNothing(t *testing.T) {
	home := t.TempDir()
	if got := ScanDerivedCredentials(Config{HomeDir: home}); len(got) != 0 {
		t.Errorf("clean home produced %d advisory item(s): %+v", len(got), got)
	}
}

func TestDerivedCredentialsFoundWhereTheScannerWalksPast(t *testing.T) {
	home := t.TempDir()
	// Hex-named, exactly as the AWS CLI writes them: no filename hint, so the
	// content sweep never opens these and never reports them.
	writeFileIn(t, filepath.Join(home, ".aws", "cli", "cache", "3f2a91c8b7.json"), `{"Credentials":{"SessionToken":"x"}}`)
	writeFileIn(t, filepath.Join(home, ".aws", "sso", "cache", "c0ffee1234.json"), `{"accessToken":"x"}`)

	got := ScanDerivedCredentials(Config{HomeDir: home})
	if len(got) != 2 {
		t.Fatalf("got %d advisory item(s), want 2: %+v", len(got), got)
	}

	var paths []string
	for _, d := range got {
		paths = append(paths, d.Path)
		if d.What == "" {
			t.Errorf("%s has no description; an advisory that doesn't say what it found is noise", d.Path)
		}
	}
	joined := strings.Join(paths, " ")
	for _, want := range []string{".aws/cli/cache", ".aws/sso/cache"} {
		if !strings.Contains(filepath.ToSlash(joined), want) {
			t.Errorf("advisory paths %v, want one covering %s", paths, want)
		}
	}
}

// An empty cache directory is a directory, not a credential.
func TestEmptyCacheDirectoryIsNotReported(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".aws", "cli", "cache"), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if got := ScanDerivedCredentials(Config{HomeDir: home}); len(got) != 0 {
		t.Errorf("empty cache dir produced %d advisory item(s): %+v", len(got), got)
	}
}

// jit's AWS discovery selects profiles that HAVE an aws_secret_access_key, so
// an assume-role profile is invisible to it: migrating the source profile
// leaves the role's own session unmanaged, and nothing said so.
func TestAssumeRoleProfileIsReported(t *testing.T) {
	home := t.TempDir()
	writeFileIn(t, filepath.Join(home, ".aws", "config"), `[profile prod]
role_arn = arn:aws:iam::123456789012:role/Admin
source_profile = default
`)
	got := ScanDerivedCredentials(Config{HomeDir: home})
	if len(got) != 1 {
		t.Fatalf("got %d advisory item(s), want 1: %+v", len(got), got)
	}
	if !strings.Contains(got[0].What, "assume-role") {
		t.Errorf("What = %q, want it to name assume-role profiles", got[0].What)
	}
}

func TestCommentedRoleArnIsNotAnAssumeRoleProfile(t *testing.T) {
	home := t.TempDir()
	writeFileIn(t, filepath.Join(home, ".aws", "config"), `[profile prod]
# role_arn = arn:aws:iam::123456789012:role/Admin
region = us-east-1
`)
	if got := ScanDerivedCredentials(Config{HomeDir: home}); len(got) != 0 {
		t.Errorf("a commented-out role_arn produced %d advisory item(s): %+v", len(got), got)
	}
}

// The clean report is the one this advisory exists for: a user who migrated
// ~/.aws/credentials and saw "no findings" would otherwise have no way to know
// a live session token was still sitting next to it.
func TestCleanReportStillCarriesTheAdvisory(t *testing.T) {
	summary := ScanSummary{
		TotalFindings:      0,
		RiskLevel:          RiskLevelLow,
		FindingsByCategory: map[string]int{},
		DerivedCredentials: []DerivedCredential{{
			Path:   "/Users/x/.aws/cli/cache",
			What:   "STS session credentials the AWS CLI cached for itself, in plaintext",
			Advice: "they expire on their own",
		}},
	}

	var buf bytes.Buffer
	WriteHumanReport(&buf, nil, summary, "/Users/x")
	out := buf.String()

	if !strings.Contains(out, "No findings") {
		t.Error("a clean scan must still say it found nothing")
	}
	if !strings.Contains(out, ".aws/cli/cache") {
		t.Errorf("clean report omits the advisory:\n%s", out)
	}
	if !strings.Contains(out, "Outside jit's scope") {
		t.Errorf("advisory is not labelled as a scope boundary:\n%s", out)
	}
}

// The triage view is `jit scan`'s default output — the one people actually
// read. An advisory that only appears behind --full is an advisory that does
// not exist, and "Nothing exposed" is precisely the verdict it has to qualify.
func TestTriageReportCarriesTheAdvisory(t *testing.T) {
	summary := ScanSummary{
		TotalFindings:      0,
		RiskLevel:          RiskLevelLow,
		FindingsByCategory: map[string]int{},
		DerivedCredentials: []DerivedCredential{{
			Path: "/Users/x/.aws/cli/cache",
			What: "STS session credentials the AWS CLI cached for itself, in plaintext",
		}},
	}

	var buf bytes.Buffer
	WriteTriageReport(&buf, nil, summary, "/Users/x", Coverage{})
	out := buf.String()

	if !strings.Contains(out, "Nothing exposed") {
		t.Error("a clean scan must still give its verdict")
	}
	if !strings.Contains(out, ".aws/cli/cache") {
		t.Errorf("the default scan view omits the advisory:\n%s", out)
	}
	if !strings.Contains(out, "Outside jit's scope") {
		t.Errorf("advisory is not labelled as a scope boundary:\n%s", out)
	}
}

func TestMarkdownReportCarriesTheAdvisory(t *testing.T) {
	summary := ScanSummary{
		TotalFindings:      0,
		RiskLevel:          RiskLevelLow,
		FindingsByCategory: map[string]int{},
		DerivedCredentials: []DerivedCredential{{
			Path: "/Users/x/.aws/sso/cache",
			What: "SSO access tokens and role credentials, in plaintext",
		}},
	}

	var buf bytes.Buffer
	WriteMarkdownReport(&buf, nil, summary)
	if out := buf.String(); !strings.Contains(out, ".aws/sso/cache") {
		t.Errorf("markdown report omits the advisory:\n%s", out)
	}
}

// The advisory is a note, not a finding: it must never move a number that a
// command or a dashboard reads.
func TestAdvisoryDoesNotAffectTotals(t *testing.T) {
	home := t.TempDir()
	writeFileIn(t, filepath.Join(home, ".aws", "cli", "cache", "3f2a91c8b7.json"), `{"Credentials":{}}`)

	_, summary, err := Scan(Config{HomeDir: home, RunID: "test", ScannerVersion: "test"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(summary.DerivedCredentials) == 0 {
		t.Fatal("Scan did not attach the advisory")
	}
	if summary.TotalFindings != 0 {
		t.Errorf("TotalFindings = %d, want 0 — an advisory is not a finding", summary.TotalFindings)
	}
	if summary.SecretsTotal != 0 {
		t.Errorf("SecretsTotal = %d, want 0 — an advisory must not enter the coverage ledger", summary.SecretsTotal)
	}
}

func TestDerivedCredentialsClissoCacheAndLog(t *testing.T) {
	home := t.TempDir()
	// clisso's --cache-path default: AWS INI format at a name no
	// ~/.aws/credentials sweep matches.
	writeFileIn(t, filepath.Join(home, ".aws", "credentials-cache"), "[prod]\naws_session_token = x\n")
	// Exists only when someone turned on file logging — at trace level it
	// holds every minted session's secret key and token.
	writeFileIn(t, filepath.Join(home, ".clisso.log"), "level=info msg=ok\n")

	got := ScanDerivedCredentials(Config{HomeDir: home})
	if len(got) != 2 {
		t.Fatalf("got %d advisory item(s), want 2: %+v", len(got), got)
	}
	var paths []string
	for _, d := range got {
		paths = append(paths, d.Path)
		if d.What == "" || d.Advice == "" {
			t.Errorf("%s: advisory missing What or Advice", d.Path)
		}
	}
	joined := filepath.ToSlash(strings.Join(paths, " "))
	for _, want := range []string{".aws/credentials-cache", ".clisso.log"} {
		if !strings.Contains(joined, want) {
			t.Errorf("advisory paths %v, want one covering %s", paths, want)
		}
	}
}
