// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"os"
	"path/filepath"
	"testing"
)

// realJWT is the token shape `jit scan token.txt` must catch: a bare JWT in a
// file whose name matches no structured category. Payload is inert.
const realJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
	"eyJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20iLCJpZCI6MX0." +
	"i-Bx9F2fjO5nvvo_hlUFY6bvnAOeTs68BiTBa-1zfoE"

func countByType(findings []Finding, ft string) int {
	n := 0
	for _, f := range findings {
		if f.FindingType == ft {
			n++
		}
	}
	return n
}

// TestTargetedScanNamedFileBareToken is the headline case: a token dropped in
// a file named nothing special is invisible to the name-gated scanners but
// caught by the content sweep when the file is named explicitly.
func TestTargetedScanNamedFileBareToken(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token.txt")
	writeFile(t, tokenPath, realJWT)

	findings, summary, err := TargetedScan(Config{HomeDir: dir}, []string{tokenPath})
	if err != nil {
		t.Fatalf("TargetedScan: %v", err)
	}
	if got := countByType(findings, FindingTypeExposedSecret); got != 1 {
		t.Fatalf("exposed_secret findings = %d, want 1: %+v", got, findings)
	}
	f := findings[0]
	if f.Severity != SeverityHigh {
		t.Errorf("severity = %q, want high", f.Severity)
	}
	if f.ValuePreview == nil || *f.ValuePreview == realJWT {
		t.Errorf("value must be masked, got %v", f.ValuePreview)
	}
	if summary.RiskLevel != RiskLevelHigh {
		t.Errorf("risk level = %q, want high", summary.RiskLevel)
	}
}

// TestTargetedScanNamedShellConfig proves an explicitly named shell rc is
// routed to the shell scanner (not the content sweep), so it's reported once
// as a shell_config_secret and NOT also as an exposed_secret.
func TestTargetedScanNamedShellConfig(t *testing.T) {
	dir := t.TempDir()
	rc := filepath.Join(dir, ".zshrc")
	writeFile(t, rc, "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n")

	findings, _, err := TargetedScan(Config{HomeDir: dir}, []string{rc})
	if err != nil {
		t.Fatalf("TargetedScan: %v", err)
	}
	if got := countByType(findings, FindingTypeShellConfigSecret); got != 1 {
		t.Errorf("shell_config_secret findings = %d, want 1", got)
	}
	if got := countByType(findings, FindingTypeExposedSecret); got != 0 {
		t.Errorf("exposed_secret findings = %d, want 0 (structured file must not be double-reported)", got)
	}
}

// TestTargetedScanDirectory walks a directory with the name-gated scanners and
// skips noise dirs, exactly like the machine-wide walk.
func TestTargetedScanDirectory(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".env"), "API_KEY=ghp_1234567890123456789012345678901234ab\n")
	mkdirAll(t, filepath.Join(root, "node_modules"))
	writeFile(t, filepath.Join(root, "node_modules", "leaked.env"), "AWS=AKIAIOSFODNN7EXAMPLE\n")
	// A bare token inside the dir is NOT swept (dir scan stays name-gated).
	writeFile(t, filepath.Join(root, "dump.txt"), realJWT)

	findings, _, err := TargetedScan(Config{HomeDir: root}, []string{root})
	if err != nil {
		t.Fatalf("TargetedScan: %v", err)
	}
	if got := countByType(findings, FindingTypeEnvFilePresent); got != 1 {
		t.Errorf("env_file_present = %d, want 1 (the .env, not the node_modules one)", got)
	}
	if got := countByType(findings, FindingTypeExposedSecret); got != 0 {
		t.Errorf("exposed_secret = %d, want 0 (content sweep is named-file only)", got)
	}
	for _, f := range findings {
		if filepath.Base(filepath.Dir(f.FilePath)) == "node_modules" {
			t.Errorf("finding inside node_modules should have been skipped: %s", f.FilePath)
		}
	}
}

// TestTargetedScanDedupesOverlappingTargets: naming a dir and a file inside it
// must not report that file twice.
func TestTargetedScanDedupesOverlappingTargets(t *testing.T) {
	root := t.TempDir()
	envPath := filepath.Join(root, ".env")
	writeFile(t, envPath, "API_KEY=ghp_1234567890123456789012345678901234ab\n")

	findings, _, err := TargetedScan(Config{HomeDir: root}, []string{root, envPath})
	if err != nil {
		t.Fatalf("TargetedScan: %v", err)
	}
	if got := countByType(findings, FindingTypeEnvFilePresent); got != 1 {
		t.Errorf("env_file_present = %d, want 1 (overlapping targets must dedupe)", got)
	}
}

// TestTargetedScanSkipsSymlink: a symlinked target is not followed, matching
// the home walk's no-follow policy.
func TestTargetedScanSkipsSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "token.txt")
	writeFile(t, real, realJWT)
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	findings, _, err := TargetedScan(Config{HomeDir: dir}, []string{link})
	if err != nil {
		t.Fatalf("TargetedScan: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("symlink target should be skipped, got %d findings", len(findings))
	}
}

// TestTargetedScanNamedPrivateKey: a private key body is caught by content
// even when the file has an unremarkable name, and reported as a private key
// (not an exposed_secret — key bodies are ceded to the private-key scanner).
func TestTargetedScanNamedPrivateKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "backup_key")
	// A minimal unencrypted PEM header is enough for looksLikePrivateKey.
	writeFile(t, keyPath, "-----BEGIN OPENSSH PRIVATE KEY-----\nabc123\n-----END OPENSSH PRIVATE KEY-----\n")

	findings, _, err := TargetedScan(Config{HomeDir: dir}, []string{keyPath})
	if err != nil {
		t.Fatalf("TargetedScan: %v", err)
	}
	if got := countByType(findings, FindingTypePrivateKeyRisk); got != 1 {
		t.Errorf("private_key_risk = %d, want 1: %+v", got, findings)
	}
	if got := countByType(findings, FindingTypeExposedSecret); got != 0 {
		t.Errorf("exposed_secret = %d, want 0 (key bodies belong to the private-key scanner)", got)
	}
}

// TestScanFileContentForTokensSpecificWins: a value matching both a specific
// prefix (sk-proj-…) and the generic sk-… fallback is reported once, under
// the specific vendor.
func TestScanFileContentForTokensSpecificWins(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "keys.txt")
	writeFile(t, p, "OPENAI=sk-proj-abcdefghijklmnopqrstuvwx\n")

	findings, err := scanFileContentForTokens(Config{HomeDir: dir}, p)
	if err != nil {
		t.Fatalf("scanFileContentForTokens: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (overlapping matches must not double-report): %+v", len(findings), findings)
	}
	if k := findings[0].KeyName; k == nil || *k != "OpenAI Project API Key" {
		t.Errorf("vendor = %v, want OpenAI Project API Key", findings[0].KeyName)
	}
}

// TestScanFileContentForTokensClean: an ordinary text file yields nothing.
func TestScanFileContentForTokensClean(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "notes.txt")
	writeFile(t, p, "meeting notes: ship the scan feature, no secrets here\n")

	findings, err := scanFileContentForTokens(Config{HomeDir: dir}, p)
	if err != nil {
		t.Fatalf("scanFileContentForTokens: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("clean file produced %d findings: %+v", len(findings), findings)
	}
}
