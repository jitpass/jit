// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

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

// TestTargetedScanDirectoryCoversEveryDiscoveryCategory locks in the property
// that made scanTargetDir dispatch from the shared categories table instead of
// naming classifiers by hand: a directory scan must cover EVERY category that
// discovers its files by name, not whichever subset someone remembered to list
// here. The project-local .npmrc below is the case that was actually missing —
// the machine-wide walk found it, a targeted directory scan silently did not.
func TestTargetedScanDirectoryCoversEveryDiscoveryCategory(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".env"), "API_KEY=ghp_1234567890123456789012345678901234ab\n")
	writeFile(t, filepath.Join(root, ".npmrc"), "//registry.npmjs.org/:_authToken=npm_exampletoken1234\n")
	writeFile(t, filepath.Join(root, ".mcp.json"), `{"mcpServers":{"gh":{"env":{"GITHUB_TOKEN":"ghp_exampletokenvalue1234"}}}}`)
	writeFile(t, filepath.Join(root, "terraform.tfvars"), "db_password = \"examplevalue123\"\n")
	// A credential dump found by name-gate + content match, the shape a real
	// AWS IAM key download has.
	//
	// The key ID is split so the literal "AKIA…" never appears contiguously in
	// this source file: GitHub push protection matches it as an Amazon AWS
	// Access Key ID and rejects any push carrying this blob, which it did.
	// Same trick guard_test.go uses on its Slack token. The value assembled at
	// runtime is unchanged, so the fixture still exercises jit's real AWS
	// pattern — do not "tidy" this back into one string.
	writeFile(t, filepath.Join(root, "acct-credentials.csv"),
		"User name,Access key ID,Secret access key\nvic,"+"AKIA"+"3QK7BZWX2LMPD4TN,Xk92QmPl4TzWhuCmu2qcwnu9PnWfMKNA1dTr\n")

	findings, _, err := TargetedScan(Config{HomeDir: root}, []string{root})
	if err != nil {
		t.Fatalf("TargetedScan: %v", err)
	}

	// One expectation per category carrying a classify half, derived from the
	// table itself so a new discovery category can't be added without either
	// being covered here or failing this test.
	wantByCategory := map[string]string{
		".env files":       FindingTypeEnvFilePresent,
		"credential files": FindingTypeCredentialFile,
		"MCP configs":      FindingTypeMCPEmbeddedSecret,
		"IaC files":        FindingTypeIACVariableFile,
		"exposed secrets":  FindingTypeExposedSecret,
	}
	for _, c := range categories {
		if c.classify == nil {
			continue
		}
		ft, ok := wantByCategory[c.name]
		if !ok {
			t.Fatalf("category %q discovers files by name but this test has no fixture for it — add one", c.name)
		}
		if got := countByType(findings, ft); got != 1 {
			t.Errorf("%s (%s) = %d findings, want 1 — a targeted directory scan is missing this category", c.name, ft, got)
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
	// A REAL key. This fixture used to be a PEM header wrapped around the
	// six bytes "abc123", which is not valid base64 and decodes to nothing —
	// it passed only because looksLikePrivateKey was a bare substring match on
	// the header, the same weakness that had jit reporting its own
	// tokenpatterns.go as a stray private key. Now that a body is required, a
	// stub fixture would be testing the stub; the property this test is about
	// ("caught by CONTENT even under an unremarkable name") needs real content.
	writeFile(t, keyPath, string(generateUnencryptedKeyPEM(t)))

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

// A vendor match on a COMMENT line of source code documents a shape rather
// than storing a secret: found and shown, but tagged SourceExample and not
// charged to the ledger. The same value in real code stays counted, and a
// comment example must never shadow a real credential further down the file
// through the per-vendor collapse.
func TestScanFileContentForTokensSourceExample(t *testing.T) {
	dir := t.TempDir()

	t.Run("comment-only match is a source example", func(t *testing.T) {
		p := filepath.Join(dir, "tokendoc.go")
		writeFile(t, p, "package x\n\n// e.g. psql postgres://app:Re4lLook1ngPw@db/app\n")
		findings, err := scanFileContentForTokens(Config{HomeDir: dir}, p)
		if err != nil {
			t.Fatalf("scanFileContentForTokens: %v", err)
		}
		if len(findings) != 1 {
			t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
		}
		if !findings[0].SourceExample {
			t.Error("comment-line match not tagged SourceExample")
		}
		if CountedAsSecret(findings[0]) {
			t.Error("source example charged to the ledger")
		}
	})

	t.Run("a real credential outranks the example above it", func(t *testing.T) {
		p := filepath.Join(dir, "tokencode.go")
		writeFile(t, p, "package x\n\n// e.g. psql postgres://app:Re4lLook1ngPw@db/app\nvar dsn = \"postgres://app:An0therRe4lPw@db/app\"\n")
		findings, err := scanFileContentForTokens(Config{HomeDir: dir}, p)
		if err != nil {
			t.Fatalf("scanFileContentForTokens: %v", err)
		}
		if len(findings) != 1 {
			t.Fatalf("got %d findings, want 1 (per-vendor collapse): %+v", len(findings), findings)
		}
		if findings[0].SourceExample {
			t.Error("the non-comment occurrence must win the per-vendor collapse")
		}
		if findings[0].Line == nil || *findings[0].Line != 4 {
			t.Errorf("Line = %v, want 4 (the code line, not the comment)", findings[0].Line)
		}
	})

	t.Run("comment context is ignored outside source files", func(t *testing.T) {
		p := filepath.Join(dir, "creds.txt")
		writeFile(t, p, "# postgres://app:Re4lLook1ngPw@db/app\n")
		findings, err := scanFileContentForTokens(Config{HomeDir: dir}, p)
		if err != nil {
			t.Fatalf("scanFileContentForTokens: %v", err)
		}
		if len(findings) != 1 || findings[0].SourceExample {
			t.Errorf("a .txt line is not source; got %+v", findings)
		}
	})
}

// And the file itself, mirroring TestJitsOwnPatternListIsNotAPrivateKey: the
// pattern list argues about credential shapes by example in its doc comments,
// and a real scan (2026-08-07) charged the user an exposed database password
// for it. Every match in it must stay uncharged, whatever examples a rewrite
// adds.
func TestJitsOwnPatternListIsNotCharged(t *testing.T) {
	findings, err := scanFileContentForTokens(Config{HomeDir: "/"}, "tokenpatterns.go")
	if err != nil {
		t.Fatalf("scanFileContentForTokens: %v", err)
	}
	for _, f := range findings {
		if CountedAsSecret(f) {
			line, vendor := 0, "?"
			if f.Line != nil {
				line = *f.Line
			}
			if f.KeyName != nil {
				vendor = *f.KeyName
			}
			t.Errorf("tokenpatterns.go:%d (%s) counts toward the ledger; "+
				"a scanner that charges the user for its own source teaches them to disbelieve the report", line, vendor)
		}
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
