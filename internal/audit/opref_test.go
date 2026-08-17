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

func TestIsOpSecretReference(t *testing.T) {
	yes := []string{
		"op://Personal/Stripe/credential",
		"op://Personal/Stripe/api/credential", // section segment
		"op://vault-id/item-id/field-id",
		"  op://Personal/Stripe/credential  ", // surrounding space trims
	}
	no := []string{
		"",
		"op://Personal/Stripe",  // no field
		"op://",                 //
		"op:///item/field",      // empty vault
		"op://Personal/Stripe/", // empty field
		"sk_live_abcdef123456",
		"${STRIPE_KEY}",
		"https://op.example.com/a/b/c",
	}
	for _, v := range yes {
		if !IsOpSecretReference(v) {
			t.Errorf("IsOpSecretReference(%q) = false, want true", v)
		}
		if !LooksLikeUnresolvedReference(v) {
			t.Errorf("LooksLikeUnresolvedReference(%q) = false; an op:// reference holds no secret at rest", v)
		}
	}
	for _, v := range no {
		if IsOpSecretReference(v) {
			t.Errorf("IsOpSecretReference(%q) = true, want false", v)
		}
	}
}

// A flagged .env that mixes plaintext with op:// references: the reference
// values never drive a finding (unresolved-reference rule), but the file's
// finding counts them so the report can say migrate keeps them linked.
func TestEnvFileFindingCountsOpReferences(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	content := "DB_PASSWORD=hunter2hunter2hunter2\n" +
		"STRIPE_SECRET_KEY=op://Personal/Stripe/credential\n" +
		"GITHUB_TOKEN=op://Personal/GitHub/token\n" +
		"# OLD_KEY=op://Personal/Old/key\n" // commented out: not an active value
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	f, ok, err := buildEnvFileFinding(Config{}, path, false)
	if err != nil {
		t.Fatalf("buildEnvFileFinding: %v", err)
	}
	if !ok {
		t.Fatal("expected a finding: DB_PASSWORD holds a plaintext credential")
	}
	if f.OpRefCount != 2 {
		t.Errorf("OpRefCount = %d, want 2 (active references only, never commented ones)", f.OpRefCount)
	}
}

func TestWriteHumanReportNotesOpReferences(t *testing.T) {
	key := "DB_PASSWORD"
	findings := []Finding{{
		FindingType: FindingTypeEnvFilePresent,
		Severity:    SeverityHigh,
		FilePath:    "/Users/alex/code/myapp/.env",
		KeyName:     &key,
		Evidence:    "variable name looks like a real credential",
		Confidence:  ConfidenceHigh,
		OpRefCount:  2,
	}}
	var buf bytes.Buffer
	WriteHumanReport(&buf, findings, buildScanSummary(Config{}, findings, 0, 0), "/Users/alex")
	out := buf.String()
	// termtext.Wrap may break the note anywhere between words at the
	// ambient width, so assert on a whitespace-normalized copy.
	flat := strings.Join(strings.Fields(out), " ")
	if !strings.Contains(flat, "2 values are 1Password references, not exposed") {
		t.Errorf("expected the op-reference note, got:\n%s", out)
	}
	if !strings.Contains(flat, "jit migrate keeps them linked") {
		t.Errorf("expected the migrate pointer in the note, got:\n%s", out)
	}

	// And silence without references: the note must not become boilerplate.
	findings[0].OpRefCount = 0
	buf.Reset()
	WriteHumanReport(&buf, findings, buildScanSummary(Config{}, findings, 0, 0), "/Users/alex")
	if strings.Contains(buf.String(), "1Password") {
		t.Errorf("no references, no note, got:\n%s", buf.String())
	}
}
