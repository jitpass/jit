// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/style"
)

func TestSelfRotatingCacheFor(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/Users/alex/.mcp-auth/abc123.json", true},
		{"/Users/alex/.gemini/oauth_creds.json", true},
		// A different HOME, and a home directory copied somewhere else, are
		// the same tool layout and must classify identically.
		{"/backup/home/alex/.gemini/oauth_creds.json", true},
		// clisso's config: the value never rotates, but the file is still
		// tool-rewritten — same class, same reason a mount must not be
		// offered. A copy under any directory classifies the same.
		{"/Users/alex/.clisso.yaml", true},
		{"/backup/home/alex/.clisso.yaml", true},
		// The gcloud CLI's own login store and its legacy per-account
		// copies: gcloud rewrites both on login/reauth (issue #93).
		{"/Users/alex/.config/gcloud/credentials.db", true},
		{"/Users/alex/.config/gcloud/legacy_credentials/alex@example.com/adc.json", true},
		// A project's own directory that happens to be called
		// legacy_credentials is not gcloud's: it keeps its migrate offer
		// and must not be handed `gcloud auth revoke` advice.
		{"/Users/alex/work/billing/legacy_credentials/prod.env", false},
		// The ADC file beside them stays migratable — it must never be
		// swept into the class by a loose gcloud-path match.
		{"/Users/alex/.config/gcloud/application_default_credentials.json", false},
		// Neighbours in the same directory are ordinary files.
		{"/Users/alex/.gemini/google_accounts.json", false},
		{"/Users/alex/.gemini/.env", false},
		{"/Users/alex/code/oauth_creds.json", false},
		{"/Users/alex/.aws/credentials", false},
	}
	for _, tc := range cases {
		if got := isSelfRotatingCache(tc.path); got != tc.want {
			t.Errorf("isSelfRotatingCache(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// TestSelfRotatingCacheIsNeverMigrated is the regression this class exists
// for: a token file the owning tool rewrites must never be handed a jit
// command, because a mount would be overwritten by the tool's next refresh
// and serve an already-rotated value until then.
func TestSelfRotatingCacheIsNeverMigrated(t *testing.T) {
	str := func(s string) *string { return &s }
	findings := []Finding{
		{RecordID: "g1", FindingType: FindingTypeExposedSecret, Severity: SeverityHigh,
			FilePath: "/Users/alex/.gemini/oauth_creds.json",
			KeyName:  str("JSON Web Token"), ValuePreview: str("eyJh**********")},
	}
	annotateRemedies(findings, "/Users/alex", nil, nil)

	if findings[0].Remedy != RemedyManual {
		t.Errorf("remedy = %q, want %q", findings[0].Remedy, RemedyManual)
	}
	if findings[0].FixCommand != "" {
		t.Errorf("fix_command = %q, want empty — jit cannot fix a self-rotating cache", findings[0].FixCommand)
	}

	// Tool-minted logins render in the triage view's own uncounted block, not
	// in the red section — the sign-out remedy reproduces the same file, so
	// they must not gate the "→ 100%" promise (see CountedAsSecret).
	if groups := triageGroupManual(findings, "/Users/alex"); len(groups) != 0 {
		t.Fatalf("got %d manual groups, want 0 — tool-minted logins render in their own block", len(groups))
	}
	if CountedAsSecret(findings[0]) {
		t.Errorf("a tool-minted login counted against the coverage ledger")
	}
	var buf strings.Builder
	writeToolMintedBlock(&buf, findings, "/Users/alex", style.Bold, style.Warn, style.Path)
	out := buf.String()
	if !strings.Contains(out, "Rotates itself — outside the count") {
		t.Errorf("block missing its header:\n%s", out)
	}
	if !strings.Contains(out, "A Gemini CLI OAuth token") {
		t.Errorf("block missing the finding's title:\n%s", out)
	}
	if !strings.Contains(out, "~/.gemini/oauth_creds.json") {
		t.Errorf("block missing the address:\n%s", out)
	}
	if !strings.Contains(out, "revoke") {
		t.Errorf("block = %q, want the revoke-at-the-provider advice", out)
	}
	if strings.Contains(out, "--mount") {
		t.Errorf("block offers a mount for a self-rotating cache:\n%s", out)
	}
}

// TestUserStoredSecretInToolRewrittenFileStillCounts pins the boundary inside
// the class: clisso's config is tool-REWRITTEN but its client-secret is
// user-stored and genuinely protectable (`jit wrap clisso`), so it keeps
// counting against the ledger and keeps its red-section group.
func TestUserStoredSecretInToolRewrittenFileStillCounts(t *testing.T) {
	str := func(s string) *string { return &s }
	findings := []Finding{
		{RecordID: "c1", FindingType: FindingTypeExposedSecret, Severity: SeverityHigh,
			FilePath: "/Users/alex/.clisso.yaml",
			KeyName:  str("client-secret"), ValuePreview: str("abcd**********")},
	}
	annotateRemedies(findings, "/Users/alex", nil, nil)
	if !CountedAsSecret(findings[0]) {
		t.Errorf("a user-stored secret in clisso's config fell out of the ledger")
	}
	if groups := triageGroupManual(findings, "/Users/alex"); len(groups) != 1 {
		t.Fatalf("got %d manual groups, want 1", len(groups))
	}
}

func TestMountable(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		// Read once at run time by one program: a pipe substitutes cleanly.
		{"/Users/alex/app/.env", true},
		{"/Users/alex/app/.env.production", true},
		{"/Users/alex/.npmrc", true},
		{"/Users/alex/deploy/config.yaml", true},
		{"/Users/alex/bin/deploy.sh", true},
		{"/Users/alex/.aws/credentials", true}, // extensionless config shape
		// Re-read by compilers, linters, editors and git, none of which hold
		// a `jit run` grant — a mount would serve them all decoys.
		{"/Users/alex/src/main.go", false},
		{"/Users/alex/src/app.py", false},
		{"/Users/alex/src/index.ts", false},
		// Nothing reads these at run time, so a pipe protects nothing.
		{"/Users/alex/reports/dump.html", false},
		{"/Users/alex/scraped-secrets.txt", false},
		{"/Users/alex/notes.md", false},
	}
	for _, tc := range cases {
		if got := mountable(tc.path); got != tc.want {
			t.Errorf("mountable(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestIsTerraformState(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/Users/alex/infra/terraform.tfstate", true},
		{"/Users/alex/infra/terraform.tfstate.backup", true},
		{"/Users/alex/infra/prod.tfstate", true},
		{"/Users/alex/infra/main.tf", false},
		{"/Users/alex/infra/terraform.tfvars", false},
	}
	for _, tc := range cases {
		if got := isTerraformState(tc.path); got != tc.want {
			t.Errorf("isTerraformState(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// TestTerraformStateIsManualWithBackendAdvice pins the honest verdict:
// Terraform writes state itself, so jit reports it and says what actually
// fixes it, rather than offering a command it cannot stand behind.
func TestTerraformStateIsManualWithBackendAdvice(t *testing.T) {
	str := func(s string) *string { return &s }
	findings := []Finding{
		{RecordID: "t1", FindingType: FindingTypeExposedSecret, Severity: SeverityHigh,
			FilePath: "/Users/alex/infra/terraform.tfstate",
			KeyName:  str("AWS Secret Access Key"), ValuePreview: str("wJal**********")},
	}
	annotateRemedies(findings, "/Users/alex", nil, nil)
	if findings[0].Remedy != RemedyManual {
		t.Errorf("remedy = %q, want %q", findings[0].Remedy, RemedyManual)
	}

	groups := triageGroupManual(findings, "/Users/alex")
	if len(groups) != 1 {
		t.Fatalf("got %d groups, want 1", len(groups))
	}
	if strings.Contains(groups[0].action, "--mount") {
		t.Errorf("action offers a mount for Terraform state: %q", groups[0].action)
	}
	for _, want := range []string{"rotate", "remote backend", "ephemeral"} {
		if !strings.Contains(groups[0].action, want) {
			t.Errorf("action = %q, want it to mention %q", groups[0].action, want)
		}
	}
}
