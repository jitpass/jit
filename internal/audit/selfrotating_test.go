// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"strings"
	"testing"
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
	annotateRemedies(findings, "/Users/alex", nil)

	if findings[0].Remedy != RemedyManual {
		t.Errorf("remedy = %q, want %q", findings[0].Remedy, RemedyManual)
	}
	if findings[0].FixCommand != "" {
		t.Errorf("fix_command = %q, want empty — jit cannot fix a self-rotating cache", findings[0].FixCommand)
	}

	groups := triageGroupManual(findings, "/Users/alex")
	if len(groups) != 1 {
		t.Fatalf("got %d groups, want 1", len(groups))
	}
	if strings.Contains(groups[0].action, "--mount") {
		t.Errorf("action offers a mount for a self-rotating cache: %q", groups[0].action)
	}
	if !strings.Contains(groups[0].action, "revoke") {
		t.Errorf("action = %q, want it to lead with revoking at the provider", groups[0].action)
	}
	if !strings.Contains(groups[0].title, "rotates itself") {
		t.Errorf("title = %q, want it to say the file rotates itself", groups[0].title)
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
	annotateRemedies(findings, "/Users/alex", nil)
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
