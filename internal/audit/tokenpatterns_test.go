// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"strings"
	"testing"
)

func TestMatchKnownTokenPattern(t *testing.T) {
	cases := []struct {
		name         string
		value        string
		wantVendor   string
		wantVerified bool
		wantOK       bool
	}{
		{"GitHub PAT", "ghp_" + strings.Repeat("a", 36), "GitHub Personal Access Token", true, true},
		{"GitHub fine-grained PAT", "github_pat_" + strings.Repeat("a", 22), "GitHub Fine-Grained Personal Access Token", true, true},
		{"GitLab PAT", "glpat-" + strings.Repeat("a", 20), "GitLab Personal Access Token", true, true},
		{"AWS Access Key ID", "AKIAABCDEFGHIJKLMNOP", "AWS Access Key ID", true, true},
		{"AWS temp Access Key ID", "ASIAABCDEFGHIJKLMNOP", "AWS Access Key ID", true, true},
		{"Anthropic key", "sk-ant-api03-" + strings.Repeat("a", 20), "Anthropic Claude API Key", true, true},
		{"OpenAI project key", "sk-proj-" + strings.Repeat("a", 20), "OpenAI Project API Key", true, true},
		{"bare sk- key", "sk-" + strings.Repeat("a", 20), "OpenAI (legacy) or DeepSeek API Key", true, true},
		{"Hugging Face token", "hf_" + strings.Repeat("a", 20), "Hugging Face Token", true, true},
		{"Stripe live key", "sk_live_" + strings.Repeat("a", 24), "Stripe Live Secret Key", true, true},
		{"Stripe restricted key", "rk_live_" + strings.Repeat("a", 24), "Stripe Restricted Key", true, true},
		{"Slack bot token", "xoxb-" + strings.Repeat("1", 10), "Slack Bot Token", true, true},
		{"Shopify token", "shpat_" + strings.Repeat("a", 20), "Shopify Access Token", true, true},
		{"Twilio SID", "AC" + strings.Repeat("a", 32), "Twilio Account SID", true, true},
		{"SendGrid key", "SG.abcdefghij.abcdefghij", "SendGrid API Key", true, true},
		{"Notion token", "secret_" + strings.Repeat("a", 40), "Notion Internal Integration Token", true, true},
		{"JWT", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123", "JSON Web Token (JWT)", true, true},
		{"RSA private key header", "-----BEGIN RSA PRIVATE KEY-----", "RSA Private Key", true, true},
		{"DB connection string with real creds", "postgres://admin:hunter2xyz@db.internal/prod", "Database connection string with embedded credentials", true, true},
		{"unverified Cursor key", "crsr_" + strings.Repeat("a", 10), "Cursor API Key", false, true},
		{"unverified Tavily key", "tvly-" + strings.Repeat("a", 10), "Tavily API Key", false, true},
		{"plain string, no match", "just a normal value", "", false, false},
		{"bare UUID, deliberately not matched", "550e8400-e29b-41d4-a716-446655440000", "", false, false},
		{"bare 64-char hex, deliberately not matched", strings.Repeat("a", 64), "", false, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			vendor, verified, ok := MatchKnownTokenPattern(c.value)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v (vendor=%q)", ok, c.wantOK, vendor)
			}
			if !ok {
				return
			}
			if vendor != c.wantVendor {
				t.Errorf("vendor = %q, want %q", vendor, c.wantVendor)
			}
			if verified != c.wantVerified {
				t.Errorf("verified = %v, want %v", verified, c.wantVerified)
			}
		})
	}
}

// TestMatchKnownTokenPatternDBConnectionStringPlaceholder locks in a real
// false-positive found while adding this feature: the DB connection-string
// pattern's own shape ("scheme://user:pass@host") is indistinguishable from
// the placeholder credentials every .env.example uses. Only a literal
// placeholder word in the password position should be excluded — a real
// (if bad) password must still match.
func TestMatchKnownTokenPatternDBConnectionStringPlaceholder(t *testing.T) {
	placeholders := []string{
		"postgres://user:password@localhost/dbname",
		"postgres://admin:changeme@localhost/dbname",
		"mongodb://user:pass@localhost/dbname",
		"redis://:secret@localhost:6379",
	}
	for _, v := range placeholders {
		if _, _, ok := MatchKnownTokenPattern(v); ok {
			t.Errorf("MatchKnownTokenPattern(%q) matched, want excluded as a placeholder", v)
		}
	}

	if _, _, ok := MatchKnownTokenPattern("postgres://admin:hunter2xyz@db.internal/prod"); !ok {
		t.Error("MatchKnownTokenPattern with a non-placeholder password should still match")
	}
}
