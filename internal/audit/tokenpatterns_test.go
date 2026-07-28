// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tokenBody builds n characters of realistic token body: base62, and never
// the same character twice in a row. Fixtures used to be strings.Repeat("a",
// n), which isPlaceholderToken now (correctly) rejects as filler — a run of
// 36 a's is not what a real credential looks like, so those fixtures were
// quietly testing the patterns against a value no vendor would ever issue.
// The stride of 7 is coprime with the alphabet length, so consecutive
// characters always differ and no placeholder word can form.
func tokenBody(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[(i*7+3)%len(alphabet)]
	}
	return string(b)
}

// hexBody is tokenBody for the formats whose body is hex-only (Twilio's SID,
// DigitalOcean's token) — base62 filler doesn't satisfy their patterns at all.
// Stride 3 is coprime with 16, so again no character repeats back to back.
func hexBody(n int) string {
	const alphabet = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[(i*3+1)%len(alphabet)]
	}
	return string(b)
}

func TestMatchKnownTokenPattern(t *testing.T) {
	cases := []struct {
		name         string
		value        string
		wantVendor   string
		wantVerified bool
		wantOK       bool
	}{
		{"GitHub PAT", "ghp_" + tokenBody(36), "GitHub Personal Access Token", true, true},
		{"GitHub fine-grained PAT", "github_pat_" + tokenBody(22), "GitHub Fine-Grained Personal Access Token", true, true},
		{"GitLab PAT", "glpat-" + tokenBody(20), "GitLab Personal Access Token", true, true},
		{"AWS Access Key ID", "AKIAABCDEFGHIJKLMNOP", "AWS Access Key ID", true, true},
		{"AWS temp Access Key ID", "ASIAABCDEFGHIJKLMNOP", "AWS Access Key ID", true, true},
		{"Anthropic key", "sk-ant-api03-" + tokenBody(20), "Anthropic Claude API Key", true, true},
		{"OpenAI project key", "sk-proj-" + tokenBody(20), "OpenAI Project API Key", true, true},
		{"bare sk- key", "sk-" + tokenBody(20), "OpenAI (legacy) or DeepSeek API Key", true, true},
		{"Hugging Face token", "hf_" + tokenBody(20), "Hugging Face Token", true, true},
		{"Stripe live key", "sk_live_" + tokenBody(24), "Stripe Live Secret Key", true, true},
		{"Stripe restricted key", "rk_live_" + tokenBody(24), "Stripe Restricted Key", true, true},
		{"Slack bot token", "xoxb-" + tokenBody(10), "Slack Bot Token", true, true},
		{"Shopify token", "shpat_" + tokenBody(20), "Shopify Access Token", true, true},
		{"Twilio SID", "AC" + hexBody(32), "Twilio Account SID", true, true},
		{"SendGrid key", "SG.abcdefghij.abcdefghij", "SendGrid API Key", true, true},
		{"Notion token", "ntn_" + tokenBody(40), "Notion Internal Integration Token", true, true},
		{"Notion token, legacy secret_ form", "secret_" + tokenBody(40), "Notion Internal Integration Token (legacy)", true, true},
		{"GitHub App refresh token", "ghr_" + tokenBody(36), "GitHub App Refresh Token", true, true},
		{"GitLab deploy token", "gldt-" + tokenBody(20), "GitLab Deploy Token", true, true},
		{"GitLab runner token", "glrt-" + tokenBody(20), "GitLab Runner Authentication Token", true, true},
		{"GitLab runner token, registration form", "glrtr-" + tokenBody(20), "GitLab Runner Authentication Token", true, true},
		{"GitLab PAT longer than the legacy 20", "glpat-" + tokenBody(32), "GitLab Personal Access Token", true, true},
		{"Google API key", "AIza" + tokenBody(35), "Google API Key", true, true},
		{"Slack app-level token", "xapp-" + tokenBody(10), "Slack App-Level Token", true, true},
		{"Stripe webhook signing secret", "whsec_" + tokenBody(24), "Stripe Webhook Signing Secret", true, true},
		{"Supabase secret key", "sb_secret_" + tokenBody(20), "Supabase Secret Key", true, true},
		{"Grafana service account token", "glsa_" + tokenBody(20), "Grafana Service Account Token", true, true},
		{"Doppler service token", "dp.st." + tokenBody(20), "Doppler Service Token", true, true},
		{"Vault service token", "hvs." + tokenBody(24), "HashiCorp Vault Token", true, true},
		{"Vault batch token", "hvb." + tokenBody(24), "HashiCorp Vault Token", true, true},
		{"age secret key", "AGE-SECRET-KEY-1" + "QWERTYUIOPASDFGHJKLZXCVBNM234567", "age Secret Key", true, true},
		{"Anthropic admin key", "sk-ant-admin01-" + tokenBody(20), "Anthropic Admin API Key", true, true},
		{"OpenAI service account key", "sk-svcacct-" + tokenBody(20), "OpenAI Service Account Key", true, true},
		{"OpenAI admin key", "sk-admin-" + tokenBody(20), "OpenAI Admin API Key", true, true},
		{"JWT", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123", "JSON Web Token (JWT)", true, true},
		{"RSA private key header", "-----BEGIN RSA PRIVATE KEY-----", "RSA Private Key", true, true},
		{"DB connection string with real creds", "postgres://admin:hunter2xyz@db.internal/prod", "Database connection string with embedded credentials", true, true},
		{"DB connection string, SQLAlchemy +driver", "postgresql+asyncpg://postgres:Xk92QmPl4TzWhu@db.prod.internal/main", "Database connection string with embedded credentials", true, true},
		{"DB connection string, mysql +driver", "mysql+pymysql://svc:S3cretPwLong@db.example.com/app", "Database connection string with embedded credentials", true, true},
		{"DB connection string, scheme-less", "scanner_user:Dnn07HjN5s5C0tM4@scanner.cluster-abc.rds.amazonaws.com/postgres", "Database connection string with embedded credentials (scheme-less)", true, true},
		{"unverified Cursor key", "crsr_" + tokenBody(10), "Cursor API Key", false, true},
		{"unverified Tavily key", "tvly-" + tokenBody(10), "Tavily API Key", false, true},
		{"plain string, no match", "just a normal value", "", false, false},
		{"bare UUID, deliberately not matched", "550e8400-e29b-41d4-a716-446655440000", "", false, false},
		{"bare 64-char hex, deliberately not matched", tokenBody(64), "", false, false},
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

// TestMatchKnownTokenPatternSchemeLessConnString pins the scheme-less
// connection-string pattern's deliberate limits. Without a "://" to anchor on
// it leans entirely on shape, so it must stay narrow enough that ordinary
// non-credential text doesn't trip it — a host:port pair and a bare hostname
// are the shapes that would otherwise fire constantly in a real .env.
func TestMatchKnownTokenPatternSchemeLessConnString(t *testing.T) {
	shouldMatch := []string{
		"scanner_user:Dnn07HjN5s5C0tM4@scanner.cluster-abc.rds.amazonaws.com/postgres",
		"svc.account:S3cretPwLong@db.example.co.uk:5432/app",
	}
	for _, v := range shouldMatch {
		if _, _, ok := MatchKnownTokenPattern(v); !ok {
			t.Errorf("MatchKnownTokenPattern(%q) did not match, want a scheme-less connection string", v)
		}
	}

	shouldNotMatch := []string{
		"redis-cluster.internal.acme.com:6379", // host:port, no userinfo at all
		"user:realpasswd1@localhost/db",        // bare host, deliberately given up
		"user:realpasswd1@127.0.0.1/db",        // IP, deliberately given up
		"user:short@db.acme.com/db",            // password under the 8-char floor
		"myuser:changeme@db.acme.com/app",      // placeholder password
		// Contact URIs share the "scheme:something@host.tld" shape. Review
		// (2026-07-28) caught this reporting as a database credential.
		"mailto:engineering@blockaid.io",
		"mailto:somebody@company.co.uk",
		"tel:pluslongnumber@carrier.example",
	}
	for _, v := range shouldNotMatch {
		if vendor, _, ok := MatchKnownTokenPattern(v); ok {
			t.Errorf("MatchKnownTokenPattern(%q) matched as %s, want no match", v, vendor)
		}
	}
}

// TestConnStringHumanReadableWords guards the false NEGATIVE that
// tokenPattern.humanReadable exists to prevent. placeholderTokenWords assumes
// a credential is opaque base62, so a literal "here"/"example" in it means
// filler — but connection strings carry a hostname and a username, where those
// substrings occur naturally ("db.sphere.internal" contains "here"). Without
// the exemption, a live production credential at such a host is silently
// dropped, which is the worst outcome this scanner has.
func TestConnStringHumanReadableWords(t *testing.T) {
	live := []string{
		"postgres://svc:Xk92QmPl4TzWhu@db.sphere.internal/prod",      // "here" inside "sphere"
		"appuser:Dnn07HjN5s5C0tM4@db.adhere-health.com/records",      // "here" inside "adhere"
		"postgresql+asyncpg://u:Zk92QmPl4Tz@shop.example-corp.io/db", // real host that is literally "example-corp"
	}
	for _, v := range live {
		if _, _, ok := MatchKnownTokenPattern(v); !ok {
			t.Errorf("MatchKnownTokenPattern(%q) was suppressed, want a match: a real host containing a placeholder word must not hide a live credential", v)
		}
	}

	// The run half of the check still applies to these formats: an all-x
	// password is filler regardless of how human-readable the format is.
	if _, _, ok := MatchKnownTokenPattern("postgres://svc:xxxxxxxxxxxx@db.internal/prod"); ok {
		t.Error("an all-x password should still be rejected as filler")
	}
}

// TestFindFileTokensConnStringNotDoubleReported locks in the ordering
// contract between the two connection-string patterns: a full URL contains a
// scheme-less-shaped span inside it, so without first-claim-wins ordering one
// credential would be reported twice under two vendor names.
func TestFindFileTokensConnStringNotDoubleReported(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	line := "DB_URI=postgresql+asyncpg://postgres:Xk92QmPl4TzWhu@postgres.db-prod.internal/maindb\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}

	tokens, err := FindFileTokens(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 1 {
		for _, tk := range tokens {
			t.Logf("vendor=%q value=%q", tk.Vendor, tk.Value)
		}
		t.Fatalf("got %d tokens, want exactly 1", len(tokens))
	}
	if want := "Database connection string with embedded credentials"; tokens[0].Vendor != want {
		t.Errorf("vendor = %q, want %q", tokens[0].Vendor, want)
	}
}

// TestMatchKnownTokenPatternPlaceholderToken locks in the false positive that
// prompted isPlaceholderToken (2026-07-26 dogfooding): a real .env.example
// holding "NOTION_API_KEY=secret_xxxxxxxx…" reported HIGH, because the masked
// body is still [A-Za-z0-9] as far as the Notion pattern is concerned. Every
// vendor format is affected the same way — the mask goes AFTER the prefix, so
// the whole-value IsAlreadyMasked check can't see it.
func TestMatchKnownTokenPatternPlaceholderToken(t *testing.T) {
	placeholders := []string{
		"secret_" + strings.Repeat("x", 43), // the reported .env.example, verbatim shape
		"secret_" + strings.Repeat("X", 40),
		"ghp_" + strings.Repeat("x", 36),
		"ghp_" + strings.Repeat("0", 36),
		"AKIA" + strings.Repeat("X", 16),
		"sk-ant-api03-" + strings.Repeat("x", 20),
		"sk_live_" + strings.Repeat("x", 24),
		"xoxb-" + strings.Repeat("0", 10),
		"hf_your_token_here_abcdefghij",
		"shpat_placeholder_abcdefghijkl",
		"github_pat_EXAMPLEEXAMPLEEXAMPLE12",
	}
	for _, v := range placeholders {
		if vendor, _, ok := MatchKnownTokenPattern(v); ok {
			t.Errorf("MatchKnownTokenPattern(%q) matched as %s, want rejected as a placeholder", v, vendor)
		}
	}

	// The rejection must be narrow enough that a real credential still fires —
	// a filter that silences genuine tokens is far worse than the noise it set
	// out to remove. Short runs (up to placeholderRunLen-1) stay matched.
	real := []string{
		"secret_" + tokenBody(40),
		"ghp_" + tokenBody(36),
		"AKIAABCDEFGHIJKLMNOP",
		"sk-ant-api03-" + tokenBody(20),
		"ghp_aaaaaaa" + tokenBody(29), // a 7-long run is not enough
	}
	for _, v := range real {
		if _, _, ok := MatchKnownTokenPattern(v); !ok {
			t.Errorf("MatchKnownTokenPattern(%q) rejected, want a real-token match", v)
		}
	}
}

// TestFindFileTokensSkipsPlaceholders covers the content scanner's own copy of
// the check (content.go) — the exposed-secret path is separate from
// MatchKnownTokenPattern's and would otherwise still report template filler.
func TestFindFileTokensSkipsPlaceholders(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env.example")
	body := "NOTION_API_KEY=secret_" + strings.Repeat("x", 43) + "\nGH=ghp_" + strings.Repeat("0", 36) + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	tokens, err := FindFileTokens(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 0 {
		t.Errorf("FindFileTokens found %d token(s) in an all-placeholder template, want 0: %+v", len(tokens), tokens)
	}

	realPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(realPath, []byte("NOTION_API_KEY=secret_"+tokenBody(40)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tokens, err = FindFileTokens(realPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 1 {
		t.Fatalf("FindFileTokens found %d token(s) for a real credential, want 1", len(tokens))
	}
	if tokens[0].Vendor != "Notion Internal Integration Token (legacy)" {
		t.Errorf("vendor = %q, want the legacy Notion format", tokens[0].Vendor)
	}
}
