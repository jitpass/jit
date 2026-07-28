// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import "testing"

func TestIsProductionIndicator(t *testing.T) {
	// These four cases are RFC.md §4's own explicit examples — the whole
	// point of the custom-boundary regex is to satisfy exactly these.
	cases := []struct {
		input string
		want  bool
	}{
		{"PROD_DB_URL", true},
		{"evm-prod-ro-endpoint", true},
		{"nonprod", false},
		{"product", false},
		// Additional boundary coverage beyond RFC's own examples.
		{"prod", true},
		{"PRODUCTION_API_KEY", true},
		{"production", true},
		{"productive", false},
		{"myproduct", false},
		{"db.prod.internal", true},
		{"unproductive", false},
		{"", false},
	}
	for _, c := range cases {
		got := IsProductionIndicator(c.input)
		if got != c.want {
			t.Errorf("IsProductionIndicator(%q) = %v, want %v", c.input, got, c.want)
		}
	}
}

func TestMatchPublicIP(t *testing.T) {
	cases := []struct {
		input   string
		wantIP  string
		wantOK  bool
		comment string
	}{
		{"postgres://10.0.0.5:5432/db", "", false, "RFC1918 private (10.0.0.0/8)"},
		{"host=172.16.4.1", "", false, "RFC1918 private (172.16.0.0/12)"},
		{"192.168.1.1", "", false, "RFC1918 private (192.168.0.0/16)"},
		{"http://127.0.0.1:8080", "", false, "loopback — excluded despite being outside RFC1918"},
		{"169.254.1.1", "", false, "link-local — excluded despite being outside RFC1918"},
		{"0.0.0.0", "", false, "unspecified — excluded despite being outside RFC1918"},
		{"evm-prod-ro-endpoint=8.8.8.8", "8.8.8.8", true, "genuine public IP"},
		{"no ip here", "", false, "no match"},
	}
	for _, c := range cases {
		gotIP, gotOK := MatchPublicIP(c.input)
		if gotOK != c.wantOK || (gotOK && gotIP != c.wantIP) {
			t.Errorf("MatchPublicIP(%q) = (%q, %v), want (%q, %v) [%s]", c.input, gotIP, gotOK, c.wantIP, c.wantOK, c.comment)
		}
	}
}

func TestLooksLikeBareURL(t *testing.T) {
	cases := []struct {
		input   string
		want    bool
		comment string
	}{
		{"http://localhost:8080", true, "plain local tool endpoint (the real CAIDO_URL case)"},
		{"https://caido.example.com/api", true, "plain remote endpoint, short path"},
		{"not a url at all", false, "no http(s) prefix"},
		{"https://user:hunter2@db.internal/path", false, "userinfo present — treat as potentially credential-bearing"},
		// Literal split so GitHub push protection doesn't flag this fake
		// fixture as a real webhook; the compiled string is unchanged.
		{"https://hooks.slack.com" + "/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX", false, "long opaque token segment — Slack webhook URLs ARE secrets"},
		{"", false, "empty string"},
	}
	for _, c := range cases {
		got := LooksLikeBareURL(c.input)
		if got != c.want {
			t.Errorf("LooksLikeBareURL(%q) = %v, want %v [%s]", c.input, got, c.want, c.comment)
		}
	}
}

// TestLooksLikeNonSecretName covers the name-signal suppression added after
// five real developer scans (2026-07-28) were dominated by browser-public
// build variables and path-holding names. The safety property this must never
// break: suppression is name-only, so anything the caller detects by VALUE is
// unaffected.
func TestLooksLikeNonSecretName(t *testing.T) {
	cases := []struct {
		input   string
		want    bool
		comment string
	}{
		// Documented-public build prefixes — the bundler inlines these into
		// client JavaScript, so they are public by construction.
		{"VITE_AUTH0_DOMAIN", true, "the real case: value was the bare hostname id.blockaid.io"},
		{"VITE_DATADOG_CLIENT_TOKEN", true, "Datadog client tokens are the browser-facing credential by design"},
		{"NEXT_PUBLIC_ANALYTICS_ID", true, "Next.js inlines NEXT_PUBLIC_ into the browser bundle"},
		{"REACT_APP_DATADOG_PROXY_URL", true, "CRA public prefix; the real value was the path /logsProxy"},
		{"EXPO_PUBLIC_API_URL", true, "Expo public prefix"},

		// Vendor names documented as publicly exposable.
		{"SUPABASE_ANON_KEY", true, "Supabase documents anon keys as safe to expose"},
		{"STRIPE_PUBLISHABLE_KEY", true, "publishable by name"},
		{"AUTH0_CLIENT_ID", true, "OAuth client IDs are public per RFC 6749"},

		// Paths are pointers, not credentials.
		{"CALLBACK_PRIVATE_KEY_PATH", true, "the real case: rated HIGH despite holding a filesystem path"},
		{"FIREBLOCKS_API_PRIVATE_KEY_PATH", true, "same, from a second machine"},
		{"GOOGLE_APPLICATION_CREDENTIALS_FILE", true, "_FILE holds a path"},
		{"SSH_KEY_DIR", true, "_DIR holds a path"},

		// The override: a public prefix must NOT excuse a secret-shaped name.
		// NEXT_PUBLIC_STRIPE_SECRET_KEY is a misconfiguration, not a safe key.
		{"NEXT_PUBLIC_STRIPE_SECRET_KEY", false, "SECRET is never legitimately public"},
		{"VITE_DB_PASSWORD", false, "PASSWORD is never legitimately public"},
		{"PUBLIC_PRIVATE_KEY", false, "PRIVATE is never legitimately public"},
		{"AUTH0_CLIENT_SECRET", false, "the client SECRET is not public, unlike the client ID"},

		// Ordinary secret names are untouched.
		{"MONGO_PASSWORD", false, "ordinary secret name"},
		{"OPENAI_API_KEY", false, "ordinary secret name"},
		{"DB_URI", false, "ordinary secret name"},
	}
	for _, c := range cases {
		if got := LooksLikeNonSecretName(c.input); got != c.want {
			t.Errorf("LooksLikeNonSecretName(%q) = %v, want %v [%s]", c.input, got, c.want, c.comment)
		}
	}
}

// TestLooksLikeNonSecretValue covers the value-side suppression. Across eleven
// real developer scans (2026-07-28) the same non-secret shapes were reported as
// credentials over and over, purely because their NAMES matched
// secretKeyMarkers. The safety line this must not cross: anything a human
// could plausibly have chosen as a password keeps its full weight.
func TestLooksLikeNonSecretValue(t *testing.T) {
	cases := []struct {
		input   string
		want    bool
		comment string
	}{
		// Feature flags and settings.
		{"true", true, "SF_TEMP_SHOW_SECRETS=true — a boolean flag, reported as a credential"},
		{"False", true, "WIPE_REDIS_ON_START=False"},
		{"none", true, "explicit empty sentinel"},
		{"6379", true, "REDIS_PORT=6379"},
		{"0.1", true, "REACT_APP_SENTRY_TRACES_SAMPLE_RATE=0.1"},
		{"-1", true, "a negative timeout"},
		{"", true, "REDIS_STAGING_HOST= — an empty value is never a secret"},

		// Endpoints with no credentials in them.
		{"http://127.0.0.1:4000", true, "ANTHROPIC_BASE_URL — a local endpoint"},
		{"https://api.hibob.com", true, "HIBOB_BASE_URL"},
		{"redis://cache.internal:6379", true, "REDIS_URL with no userinfo; non-http scheme"},
		{"postgresql://localhost:5432/app", true, "DATABASE_URL pointing at localhost, no credentials"},

		// Unfilled template values in an otherwise real .env.
		{"service-user-token-here", true, "HIBOB_SERVICE_USER_TOKEN, verbatim"},
		{"your-api-key", true, "kebab filler"},
		{"<your-token>", true, "angle-bracket convention"},

		// --- Must NOT be suppressed ---
		{"redis://:hunter2secret@cache.internal:6379", false, "userinfo present — credential-bearing"},
		{"https://hooks.example.com/services/T00/B00/XXXXXXXXXXXXXXXXXXXXXXXX", false, "long opaque path segment — webhook URLs ARE secrets"},
		{"Tr0ub4dor3xKq9ZmPq2Lr", false, "an ordinary password"},
		// The discriminator that makes reusing placeholderTokenWords safe:
		// these contain filler words but are not lowercase filler SHAPE.
		{"Wherever2024!", false, "human-chosen password containing 'here'"},
		{"Yourk3yIsHere2024xK", false, "human-chosen password containing 'your' and 'here'"},
		{"example-Corp-2024-Xk9", false, "mixed case and digits — not filler shape"},
		{"1234567890123456789", false, "too long to read as a setting"},
	}
	for _, c := range cases {
		if got := LooksLikeNonSecretValue(c.input); got != c.want {
			t.Errorf("LooksLikeNonSecretValue(%q) = %v, want %v [%s]", c.input, got, c.want, c.comment)
		}
	}
}
