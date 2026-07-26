// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"regexp"
	"strings"
)

// tokenPattern is one recognizable vendor credential format. "Token
// prefixing" — a stable, greppable prefix baked into the credential itself
// — is a deliberate industry convention (popularized by GitHub's 2021
// secret-scanning overhaul) specifically so tools like this one can
// identify a leaked credential by VALUE alone, independent of what the
// variable holding it happens to be named. This is a meaningfully stronger
// signal than the name-based LooksLikeSecretKey heuristic: a value that
// matches "ghp_" followed by exactly 36 base62 characters is almost
// certainly a real GitHub token regardless of whether the variable is
// named "GITHUB_TOKEN" or just "X".
type tokenPattern struct {
	vendor  string
	pattern *regexp.Regexp
	// verified is true for formats independently confirmed against a
	// stable, well-documented vendor spec (GitHub, AWS, Stripe, Slack,
	// GitLab, JWT, DB connection-string syntax). false for formats reported
	// but not independently confirmed (Cursor, Tavily, Slack's less-common
	// token classes) — a match still fires, but at Medium rather than High
	// confidence, so a wrong guess about the exact format doesn't overstate
	// certainty.
	verified bool
	// exclude, when set, is checked against the same value on a match;
	// a hit suppresses it as a known false-positive shape. Needed for the DB
	// connection-string pattern: "postgres://user:password@localhost/db" is
	// the overwhelmingly common template placeholder, and structurally
	// indistinguishable from a real credential by prefix/shape alone.
	exclude *regexp.Regexp
}

// knownTokenPatterns is checked in order — more specific prefixes must
// come before more generic ones they could otherwise be shadowed by (e.g.
// OpenAI's "sk-proj-" and Anthropic's "sk-ant-api03-" before the bare
// "sk-" fallback).
//
// Deliberately excluded, with reasons:
//   - UUIDs and bare 32/64-char hex strings (MD5/SHA-256-shaped, Shodan
//     keys, Datadog API keys): structurally identical to countless
//     non-secret things (hashes, correlation IDs, commit SHAs). Reliably
//     catching these needs entropy analysis, not pattern matching — out
//     of scope here, not an oversight.
//   - Heroku ("heroku_"): real Heroku API keys are, to the best of this
//     project's knowledge, bare UUIDs with no distinguishing prefix — a
//     "heroku_" pattern would never match a real key, so it was omitted
//     rather than included as a well-intentioned but non-functional entry.
var knownTokenPatterns = []tokenPattern{
	// --- Verified against stable, well-documented vendor specs ---
	{"GitHub Fine-Grained Personal Access Token", regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}`), true, nil},
	{"GitHub Personal Access Token", regexp.MustCompile(`\bghp_[A-Za-z0-9]{36}\b`), true, nil},
	{"GitHub OAuth Access Token", regexp.MustCompile(`\bgho_[A-Za-z0-9]{36}\b`), true, nil},
	{"GitHub App Server Token", regexp.MustCompile(`\bghs_[A-Za-z0-9]{36}\b`), true, nil},
	{"GitHub User-to-Server Token", regexp.MustCompile(`\bghu_[A-Za-z0-9]{36}\b`), true, nil},
	{"GitLab Personal Access Token", regexp.MustCompile(`\bglpat-[A-Za-z0-9_\-]{20}\b`), true, nil},
	{"AWS Access Key ID", regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`), true, nil},
	{"DigitalOcean API Token", regexp.MustCompile(`\bdop_v1_[a-f0-9]{40,}\b`), true, nil},
	{"npm Publishing Token", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36,}\b`), true, nil},
	{"Anthropic Claude API Key", regexp.MustCompile(`\bsk-ant-api03-[A-Za-z0-9_\-]{20,}\b`), true, nil},
	{"OpenAI Project API Key", regexp.MustCompile(`\bsk-proj-[A-Za-z0-9_\-]{20,}\b`), true, nil},
	// Bare "sk-" is shared by OpenAI's legacy key format and DeepSeek's
	// current format — the prefix alone can't distinguish them, so the
	// vendor name says both rather than falsely picking one.
	{"OpenAI (legacy) or DeepSeek API Key", regexp.MustCompile(`\bsk-[A-Za-z0-9]{20,}\b`), true, nil},
	{"Hugging Face Token", regexp.MustCompile(`\bhf_[A-Za-z0-9]{20,}\b`), true, nil},
	{"Stripe Live Secret Key", regexp.MustCompile(`\bsk_live_[A-Za-z0-9]{24,}\b`), true, nil},
	{"Stripe Test Secret Key", regexp.MustCompile(`\bsk_test_[A-Za-z0-9]{24,}\b`), true, nil},
	{"Stripe Restricted Key", regexp.MustCompile(`\brk_live_[A-Za-z0-9]{24,}\b`), true, nil},
	{"Slack Bot Token", regexp.MustCompile(`\bxoxb-[0-9A-Za-z\-]{10,}\b`), true, nil},
	{"Slack User Token", regexp.MustCompile(`\bxoxp-[0-9A-Za-z\-]{10,}\b`), true, nil},
	{"Shopify Access Token", regexp.MustCompile(`\bshpat_[A-Za-z0-9]{20,}\b`), true, nil},
	{"Twilio Account SID", regexp.MustCompile(`\bAC[a-fA-F0-9]{32}\b`), true, nil},
	{"SendGrid API Key", regexp.MustCompile(`\bSG\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`), true, nil},
	{"Notion Internal Integration Token", regexp.MustCompile(`\bsecret_[A-Za-z0-9]{40,}\b`), true, nil},
	{"JSON Web Token (JWT)", regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*\b`), true, nil},
	{"RSA Private Key", regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`), true, nil},
	{"OpenSSH Private Key", regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`), true, nil},
	{"EC Private Key", regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`), true, nil},
	{"PKCS8 Private Key", regexp.MustCompile(`-----BEGIN PRIVATE KEY-----`), true, nil},
	// Database connection strings — only when they actually embed
	// user:pass@ credentials, same reasoning as LooksLikeBareURL: a bare
	// "redis://localhost:6379" isn't a secret, "redis://:hunter2@host" is.
	// dbConnStringPlaceholder excludes the placeholder userinfo every
	// .env.example/README on the internet uses (real-world dogfooding
	// 2026-07-06 found "postgres://user:password@localhost/dbname" firing
	// on a template file — structurally identical to a real credential by
	// shape alone, so the exclusion has to check the literal words).
	{"Database connection string with embedded credentials",
		regexp.MustCompile(`\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|redis|amqp)://[^/@\s:]+:[^/@\s]+@`),
		true,
		regexp.MustCompile(`(?i)://[^/@\s:]*:(?:pass(?:word)?|changeme|secret|admin|user(?:name)?|test|xxx+|your[_-]?password(?:_here)?)@`)},

	// --- Reported (2026-07-06) but not independently verified against a
	// published spec — matched at lower (Medium) confidence. ---
	{"Cursor API Key", regexp.MustCompile(`\bcrsr_[A-Za-z0-9]{10,}\b`), false, nil},
	{"Tavily API Key", regexp.MustCompile(`\btvly-[A-Za-z0-9\-]{10,}\b`), false, nil},
	{"Slack Refresh Token", regexp.MustCompile(`\bxoxa-[0-9A-Za-z\-]{10,}\b`), false, nil},
	{"Slack Configuration Token", regexp.MustCompile(`\bxoxr-[0-9A-Za-z\-]{10,}\b`), false, nil},
}

// placeholderRunLen is how many identical characters in a row mark a matched
// token as hand-written filler rather than a real credential. Vendor formats
// are random (base62 from a CSPRNG), so a run this long essentially cannot
// occur in a genuine token: for a 40-character base62 credential the odds are
// about 34 x 62^-7, or one in ten billion. Every hand-written placeholder, on
// the other hand, is a run — "secret_xxxxxxxx…", "AKIAXXXXXXXXXXXXXXXX",
// "ghp_000000…". Eight is low enough to catch the short ones and still far
// past anything randomness produces.
const placeholderRunLen = 8

// placeholderTokenWords are literal words that only appear in a token a human
// typed. Matched case-insensitively as substrings of the token itself, so
// deliberately none of them occur inside any vendor PREFIX above — "test"
// would kill every real sk_test_ key, "secret" every real Notion token.
// Same one-in-billions reasoning as placeholderRunLen for a random credential
// happening to contain one.
var placeholderTokenWords = []string{
	"your", "here", "changeme", "placeholder", "example", "dummy", "redacted",
}

// isPlaceholderToken reports whether a matched token span is obviously filler
// a human typed into a template rather than a real credential.
//
// This is the general form of the per-pattern exclude regex (which stays for
// the DB connection-string case, whose placeholder shape is about the userinfo
// field, not the token body). Real-world dogfooding (2026-07-26) found the gap
// it closes: an .env.example holding "NOTION_API_KEY=secret_xxxxxxxx…" was
// reported HIGH by jit scan, because 43 x's are perfectly good [A-Za-z0-9] as
// far as the Notion pattern is concerned. IsAlreadyMasked didn't catch it
// either — alreadyMaskedPattern is anchored to the whole value (^[*xX]{3,}$),
// so a vendor prefix in front of the mask defeats it. Since a token match is
// what escalates a template file past buildEnvFileFinding's bail-out, that one
// placeholder was enough to turn an ordinary .env.example into a HIGH finding,
// and jit migrate — which skips template files outright — then had nothing to
// offer for it. A scanner that cries wolf on .env.example files is exactly the
// noise envTemplateSuffixes exists to prevent.
func isPlaceholderToken(match string) bool {
	run := 1
	for i := 1; i < len(match); i++ {
		if match[i] != match[i-1] {
			run = 1
			continue
		}
		if run++; run >= placeholderRunLen {
			return true
		}
	}
	lower := strings.ToLower(match)
	for _, word := range placeholderTokenWords {
		if strings.Contains(lower, word) {
			return true
		}
	}
	return false
}

// MatchKnownTokenPattern checks value against well-known vendor credential
// formats. Returns the vendor/format name, whether that format is verified
// (see tokenPattern.verified), and whether anything matched at all.
func MatchKnownTokenPattern(value string) (vendor string, verified bool, ok bool) {
	for _, tp := range knownTokenPatterns {
		match := tp.pattern.FindString(value)
		if match == "" {
			continue
		}
		if tp.exclude != nil && tp.exclude.MatchString(value) {
			continue
		}
		if isPlaceholderToken(match) {
			continue
		}
		return tp.vendor, tp.verified, true
	}
	return "", false, false
}
