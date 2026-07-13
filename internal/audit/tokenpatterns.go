// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package audit

import "regexp"

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

// MatchKnownTokenPattern checks value against well-known vendor credential
// formats. Returns the vendor/format name, whether that format is verified
// (see tokenPattern.verified), and whether anything matched at all.
func MatchKnownTokenPattern(value string) (vendor string, verified bool, ok bool) {
	for _, tp := range knownTokenPatterns {
		if tp.pattern.MatchString(value) && (tp.exclude == nil || !tp.exclude.MatchString(value)) {
			return tp.vendor, tp.verified, true
		}
	}
	return "", false, false
}
