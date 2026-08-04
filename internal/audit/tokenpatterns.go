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
	// humanReadable exempts this format from placeholderTokenWords (but NOT
	// from placeholderRunLen). That word list rests on "a random base62
	// credential essentially cannot contain the literal word 'here'", which
	// is true of an opaque token body and false of any format that embeds a
	// hostname or username — a perfectly real credential at
	// db.sphere.internal contains "here", and "adhere"/"therefore"/
	// "yourcompany" are all plausible in a genuine host or user field.
	// Suppressing those would be a false NEGATIVE on a live credential,
	// which this project weighs as strictly worse than an extra finding
	// (see LooksLikeBareURL's doc comment). The connection-string formats
	// police their own placeholders through exclude, which checks the
	// password position specifically and is the right tool for them.
	humanReadable bool
}

// connStringPlaceholderUserinfo matches the userinfo half of a connection
// string whose password is the literal filler every .env.example and README
// on the internet ships ("postgres://user:password@localhost/dbname"). Shared
// by both connection-string patterns below.
//
// Deliberately NOT anchored on "://": the scheme-less pattern has no scheme to
// anchor against, and checking for ":<filler-word>@" alone is correct for both
// forms. Note this tests the PASSWORD field, not the username — "admin:hunter2@"
// is a real credential and stays reported, while "user:admin@" is filler.
const placeholderUserinfoAlt = `:(?:pass(?:word)?|changeme|secret|admin|user(?:name)?|test|xxx+|your[_-]?password(?:_here)?)@`

// shellExpansionUserinfoAlt matches a connection-string password that is a
// SHELL EXPANSION rather than a literal: "$PGPASSWORD", "${DB_PASS}",
// "$(op read …)", "`cat pw`". Nothing is exposed by such a line — the secret
// lives wherever the expansion reads it from, which is usually the correct
// place — so reporting it is a false positive on a user who is already doing
// the right thing.
//
// This matters far more for shell history than for the config files these
// patterns were written against. In a .env an interpolated password is
// unusual; in history it is the DOMINANT form, because typing
// `psql "postgres://app:$PGPASSWORD@db/app"` is how a careful developer avoids
// the very exposure this scanner looks for. Measured against realistic history
// lines before this exclusion existed, 6 of 8 interpolated connection strings
// were reported as embedded credentials.
//
// Shares placeholderUserinfoAlt's structure deliberately: it tests the
// PASSWORD field only. A literal password beside an interpolated username
// ("$DBUSER:hunter2@") is still a real credential and stays reported.
const shellExpansionUserinfoAlt = ":(?:" +
	`\$\{[^}]*\}` + "|" + // ${VAR}
	`\$[A-Za-z_][A-Za-z0-9_]*` + "|" + // $VAR
	`\$\([^)]*\)` + "|" + // $(command substitution)
	"`[^`]*`" + // `command substitution`
	")@"

// angleBracketUserinfoAlt rejects any candidate span carrying an angle
// bracket. RFC 3986 forbids bare "<" and ">" anywhere in a URI (they must be
// percent-encoded), so a span containing one is not a connection string —
// it is a placeholder. Two things write that shape and neither is a live
// credential: every README's fill-me-in form ("postgres://user:<password>@
// host"), and jit migrate's own history redaction marker
// ("<jit:redacted:VAR>"). The second is the load-bearing one — without this
// exclusion, scan re-flagged the exact line migrate just cleaned, forever,
// as a database credential. A bare "[<>]" (not an anchored ":<...>@" form)
// because the password character class already excludes "<": the pattern's
// match can START inside the marker ("redacted:VAR>@host"), so only a test
// the partial span still fails is safe.
const angleBracketUserinfoAlt = `[<>]`

var connStringPlaceholderUserinfo = regexp.MustCompile(
	`(?i)` + placeholderUserinfoAlt + `|` + shellExpansionUserinfoAlt + `|` + angleBracketUserinfoAlt)

// schemeLessConnStringExclude adds one more rejection on top of the
// placeholder-userinfo check, for the scheme-less pattern only.
//
// A "scheme:user@host.tld" span is the shape of a contact URI as much as a
// credential, and RE2 has no lookbehind to say "not preceded by a known
// non-credential scheme" inside the pattern itself. Review (2026-07-28) caught
// "CONTACT=mailto:engineering@blockaid.io" reporting as a database credential
// — a realistic line in a real .env, and exactly the kind of false positive
// that erodes trust in the report.
//
// Anchored at the start because both call sites test it against a span that
// begins at the userinfo: MatchKnownTokenPattern passes the whole value, and
// FindFileTokens passes the matched span, which starts at the scheme.
// It composes with placeholderUserinfoAlt rather than replacing it: a
// scheme-less match must clear BOTH checks, and tokenPattern carries a single
// exclude, so the two alternatives are ORed into one regex here.
var schemeLessConnStringExclude = regexp.MustCompile(
	`(?i)^(?:mailto|tel|sms|callto|skype|xmpp|urn|data|geo|magnet):` + `|` +
		placeholderUserinfoAlt + `|` + shellExpansionUserinfoAlt + `|` + angleBracketUserinfoAlt)

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
	{"GitHub Fine-Grained Personal Access Token", regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}`), true, nil, false},
	{"GitHub Personal Access Token", regexp.MustCompile(`\bghp_[A-Za-z0-9]{36}\b`), true, nil, false},
	{"GitHub OAuth Access Token", regexp.MustCompile(`\bgho_[A-Za-z0-9]{36}\b`), true, nil, false},
	{"GitHub App Server Token", regexp.MustCompile(`\bghs_[A-Za-z0-9]{36}\b`), true, nil, false},
	{"GitHub User-to-Server Token", regexp.MustCompile(`\bghu_[A-Za-z0-9]{36}\b`), true, nil, false},
	{"GitHub App Refresh Token", regexp.MustCompile(`\bghr_[A-Za-z0-9]{36}\b`), true, nil, false},
	// GitLab documents the prefix per token class but NOT a length, so these
	// are all open-ended. glpat- was previously pinned to exactly 20 body
	// characters, which is the legacy size — newer instances issue longer
	// ones, so an exact count silently missed them.
	{"GitLab Personal Access Token", regexp.MustCompile(`\bglpat-[A-Za-z0-9_\-]{20,}`), true, nil, false},
	{"GitLab Deploy Token", regexp.MustCompile(`\bgldt-[A-Za-z0-9_\-]{20,}`), true, nil, false},
	// glrt- normally; glrtr- when created from a registration token.
	{"GitLab Runner Authentication Token", regexp.MustCompile(`\bglrtr?-[A-Za-z0-9_\-]{20,}`), true, nil, false},
	{"GitLab CI/CD Job Token", regexp.MustCompile(`\bglcbt-[A-Za-z0-9_\-]{20,}`), true, nil, false},
	{"GitLab Pipeline Trigger Token", regexp.MustCompile(`\bglptt-[A-Za-z0-9_\-]{20,}`), true, nil, false},
	{"GitLab OAuth Application Secret", regexp.MustCompile(`\bgloas-[A-Za-z0-9_\-]{20,}`), true, nil, false},
	{"GitLab Agent for Kubernetes Token", regexp.MustCompile(`\bglagent-[A-Za-z0-9_\-]{20,}`), true, nil, false},
	{"GitLab Feed Token", regexp.MustCompile(`\bglft-[A-Za-z0-9_\-]{20,}`), true, nil, false},
	{"AWS Access Key ID", regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`), true, nil, false},
	{"DigitalOcean API Token", regexp.MustCompile(`\bdop_v1_[a-f0-9]{40,}\b`), true, nil, false},
	{"npm Publishing Token", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36,}\b`), true, nil, false},
	// pypi.org's help page: "Set your password to the token value, including
	// the `pypi-` prefix". The body is base64 of a macaroon, so it carries
	// "-" and "_" as well as base62.
	{"PyPI Upload Token", regexp.MustCompile(`\bpypi-[A-Za-z0-9_\-]{32,}`), true, nil, false},
	{"Anthropic Claude API Key", regexp.MustCompile(`\bsk-ant-api03-[A-Za-z0-9_\-]{20,}\b`), true, nil, false},
	// An Admin API key manages org members, workspaces and API keys rather
	// than calling models — a strictly higher-privilege credential than the
	// api03 key above, so it is worth naming separately.
	{"Anthropic Admin API Key", regexp.MustCompile(`\bsk-ant-admin[A-Za-z0-9_\-]{20,}`), true, nil, false},
	{"OpenAI Project API Key", regexp.MustCompile(`\bsk-proj-[A-Za-z0-9_\-]{20,}\b`), true, nil, false},
	{"OpenAI Service Account Key", regexp.MustCompile(`\bsk-svcacct-[A-Za-z0-9_\-]{20,}`), true, nil, false},
	{"OpenAI Admin API Key", regexp.MustCompile(`\bsk-admin-[A-Za-z0-9_\-]{20,}`), true, nil, false},
	// Bare "sk-" is shared by OpenAI's legacy key format and DeepSeek's
	// current format — the prefix alone can't distinguish them, so the
	// vendor name says both rather than falsely picking one.
	{"OpenAI (legacy) or DeepSeek API Key", regexp.MustCompile(`\bsk-[A-Za-z0-9]{20,}\b`), true, nil, false},
	{"Hugging Face Token", regexp.MustCompile(`\bhf_[A-Za-z0-9]{20,}\b`), true, nil, false},
	{"Stripe Live Secret Key", regexp.MustCompile(`\bsk_live_[A-Za-z0-9]{24,}\b`), true, nil, false},
	{"Stripe Test Secret Key", regexp.MustCompile(`\bsk_test_[A-Za-z0-9]{24,}\b`), true, nil, false},
	{"Stripe Restricted Key", regexp.MustCompile(`\brk_live_[A-Za-z0-9]{24,}\b`), true, nil, false},
	{"Slack Bot Token", regexp.MustCompile(`\bxoxb-[0-9A-Za-z\-]{10,}\b`), true, nil, false},
	{"Slack User Token", regexp.MustCompile(`\bxoxp-[0-9A-Za-z\-]{10,}\b`), true, nil, false},
	{"Shopify Access Token", regexp.MustCompile(`\bshpat_[A-Za-z0-9]{20,}\b`), true, nil, false},
	{"Twilio Account SID", regexp.MustCompile(`\bAC[a-fA-F0-9]{32}\b`), true, nil, false},
	{"SendGrid API Key", regexp.MustCompile(`\bSG\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`), true, nil, false},
	// Notion switched newly-issued tokens from "secret_" to "ntn_" on
	// 2024-09-25 (their changelog), explicitly so secret scanners could
	// recognize them; pre-existing "secret_" tokens keep working, so both
	// formats are live and both are matched. Real developer machines still
	// carry NOTION_SECRET values of each shape.
	{"Notion Internal Integration Token", regexp.MustCompile(`\bntn_[A-Za-z0-9]{20,}\b`), true, nil, false},
	{"Notion Internal Integration Token (legacy)", regexp.MustCompile(`\bsecret_[A-Za-z0-9]{40,}\b`), true, nil, false},
	// Google API keys are a fixed 39 characters: "AIza" plus 35 of
	// [A-Za-z0-9_-]. This is also the format of a Gemini API key, which is
	// what makes it worth having even though jit already wraps the gemini
	// CLI — wrap moves the key it knows about, scan has to recognize one
	// pasted anywhere else.
	{"Google API Key", regexp.MustCompile(`\bAIza[A-Za-z0-9_\-]{35}\b`), true, nil, false},
	{"Slack App-Level Token", regexp.MustCompile(`\bxapp-[0-9A-Za-z\-]{10,}\b`), true, nil, false},
	{"Slack Workflow Token", regexp.MustCompile(`\bxwfp-[0-9A-Za-z\-]{10,}\b`), true, nil, false},
	{"Stripe Webhook Signing Secret", regexp.MustCompile(`\bwhsec_[A-Za-z0-9]{24,}\b`), true, nil, false},
	{"Supabase Secret Key", regexp.MustCompile(`\bsb_secret_[A-Za-z0-9_\-]{20,}`), true, nil, false},
	{"Grafana Service Account Token", regexp.MustCompile(`\bglsa_[A-Za-z0-9_]{20,}`), true, nil, false},
	{"Doppler Service Token", regexp.MustCompile(`\bdp\.st\.[A-Za-z0-9_\-]{20,}`), true, nil, false},
	// Vault 1.10+ prefixes: hvs. service, hvb. batch, hvr. recovery, each
	// followed by "24 or more randomly-generated characters" per the docs.
	// The pre-1.10 "s." prefix is deliberately NOT matched: two characters of
	// which one is a dot is far too generic to identify a credential by, and
	// it would fire on ordinary prose and version strings.
	{"HashiCorp Vault Token", regexp.MustCompile(`\bhv[sbr]\.[A-Za-z0-9_\-]{24,}`), true, nil, false},
	// age identities. jit already has a whole sops-age migrate category, but
	// had no way to recognize the key by VALUE — so an age key pasted into a
	// .env or a note went unseen. AGE-SECRET-KEY-1 is the standard identity;
	// the PQ- variant is the post-quantum one.
	{"age Secret Key", regexp.MustCompile(`\bAGE-SECRET-KEY-(?:PQ-)?1[0-9A-Z]{20,}`), true, nil, false},
	{"JSON Web Token (JWT)", regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*\b`), true, nil, false},
	{"RSA Private Key", regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`), true, nil, false},
	{"OpenSSH Private Key", regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`), true, nil, false},
	{"EC Private Key", regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`), true, nil, false},
	{"PKCS8 Private Key", regexp.MustCompile(`-----BEGIN PRIVATE KEY-----`), true, nil, false},
	// Database connection strings — only when they actually embed
	// user:pass@ credentials, same reasoning as LooksLikeBareURL: a bare
	// "redis://localhost:6379" isn't a secret, "redis://:hunter2@host" is.
	// connStringPlaceholderUserinfo excludes the placeholder userinfo every
	// .env.example/README on the internet uses (real-world dogfooding
	// 2026-07-06 found "postgres://user:password@localhost/dbname" firing
	// on a template file — structurally identical to a real credential by
	// shape alone, so the exclusion has to check the literal words).
	//
	// The optional "+driver" suffix matters more than it looks: SQLAlchemy
	// and Alembic spell their URLs "postgresql+asyncpg://" and
	// "mysql+pymysql://", which a bare "postgres(ql)?://" alternation
	// silently missed. Real-world dogfooding (2026-07-28) found a live
	// production password in a "DB_URI=postgresql+asyncpg://..." assignment
	// scoring LOW on three separate machines for exactly this reason — the
	// value pattern didn't fire, and "URI" wasn't a secretKeyMarker either,
	// so nothing escalated it.
	{"Database connection string with embedded credentials",
		regexp.MustCompile(`\b(?:mongodb|postgres(?:ql)?|mysql|mariadb|redis|rediss|amqps?|clickhouse|mssql|oracle)(?:\+[a-z0-9_]+)?://[^/@\s:]+:[^/@\s]+@`),
		true,
		connStringPlaceholderUserinfo,
		true},
	// Scheme-less "user:pass@host/db". Postgres and MySQL clients, and plenty
	// of hand-rolled config, accept a bare authority with no scheme, and it
	// shows up in real .env files
	// ("DB_URL=scanner_user:hunter2@db.example.com/postgres").
	//
	// Must come AFTER the scheme'd pattern above: on a full URL this would
	// otherwise match the userinfo span on its own. Both the content
	// scanner's first-claim-wins overlap check and MatchKnownTokenPattern's
	// first-match-wins loop resolve that in favor of whichever is listed
	// first, so ordering is what keeps one credential from being reported
	// under two vendor names.
	//
	// Stricter than the scheme'd form because it has no "://" to anchor on:
	// the password must be 8+ non-delimiter characters and the host must be a
	// dotted name ending in letters. That deliberately gives up
	// "user:pw@localhost" and "user:pw@127.0.0.1" — a bare hostname or IP
	// with a colon in front of it is far too common in non-credential text
	// (clock times, host:port pairs, Go map literals) to match on shape alone.
	{"Database connection string with embedded credentials (scheme-less)",
		regexp.MustCompile(`\b[A-Za-z0-9._%+\-]{2,}:[^\s:@/]{8,}@[A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,}(?::\d+)?(?:/|\b)`),
		true,
		schemeLessConnStringExclude,
		true},

	// --- Reported (2026-07-06) but not independently verified against a
	// published spec — matched at lower (Medium) confidence. ---
	{"Cursor API Key", regexp.MustCompile(`\bcrsr_[A-Za-z0-9]{10,}\b`), false, nil, false},
	{"Tavily API Key", regexp.MustCompile(`\btvly-[A-Za-z0-9\-]{10,}\b`), false, nil, false},
	{"Slack Refresh Token", regexp.MustCompile(`\bxoxa-[0-9A-Za-z\-]{10,}\b`), false, nil, false},
	{"Slack Configuration Token", regexp.MustCompile(`\bxoxr-[0-9A-Za-z\-]{10,}\b`), false, nil, false},
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
// "fixture"/"sample"/"mock"/"fake" were added after dogfooding jit against its
// own repository (2026-07-28): every sanitized file under internal/wrap/testdata
// labels itself in the token body ("hf_FIXTUREtoken0123…"), and reporting a
// project's own scrubbed test data as a live credential is the same cry-wolf
// failure envTemplateSuffixes exists to prevent. Any repo with fixtures has
// this shape. The odds of a CSPRNG-drawn credential containing one of these
// words are the same one-in-billions the list already rests on.
var placeholderTokenWords = []string{
	"your", "here", "changeme", "placeholder", "example", "dummy", "redacted",
	"fixture", "sample", "mock", "fake",
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
// humanReadable formats are exempt from the word half of the check only; see
// tokenPattern.humanReadable for why, and note the run half still applies to
// them (a "xxxxxxxx" password is filler in any format).
func isPlaceholderToken(match string, humanReadable bool) bool {
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
	if humanReadable {
		return false
	}
	lower := strings.ToLower(match)
	for _, word := range placeholderTokenWords {
		if strings.Contains(lower, word) {
			return true
		}
	}
	return false
}

// jwtVendor is the one entry in knownTokenPatterns that names a CONTAINER
// FORMAT rather than a specific vendor's credential.
const jwtVendor = "JSON Web Token (JWT)"

// IsAmbiguousTokenFormat reports whether a vendor name identifies a format
// that does not, on its own, prove the value is secret.
//
// Every other pattern here matches an issuer-specific prefix, so a hit is
// near-proof of a real credential. "eyJ…" only proves the value is a JWT, and
// plenty of JWTs are designed to be public: a Supabase anon key is a JWT the
// vendor documents as "safe to expose… in web pages and mobile apps", as is an
// OIDC ID token. Callers pair this with LooksLikeNonSecretName so a JWT in a
// documented-public variable stops escalating, while a JWT in any other
// variable keeps its full weight.
func IsAmbiguousTokenFormat(vendor string) bool { return vendor == jwtVendor }

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
		if isPlaceholderToken(match, tp.humanReadable) {
			continue
		}
		return tp.vendor, tp.verified, true
	}
	return "", false, false
}
