// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"net"
	"regexp"
	"strings"
)

// productionIndicatorPattern matches "prod"/"production" as a whole token,
// where a token boundary is any non-alphanumeric character (or start/end of
// string) — deliberately NOT regexp's \b, which treats '_' as a word
// character and would fail to match "PROD_DB_URL" (no boundary between 'D'
// and '_'). RFC.md §4 gives four explicit examples this must satisfy:
// PROD_DB_URL and evm-prod-ro-endpoint must match; nonprod and product must
// not.
var productionIndicatorPattern = regexp.MustCompile(`(?i)(?:^|[^a-zA-Z0-9])(?:prod|production)(?:$|[^a-zA-Z0-9])`)

// IsProductionIndicator reports whether s (a key name or a value) contains a
// "prod"/"production" token at a word boundary, per RFC.md §4's
// production-indicator signal.
func IsProductionIndicator(s string) bool {
	return productionIndicatorPattern.MatchString(s)
}

// ipv4Pattern extracts dotted-quad substrings from a value for public-IP
// checking. Deliberately permissive (a component could be 0-999) — every
// candidate is validated with net.ParseIP afterward, so an over-broad regex
// here just means a few more (cheap) ParseIP calls, not false positives.
var ipv4Pattern = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)

// MatchPublicIP scans s for an IPv4 address outside RFC 1918 private ranges
// and returns the first one found. RFC.md §4 says "anything outside RFC 1918
// private ranges," but taken fully literally that would flag loopback
// (127.0.0.1) and link-local (169.254.x.x) addresses as "public" — a false
// positive that would immediately undermine trust in the scanner. This
// deliberately also excludes loopback, link-local, and unspecified (0.0.0.0)
// addresses, which is a documented departure from RFC.md's literal wording,
// not an oversight.
func MatchPublicIP(s string) (ip string, ok bool) {
	for _, candidate := range ipv4Pattern.FindAllString(s, -1) {
		parsed := net.ParseIP(candidate)
		if parsed == nil {
			continue
		}
		v4 := parsed.To4()
		if v4 == nil {
			continue
		}
		if v4.IsPrivate() || v4.IsLoopback() || v4.IsLinkLocalUnicast() || v4.IsUnspecified() {
			continue
		}
		return candidate, true
	}
	return "", false
}

// secretKeyMarkers are case-insensitive substrings that make a variable name
// worth flagging. This is the primary noise-reduction lever for categories
// like shell configs, where most `export` statements (PATH, EDITOR, LANG)
// are not secrets — without this gate, every shell config would be reported
// as high-risk, which would erode trust in the tool fast. Substring
// matching means some false positives are expected (e.g. KEYBOARD_LAYOUT
// contains "KEY") — acceptable because these are findings for a human to
// review, not automatic failures.
var secretKeyMarkers = []string{
	"KEY", "SECRET", "TOKEN", "PASSWORD", "PASSWD", "PASS",
	"CREDENTIAL", "AUTH", "PWD", "DSN", "PRIVATE",
	// Connection-string-shaped variables (DB_URL, DATABASE_URL,
	// CONNECTION_STRING) very commonly embed a username:password —
	// RFC.md §4's own canonical example (PROD_DB_URL) is exactly this
	// case, and it wouldn't be caught without "URL"/"CONNECTION" here.
	"URL", "CONNECTION",
}

// LooksLikeSecretKey reports whether a variable/key name looks like it holds
// a secret, based on common naming conventions.
func LooksLikeSecretKey(name string) bool {
	upper := strings.ToUpper(name)
	for _, marker := range secretKeyMarkers {
		if strings.Contains(upper, marker) {
			return true
		}
	}
	return false
}

// opaqueTokenPattern flags a long, opaque-looking run of characters anywhere
// in a value — used to distinguish a URL that likely embeds a secret (a
// Slack/Discord webhook, a signed URL with a token in the path) from one
// that's just a plain endpoint.
var opaqueTokenPattern = regexp.MustCompile(`[A-Za-z0-9_\-]{24,}`)

// LooksLikeBareURL reports whether v is a plain http(s) URL with nothing
// suggesting it embeds credentials: no userinfo (user:pass@) and no long
// opaque token segment. This is a judgment call, not a guarantee — MCP env
// blocks and .env files can and do embed real secrets inside otherwise
// plain-looking URLs (a webhook URL's token lives in its path, not in a
// "key" at all), so this should lower a finding's confidence/severity, not
// suppress it outright. Under-flagging a real secret is worse than a human
// spending five seconds glancing at an unnecessary finding — real-world
// review (2026-07-06) showed a bare tool-endpoint URL (CAIDO_URL) getting
// flagged identically to an actual credential, which is the false-positive
// side of that same tradeoff worth correcting.
func LooksLikeBareURL(v string) bool {
	if !strings.HasPrefix(v, "http://") && !strings.HasPrefix(v, "https://") {
		return false
	}
	if strings.Contains(v, "@") {
		return false
	}
	return !opaqueTokenPattern.MatchString(v)
}
