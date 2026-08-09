// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"unicode"

	"github.com/jitpass/jit/internal/auditlog"
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

// secretKeySegmentMarkers are markers matched as a whole delimiter-separated
// SEGMENT of the name rather than as a bare substring. They exist because both
// words below are short and common enough inside unrelated identifiers that
// substring matching would be pure noise: "URI" is a substring of "SECURITY"
// (SECURITY_MODE, SPRING_SECURITY_ENABLED), and substring "BEARER" is fine but
// is kept here for symmetry with the field it belongs to.
//
// Real-world dogfooding (2026-07-28) found both gaps on developer machines:
// "DB_URI=postgresql+asyncpg://user:<live prod password>@host/db" scored LOW
// because secretKeyMarkers has "URL" but not "URI", and "PLATFORM_BEARER"
// wasn't flagged at all. Splitting on non-alphanumerics also handles the
// dotted style real config files use (config.database.url).
var secretKeySegmentMarkers = []string{"URI", "BEARER"}

// LooksLikeSecretKey reports whether a variable/key name looks like it holds
// a secret, based on common naming conventions.
func LooksLikeSecretKey(name string) bool {
	upper := strings.ToUpper(name)
	for _, marker := range secretKeyMarkers {
		if strings.Contains(upper, marker) {
			return true
		}
	}
	for _, segment := range strings.FieldsFunc(upper, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}) {
		for _, marker := range secretKeySegmentMarkers {
			if segment == marker {
				return true
			}
		}
	}
	return false
}

// publicVarPrefixes are build-tool prefixes whose entire documented purpose is
// to mark a variable as SAFE TO SHIP TO A BROWSER. The bundler inlines these
// into the client JavaScript at build time, so a value behind one of them is
// public by construction — flagging it as a credential is backwards.
//
// Vite: "VITE_* variables should not contain sensitive information… The values
// of these variables are bundled into your source code at build time."
// Next.js: a NEXT_PUBLIC_ value "will be inlined into any JavaScript sent to
// the browser."
//
// Real-world dogfooding (2026-07-28) found this dominating five developer
// scans: .env files containing nothing but VITE_* analytics IDs rated HIGH, on
// the strength of names like VITE_AUTH0_DOMAIN — whose value was the bare
// hostname "id.blockaid.io".
var publicVarPrefixes = []string{
	"VITE_", "NEXT_PUBLIC_", "REACT_APP_", "PUBLIC_", "EXPO_PUBLIC_",
	"NUXT_PUBLIC_", "GATSBY_", "VUE_APP_", "STORYBOOK_",
}

// pointerVarSuffixes name a variable that holds a FILESYSTEM PATH, not a
// credential. "/etc/keys/callback_private.pem" is not a secret even though the
// name around it is full of secret-shaped words — the file it points at is
// what matters, and ScanPrivateKeys already covers that separately.
//
// Checked before neverPublicMarkers below, deliberately: the motivating
// real-world case was CALLBACK_PRIVATE_KEY_PATH rating HIGH, and it contains
// "PRIVATE". A path is a path regardless of what it points at.
var pointerVarSuffixes = []string{"_PATH", "_PATHS", "_FILE", "_FILEPATH", "_DIR", "_FOLDER"}

// publicVarMarkers are vendor-specific names documented as publicly
// exposable, independent of any build-tool prefix:
//   - Supabase anon / publishable keys: documented "safe to expose… in web
//     pages and mobile apps".
//   - OAuth client IDs are public by RFC 6749; only the client SECRET is not,
//     and that is caught by neverPublicMarkers below.
//   - Analytics application IDs (Datadog RUM and friends) identify an app,
//     not a caller; the paired credential is a separate variable.
//
// Each entry has to EARN its place against observed data, because every one
// is a potential false negative. "CLIENT_TOKEN" was dropped in review
// (2026-07-28) for failing that test: every occurrence across eleven scanned
// machines was VITE_DATADOG_CLIENT_TOKEN, already covered by the VITE_ prefix
// above — so the marker suppressed nothing extra, while a vendor that happens
// to call its real secret a "client token" would have been silenced by it. The
// survivors all appear WITHOUT a public prefix in the wild (SUPABASE_ANON_KEY,
// GOOGLE_CLIENT_ID, SPOTIFY_CLIENT_ID, BIG_QUERY_CLIENT_ID), so they do work
// the prefix rule cannot.
//   - Cloud project identifiers: a GCP project id is in every gcloud
//     invocation, every console URL and every IAM policy document. It names
//     which project, and grants nothing. Observed on a real machine reported
//     as an exposed secret with "rotate it now" — advice with no referent,
//     since there is nothing about a project id to rotate.
//
// Narrow forms only, and the reason is worth stating: a bare "PROJECT" would
// also swallow PROJECT_TOKEN, and TOKEN is deliberately absent from
// neverPublicMarkers below, so nothing would catch it. Every widening of this
// list has to be checked against that list, not just read on its own.
var publicVarMarkers = []string{
	"ANON_KEY", "PUBLISHABLE_KEY", "CLIENT_ID", "APPLICATION_ID",
	"CLOUD_PROJECT", "PROJECT_ID",
}

// neverPublicMarkers override publicVarPrefixes/publicVarMarkers. A variable
// whose name says "secret", "password" or "private" is never legitimately a
// public browser value — NEXT_PUBLIC_STRIPE_SECRET_KEY is a misconfiguration,
// not a safe publishable key, and must keep escalating rather than be excused
// by its prefix.
var neverPublicMarkers = []string{"SECRET", "PASSWORD", "PASSWD", "PRIVATE", "CREDENTIAL"}

// LooksLikeNonSecretName reports whether a variable name is documented-public
// or names a filesystem path, so a NAME-based secret heuristic should not
// escalate on it.
//
// This suppresses the name signal only. Value-based detection
// (MatchKnownTokenPattern, MatchPublicIP, IsProductionIndicator) runs
// independently and still fires, so a real credential sitting behind a public
// prefix — the genuinely dangerous case, a live key about to be shipped to
// browsers — is still caught on the strength of its value.
//
// On the migrate side the usage is split, on purpose. The loose-file
// migrator's secretAssignmentTokens DOES apply this gate (and
// LooksLikeNonSecretValue), so scan and migrate agree about which bare
// assignments are secrets — a value this gate suppresses there stays in the
// on-disk template in plaintext, so broadening these lists changes what
// migrate vaults, not just what scan reports. The structured migrators
// (npmrc, pypirc, netrc, …) do NOT use it: their formats name their secret
// fields explicitly, so a name heuristic has nothing to add and could only
// suppress a field the format itself declares secret.
func LooksLikeNonSecretName(name string) bool { return NonSecretNameReason(name) != "" }

// NonSecretNameReason is LooksLikeNonSecretName with its verdict explained:
// it returns WHY the name signal is suppressed, or "" when it isn't. The
// non-empty reasons are short clauses the --unfiltered report prints
// verbatim ("shown by --unfiltered: <reason>"), naming the rule that fired
// so a reader auditing the gates can judge each one instead of taking the
// filtering on faith — which is the whole point of that flag.
func NonSecretNameReason(name string) string {
	upper := strings.ToUpper(name)
	for _, suffix := range pointerVarSuffixes {
		if strings.HasSuffix(upper, suffix) {
			return fmt.Sprintf("the name holds a filesystem path (*%s)", suffix)
		}
	}
	for _, marker := range neverPublicMarkers {
		if strings.Contains(upper, marker) {
			return ""
		}
	}
	for _, prefix := range publicVarPrefixes {
		if strings.HasPrefix(upper, prefix) {
			return fmt.Sprintf("the name matched the browser-public build-variable rule (%s*)", prefix)
		}
	}
	for _, marker := range publicVarMarkers {
		// Suffix, not Contains. These markers name what a variable IS, and
		// that is only true when the marker ends the name: SUPABASE_ANON_KEY
		// is an anon key, CLOUD_PROJECT_TOKEN is a token that happens to
		// mention a project. Contains excused the second, and nothing behind
		// this would have caught it — TOKEN is deliberately absent from
		// neverPublicMarkers, so the suppression was final.
		//
		// Erring toward NOT suppressing is the safe direction here: a missed
		// suppression is a false positive the reader dismisses, a wrong one
		// is a credential the report never mentions.
		if strings.HasSuffix(upper, marker) {
			return fmt.Sprintf("the name matched the documented-public rule (%s)", marker)
		}
	}
	return ""
}

// booleanValues are the literals configuration flags use. A credential is
// high-entropy by definition, so a value drawn from this fixed set is a
// setting, never a secret — no matter how alarming the variable name is.
var booleanValues = []string{"true", "false", "yes", "no", "on", "off", "none", "null", "nil"}

// numericValuePattern matches a plain decimal number: a port, a timeout, a
// sampling rate, a retry count. Capped at numericValueMaxLen so a long digit
// run — which could plausibly be a numeric credential — keeps its weight.
var numericValuePattern = regexp.MustCompile(`^-?\d+(?:\.\d+)?$`)

// numericValueMaxLen is where "obviously a setting" stops. 15 digits covers
// every port, millisecond timeout, byte size and epoch timestamp a config
// holds, while staying short of the length a numeric secret would need.
const numericValueMaxLen = 15

// schemeURLPattern matches any scheme://host URL, not just http(s) — the
// endpoints that show up in real .env files are as often redis://, postgres://
// or grpc:// as they are https://.
var schemeURLPattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.\-]*://`)

// LooksLikeNonSecretValue reports whether a VALUE is self-evidently not a
// credential, so a secret-shaped NAME alone shouldn't escalate it.
//
// The name heuristic is deliberately broad (see secretKeyMarkers), which means
// it fires on plenty of ordinary configuration. Real developer scans
// (2026-07-28, eleven machines) showed the same shapes over and over:
//
//	SF_TEMP_SHOW_SECRETS=true                  a feature flag
//	REACT_APP_SENTRY_TRACES_SAMPLE_RATE=0.1    a sampling rate
//	REDIS_PORT=6379                            a port
//	ANTHROPIC_BASE_URL=http://127.0.0.1:4000   a local endpoint
//	REDIS_URL=redis://cache.internal:6379      an endpoint with no credentials
//
// Every one was reported as a credential on the strength of its name. None is
// a secret, and none has a fix `jit migrate` could offer.
//
// A URL only counts when it carries no userinfo and no long opaque segment —
// the same test LooksLikeBareURL applies, generalized past http(s), so a
// webhook URL with a token in its path or a "postgres://user:pass@host" still
// counts as secret-bearing.
func LooksLikeNonSecretValue(v string) bool { return NonSecretValueReason(v) != "" }

// NonSecretValueReason is LooksLikeNonSecretValue with its verdict explained
// — the value-gate twin of NonSecretNameReason, with the same contract: ""
// means the value keeps its weight, anything else is the clause the
// --unfiltered report prints for the finding this gate would have dropped.
func NonSecretValueReason(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "the value is empty"
	}
	lower := strings.ToLower(v)
	for _, b := range booleanValues {
		if lower == b {
			return "the value is a boolean or null setting"
		}
	}
	if len(v) <= numericValueMaxLen && numericValuePattern.MatchString(v) {
		return "the value is a plain number"
	}
	if schemeURLPattern.MatchString(v) {
		if !strings.Contains(v, "@") && !opaqueTokenPattern.MatchString(stripURLScheme(v)) {
			return "the value is a bare URL with no embedded token"
		}
		return ""
	}
	if isPlaceholderValue(v) {
		return "the value is unfilled template filler"
	}
	return ""
}

// angleBracketPlaceholder matches the "<your-token>" convention.
var angleBracketPlaceholder = regexp.MustCompile(`^<[^>]+>$`)

// placeholderPhrase matches lowercase kebab/snake filler text — the shape a
// human types into a template ("service-user-token-here"). Requiring the WHOLE
// value to be lowercase letters, digits and separators is what makes this safe
// to pair with placeholderTokenWords: it is the discriminator between filler
// and a real credential that merely contains one of those words. A
// human-chosen password like "Wherever2024!" contains "here" but has uppercase
// and punctuation, so it fails this shape and keeps its full weight — the
// reasoning placeholderTokenWords relies on ("a random base62 credential
// cannot contain the word 'here'") does NOT hold for human-chosen passwords,
// so the word list alone must never gate a raw value.
var placeholderPhrase = regexp.MustCompile(`^[a-z0-9][a-z0-9._\-]*$`)

// isPlaceholderValue reports whether a value is unfilled template filler.
//
// A copied-but-not-filled-in .env is ordinary — the file is real (so the
// envTemplateSuffixes check doesn't apply) while its values are not. Reported
// as credentials they are pure noise, and `jit migrate` has nothing to move.
// Real-world example (2026-07-28):
//
//	HIBOB_SERVICE_USER_TOKEN=service-user-token-here
func isPlaceholderValue(v string) bool {
	if angleBracketPlaceholder.MatchString(v) {
		return true
	}
	if !placeholderPhrase.MatchString(v) {
		return false
	}
	for _, word := range placeholderTokenWords {
		if strings.Contains(v, word) {
			return true
		}
	}
	return false
}

// stripURLScheme drops the "scheme://" prefix before the opaque-segment test,
// so a long scheme name can't itself look like an embedded token.
func stripURLScheme(v string) string {
	if i := strings.Index(v, "://"); i >= 0 {
		return v[i+3:]
	}
	return v
}

// entropyExcludedNameMarkers are names whose value is legitimately a long
// opaque string that is NOT a credential: a commit SHA, a content digest, a
// correlation ID. They matter only for the entropy path — a name here that
// ALSO looks secret-shaped ("BUILD_SECRET") is still caught by the name gate,
// which runs first and independently.
var entropyExcludedNameMarkers = []string{
	"SHA", "COMMIT", "DIGEST", "HASH", "CHECKSUM", "REVISION", "ETAG",
	"VERSION", "BUILD", "TRACE", "REQUEST", "CORRELATION", "UUID", "GUID",
}

// hexOnlyPattern matches a value drawn entirely from the hex alphabet.
var hexOnlyPattern = regexp.MustCompile(`^[0-9a-fA-F]+$`)

// LooksLikeHighEntropySecret reports whether a value is credential-shaped
// enough to flag on its own, when neither its NAME nor a vendor pattern gave
// it away.
//
// This closes the last big detection hole: most real credentials carry no
// vendor prefix at all — CrowdStrike, Datadog, Heroku, Mistral, and every
// internal company API — so before this they were caught only if someone had
// named the variable helpfully. "FALCON_ID=a00c30f2…" and "cfg1=6I1evXdj…"
// both scored Low.
//
// The entropy judgement itself is auditlog.LooksHighEntropy, reused rather
// than reimplemented: it is already trusted for the security-critical job of
// never letting a credential reach the audit log, and a second copy would
// drift from it exactly as secretPrefixes drifted from knownTokenPatterns.
//
// Two narrowings make it safe for a scanner, which (unlike a redactor) has to
// justify every finding to a human:
//
//   - Pure hex is rejected. knownTokenPatterns already documents why bare
//     32/64-character hex is deliberately unmatched — it is "structurally
//     identical to countless non-secret things (hashes, correlation IDs,
//     commit SHAs)" — and that reasoning does not stop being true here. It
//     costs the CrowdStrike client ID (32 hex) and keeps its secret (base62),
//     which is the half that authenticates.
//   - Names that announce an opaque non-secret are excluded, so BUILD_SHA and
//     GIT_COMMIT don't become findings.
//
// Callers pair this with the existing gates; it is an ADDITIONAL signal, never
// a suppression, so --unfiltered does not affect it.
func LooksLikeHighEntropySecret(name, value string) bool {
	if !auditlog.LooksHighEntropy(value) {
		return false
	}
	if hexOnlyPattern.MatchString(value) {
		return false
	}
	if LooksLikeNonSecretName(name) || LooksLikeNonSecretValue(value) {
		return false
	}
	upper := strings.ToUpper(name)
	for _, marker := range entropyExcludedNameMarkers {
		if strings.Contains(upper, marker) {
			return false
		}
	}
	return true
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

// unresolvedReferenceValue matches a value that holds NO secret at rest
// because it is entirely a reference the runtime resolves elsewhere: a shell
// expansion (${VAR}, $VAR, $(cmd), `cmd`) or a fill-me-in placeholder
// (<your-token>), optionally behind one auth-scheme word ("Bearer ${PAT}",
// "token $GH_TOKEN").
//
// The reasoning is shellExpansionUserinfoAlt's, generalised past connection
// strings: the credential lives wherever the expansion reads it from, which is
// usually the right place, and if that source is a plaintext .env jit reports
// THAT file on its own. See LooksLikeUnresolvedReference.
var unresolvedReferenceValue = regexp.MustCompile(
	`^(?:[A-Za-z][A-Za-z0-9_-]*\s+)?` + // optional auth scheme: "Bearer ", "token "
		`(?:` +
		`\$\{[^}]*\}` + `|` + // ${VAR}
		`\$[A-Za-z_][A-Za-z0-9_]*` + `|` + // $VAR
		`\$\([^)]*\)` + `|` + // $(command)
		"`[^`]*`" + `|` + // `command`
		`<[^>]*>` + // <placeholder>
		`)$`)

// LooksLikeUnresolvedReference reports whether v exposes no secret because it
// is only a reference to one — an env expansion or a template placeholder.
//
// This is jit's premise made precise: it finds secrets sitting in plaintext at
// REST, and a reference is not one. It exists because the MCP header scanner
// flagged `Authorization: Bearer ${SNOWFLAKE_PAT_TOKEN}` — a value with no
// secret in it — purely because the header is NAMED "Authorization" (reported
// by a user, 2026-08-09). A header name is a signal that a value is likely a
// credential; it is not itself a credential, and a value the runtime resolves
// elsewhere is not exposed here.
//
// Hard exclusion, not a --unfiltered gate: like isPlaceholderToken, a
// reference is not a judgment call about a real secret, it is the absence of
// one. A trimmed empty string is not a reference (an empty value is handled by
// the callers' own empty checks).
func LooksLikeUnresolvedReference(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	return unresolvedReferenceValue.MatchString(v)
}
