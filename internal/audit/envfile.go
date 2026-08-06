// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/jitpass/jit/internal/pointerfile"
	"github.com/jitpass/jit/internal/wrap"
)

// envFileNamePattern matches .env, .env.local, .env.production, etc.
var envFileNamePattern = regexp.MustCompile(`^\.env(\..+)?$`)

// envTemplateSuffixes mark a .env-family file as a template/example, not a
// real file with real values — a universal, well-established convention
// (committed to git on purpose, meant to be shared). Real-world dogfooding
// (2026-07-06) showed roughly half of all .env findings on a real machine
// were .env.example files, which is exactly the kind of noise that erodes
// trust in the tool: flagging a template's mere existence the same as a
// real .env file is wrong. Content is still scanned for escalation (a real
// secret accidentally left in a template is still worth catching) — only
// the baseline "presence" finding is suppressed when nothing escalates.
var envTemplateSuffixes = map[string]bool{
	"example":  true,
	"sample":   true,
	"template": true,
	"dist":     true,
}

func isEnvTemplateFile(name string) bool {
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(name), "."))
	return envTemplateSuffixes[ext]
}

// jitPointerFileSuffix mirrors internal/migrate/pointerfile.go's own
// PointerFilePath suffix (small independent copy, matching this file's
// existing convention for envFileNamePattern/envTemplateSuffixes rather
// than an audit->migrate import). envFileNamePattern's wildcard suffix
// match (meant to catch `.env.local`/`.env.production`) also matches
// jit's own `<file>.pointers` companion — e.g. `.env.pointers` — since
// it's just ".env" followed by another suffix. Without this exclusion,
// `jit scan` would falsely report a git-safe pointer file (which holds
// only `KEY=jit://vault/...` lines, never a real value) as an exposed
// .env secret — confirmed as the same underlying pattern bug that made
// `jit migrate` re-discover and destroy its own `.pointers` files on a
// second run (a real, reported incident — GAPS.md #30).
const jitPointerFileSuffix = pointerfile.CompanionSuffix

func isJitPointerFile(name string) bool {
	return strings.HasSuffix(name, jitPointerFileSuffix)
}

// pointerFileHeaderPrefix mirrors internal/migrate's own constant of the
// same name (small independent copy, matching this package's convention of
// not importing internal/migrate). It's the start of a jit pointer file's
// first line.
const pointerFileHeaderPrefix = pointerfile.Header

// isJitPointerContent recognizes a jit pointer file by CONTENT, not name —
// the case isJitPointerFile's suffix check misses: a backup-suffixed .env
// file (.env.bak etc.) that `jit migrate` replaced in place with pointer
// content, keeping its original name (GAPS.md #66). Without this, audit
// re-reports that git-safe pointer file (only `KEY=jit://vault/...` lines,
// never a real value) as an exposed .env secret. Guarded to regular files:
// opening a live-mount FIFO with no writer would block the whole scan.
func isJitPointerContent(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	f, err := openFile(path)
	if err != nil {
		return false
	}
	defer f.Close()
	scanner := newLineScanner(f)
	if !scanner.Scan() {
		return false
	}
	return strings.HasPrefix(scanner.Text(), pointerFileHeaderPrefix)
}

// envLinePattern matches `KEY=value` or `# KEY=value` (commented out).
// Group 1 is the optional leading "#" (non-empty means commented), group 2
// is the key, group 3 is the raw value.
var envLinePattern = regexp.MustCompile(`^\s*(#\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$`)

// ScanEnvFiles implements RFC.md §4 category 2: presence and location of
// .env files. Findings are file-level (RFC's literal wording — "presence
// and location," not "every variable inside"), not per-variable, but file
// content is still inspected to decide whether a file-level finding
// escalates to Critical, per the cross-cutting signals in RFC.md §4.
func ScanEnvFiles(cfg Config) ([]Finding, error) {
	return walkForCategory(cfg, classifyEnvFile)
}

// classifyEnvFile is the per-file half of ScanEnvFiles, split out so the
// machine-wide walk (see categories), a standalone ScanEnvFiles, and `jit
// scan <path>`'s targeted walk all apply the exact same .env naming,
// pointer-file, and template/escalation rules to a file — the coupling of
// "which files" (discovery) to "is it exposed" (classification) is what once
// made a file impossible to scan on its own. Returns nil (no findings) for a
// name that isn't .env-shaped, for a jit pointer file, and for a file that
// can't be read: an unreadable file is a skip, never a failed scan, which is
// what every caller of the old ([]Finding, error) form did with the error
// anyway.
func classifyEnvFile(cfg Config, path, name string) []Finding {
	if !envFileNamePattern.MatchString(name) {
		return nil
	}
	if isJitPointerFile(name) || isJitPointerContent(path) {
		return nil
	}
	f, found, err := buildEnvFileFinding(cfg, path, isEnvTemplateFile(name))
	if err != nil || !found {
		return nil
	}
	return []Finding{f}
}

// buildEnvFileFinding returns found=false (no Finding) when path is a
// template file and nothing in it escalates — see envTemplateSuffixes.
func buildEnvFileFinding(cfg Config, path string, isTemplate bool) (Finding, bool, error) {
	file, err := openFile(path)
	if err != nil {
		return Finding{}, false, err
	}
	defer file.Close()

	var active, commented int
	var prodMatch, ipMatch, secretShaped, tokenMatch, entropyMatch bool
	var publicIP, secretShapedKey, tokenVendor, entropyKey string
	var tokenVerified bool
	// The unfiltered bookkeeping: whether any secret-shaped key passed the
	// REAL gates (normalShaped, with the first such key as the honest lead),
	// and the first gate reason for a key that survived on --unfiltered
	// alone. When every shaped key is gate-suppressed, the finding is tagged
	// UnfilteredOnly instead of claiming the names look like credentials.
	var normalShaped bool
	var normalShapedKey, shapedUnfReason string
	// EVERY credential in the file, not just the first one that set a flag
	// above. The flags decide severity (one match is enough to escalate);
	// these decide what the report actually names. A real .env holding a
	// database URL, a Stripe live key, and an AWS secret used to report only
	// "contains a value matching Database connection string with embedded
	// credentials's known token format" — whichever the severity switch
	// happened to reach first — so the scariest thing in the file (an
	// sk_live_ key) went unmentioned and the user had no way to know the
	// scan had seen it. See describeEnvHits.
	var tokenHits []envTokenHit
	// The values this scanner judges to be real credentials, kept so the
	// file-level finding can still hand them to crossReferenceAgentCaches as
	// search needles. Never reported and never serialized — see
	// Finding.claimedRawValues.
	var claimedRaw []claimedValue
	claim := func(k, v string) { claimedRaw = append(claimedRaw, claimedValue{Key: k, Value: v}) }
	var secretShapedKeys []string

	scanner := newLineScanner(file)
	for scanner.Scan() {
		m := envLinePattern.FindStringSubmatch(scanner.Text())
		if m == nil {
			continue
		}
		if m[1] != "" {
			commented++
		} else {
			active++
		}

		key := m[2]
		rawValue := unquote(m[3])
		if IsAlreadyMasked(rawValue) {
			continue // per RFC.md §4: already-masked values are never evaluated for these signals
		}
		if IsProductionIndicator(key) || IsProductionIndicator(rawValue) {
			prodMatch = true
		}
		if ip, ok := MatchPublicIP(rawValue); ok && !ipMatch {
			ipMatch = true
			publicIP = ip
		}
		// Checked regardless of template/comment status, same as
		// prodMatch/ipMatch above: a value that positively matches a known
		// vendor token format is meaningful evidence even in a template
		// file (a real token pasted into a .env.example is exactly the
		// kind of accident worth catching) and even when commented out
		// (still plaintext at rest).
		if vendor, verified, ok := MatchKnownTokenPattern(rawValue); ok {
			// A JWT is only a container format, so it proves nothing on its own
			// when the variable holding it is one the vendor documents as
			// public — SUPABASE_ANON_KEY is a JWT by design. Any other format
			// here is issuer-specific and keeps escalating regardless of the
			// name, which is what keeps a real sk_live_ key behind a
			// NEXT_PUBLIC_ prefix reported.
			ambiguousDrop := false
			unfReason := ""
			if IsAmbiguousTokenFormat(vendor) {
				if r := NonSecretNameReason(key); r != "" {
					if cfg.Unfiltered {
						unfReason = "a JWT is a container format, not proof of a secret, and " + r
					} else {
						ambiguousDrop = true
					}
				}
			}
			if !ambiguousDrop {
				tokenHits = append(tokenHits, envTokenHit{key: key, vendor: vendor, verified: verified, unfilteredReason: unfReason})
				claim(key, rawValue)
			}
		}
		// Only active (uncommented) variables count toward this, only for
		// real files (not templates — see below), and rawValue being
		// non-empty rules out a bare `KEY=` placeholder line. Real-world
		// review (2026-07-06) found this gap directly: a real, company-wide
		// management key sat in a variable named "DESCOPE_MGMT_KEY" and was
		// rated Low, identical to a file containing nothing but
		// NAME=whatever — because nothing here was checking whether a
		// variable NAME looks like a real secret, the same LooksLikeSecretKey
		// check the shell-config scanner already applies.
		//
		// Templates are deliberately exempt from this specific check: an
		// .env.example's entire purpose is documenting which secret-shaped
		// variable NAMES a real .env needs (API_KEY, DATABASE_URL are
		// exactly what a template is supposed to contain) — the name alone
		// is not evidence of anything for a template, only its value is
		// (still covered by prodMatch/ipMatch above, which inspect values).
		// LooksLikeNonSecretName excuses documented-public names (VITE_*,
		// NEXT_PUBLIC_*, Datadog client tokens, Supabase anon keys) and
		// path-holding variables from the NAME signal only — the value checks
		// above still run on them, so a real credential behind a public
		// prefix is still caught.
		if !isTemplate && m[1] == "" && rawValue != "" && LooksLikeSecretKey(key) {
			suppress, unfReason := cfg.nameGate(key)
			if !suppress && unfReason == "" {
				suppress, unfReason = cfg.valueGate(rawValue)
			}
			// A gate-suppressed key skips the entropy branch below on purpose:
			// LooksLikeHighEntropySecret applies the same two gates internally
			// and would return false for it anyway.
			if !suppress {
				secretShaped = true
				secretShapedKeys = append(secretShapedKeys, key)
				claim(key, rawValue)
				if unfReason == "" {
					if !normalShaped {
						normalShaped, normalShapedKey = true, key
					}
				} else if shapedUnfReason == "" {
					shapedUnfReason = unfReason
				}
			}
		} else if !isTemplate && m[1] == "" && LooksLikeHighEntropySecret(key, rawValue) {
			// Neither the name nor any vendor pattern gave this away, but the
			// value is credential-shaped on its own. Most real credentials
			// carry no vendor prefix (CrowdStrike, Datadog, Heroku, every
			// internal API), so without this they were caught only when
			// someone happened to name the variable helpfully.
			if !entropyMatch {
				entropyMatch = true
				entropyKey = key
				claim(key, rawValue)
			}
		}
	}
	if err := lineScanErr(scanner); err != nil {
		return Finding{}, false, err
	}

	// Lead selection prefers evidence the everyday gates would keep, so a
	// file mixing normal and gate-suppressed hits is never led (or tagged)
	// by the suppressed half.
	var tokenUnfReason string
	if len(tokenHits) > 0 {
		lead := tokenHits[0]
		for _, h := range tokenHits {
			if h.unfilteredReason == "" {
				lead = h
				break
			}
		}
		tokenMatch, tokenVendor, tokenVerified = true, lead.vendor, lead.verified
		tokenUnfReason = lead.unfilteredReason
	}
	if secretShaped {
		secretShapedKey = secretShapedKeys[0]
		if normalShaped {
			secretShapedKey = normalShapedKey
		}
	}

	if isTemplate && !prodMatch && !ipMatch && !tokenMatch {
		return Finding{}, false, nil
	}

	f := cfg.baseFinding()
	f.FindingType = FindingTypeEnvFilePresent
	f.FilePath = path
	f.claimedRawValues = claimedRaw
	f.Confidence = ConfidenceHigh
	f.ProductionIndicatorMatch = prodMatch
	if ipMatch {
		f.PublicIPMatch = &publicIP
	}

	switch {
	case prodMatch:
		f.Severity = SeverityCritical
		f.Evidence = "contains a value matching the production-indicator pattern"
	case ipMatch:
		f.Severity = SeverityCritical
		f.Evidence = "contains a public IP address in a visible value"
	case tokenMatch:
		f.Severity = SeverityHigh
		if tokenUnfReason != "" {
			// Every token hit was the ambiguous-format-in-a-public-name case:
			// the value evidence is real (it IS a JWT), but the everyday scan
			// drops it, and this view's job is to say so.
			f.UnfilteredOnly = true
			f.UnfilteredReason = tokenUnfReason
		}
		if tokenVerified {
			f.Confidence = ConfidenceHigh
			f.Evidence = fmt.Sprintf("contains a value matching %s known token format", possessive(tokenVendor))
		} else {
			f.Confidence = ConfidenceMedium
			f.Evidence = fmt.Sprintf("contains a value that looks like it may be a %s (pattern not independently verified)", tokenVendor)
		}
	case secretShaped:
		f.Severity = SeverityHigh
		if !normalShaped {
			// Every shaped key here survived on --unfiltered alone: count them
			// honestly instead of asserting the names look like credentials —
			// the gate concluded the opposite, and UnfilteredReason names the
			// rule that did.
			f.UnfilteredOnly = true
			f.UnfilteredReason = shapedUnfReason
			f.Evidence = shapedNamesEvidence(secretShapedKeys)
		} else {
			f.Evidence = fmt.Sprintf("contains %q, a variable name that looks like a real credential", secretShapedKey)
		}
	case entropyMatch:
		// Ranked below the name signal and rated Medium confidence on purpose:
		// "this value is shaped like a credential" is real evidence but weaker
		// than a vendor prefix or a name that says so, and the wording has to
		// admit that rather than assert more than the shape supports.
		f.Severity = SeverityHigh
		f.Confidence = ConfidenceMedium
		f.Evidence = fmt.Sprintf("contains %q, whose value is a long opaque credential-shaped string (no vendor format matched, so this is a judgement about shape)", entropyKey)
	default:
		f.Severity = SeverityLow
		// Lead with *why* this is a finding at all, not just the raw count —
		// a real user reading "12 variable(s) found (12 active, 0 commented
		// out)" understandably asked what that meant. "plaintext" up front
		// carries that answer; commented-out values count because they are
		// stored here just the same. Kept terse: the reason renders on one
		// line in the report.
		f.Evidence = fmt.Sprintf(
			"%s (%d active, %d commented out)",
			countWord(active+commented, "plaintext variable", "plaintext variables"), active, commented,
		)
	}

	// Name the REST of what's in the file. The switch above reports only the
	// single signal that set the severity, which on a file holding several
	// credentials silently drops the others — see the tokenHits comment.
	// Appended after the switch rather than folded into each case so the
	// leading sentence stays exactly as it was; the default (Low) branch
	// means nothing matched at all, so there is never anything to append to
	// it.
	// A shapedNamesEvidence lead already counts every shaped key, so the
	// "; also" append would restate it. Token-led findings keep the append
	// even when tagged: their extra hits are new information.
	if !(f.UnfilteredOnly && !tokenMatch) {
		if rest := describeEnvHits(tokenHits, secretShapedKeys, tokenVendor, secretShapedKey); rest != "" {
			f.Evidence += "; also " + rest
		}
	}

	// If this .env-family file IS a wrappable CLI's own token Source (gemini's
	// ~/.gemini/.env or ~/.env), add the wrap remediation here. ScanEnvFiles
	// owns these paths and ScanWrappableCLITokens deliberately skips them to
	// avoid double-counting the same secret — but the skip must not cost the
	// user the actionable "one command fixes this" hint the wrappable finding
	// carried, so it rides this finding instead.
	if tool, ok := wrap.WrappableToolForPath(cfg.HomeDir, path); ok {
		f.Evidence += fmt.Sprintf("; one command moves it into the vault and keeps %s working: jit wrap %s", tool, tool)
	}

	f.RecordID = RecordID(f.FindingType, f.FilePath, nil)
	return f, true, nil
}

// envTokenHit is one variable in a .env whose VALUE matched a known vendor
// token pattern — the vendor plus the variable that held it. unfilteredReason
// is non-empty when the hit survives only under Config.Unfiltered (the
// ambiguous-format-in-a-documented-public-name case).
type envTokenHit struct {
	key              string
	vendor           string
	verified         bool
	unfilteredReason string
}

// shapedNamesEvidence words the lead sentence for an UnfilteredOnly finding
// whose only signal is gate-suppressed names: it counts them as
// "secret-shaped" rather than asserting they look like real credentials —
// the gate concluded the opposite, and the finding's UnfilteredReason says
// which rule did.
func shapedNamesEvidence(keys []string) string {
	if len(keys) == 1 {
		return fmt.Sprintf("contains %q, a secret-shaped name", keys[0])
	}
	return fmt.Sprintf("contains %q and %s", keys[0],
		countWord(len(keys)-1, "more secret-shaped name", "more secret-shaped names"))
}

// maxNamedEnvHits caps how many credentials describeEnvHits names before it
// summarizes the tail. A .env with thirty secret-shaped variables is real,
// and the finding renders on a couple of report lines; the point is to tell
// the user there is more than one thing here and what the notable ones are,
// not to reproduce the file's variable list.
const maxNamedEnvHits = 4

// describeEnvHits renders every credential in a .env that the finding's own
// severity sentence didn't already name. leadVendor and leadKey are what that
// sentence covered, so they're skipped here rather than repeated.
//
// Vendor-pattern hits come first and carry their variable name ("Stripe Live
// Secret Key in STRIPE_API_KEY"): a positively-matched token is stronger
// evidence than a suggestive variable name, and naming the variable is what
// makes the finding actionable — "there's a Stripe key in this file" is not
// something the user can act on without knowing which line. Name-only matches
// follow as a plain list. Returns "" when there's nothing left to say.
func describeEnvHits(tokens []envTokenHit, shapedKeys []string, leadVendor, leadKey string) string {
	var parts []string
	seen := map[string]bool{}
	leadCovered := false
	for _, h := range tokens {
		// The lead sentence names a vendor but not which variable held it, so
		// the FIRST hit for that vendor is what it was describing.
		if !leadCovered && h.vendor == leadVendor {
			leadCovered = true
			continue
		}
		if seen[h.key+"\x00"+h.vendor] {
			continue
		}
		seen[h.key+"\x00"+h.vendor] = true
		if h.verified {
			parts = append(parts, fmt.Sprintf("%s in %q", h.vendor, h.key))
		} else {
			parts = append(parts, fmt.Sprintf("a possible %s in %q", h.vendor, h.key))
		}
	}

	var names []string
	nameSeen := map[string]bool{}
	for _, k := range shapedKeys {
		// Skip a variable already named above by its vendor match, and the
		// one the lead sentence quoted.
		if k == leadKey || nameSeen[k] {
			continue
		}
		nameSeen[k] = true
		if slices.ContainsFunc(tokens, func(h envTokenHit) bool { return h.key == k }) {
			continue
		}
		names = append(names, fmt.Sprintf("%q", k))
	}

	if len(names) > 0 {
		shown := names
		extra := 0
		if len(shown) > maxNamedEnvHits {
			extra = len(shown) - maxNamedEnvHits
			shown = shown[:maxNamedEnvHits]
		}
		list := strings.Join(shown, ", ")
		if extra > 0 {
			list += fmt.Sprintf(" and %d more", extra)
		}
		if len(names) == 1 {
			parts = append(parts, list+" looks like a credential name")
		} else {
			parts = append(parts, list+" look like credential names")
		}
	}

	if len(parts) == 0 {
		return ""
	}
	if len(parts) > maxNamedEnvHits {
		parts = append(parts[:maxNamedEnvHits], fmt.Sprintf("and %d more", len(parts)-maxNamedEnvHits))
	}
	return strings.Join(parts, ", ")
}
