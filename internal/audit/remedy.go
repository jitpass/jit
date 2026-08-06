// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"unicode"

	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/profile"
)

// Remedy values. The taxonomy is the user's, not the scanner's: "migrate"
// and "wrap" mean jit acts (FixCommand is runnable as-is), "manual" means
// only the user can act and the finding's Evidence says how.
const (
	RemedyMigrate = "migrate"
	RemedyWrap    = "wrap"
	RemedyManual  = "manual"
)

// annotateRemedies stamps Remedy/FixCommand/CauseGroup onto every finding,
// centrally — the same seam that sets Archived — so the human report, the
// NDJSON stream, and (via the same field) bare `jit migrate`'s protect plan
// can never disagree about what jit can act on. Wrappable findings arrive
// with both fields already set by their scanner, which alone knows the
// catalog tool name; everything else is derived here.
//
// The manual bucket, and why each member is in it:
//
//   - Private keys: FindFileTokens cedes key bodies to ScanPrivateKeys, so
//     `jit migrate` finds nothing to move (hasAutoFix's original case).
//   - Self-rotating token caches (~/.mcp-auth, ~/.gemini/oauth_creds.json):
//     the owning tool rewrites those files itself, so a mount would be fought
//     by the tool and serve stale tokens. See selfRotatingCache.
//   - Terraform state: Terraform writes the file itself and there is no seam
//     to interpose on, so the remedy is a remote encrypted backend and
//     rotation — never a jit command.
//   - Kubernetes Secret manifests: sealed-secrets/SOPS territory; jit's
//     local vault is the wrong home for cluster state. (.tfvars stays
//     migratable — scanTfvarsAssignments' own evidence offers it.)
//   - An exposed secret carrying a production indicator: protecting the
//     file in place does not un-expose a production credential that sat in
//     plaintext; the remedy is rotation, and offering a migrate command
//     would dress the wound without treating it.
//   - An exposed secret in a file that mixes tokens with other content
//     (a generated report, a script): bare `jit migrate` deliberately skips
//     those (neutralizing would destroy the non-secret content), so calling
//     them "migrate" would promise coverage the recommended command doesn't
//     deliver. The evidence-side remedy is --mount or moving the secret out.
//   - A PRODUCTION-flagged credential in shell history: `jit migrate` can
//     redact a history file in place (ApplyShellHistory), so an ordinary
//     history finding falls through to RemedyMigrate like any other file
//     jit can rewrite. The production case stays manual for the same reason
//     the production exposed_secret case does: clearing the recorded copy
//     does not un-expose a production credential, and offering a migrate
//     command as THE fix would dress the wound without treating it. The
//     migrate result output carries the rotation advice for the ordinary
//     case; for production, rotation IS the remedy and the report says so.
func annotateRemedies(findings []Finding, home string) {
	// Purity is per file and can involve a re-read; cache it, since copies
	// of one dump produce many findings for the same path.
	pureCache := map[string]bool{}
	isPure := func(path string) bool {
		if v, ok := pureCache[path]; ok {
			return v
		}
		v := isPureTokenFile(path)
		pureCache[path] = v
		return v
	}
	for i := range findings {
		f := &findings[i]
		if f.Remedy != "" {
			continue // the scanner knew better (wrappables)
		}
		switch {
		case f.FindingType == FindingTypePrivateKeyRisk:
			f.Remedy = RemedyManual
		case isSelfRotatingCache(f.FilePath):
			f.Remedy = RemedyManual
		case isTerraformState(f.FilePath):
			f.Remedy = RemedyManual
		case f.FindingType == FindingTypeIACVariableFile &&
			!strings.HasSuffix(f.FilePath, ".tfvars") &&
			f.Confidence != ConfidenceHigh:
			// Only the LEGACY Kubernetes finding (a "kind: Secret" file that
			// wouldn't parse as YAML, line-scanned at ConfidenceMedium) stays
			// manual: migrate needs a parseable manifest. A structurally
			// parsed Secret manifest (ConfidenceHigh, buildK8sSecretFinding)
			// falls through to RemedyMigrate — `jit migrate <path>` either
			// converts it to a rejectable-decoy mount or explains exactly why
			// it refused (block scalars, mixed data:/stringData:).
			f.Remedy = RemedyManual
		case f.FindingType == FindingTypeShellHistorySecret && f.ProductionIndicatorMatch:
			f.Remedy = RemedyManual
		case AgentLabelForPath(home, f.FilePath) != "":
			// Anything inside an AI agent's own directory is manual, whatever
			// found it. The agent-store sweep emits ordinary exposed_secret
			// findings, and a pasted credential is usually a BARE token, which
			// isPureTokenFile then judges migratable — so `jit scan` was about
			// to recommend `jit migrate ~/.claude/paste-cache/50440ea9.txt`,
			// which would neutralize a file inside Claude Code's private state
			// into a jit pointer and name a vault secret after a cache blob.
			// The credential's home is the file it came from; its copy here is
			// something to delete, not to relocate.
			f.Remedy = RemedyManual
		case f.FindingType == FindingTypeExposedSecret &&
			(f.ProductionIndicatorMatch || !isPure(f.FilePath)):
			f.Remedy = RemedyManual
		default:
			f.Remedy = RemedyMigrate
			f.FixCommand = "jit migrate " + shellSafePath(home, f.FilePath)
		}
	}
	annotateCauseGroups(findings)
}

// shellSafePath renders a path for a copy-pasteable command. The pretty
// "~/"-shortened form is used when it pastes cleanly, and a path that needs
// quoting keeps it anyway by putting the tilde OUTSIDE the quotes:
// ~/'Documents/we$ird/.env'.
//
// That is not the same construction as "~/Documents/…", which is what the
// earlier "quote it ABSOLUTE instead" rule was guarding against: a tilde
// INSIDE quotes is literal, so `jit migrate "~/My Project/.env"` really does
// look for a directory named "~". A tilde outside them expands, because the
// shell ends the tilde-prefix at the first unquoted "/" and treats only the
// remainder as quoted text. Checked against sh, bash and zsh — including a
// $HOME that itself contains a metacharacter, which stays safe because the
// result of tilde expansion is itself treated as quoted.
//
// It is worth the extra branch because the hint this feeds is the one line in
// the report that WRAPS rather than truncating (a path cut at the front still
// identifies the file; a command cut anywhere is no longer a command). Path
// length is therefore the only lever on wrapping, and "~/" is worth about 30
// columns. It also keeps the report's one visual invariant — every path reads
// "~/…" — instead of leaving a single absolute outlier.
//
// A path OUTSIDE $HOME that needs quoting is still rendered quoted-absolute,
// and that residue is deliberate: there is no home prefix to shorten against.
//
// What comes out of here is pasted into a shell by a human, and it is also
// Finding.FixCommand — the NDJSON field a consumer may hand straight to sh.
// Scan walks whatever repos the user has checked out, so a filename is not
// jit's to trust: it is the one part of a jit command line that an outsider
// can choose.
func shellSafePath(home, path string) string {
	short := ShortenHome(home, path)
	if shellBarePath(path) {
		return short
	}
	if rest, under := strings.CutPrefix(short, "~/"); under {
		return "~/" + shellQuote(rest)
	}
	return shellQuote(path)
}

// shellBarePath reports whether path can be printed with no quoting at all.
//
// An ALLOWLIST, and that inversion is the fix: this was a
// ContainsAny(" \t'\"\\$&();|<>*?[]#") denylist, which read as thorough and
// left out a backtick and a newline. `~/x`+"`id`"+`.env` therefore printed
// bare, and `x$(id).env` — matching on the parens — was handed to %q, which
// is GO quoting: "x$(id).env" keeps command substitution live inside those
// double quotes. Either one runs a stranger's command when the reader pastes
// the line jit told them to paste. A denylist of shell metacharacters is a
// list of things someone has to remember; the safe set is short, closed, and
// checkable by eye.
//
// Runes above ASCII pass: a multi-byte UTF-8 encoding contains no byte that
// is an ASCII metacharacter, so "~/Résumé/.env" is safe bare and keeps the
// pretty form. "~" is in the set because tilde expansion only fires at the
// START of a word, and a path here is always absolute or already "~/"-rooted
// — which keeps Emacs backups (".env~") off the quoted path, common enough in
// a home directory to matter.
func shellBarePath(path string) bool {
	if path == "" {
		return false
	}
	for _, r := range path {
		switch {
		case r > unicode.MaxASCII:
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("._/-+:@,~", r):
		default:
			return false
		}
	}
	return true
}

// shellQuote wraps s in single quotes, which is the only shell quoting with no
// interior expansion of any kind: no $, no backtick, no backslash escape. The
// one character that cannot appear inside is the quote itself, and the
// ...'\”... idiom closes the string, emits an escaped quote, and reopens.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// annotateCauseGroups gives findings that describe the same underlying
// secret one shared opaque id. Identity is the FULL raw value's digest
// (rawValueDigest, stamped by ValueFinding) — never the masked preview: a
// preview keeps only 4 characters, which for vendor-prefixed tokens is the
// constant prefix, so grouping on it would fold two DIFFERENT AWS keys into
// "one secret" and undercount the ledger (review finding, 2026-07-28). A
// finding built outside ValueFinding falls back to key+preview — coarser,
// but those paths (wrapcli) emit one finding per source anyway.
//
// The id is salted with per-run randomness and is therefore stable only
// WITHIN a run — deliberately: an unsalted digest of the raw value would
// hand NDJSON consumers an offline dictionary-check oracle for weak
// passwords. record_id remains the documented cross-run key.
//
// A finding with no value gets no group — with nothing to compare, claiming
// two file-presence findings share a cause would be invented knowledge.
//
// The key name is mixed in ONLY on the preview fallback. When the full value's
// digest is available it stands alone, because two findings holding the same
// secret ARE one secret however differently their scanners chose to name it —
// which is the whole definition this function exists to implement. Including
// the key alongside the digest quietly broke that across scanners: one GitHub
// token in ~/.mcp.json (key "internal-tool/GITHUB_TOKEN") and in
// ~/.zsh_history (key "GitHub Personal Access Token") scored as TWO secrets,
// so a machine with one token reported "YOUR SECRETS: 2" and charged the user
// twice for rotating it once. On the fallback path the key is still needed:
// a 4-character preview is the constant vendor prefix for most formats, so
// "ghp_****" alone would fold together every GitHub token on the machine.
func annotateCauseGroups(findings []Finding) {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt) // a zeroed salt degrades stability guarantees, never correctness
	for i := range findings {
		f := &findings[i]
		identity := f.rawValueDigest
		if identity == "" {
			if f.ValuePreview == nil || *f.ValuePreview == "" {
				continue
			}
			key := ""
			if f.KeyName != nil {
				key = *f.KeyName
			}
			identity = "preview:" + key + "\x00" + *f.ValuePreview
		}
		h := sha256.New()
		h.Write(salt)
		h.Write([]byte(identity))
		f.CauseGroup = hex.EncodeToString(h.Sum(nil)[:8])
	}
}

// CountedAsSecret reports whether a finding counts toward the distinct-secret
// ledger. Low/Info sightings deliberately do not: they are jit saying "could
// be, probably isn't", and counting the scanner's own uncertainty against the
// user's coverage score would demand user work (judging them) to reach 100%.
// What jit does not stand behind, it does not charge for. The sightings stay
// fully visible in `jit scan --full` and NDJSON.
//
// Test fixtures are excluded for the neighbouring reason: the match is real,
// but the credential is not the user's to rotate (see LooksTestFixture).
func CountedAsSecret(f Finding) bool {
	if f.TestFixture {
		return false
	}
	switch f.Severity {
	case SeverityCritical, SeverityHigh, SeverityMedium:
		return true
	default:
		return false
	}
}

// Coverage is the report's ledger, in distinct secrets — never findings.
type Coverage struct {
	Protected  int // vault entries served by live jit mounts
	Exposed    int // distinct counted secrets in the findings
	Migratable int // of Exposed: covered by a remedy jit can run
}

// Total is every secret jit knows about on this machine.
func (c Coverage) Total() int { return c.Protected + c.Exposed }

// Percent is the headline number: protected / total, in whole percent.
// A machine jit knows nothing about scores 100 — nothing exposed is clean,
// not division by zero.
func (c Coverage) Percent() int {
	if c.Total() == 0 {
		return 100
	}
	return c.Protected * 100 / c.Total()
}

// manualRemainder is how many counted secrets are left once every jit-runnable
// remedy has run: the size of the "only you can protect these" bucket, in the
// same distinct-secret unit as the rest of the ledger.
//
// Derived from the ledger rather than counted off the rendered groups, so the
// two halves of the report's arithmetic cannot disagree. Summing the groups'
// own badges double-counted any secret found in BOTH a migratable file and a
// manual one — it was charged once to Migratable and again to the manual
// total, so "one command +75% · 2 things only you can fix +40%" could add past
// 100%. Rare before shell history existed (a secret rarely sat in a migratable
// file and a manual one at once) and routine after it, since a token pasted at
// the shell is usually also in the config file it was pasted into.
//
// By construction Percent + PercentAfterMigrate's gain + this remainder's share
// is exactly 100: Protected + Migratable + (Exposed - Migratable) == Total.
func (c Coverage) manualRemainder() int { return c.Exposed - c.Migratable }

// PercentAfterMigrate projects the score after every jit-runnable remedy is
// applied — the number the report prints next to the command it recommends.
func (c Coverage) PercentAfterMigrate() int {
	if c.Total() == 0 {
		return 100
	}
	return (c.Protected + c.Migratable) * 100 / c.Total()
}

// ComputeCoverage builds the ledger from the two sources of truth: the mount
// registry (what jit already protects) and this scan's findings (what is
// still exposed).
//
// Protected counts vault entries, not mounts: one mounted .pypirc serving
// three passwords protects three secrets. Only entries whose mount path is
// currently a live FIFO count — a registry row whose pipe was replaced by a
// regular file protects nothing (countProtectedMounts' rule, same reason).
// A missing or unreadable registry/manifest contributes zero, never an
// error: coverage is reporting, and reporting must not fail the scan.
//
// Exposed dedupes by cause group (same key + masked value = one secret) so
// copies of a file don't inflate the denominator; a counted finding with no
// value preview stands for one secret of its own.
func ComputeCoverage(home, registryPath string, findings []Finding) Coverage {
	var c Coverage
	c.Protected = countProtectedSecrets(registryPath)

	// Two passes so the verdict for a secret seen in several places is
	// order-independent: the same value in an archived backup AND a live
	// .env is one exposed secret, and it IS migratable — bare `jit migrate`
	// protects the live copy. Deciding off whichever finding happened to
	// sort first made that a coin flip (review finding, 2026-07-28).
	// Archived-only groups stay non-migratable: `jit migrate` deliberately
	// skips archived/backup directories, so counting them would promise a
	// coverage gain the recommended command doesn't deliver.
	migratable := map[string]bool{}
	// A cause group with a MANUAL history copy is never migratable, whatever
	// its other findings say. The two-pass rule above exists because migrate
	// protects the LIVE copy of a secret that also sits in a backup — but a
	// history line is itself a live plaintext copy, and the manual-remedy
	// case (a production-flagged credential, see annotateRemedies) is the one
	// copy bare `jit migrate` will not touch. Vaulting the .mcp.json that
	// holds the same token leaves it readable in ~/.zsh_history, so counting
	// the group as migratable would promise a coverage gain the recommended
	// command does not deliver. An ORDINARY history finding carries
	// RemedyMigrate now that ApplyShellHistory redacts in place, so it marks
	// its group migratable through the same rule as everything else.
	manualHistory := map[string]bool{}
	// Files whose credentials have an uncleaned copy in an AI agent's cache.
	// Keyed by the ORIGIN path rather than by cause group because the most
	// common origin — env_file_present — is a file-level finding with no
	// value digest, so its copies share no group with it and the group-level
	// rules below cannot see them.
	//
	// Collected in its own pass, before the tally below reads it: the
	// cross-reference phase appends its findings after every category, so a
	// single-pass version had the map still empty at the moment each origin
	// was judged and silently marked everything migratable.
	hasAgentCopy := map[string]bool{}
	for _, f := range findings {
		if f.FindingType == FindingTypeAgentCachedSecret && f.originPath != "" {
			hasAgentCopy[f.originPath] = true
		}
	}
	// Values a FILE-LEVEL finding already stands for. env_file_present has no
	// digest of its own, so a second finding holding the same credential shares
	// no cause_group with it and would be tallied as a separate secret.
	//
	// The case that makes this real: a Stripe key in ~/proj/.env that the user
	// once pasted into a prompt. The .env is one counted secret; the agent-store
	// sweep finds the same value in ~/.claude/paste-cache and counts a second.
	// One credential, "YOUR SECRETS: 2" — the exact double-count the cached-copy
	// findings were designed to avoid, arriving through the sweep's door instead.
	claimedBy := map[string]string{}
	for _, f := range findings {
		for _, cv := range f.claimedRawValues {
			if _, seen := claimedBy[cv.Value]; !seen {
				claimedBy[cv.Value] = f.FilePath
			}
		}
	}
	for _, f := range findings {
		// A copy is never a NEW secret — it is the same secret in another
		// place, and the finding that named it is already counted. Left in
		// the tally it would double-charge the user for one credential, and
		// for a file-level origin it would charge once per copy: a .env with
		// three secrets and nine cached copies scored as twelve.
		if f.FindingType == FindingTypeAgentCachedSecret {
			continue
		}
		if !CountedAsSecret(f) {
			continue
		}
		// The same secret a file-level finding already stands for, found again
		// somewhere else. Counted once, at its origin. When the duplicate sits
		// in an AI agent's directory it also makes the origin non-migratable,
		// for the reason a cached copy does: `jit migrate` rewrites the .env
		// and cannot reach into the agent's cache.
		if origin, dup := claimedBy[f.rawValue]; dup && f.rawValue != "" && origin != f.FilePath {
			if AgentLabelForPath(home, f.FilePath) != "" {
				hasAgentCopy[origin] = true
			}
			continue
		}
		key := f.CauseGroup
		if key == "" {
			key = f.RecordID
		}
		if _, ok := migratable[key]; !ok {
			migratable[key] = false
			c.Exposed++
		}
		if f.FindingType == FindingTypeShellHistorySecret && f.Remedy == RemedyManual {
			manualHistory[key] = true
		}
		// An uncleaned agent copy makes the whole group non-migratable, by the
		// same rule a manual history finding does: `jit migrate` rewrites the
		// file the credential lives in, and the agent's copy is not that file.
		// Vaulting the .env while file-history/ keeps the plaintext is not
		// protection, so promising the coverage gain would be a lie the
		// recommended command cannot make true.
		if f.Remedy != RemedyManual && !f.Archived && !hasAgentCopy[f.FilePath] {
			migratable[key] = true
		}
	}
	for key, ok := range migratable {
		if ok && !manualHistory[key] {
			c.Migratable++
		}
	}
	return c
}

// countProtectedSecrets sums the vault entries behind every live mount.
func countProtectedSecrets(registryPath string) int {
	if registryPath == "" {
		return 0
	}
	entries, err := mount.LoadRegistry(registryPath)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		info, statErr := os.Lstat(e.MountPath)
		if statErr != nil || info.Mode()&os.ModeNamedPipe == 0 {
			continue
		}
		p, err := profile.LoadFile(e.ProfilePath)
		if err != nil {
			// A live pipe with an unreadable manifest still protects
			// SOMETHING; one is the honest floor.
			n++
			continue
		}
		if len(p) == 0 {
			n++
			continue
		}
		n += len(p)
	}
	return n
}
