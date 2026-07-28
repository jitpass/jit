// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
//   - ~/.mcp-auth: mcp-remote rotates those files itself; a mount would be
//     fought by the tool and serve stale tokens.
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
		case strings.Contains(f.FilePath, string(filepath.Separator)+mcpAuthDir+string(filepath.Separator)):
			f.Remedy = RemedyManual
		case f.FindingType == FindingTypeIACVariableFile &&
			!strings.HasSuffix(f.FilePath, ".tfvars"):
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
// "~/"-shortened form is used when it pastes cleanly; a path with shell-
// significant characters is quoted ABSOLUTE instead, because "~" inside
// quotes does not expand ("jit migrate \"~/My Project/.env\"" would look
// for a literal ~ directory).
func shellSafePath(home, path string) string {
	if strings.ContainsAny(path, " \t'\"\\$&();|<>*?[]#") {
		return fmt.Sprintf("%q", path)
	}
	return ShortenHome(home, path)
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
			identity = "preview:" + *f.ValuePreview
		}
		key := ""
		if f.KeyName != nil {
			key = *f.KeyName
		}
		h := sha256.New()
		h.Write(salt)
		h.Write([]byte(key))
		h.Write([]byte{0})
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
func CountedAsSecret(f Finding) bool {
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
func ComputeCoverage(registryPath string, findings []Finding) Coverage {
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
	for _, f := range findings {
		if !CountedAsSecret(f) {
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
		if f.Remedy != RemedyManual && !f.Archived {
			migratable[key] = true
		}
	}
	for _, ok := range migratable {
		if ok {
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
