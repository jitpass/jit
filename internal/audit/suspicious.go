// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"io/fs"
	"strings"
)

// suspiciousFilenameRule is a precise, narrow filename check — RFC.md §4
// category 7, detection only. Real-world review (2026-07-06, see
// ROADMAP.md) showed an existing tool's naive broad heuristic (matching
// "token" as a bare substring) produced heavy false-positive noise
// (blockchain-token filenames, Jira ticket exports entirely unrelated to
// auth tokens) that would erode trust in the tool. Every rule here is
// specific enough not to repeat that mistake. Deliberately does NOT
// duplicate patterns other categories already cover more precisely:
// secrets.yaml is category 6's job (content-confirmed there), and
// key-shaped filenames outside ~/.ssh are category 5's job (content-sniffed
// there) — flagging either again here by name alone would double-count the
// same file or, worse, flag something by name that isn't actually a secret.
type suspiciousFilenameRule struct {
	match      func(name string) bool
	evidence   string
	severity   string
	confidence string
}

var suspiciousFilenameRules = []suspiciousFilenameRule{
	{
		match:      func(name string) bool { return strings.HasSuffix(strings.ToLower(name), ".env.bak") },
		evidence:   "backup of a .env file",
		severity:   SeverityLow,
		confidence: ConfidenceMedium,
	},
	{
		match: func(name string) bool {
			lower := strings.ToLower(name)
			return lower == "credentials.json" || lower == "secrets.json"
		},
		evidence:   "generically-named credential dump file",
		severity:   SeverityLow,
		confidence: ConfidenceMedium,
	},
	{
		match: func(name string) bool {
			return strings.HasPrefix(strings.ToLower(name), "1password emergency kit")
		},
		evidence:   "1Password Emergency Kit — contains the account's master and secret key if genuine",
		severity:   SeverityMedium,
		confidence: ConfidenceHigh,
	},
}

// ScanSuspiciousFilenames implements RFC.md §4 category 7, detection only.
func ScanSuspiciousFilenames(cfg Config) ([]Finding, error) {
	var findings []Finding
	err := walkHomeDir(cfg.HomeDir, func(path string, d fs.DirEntry) error {
		// A backup-suffixed file (.env.bak etc.) that `jit migrate` replaced
		// in place with pointer content is jit's own git-safe artifact, not a
		// stray credential backup — don't re-flag it as suspicious (GAPS.md
		// #66). Content-based, since the name still ends in .bak.
		if isJitPointerContent(path) {
			return nil
		}
		for _, rule := range suspiciousFilenameRules {
			if !rule.match(d.Name()) {
				continue
			}
			f := cfg.baseFinding()
			f.FindingType = FindingTypeSuspiciousFilename
			f.FilePath = path
			f.Severity = rule.severity
			f.Confidence = rule.confidence
			f.Evidence = rule.evidence
			f.RecordID = RecordID(f.FindingType, f.FilePath, nil)
			findings = append(findings, f)
			break // one finding per file, even if multiple rules would match
		}
		return nil
	})
	return findings, err
}
