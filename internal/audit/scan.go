// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/jitpass/jit/internal/mount"
)

// categoryScanners lists every RFC.md §4 category scanner, in the same
// order as AllFindingTypes. Scan runs them in this fixed order so output
// (and NDJSON in particular) is deterministic across runs, even though
// record_id — not list position — is the documented dedup key.
var categoryScanners = []func(Config) ([]Finding, error){
	ScanShellConfigs,
	ScanEnvFiles,
	ScanCredentialFiles,
	ScanMCPConfigs,
	ScanPrivateKeys,
	ScanIACFiles,
	ScanSuspiciousFilenames,
	ScanWrappableCLITokens,
	ScanSOPSAgeKeys,
}

// Scan runs every category scanner and returns the individual findings plus
// the aggregate summary (RFC.md §4).
func Scan(cfg Config) ([]Finding, ScanSummary, error) {
	start := time.Now()

	var all []Finding
	for _, scan := range categoryScanners {
		findings, err := scan(cfg)
		if err != nil {
			return all, ScanSummary{}, err
		}
		all = append(all, findings...)
	}

	// Drop findings that live inside a jitpass playground checkout crossed
	// during the walk: they are synthetic bait, not real at-rest secrets, and
	// must not inflate a real machine's score. The count and source paths are
	// surfaced in the summary so the exclusion is visible, never silent.
	real, syntheticCount, playgrounds := partitionSynthetic(cfg, all)

	// Tag findings under archived/backup-looking directories centrally
	// (not per scanner): `jit migrate home` skips exactly these by default,
	// and the report renderers surface the tag so that skip is legible from
	// the audit side of the funnel too.
	for i := range real {
		real[i].Archived = LooksArchived(real[i].FilePath)
	}

	summary := buildScanSummary(cfg, real, countProtectedMounts(cfg.MountRegistryPath), time.Since(start))
	summary.SyntheticFindingCount = syntheticCount
	summary.SyntheticPlaygroundPaths = playgrounds
	return real, summary, nil
}

// partitionSynthetic splits findings into the real ones to score and report,
// and a count (+ source playground roots) of those excluded for living inside
// a jitpass playground subtree of the scan root.
//
// When the scan root is ITSELF a playground — the first-run tour points the
// scanner straight at the checkout (internal/cli scanRoot) — nothing is
// synthetic: showing and scoring those findings is the entire point of the
// tour, so this returns everything unchanged. `jit scan` proper always roots
// at real $HOME, so a playground can only ever appear as a crossed subtree
// there, which is exactly the case this filters.
func partitionSynthetic(cfg Config, all []Finding) (real []Finding, syntheticCount int, playgrounds []string) {
	if cfg.HomeDir == "" || rootInPlayground(cfg.HomeDir) {
		return all, 0, nil
	}

	cache := map[string]string{} // dir -> playground root ("" = not synthetic)
	playgroundSet := map[string]bool{}
	for _, f := range all {
		root := playgroundRootFor(filepath.Dir(f.FilePath), cfg.HomeDir, cache)
		if root == "" {
			real = append(real, f)
			continue
		}
		syntheticCount++
		playgroundSet[root] = true
	}

	for p := range playgroundSet {
		playgrounds = append(playgrounds, p)
	}
	sort.Strings(playgrounds)
	return real, syntheticCount, playgrounds
}

// InSyntheticPlayground reports whether path lives inside a
// jitpass-playground checkout beneath home, mirroring partitionSynthetic's
// own exclusion exactly, including its escape hatch: when home itself sits
// inside a playground (a scan deliberately rooted at the checkout, like the
// first-run tour), nothing counts as synthetic. Exported for
// internal/migrate: a whole-machine sweep must skip the same playground
// subtrees audit excludes from its score, or `jit migrate home` would
// convert the tour repo's planted bait into vault entries and live mounts.
func InSyntheticPlayground(home, path string) bool {
	if home == "" || rootInPlayground(home) {
		return false
	}
	return playgroundRootFor(filepath.Dir(path), home, map[string]string{}) != ""
}

// hasPlaygroundMarker reports whether dir directly holds the playground marker.
func hasPlaygroundMarker(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, PlaygroundMarkerFile))
	return err == nil
}

// rootInPlayground reports whether dir or any ancestor (up to the filesystem
// root) is a playground checkout — used to detect a scan deliberately rooted
// inside the playground, where exclusion must not apply.
func rootInPlayground(dir string) bool {
	for {
		if hasPlaygroundMarker(dir) {
			return true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}

// playgroundRootFor walks up from dir toward stopAt (the scan root, which the
// caller has already established is not itself a playground) and returns the
// nearest ancestor holding the playground marker, or "" if none up to and
// including stopAt. Results are cached per starting dir so a dense scan does
// at most one stat chain per distinct finding directory.
func playgroundRootFor(dir, stopAt string, cache map[string]string) string {
	if v, ok := cache[dir]; ok {
		return v
	}
	root := ""
	for d := dir; ; {
		if hasPlaygroundMarker(d) {
			root = d
			break
		}
		if d == stopAt {
			break
		}
		parent := filepath.Dir(d)
		if parent == d {
			break // reached the filesystem root without meeting stopAt
		}
		d = parent
	}
	cache[dir] = root
	return root
}

// countProtectedMounts returns how many of the mount registry's entries are
// currently live (a named pipe occupies the registered path). Purely
// informational — walkHomeDir's regular-file guard is what actually keeps
// scanners away from pipes, registry or no registry — so any failure here
// (no registry, unreadable, malformed) is a 0, never an error: this
// package's read-only scan must not fail because jit's own bookkeeping is
// absent or damaged. A registered path that is a regular file again (e.g.
// someone replaced the pipe by hand) is deliberately NOT counted: whatever
// is in that file now is plaintext at rest, and the scanners will judge it
// like any other file.
func countProtectedMounts(registryPath string) int {
	if registryPath == "" {
		return 0
	}
	entries, err := mount.LoadRegistry(registryPath)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if info, statErr := os.Lstat(e.MountPath); statErr == nil && info.Mode()&os.ModeNamedPipe != 0 {
			n++
		}
	}
	return n
}

func buildScanSummary(cfg Config, findings []Finding, protectedMounts int, duration time.Duration) ScanSummary {
	byCategory := map[string]int{}
	for _, ft := range AllFindingTypes {
		byCategory[ft] = 0 // RFC.md §4: "all seven keys always present"
	}

	prodCount := 0
	ipCount := 0
	for _, f := range findings {
		byCategory[f.FindingType]++
		if f.ProductionIndicatorMatch {
			prodCount++
		}
		if f.PublicIPMatch != nil {
			ipCount++
		}
	}

	return ScanSummary{
		RecordType:               RecordTypeScanSummary,
		RecordID:                 nil, // always null — run_id is already unique per run
		SchemaVersion:            SchemaVersion,
		ScannerName:              ScannerName,
		ScannerVersion:           cfg.ScannerVersion,
		RunID:                    cfg.RunID,
		ScanTime:                 nowISO8601(),
		Endpoint:                 cfg.Endpoint,
		TotalFindings:            len(findings),
		FindingsByCategory:       byCategory,
		RiskLevel:                ComputeRiskLevel(findings),
		ExposureScore:            ComputeExposureScore(findings),
		ProductionIndicatorCount: prodCount,
		PublicIPCount:            ipCount,
		ScanDurationMs:           duration.Milliseconds(),
		JitProtectedCount:        protectedMounts,
	}
}

// ComputeRiskLevel implements RFC.md §4's risk-level table, aggregating
// across every finding from a scan:
//
//	Critical: any production-indicator match or public IP found
//	High:     unencrypted SSH key, a loose key/cert file outside a
//	          protected directory, any shell-config plaintext export,
//	          any MCP-embedded secret, or >=5 total findings
//	Medium:   >=3 total findings
//	Low:      1-2 total findings
//	Clean:    0 findings
//
// Rather than hardcoding which finding_types can produce a High-severity
// finding (RFC.md §4's own list — unencrypted SSH key, loose key/cert file,
// shell-config export, MCP-embedded secret — happens to be exactly the set
// of categories that assign Severity: High today), this checks
// Finding.Severity directly. That is behaviorally identical for those
// categories, and it fixes a real gap the hardcoded version had: a single
// FindingTypeCredentialFile finding (a real AWS/kubeconfig/GCP credential,
// always Severity: High per credfile.go) was NOT escalating the aggregate
// risk level, because credential_file was missing from the hardcoded list.
// It also means a future category that starts assigning Severity: High
// (e.g. envfile.go's secret-shaped-variable-name escalation) is covered
// automatically instead of needing a second place to remember to update.
func ComputeRiskLevel(findings []Finding) string {
	for _, f := range findings {
		if f.ProductionIndicatorMatch || f.PublicIPMatch != nil {
			return RiskLevelCritical
		}
	}

	highTriggered := false
	for _, f := range findings {
		if f.Severity == SeverityHigh {
			highTriggered = true
			break
		}
	}

	switch {
	case highTriggered || len(findings) >= 5:
		return RiskLevelHigh
	case len(findings) >= 3:
		return RiskLevelMedium
	case len(findings) >= 1:
		return RiskLevelLow
	default:
		return RiskLevelClean
	}
}
