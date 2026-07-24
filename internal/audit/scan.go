// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"os"
	"time"

	"github.com/jitpass/jit/internal/mount"
)

// categoryScanner pairs a scanner with a short human noun for it. The name is
// what Config.Progress reports as each one runs (see Scan) — kept next to the
// function so the label and the scanner can never drift out of sync the way a
// parallel []string would.
type categoryScanner struct {
	name string
	scan func(Config) ([]Finding, error)
}

// categoryScanners lists every RFC.md §4 category scanner, in the same
// order as AllFindingTypes. Scan runs them in this fixed order so output
// (and NDJSON in particular) is deterministic across runs, even though
// record_id — not list position — is the documented dedup key.
var categoryScanners = []categoryScanner{
	{"shell configs", ScanShellConfigs},
	{".env files", ScanEnvFiles},
	{"credential files", ScanCredentialFiles},
	{"MCP configs", ScanMCPConfigs},
	{"private keys", ScanPrivateKeys},
	{"IaC files", ScanIACFiles},
	{"suspicious filenames", ScanSuspiciousFilenames},
	{"wrappable CLI tokens", ScanWrappableCLITokens},
	{"SOPS age keys", ScanSOPSAgeKeys},
}

// Scan runs every category scanner and returns the individual findings plus
// the aggregate summary (RFC.md §4).
func Scan(cfg Config) ([]Finding, ScanSummary, error) {
	start := time.Now()

	var all []Finding
	for _, cs := range categoryScanners {
		if cfg.Progress != nil {
			cfg.Progress(cs.name)
		}
		findings, err := cs.scan(cfg)
		if err != nil {
			return all, ScanSummary{}, err
		}
		all = append(all, findings...)
	}

	// Tag findings under archived/backup-looking directories centrally
	// (not per scanner): `jit migrate home` skips exactly these by default,
	// and the report renderers surface the tag so that skip is legible from
	// the audit side of the funnel too.
	for i := range all {
		all[i].Archived = LooksArchived(all[i].FilePath)
	}

	summary := buildScanSummary(cfg, all, countProtectedMounts(cfg.MountRegistryPath), time.Since(start))
	return all, summary, nil
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
