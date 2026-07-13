// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package audit

import "time"

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

	return all, buildScanSummary(cfg, all, time.Since(start)), nil
}

func buildScanSummary(cfg Config, findings []Finding, duration time.Duration) ScanSummary {
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
		ProductionIndicatorCount: prodCount,
		PublicIPCount:            ipCount,
		ScanDurationMs:           duration.Milliseconds(),
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
