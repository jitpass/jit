// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

// severityWeight is the exposure "load" each finding contributes. info is 0:
// an info finding (an IaC variable file, say) is detection-only, not an
// at-rest secret a stealer walks away with.
var severityWeight = map[string]int{
	SeverityCritical: 30,
	SeverityHigh:     15,
	SeverityMedium:   6,
	SeverityLow:      2,
	SeverityInfo:     0,
}

// escalationBonus is added per finding carrying a production-indicator or
// public-IP match: the same signals that escalate a whole scan to CRITICAL
// (ComputeRiskLevel), because those are what turn "a key leaked" into "prod is
// reachable".
const escalationBonus = 40

// scoreBands clamps the computed load into the band of the scan's RiskLevel,
// keyed by risk level, so the number can never disagree with the printed
// RISK LEVEL: a CRITICAL machine always reads high, a LOW one always low. The
// bands partition 0..100 with no gaps or overlaps.
var scoreBands = map[string][2]int{
	RiskLevelClean:    {0, 0},
	RiskLevelLow:      {10, 39},
	RiskLevelMedium:   {40, 64},
	RiskLevelHigh:     {65, 84},
	RiskLevelCritical: {85, 100},
}

// ComputeExposureScore returns a 0..100 exposure score for a scan: 0 is clean,
// 100 is maximally exposed. It sums a severity-weighted load (plus a bonus for
// the production-indicator/public-IP findings that make a scan critical), caps
// it at 100, then clamps into the band of the scan's RiskLevel so the number
// and the categorical label always agree. Deterministic and purely local, like
// everything else in this package.
func ComputeExposureScore(findings []Finding) int {
	if len(findings) == 0 {
		return 0
	}

	load := 0
	for _, f := range findings {
		load += severityWeight[f.Severity]
		if f.ProductionIndicatorMatch || f.PublicIPMatch != nil {
			load += escalationBonus
		}
	}
	if load > 100 {
		load = 100
	}

	band := scoreBands[ComputeRiskLevel(findings)]
	switch {
	case load < band[0]:
		return band[0]
	case load > band[1]:
		return band[1]
	default:
		return load
	}
}
