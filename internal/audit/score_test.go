// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import "testing"

func TestComputeExposureScore(t *testing.T) {
	ip := "203.0.113.7"
	critProd := Finding{Severity: SeverityCritical, ProductionIndicatorMatch: true}
	high := Finding{Severity: SeverityHigh}
	med := Finding{Severity: SeverityMedium}
	low := Finding{Severity: SeverityLow}
	lowIP := Finding{Severity: SeverityLow, PublicIPMatch: &ip}

	cases := []struct {
		name string
		in   []Finding
		want int
	}{
		{"clean is zero", nil, 0},
		{"single low clamps up to low floor", []Finding{low}, 10},
		{"three medium land at medium floor", []Finding{med, med, med}, 40},
		{"single high clamps up to high floor", []Finding{high}, 65},
		{"five highs land mid high band", []Finding{high, high, high, high, high}, 75},
		{"six highs clamp to high ceil", []Finding{high, high, high, high, high, high}, 84},
		{"single production-indicator critical clamps to critical floor", []Finding{critProd}, 85},
		{"public-IP match alone escalates to critical floor", []Finding{lowIP}, 85},
		{"heavy exposure caps at 100", []Finding{critProd, critProd, high, high, high, low, low}, 100},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ComputeExposureScore(tc.in); got != tc.want {
				t.Errorf("ComputeExposureScore = %d, want %d", got, tc.want)
			}
		})
	}
}

// The score must never contradict the printed RISK LEVEL: every score sits in
// its risk band, and score 0 happens only when the risk level is clean.
func TestExposureScoreAgreesWithRiskLevel(t *testing.T) {
	ip := "203.0.113.7"
	inputs := [][]Finding{
		nil,
		{{Severity: SeverityLow}},
		{{Severity: SeverityMedium}, {Severity: SeverityMedium}, {Severity: SeverityMedium}},
		{{Severity: SeverityHigh}},
		{{Severity: SeverityLow}, {Severity: SeverityLow}, {Severity: SeverityLow}, {Severity: SeverityLow}, {Severity: SeverityLow}},
		{{Severity: SeverityCritical, ProductionIndicatorMatch: true}},
		{{Severity: SeverityMedium, PublicIPMatch: &ip}},
	}
	for _, in := range inputs {
		level := ComputeRiskLevel(in)
		score := ComputeExposureScore(in)
		band, ok := scoreBands[level]
		if !ok {
			t.Fatalf("no band for risk level %q", level)
		}
		if score < band[0] || score > band[1] {
			t.Errorf("risk %q score %d outside band %v", level, score, band)
		}
		if (score == 0) != (level == RiskLevelClean) {
			t.Errorf("score 0 must correspond exactly to clean: score=%d level=%q", score, level)
		}
	}
}
