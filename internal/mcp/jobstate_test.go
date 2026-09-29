// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package mcp

import (
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/agent"
)

// A ready job that runs without a value deleted from the vault says so, so
// the model can tell the user why its output may be short, instead of only
// "ready".
func TestJobStateLineNamesWhatAReadyJobRunsWithout(t *testing.T) {
	j := agent.JobStatus{State: agent.JobReady, Ask: "never", Secrets: []agent.JobSecretStatus{
		{Var: "BILLING_TOKEN"}, {Var: "REPORT_URL", Gone: true},
	}}
	got := jobStateLine(j)
	if !strings.HasPrefix(got, "ready, runs without asking the user") || !strings.Contains(got, "runs without REPORT_URL") || strings.Contains(got, "BILLING_TOKEN") {
		t.Fatalf("jobStateLine = %q", got)
	}
}
