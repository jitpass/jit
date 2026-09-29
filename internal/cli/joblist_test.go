// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/agent"
)

// `jit job list` names what a ready job runs without, and prints the line
// that approves each stopped job again, not only the first: one move out of
// the vault can stop several.
func TestJobListShowsGoneValuesAndEveryStoppedJob(t *testing.T) {
	now := time.Now()
	jobs := []agent.JobStatus{
		{Name: "billing-sync", Dir: "/work/billing", Argv: []string{"./sync.sh"}, State: agent.JobReady, Ask: "never",
			Secrets: []agent.JobSecretStatus{{Var: "BILLING_TOKEN"}, {Var: "REPORT_URL", Gone: true}}},
		{Name: "report-a", Dir: "/work/a", Argv: []string{"./a.sh"}, State: agent.JobChanged, Stopped: true, LastRefusal: "REPORT_URL was moved out of the vault into settings since you approved it"},
		{Name: "report-b", Dir: "/work/b", Argv: []string{"./b.sh"}, State: agent.JobChanged, Stopped: true, LastRefusal: "REPORT_URL was moved out of the vault into settings since you approved it"},
	}
	var buf bytes.Buffer
	renderJobRows(&buf, jobs, now)
	out := buf.String()
	for _, want := range []string{
		"runs without REPORT_URL (no longer in the vault)",
		"jit job allow report-a --replace",
		"jit job allow report-b --replace",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("list lacks %q:\n%s", want, out)
		}
	}
}
