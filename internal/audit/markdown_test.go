// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriteMarkdownReportNeverLeaksRawValue(t *testing.T) {
	key := "AWS_SECRET_ACCESS_KEY"
	rawSecretForComparisonOnly := "AKIAABCDEFGHIJKLMNOPQRSTUVWXYZ12"
	preview := MaskValue(rawSecretForComparisonOnly)
	line := 12

	findings := []Finding{
		{
			FindingType:              FindingTypeShellConfigSecret,
			Severity:                 SeverityCritical,
			ProductionIndicatorMatch: true,
			FilePath:                 "/Users/alex/.zshrc",
			Line:                     &line,
			KeyName:                  &key,
			ValuePreview:             &preview,
			Evidence:                 "key name matches production-indicator pattern",
		},
	}
	summary := buildScanSummary(Config{Endpoint: Endpoint{Username: "alex", Hostname: "host"}}, findings, 0)

	var buf bytes.Buffer
	WriteMarkdownReport(&buf, findings, summary)
	out := buf.String()

	if strings.Contains(out, rawSecretForComparisonOnly) {
		t.Fatal("markdown report must never contain the raw secret value")
	}
	for _, want := range []string{
		"# jit audit report",
		"alex@host",
		"CRITICAL",
		"### Shell Configs",
		"`/Users/alex/.zshrc`",
		"[critical]** :12 key: `AWS_SECRET_ACCESS_KEY`",
		"value: `" + preview + "`",
		"key name matches production-indicator pattern",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown output missing expected substring %q\n--- full output ---\n%s", want, out)
		}
	}
}

// TestWriteMarkdownReportGroupsMultipleFindingsInSameFile mirrors the text
// renderer's equivalent test — the file path must appear once even when a
// file has multiple findings (e.g. two secrets in one MCP env block).
func TestWriteMarkdownReportGroupsMultipleFindingsInSameFile(t *testing.T) {
	keyA, keyB := "jamf/JAMF_PRO_CLIENT_ID", "jamf/JAMF_PRO_CLIENT_SECRET"
	findings := []Finding{
		{FindingType: FindingTypeMCPEmbeddedSecret, Severity: SeverityHigh, FilePath: "/Users/alex/config.json", KeyName: &keyA, Evidence: "e"},
		{FindingType: FindingTypeMCPEmbeddedSecret, Severity: SeverityHigh, FilePath: "/Users/alex/config.json", KeyName: &keyB, Evidence: "e"},
	}
	summary := buildScanSummary(Config{Endpoint: Endpoint{Username: "alex", Hostname: "host"}}, findings, 0)

	var buf bytes.Buffer
	WriteMarkdownReport(&buf, findings, summary)
	out := buf.String()

	if got := strings.Count(out, "/Users/alex/config.json"); got != 1 {
		t.Errorf("file path should appear exactly once even with 2 findings in it, appeared %d times:\n%s", got, out)
	}
}

func TestWriteMarkdownReportCleanScan(t *testing.T) {
	summary := buildScanSummary(Config{Endpoint: Endpoint{Username: "alex", Hostname: "host"}}, nil, 0)
	var buf bytes.Buffer
	WriteMarkdownReport(&buf, nil, summary)
	out := buf.String()
	if !strings.Contains(out, "CLEAN") {
		t.Errorf("expected CLEAN risk level in output, got:\n%s", out)
	}
	if !strings.Contains(out, "looks clean") {
		t.Errorf("expected a clean-scan message, got:\n%s", out)
	}
}
