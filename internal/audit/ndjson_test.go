// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestWriteNDJSON(t *testing.T) {
	preview := "sk_t" + maskSuffix
	key := "STRIPE_KEY"
	findings := []Finding{
		{
			RecordType:    RecordTypeFinding,
			RecordID:      RecordID(FindingTypeShellConfigSecret, "/home/x/.zshrc", &key),
			SchemaVersion: SchemaVersion,
			ScannerName:   ScannerName,
			FindingType:   FindingTypeShellConfigSecret,
			Severity:      SeverityHigh,
			FilePath:      "/home/x/.zshrc",
			KeyName:       &key,
			ValuePreview:  &preview,
			Confidence:    ConfidenceHigh,
			Evidence:      "test evidence",
		},
	}
	summary := ScanSummary{
		RecordType:         RecordTypeScanSummary,
		SchemaVersion:      SchemaVersion,
		ScannerName:        ScannerName,
		TotalFindings:      1,
		FindingsByCategory: map[string]int{FindingTypeShellConfigSecret: 1},
		RiskLevel:          RiskLevelHigh,
	}

	var buf bytes.Buffer
	if err := WriteNDJSON(&buf, findings, summary); err != nil {
		t.Fatalf("WriteNDJSON: %v", err)
	}

	lines := []string{}
	scanner := bufio.NewScanner(&buf)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2 (1 finding + 1 summary)", len(lines))
	}

	var decodedFinding map[string]interface{}
	if err := json.Unmarshal([]byte(lines[0]), &decodedFinding); err != nil {
		t.Fatalf("line 1 is not valid JSON: %v", err)
	}
	if decodedFinding["record_type"] != "finding" {
		t.Errorf("line 1 record_type = %v, want %q", decodedFinding["record_type"], "finding")
	}

	var decodedSummary map[string]interface{}
	if err := json.Unmarshal([]byte(lines[1]), &decodedSummary); err != nil {
		t.Fatalf("line 2 is not valid JSON: %v", err)
	}
	if decodedSummary["record_type"] != "scan_summary" {
		t.Errorf("line 2 record_type = %v, want %q", decodedSummary["record_type"], "scan_summary")
	}
	if decodedSummary["record_id"] != nil {
		t.Errorf("scan_summary record_id = %v, want null", decodedSummary["record_id"])
	}

	// The one property that must never break: no raw secret value anywhere
	// in the output, only the pre-masked preview.
	if strings.Contains(buf.String(), "sk_test") {
		t.Error("NDJSON output must never contain a value beyond its masked preview")
	}
}

func TestWriteNDJSONEmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	summary := ScanSummary{RecordType: RecordTypeScanSummary, RiskLevel: RiskLevelClean, FindingsByCategory: map[string]int{}}
	if err := WriteNDJSON(&buf, nil, summary); err != nil {
		t.Fatalf("WriteNDJSON: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want 1 (just the summary)", len(lines))
	}
}
