// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestBuildAWSCredentialProcessOutputShape(t *testing.T) {
	out, err := buildAWSCredentialProcessOutput(map[string]string{
		"ACCESS_KEY_ID":     "AKIAIOSFODNN7EXAMPLE",
		"SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}, time.Now())
	if err != nil {
		t.Fatalf("buildAWSCredentialProcessOutput: %v", err)
	}
	if out.Version != 1 {
		t.Errorf("Version = %d, want 1", out.Version)
	}

	data, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	got := string(data)
	if strings.Contains(got, "SessionToken") {
		t.Errorf("expected SessionToken omitted when absent (omitempty), got: %s", got)
	}
	if strings.Contains(got, "Expiration") {
		t.Errorf("expected Expiration omitted when absent (omitempty), got: %s", got)
	}
	if !strings.Contains(got, `"Version":1`) {
		t.Errorf("expected Version:1 in output, got: %s", got)
	}
}

func TestBuildAWSCredentialProcessOutputIncludesSessionToken(t *testing.T) {
	out, err := buildAWSCredentialProcessOutput(map[string]string{
		"ACCESS_KEY_ID":     "AKIA1",
		"SECRET_ACCESS_KEY": "secret1",
		"SESSION_TOKEN":     "tok123",
	}, time.Now())
	if err != nil {
		t.Fatalf("buildAWSCredentialProcessOutput: %v", err)
	}
	data, _ := json.Marshal(out)
	if !strings.Contains(string(data), `"SessionToken":"tok123"`) {
		t.Errorf("expected SessionToken in output, got: %s", data)
	}
}

func TestBuildAWSCredentialProcessOutputMissingKeysErrors(t *testing.T) {
	if _, err := buildAWSCredentialProcessOutput(map[string]string{"ACCESS_KEY_ID": "AKIA1"}, time.Now()); err == nil {
		t.Fatal("expected an error for a profile missing SECRET_ACCESS_KEY")
	}
	if _, err := buildAWSCredentialProcessOutput(map[string]string{}, time.Now()); err == nil {
		t.Fatal("expected an error for an empty profile")
	}
}

func TestBuildAWSCredentialProcessOutputPassesExpirationThrough(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	out, err := buildAWSCredentialProcessOutput(map[string]string{
		"ACCESS_KEY_ID":     "AKIA1",
		"SECRET_ACCESS_KEY": "secret1",
		"SESSION_TOKEN":     "tok123",
		"EXPIRATION":        "2026-07-29T19:00:11Z",
	}, now)
	if err != nil {
		t.Fatalf("buildAWSCredentialProcessOutput: %v", err)
	}
	data, _ := json.Marshal(out)
	if !strings.Contains(string(data), `"Expiration":"2026-07-29T19:00:11Z"`) {
		t.Errorf("expected Expiration passed through, got: %s", data)
	}
}

func TestBuildAWSCredentialProcessOutputRefusesExpiredToken(t *testing.T) {
	now := time.Date(2026, 7, 29, 20, 0, 0, 0, time.UTC)
	_, err := buildAWSCredentialProcessOutput(map[string]string{
		"ACCESS_KEY_ID":     "AKIA1",
		"SECRET_ACCESS_KEY": "secret1",
		"SESSION_TOKEN":     "tok123",
		"EXPIRATION":        "2026-07-29T19:00:11Z",
	}, now)
	if err == nil {
		t.Fatal("expected an error for an expired token, got credentials")
	}
	// The error is the only channel telling the user what happened and
	// what to do — it must name the expiry time.
	if !strings.Contains(err.Error(), "2026-07-29T19:00:11Z") {
		t.Errorf("expected the expiry timestamp in the error, got: %v", err)
	}
}

func TestBuildAWSCredentialProcessOutputMalformedExpirationServed(t *testing.T) {
	// A stamp that isn't RFC3339 is passed through untouched rather than
	// blocking live credentials — the SDK's own complaint is clearer.
	out, err := buildAWSCredentialProcessOutput(map[string]string{
		"ACCESS_KEY_ID":     "AKIA1",
		"SECRET_ACCESS_KEY": "secret1",
		"EXPIRATION":        "not-a-timestamp",
	}, time.Now())
	if err != nil {
		t.Fatalf("buildAWSCredentialProcessOutput: %v", err)
	}
	if out.Expiration != "not-a-timestamp" {
		t.Errorf("Expiration = %q, want the malformed stamp passed through", out.Expiration)
	}
}
