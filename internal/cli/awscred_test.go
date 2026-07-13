// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildAWSCredentialProcessOutputShape(t *testing.T) {
	out, err := buildAWSCredentialProcessOutput(map[string]string{
		"ACCESS_KEY_ID":     "AKIAIOSFODNN7EXAMPLE",
		"SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	})
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
	if !strings.Contains(got, `"Version":1`) {
		t.Errorf("expected Version:1 in output, got: %s", got)
	}
}

func TestBuildAWSCredentialProcessOutputIncludesSessionToken(t *testing.T) {
	out, err := buildAWSCredentialProcessOutput(map[string]string{
		"ACCESS_KEY_ID":     "AKIA1",
		"SECRET_ACCESS_KEY": "secret1",
		"SESSION_TOKEN":     "tok123",
	})
	if err != nil {
		t.Fatalf("buildAWSCredentialProcessOutput: %v", err)
	}
	data, _ := json.Marshal(out)
	if !strings.Contains(string(data), `"SessionToken":"tok123"`) {
		t.Errorf("expected SessionToken in output, got: %s", data)
	}
}

func TestBuildAWSCredentialProcessOutputMissingKeysErrors(t *testing.T) {
	if _, err := buildAWSCredentialProcessOutput(map[string]string{"ACCESS_KEY_ID": "AKIA1"}); err == nil {
		t.Fatal("expected an error for a profile missing SECRET_ACCESS_KEY")
	}
	if _, err := buildAWSCredentialProcessOutput(map[string]string{}); err == nil {
		t.Fatal("expected an error for an empty profile")
	}
}
