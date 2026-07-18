// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"strings"
	"testing"
)

func TestBuildSOPSAgeKeyOutput(t *testing.T) {
	key := "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"

	got, err := buildSOPSAgeKeyOutput(map[string]string{"SOPS_AGE_KEY": key})
	if err != nil {
		t.Fatalf("buildSOPSAgeKeyOutput: %v", err)
	}
	if got != key {
		t.Errorf("output = %q, want the bare key", got)
	}
}

func TestBuildSOPSAgeKeyOutputTrimsWhitespace(t *testing.T) {
	key := "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"

	// A vault value that picked up a trailing newline somewhere must not
	// leak it into stdout twice — sops parses stdout as key material.
	got, err := buildSOPSAgeKeyOutput(map[string]string{"SOPS_AGE_KEY": key + "\n"})
	if err != nil {
		t.Fatalf("buildSOPSAgeKeyOutput: %v", err)
	}
	if got != key {
		t.Errorf("output = %q, want the trimmed key", got)
	}
}

func TestBuildSOPSAgeKeyOutputMissingEntry(t *testing.T) {
	if _, err := buildSOPSAgeKeyOutput(map[string]string{}); err == nil {
		t.Fatal("want an error for a profile with no SOPS_AGE_KEY entry")
	}
}

func TestBuildSOPSAgeKeyOutputRejectsNonKeyMaterial(t *testing.T) {
	_, err := buildSOPSAgeKeyOutput(map[string]string{"SOPS_AGE_KEY": "hunter2"})
	if err == nil || !strings.Contains(err.Error(), "not an age secret key") {
		t.Fatalf("err = %v, want the non-key rejection", err)
	}
}
