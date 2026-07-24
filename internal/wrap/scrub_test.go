// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package wrap

import (
	"os"
	"strings"
	"testing"
)

func TestScrubTokenRemovesOnlyTheTokenLines(t *testing.T) {
	gh, _ := Lookup("gh")
	src := gh.Sources[0]
	home := fixtureHomeFor(t, src, "gh/hosts.yml")
	token := "gho_FIXTUREtoken1234567890abcdefFIXTURE"

	if err := ScrubToken(home, src, token); err != nil {
		t.Fatalf("ScrubToken: %v", err)
	}
	data, err := os.ReadFile(ExpandHome(home, src.Path))
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	// The fixture carries the token twice (gh writes it under users.<name>
	// and at host level); one ScrubToken call removes one line — the wrap
	// flow extracts and scrubs per selector, and the host-level line the
	// selector names must be gone.
	if strings.Count(got, token) != 1 || !strings.Contains(got, "users:") {
		t.Errorf("scrub removed the wrong thing:\n%s", got)
	}
	if !strings.Contains(got, "git_protocol: https") || !strings.Contains(got, "user: alex") {
		t.Errorf("non-secret settings damaged:\n%s", got)
	}
}

func TestScrubTokenRawEmptiesTheTokenFile(t *testing.T) {
	hf, _ := Lookup("hf")
	src := hf.Sources[0]
	home := fixtureHomeFor(t, src, "hf/token")
	token := "hf_FIXTUREtoken0123456789abcdefFIXTURE"

	if err := ScrubToken(home, src, token); err != nil {
		t.Fatalf("ScrubToken: %v", err)
	}
	data, err := os.ReadFile(ExpandHome(home, src.Path))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data)) != "" {
		t.Errorf("raw scrub left content behind: %q", string(data))
	}
}

func TestScrubTokenRawRefusesWhenValueMoved(t *testing.T) {
	hf, _ := Lookup("hf")
	src := hf.Sources[0]
	home := fixtureHomeFor(t, src, "hf/token")

	if err := ScrubToken(home, src, "hf_aTokenTheFileNoLongerHolds"); err == nil {
		t.Fatal("expected ScrubToken to refuse when the raw file no longer holds the extracted token")
	}
	data, _ := os.ReadFile(ExpandHome(home, src.Path))
	if !strings.Contains(string(data), "hf_FIXTUREtoken") {
		t.Error("file was modified despite the refusal")
	}
}

func TestScrubTokenRefusesWhenValueMoved(t *testing.T) {
	gh, _ := Lookup("gh")
	src := gh.Sources[0]
	home := fixtureHomeFor(t, src, "gh/hosts.yml")

	if err := ScrubToken(home, src, "a-token-that-is-not-in-the-file"); err == nil {
		t.Fatal("expected ScrubToken to refuse when the extracted value isn't in the file anymore")
	}
	data, _ := os.ReadFile(ExpandHome(home, src.Path))
	if !strings.Contains(string(data), "gho_FIXTUREtoken") {
		t.Error("file was modified despite the refusal")
	}
}
