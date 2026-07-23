// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestConfiguredAgentTTLReadsPlist pins that `jit service ttl` (show) reports
// the TTL actually baked into the login item, and reports "not set up" rather
// than a misleading zero when there is no plist. This is what replaced the old
// `jit service install --ttl`, so the value has to round-trip through the same
// plist the service runs from.
func TestConfiguredAgentTTLReadsPlist(t *testing.T) {
	home := shortFixtureHome(t)

	if ttl, ok := configuredAgentTTL(); ok {
		t.Fatalf("configuredAgentTTL = %v, true with no plist installed; want ok=false", ttl)
	}

	dir := filepath.Join(home, "Library", "LaunchAgents")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// A plist with a non-default --ttl and no consent arg at all (the 4th slot):
	// this is what a pre-consent install looks like, and it must read as the
	// default — consent ON.
	plist := fmt.Sprintf(agentPlistTemplate, agentPlistLabel, "/usr/local/bin/jit", (12 * time.Minute).String(), "", "/x/agent.log", "/x/agent.log")
	if err := os.WriteFile(filepath.Join(dir, agentPlistLabel+".plist"), []byte(plist), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, ok := configuredAgentTTL()
	if !ok || got != 12*time.Minute {
		t.Fatalf("configuredAgentTTL = %v, %v; want 12m0s, true", got, ok)
	}
	if !configuredAgentConsent() {
		t.Error("configuredAgentConsent = false for a plist with no consent arg; want the default (on)")
	}
}

// TestConfiguredAgentConsentReadsPlist covers how consent state round-trips
// through ProgramArguments: `--consent` (or none) -> on by default, an explicit
// `--consent=false` -> off.
func TestConfiguredAgentConsentReadsPlist(t *testing.T) {
	home := shortFixtureHome(t)
	dir := filepath.Join(home, "Library", "LaunchAgents")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	plistPath := filepath.Join(dir, agentPlistLabel+".plist")

	// consent on: the 4th slot is the --consent element.
	on := fmt.Sprintf(agentPlistTemplate, agentPlistLabel, "/usr/local/bin/jit", (5 * time.Minute).String(), "\n\t\t<string>--consent</string>", "/x/agent.log", "/x/agent.log")
	if err := os.WriteFile(plistPath, []byte(on), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if !configuredAgentConsent() {
		t.Error("configuredAgentConsent = false for a plist with --consent")
	}

	// consent explicitly off: the 4th slot carries --consent=false.
	off := fmt.Sprintf(agentPlistTemplate, agentPlistLabel, "/usr/local/bin/jit", (5 * time.Minute).String(), "\n\t\t<string>--consent=false</string>", "/x/agent.log", "/x/agent.log")
	if err := os.WriteFile(plistPath, []byte(off), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if configuredAgentConsent() {
		t.Error("configuredAgentConsent = true for a plist with --consent=false; want off")
	}
}

// TestPlistStringValuesInOrder covers the tiny extractor configuredAgentTTL
// relies on: it must return every <string> element in document order, so the
// value right after "--ttl" is the TTL and not some other argument.
func TestPlistStringValuesInOrder(t *testing.T) {
	data := []byte("<array><string>/bin/jit</string><string>service</string><string>run</string><string>--ttl</string><string>5m0s</string></array>")
	got := plistStringValues(data)
	want := []string{"/bin/jit", "service", "run", "--ttl", "5m0s"}
	if len(got) != len(want) {
		t.Fatalf("plistStringValues = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("plistStringValues[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
