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
	// Exactly the plist installAgentService writes, with a non-default --ttl.
	plist := fmt.Sprintf(agentPlistTemplate, agentPlistLabel, "/usr/local/bin/jit", (12 * time.Minute).String(), "/x/agent.log", "/x/agent.log")
	if err := os.WriteFile(filepath.Join(dir, agentPlistLabel+".plist"), []byte(plist), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, ok := configuredAgentTTL()
	if !ok || got != 12*time.Minute {
		t.Fatalf("configuredAgentTTL = %v, %v; want 12m0s, true", got, ok)
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
