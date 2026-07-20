// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/agent"
)

func execAgentStatus(t *testing.T, args ...string) (stdout string, err error) {
	t.Helper()
	agentStatusFormat = "text"
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetArgs(append([]string{"agent", "status"}, args...))
	err = rootCmd.Execute()
	return buf.String(), err
}

// TestAgentStatusFormatJSONNotRunning confirms GAPS.md #22's JSON snapshot
// for the common "not running" case is well-formed with running=false and
// no misleading unlocked/locks_in_seconds fields.
func TestAgentStatusFormatJSONNotRunning(t *testing.T) {
	shortFixtureHome(t)

	out, err := execAgentStatus(t, "--format", "json")
	if err != nil {
		t.Fatalf("jit agent status --format json: %v", err)
	}
	var result agentStatusResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshaling output %q: %v", out, err)
	}
	if result.Running || result.Unlocked || result.LocksInSeconds != 0 {
		t.Errorf("unexpected result: %+v", result)
	}
}

// TestAgentStatusFormatJSONRunningAndUnlocked drives the real agent RPC
// (not a mock), the same pattern TestStatusReflectsRealAgentRunningAndLocked
// uses, confirming the JSON snapshot reflects a genuinely unlocked session.
func TestAgentStatusFormatJSONRunningAndUnlocked(t *testing.T) {
	home := shortFixtureHome(t)

	root := filepath.Join(home, "Library", "Application Support", "jitpass")
	socketPath := agent.SocketPath(root)
	mek := bytes.Repeat([]byte{0x24}, 32)
	server := agent.NewServer(socketPath, func() agent.MEKFetcher { return &fakeMEKFetcher{key: mek} }, time.Minute)

	if err := server.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = server.Serve(ctx); close(done) }()
	defer func() { cancel(); _ = server.Close(); <-done }()

	client := agent.NewClient(socketPath)
	if _, _, err := client.Unlock(); err != nil {
		t.Fatalf("Client.Unlock: %v", err)
	}

	out, err := execAgentStatus(t, "--format", "json")
	if err != nil {
		t.Fatalf("jit agent status --format json: %v", err)
	}
	var result agentStatusResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshaling output %q: %v", out, err)
	}
	if !result.Running || !result.Unlocked || result.LocksInSeconds <= 0 {
		t.Errorf("unexpected result: %+v", result)
	}
}

func TestAgentStatusFormatRejectsUnknownValue(t *testing.T) {
	shortFixtureHome(t)

	_, err := execAgentStatus(t, "--format", "yaml")
	if err == nil {
		t.Fatal("expected an error for an unknown --format value, got nil")
	}
}

// TestServiceNotLoadedRecognizesLaunchctlMissingService pins the trigger for
// `jit agent restart`'s bootstrap fallback: only launchctl's "Could not find
// service" wording (case-insensitive) counts as "the plist exists but launchd
// dropped the service", the one kickstart failure a bootstrap recovers.
// Real launchctl output for exit 113 opens exactly this way.
func TestServiceNotLoadedRecognizesLaunchctlMissingService(t *testing.T) {
	cases := []struct {
		name   string
		output string
		want   bool
	}{
		{"exit-113 wording", `Could not find service "com.jitpass.agent" in domain for user gui: 502`, true},
		{"lowercased", "could not find service \"com.jitpass.agent\"", true},
		{"unrelated failure", "Bootstrap failed: 5: Input/output error", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := serviceNotLoaded([]byte(tc.output)); got != tc.want {
				t.Errorf("serviceNotLoaded(%q) = %v, want %v", tc.output, got, tc.want)
			}
		})
	}
}
