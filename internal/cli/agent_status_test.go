// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	rootCmd.SetArgs(append([]string{"service", "status"}, args...))
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

// TestReloadAgentServiceBootoutThenBootstrap pins reloadAgentService's
// recovery contract (the launchctl seam is what makes this testable at all,
// which the old exec'd path was not): it ALWAYS boots out first, then
// bootstraps, and it recovers a launchd-dropped service — the bootout
// failing with "Could not find service" is expected and must not fail the
// reload, only the bootstrap result decides. Guards against a future edit
// that drops the bootout, reorders the two, or lets bootout's error abort.
func TestReloadAgentServiceBootoutThenBootstrap(t *testing.T) {
	var calls [][]string
	restore := launchctlRun
	t.Cleanup(func() { launchctlRun = restore })

	launchctlRun = func(args ...string) ([]byte, error) {
		calls = append(calls, args)
		if args[0] == "bootout" {
			// The dropped-service case: launchd has no record to boot out.
			return []byte(`Could not find service "com.jitpass.agent" in domain for user gui: 502`), errors.New("exit status 113")
		}
		return nil, nil // bootstrap succeeds
	}

	if out, err := reloadAgentService("/tmp/whatever.plist"); err != nil {
		t.Fatalf("reload must succeed when only bootout fails (dropped service): err=%v out=%q", err, out)
	}
	if len(calls) != 2 || calls[0][0] != "bootout" || calls[1][0] != "bootstrap" {
		t.Fatalf("want bootout then bootstrap, got %v", calls)
	}
	if calls[1][len(calls[1])-1] != "/tmp/whatever.plist" {
		t.Errorf("bootstrap must be handed the plist path, got %v", calls[1])
	}

	// And a non-transient bootstrap failure IS surfaced (a race error like EIO
	// would instead be retried — see TestReloadAgentServiceRetriesThroughBootoutRace).
	launchctlRun = func(args ...string) ([]byte, error) {
		if args[0] == "bootstrap" {
			return []byte("Bootstrap failed: 112: Operation not permitted"), errors.New("exit status 112")
		}
		return nil, nil
	}
	if _, err := reloadAgentService("/tmp/whatever.plist"); err == nil {
		t.Fatal("a bootstrap failure must be returned, got nil")
	}
}

// TestReloadAgentServiceRetriesThroughBootoutRace pins the fix for a race
// found running on real launchd: bootout returns before the old service is
// fully torn down, and a bootstrap landing in that window fails with EIO
// ("Input/output error"). reloadAgentService must retry through it, but must
// NOT retry a genuine (non-race) bootstrap failure.
func TestReloadAgentServiceRetriesThroughBootoutRace(t *testing.T) {
	restore := launchctlRun
	t.Cleanup(func() { launchctlRun = restore })

	var bootstraps int
	launchctlRun = func(args ...string) ([]byte, error) {
		if args[0] == "bootout" {
			return nil, nil
		}
		bootstraps++
		if bootstraps < 3 { // launchd still tearing the old service down
			return []byte("Bootstrap failed: 5: Input/output error"), errors.New("exit status 5")
		}
		return nil, nil
	}
	if _, err := reloadAgentService("/tmp/x.plist"); err != nil {
		t.Fatalf("reload must retry through the EIO race and succeed, got %v", err)
	}
	if bootstraps != 3 {
		t.Errorf("want 3 bootstrap attempts (2 EIO + 1 success), got %d", bootstraps)
	}

	// A non-transient bootstrap error returns immediately, no retry.
	bootstraps = 0
	launchctlRun = func(args ...string) ([]byte, error) {
		if args[0] == "bootstrap" {
			bootstraps++
			return []byte("Bootstrap failed: 112: some permanent problem"), errors.New("exit status 112")
		}
		return nil, nil
	}
	if _, err := reloadAgentService("/tmp/x.plist"); err == nil {
		t.Fatal("a non-race bootstrap error must be returned")
	}
	if bootstraps != 1 {
		t.Errorf("a non-race error must not be retried, got %d attempts", bootstraps)
	}
}
