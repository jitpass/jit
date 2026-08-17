// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
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
// bootstraps, then KICKSTARTS — and it recovers a launchd-dropped service:
// the bootout failing with "Could not find service" is expected and must not
// fail the reload, only the bootstrap result decides. The kickstart is the
// incident guard (2026-08-17): bootstrap only registers the job, and launchd
// can pend the RunAtLoad spawn forever ("pended nondemand spawn", runs=0);
// kickstart is the explicit demand. Guards against a future edit that drops
// the bootout, reorders the verbs, lets bootout's error abort — or drops the
// kickstart again the way 660ce2c did.
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
		return nil, nil // bootstrap and kickstart succeed
	}

	if out, err := reloadAgentService("/tmp/whatever.plist"); err != nil {
		t.Fatalf("reload must succeed when only bootout fails (dropped service): err=%v out=%q", err, out)
	}
	if len(calls) != 3 || calls[0][0] != "bootout" || calls[1][0] != "bootstrap" || calls[2][0] != "kickstart" {
		t.Fatalf("want bootout, bootstrap, kickstart, got %v", calls)
	}
	if calls[1][len(calls[1])-1] != "/tmp/whatever.plist" {
		t.Errorf("bootstrap must be handed the plist path, got %v", calls[1])
	}
	// Plain kickstart, never -k: -k would kill the process RunAtLoad may
	// already have spawned; the demand must only start, not restart.
	for _, a := range calls[2] {
		if a == "-k" {
			t.Errorf("reload's kickstart must not use -k, got %v", calls[2])
		}
	}
	if calls[2][len(calls[2])-1] != agentServiceTarget() {
		t.Errorf("kickstart must target the service, got %v", calls[2])
	}

	// A kickstart error must NOT fail the reload: in the healthy case
	// RunAtLoad already spawned the process and kickstart merely reports it
	// running.
	launchctlRun = func(args ...string) ([]byte, error) {
		if args[0] == "kickstart" {
			return []byte("already running"), errors.New("exit status 37")
		}
		return nil, nil
	}
	if _, err := reloadAgentService("/tmp/whatever.plist"); err != nil {
		t.Fatalf("a kickstart error must be ignored, got %v", err)
	}

	// And a non-transient bootstrap failure IS surfaced (a race error like EIO
	// would instead be retried — see TestReloadAgentServiceRetriesThroughBootoutRace),
	// with no kickstart after it: there is no registered job to demand.
	var kickstarts int
	launchctlRun = func(args ...string) ([]byte, error) {
		if args[0] == "kickstart" {
			kickstarts++
		}
		if args[0] == "bootstrap" {
			return []byte("Bootstrap failed: 112: Operation not permitted"), errors.New("exit status 112")
		}
		return nil, nil
	}
	if _, err := reloadAgentService("/tmp/whatever.plist"); err == nil {
		t.Fatal("a bootstrap failure must be returned, got nil")
	}
	if kickstarts != 0 {
		t.Errorf("no kickstart after a failed bootstrap, got %d", kickstarts)
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

	var bootstraps, bootouts int
	launchctlRun = func(args ...string) ([]byte, error) {
		if args[0] == "bootout" {
			bootouts++
			return nil, nil
		}
		if args[0] == "kickstart" {
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
	// The PAIR retries, not bootstrap alone: a bootout that genuinely failed
	// leaves every bootstrap answering "already bootstrapped" (a transient by
	// the classifier), and only a fresh bootout can ever clear it.
	if bootouts != 3 {
		t.Errorf("want the bootout re-run on every retry (3 total), got %d", bootouts)
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

// The shortened unlock wait is for LAUNCHES, which something else may be
// timing out. It briefly applied to every command, and `jit migrate` run from
// a script that captured its output gave up mid-migration after 20s with its
// owner sitting right there. Only jit run opts in.
func TestBoundedPromptWaitIsScopedToRun(t *testing.T) {
	if boundedPromptWait {
		t.Error("boundedPromptWait defaults to true; every non-launch command must keep the full window")
	}
	t.Cleanup(func() { boundedPromptWait = false })
	boundedPromptWait = true
	if !boundedPromptWait {
		t.Error("jit run must be able to opt in")
	}
}

// TestWaitForAgentBuild pins install/restart's success condition: "the
// service is now running the current binary" is decided by the answering
// process's own BuildID matching ours, not by a bare dial succeeding. The
// bare-dial version could declare success on the OLD process still draining
// its shutdown during a reload. (The wrong-build half is structural: the
// server answers OpStatus with agent.BuildID(), so a same-process test can
// only exercise the match and the give-up; the mismatch path is the same
// comparison.)
func TestWaitForAgentBuild(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "jit-wfb-") // short path: unix sockets cap at ~104 bytes
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })

	// Nothing listening: the wait gives up. The timeout is the caller's
	// (agentStartWait in production), so the test pays 300ms, not 5s.
	if waitForAgentBuild(root, 300*time.Millisecond) {
		t.Fatal("no agent is listening; the wait must give up")
	}

	server := agent.NewServer(agent.SocketPath(root), func() agent.MEKFetcher { return &fakeMEKFetcher{key: bytes.Repeat([]byte{1}, 32)} }, time.Minute)
	if err := server.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Serve(ctx) }()
	t.Cleanup(func() { _ = server.Close() })

	// This process serves OpStatus with its own BuildID, which is by
	// definition the caller's too — the wait must succeed, locked session
	// and all (status never challenges).
	if !waitForAgentBuild(root, 2*time.Second) {
		t.Fatal("an agent on this build answers; the wait must succeed")
	}
}
