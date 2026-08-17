// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/agent"
)

// These are servicelaunchd.go's tests: everything that drives the
// launchctlRun seam. That seam is what makes this surface testable at all —
// the exec'd path it replaced was not — and it is why the 2026-08-17
// incident's exact launchd state (job loaded, runs 0, never spawned) can be
// reproduced here without a real launchd.

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

// fakeLaunchdPrint pins launchctlRun to a canned `launchctl print` answer
// (all other verbs succeed silently), so the advice-variant tests are
// deterministic regardless of the machine's real launchd state.
func fakeLaunchdPrint(t *testing.T, out string, err error) {
	t.Helper()
	restore := launchctlRun
	t.Cleanup(func() { launchctlRun = restore })
	launchctlRun = func(args ...string) ([]byte, error) {
		if args[0] == "print" {
			return []byte(out), err
		}
		return nil, nil
	}
}

// TestQueryLaunchdJobState pins the (deliberately confined) parse of
// launchctl print: the three states the health surfaces phrase advice from,
// and the read-failure case that must degrade to unknown rather than guess.
func TestQueryLaunchdJobState(t *testing.T) {
	t.Run("pended spawn: loaded, runs 0, never exited", func(t *testing.T) {
		fakeLaunchdPrint(t, "com.jitpass.agent = {\n\truns = 0\n\tlast exit code = (never exited)\n}", nil)
		st, known := queryLaunchdJobState()
		if !known || !st.loaded || st.runs != 0 || st.hasLastExit {
			t.Errorf("got %+v known=%v, want loaded runs=0 no-last-exit (the incident's exact state)", st, known)
		}
	})
	t.Run("ran and exited", func(t *testing.T) {
		fakeLaunchdPrint(t, "\truns = 3\n\tlast exit code = 78\n", nil)
		st, known := queryLaunchdJobState()
		if !known || !st.loaded || st.runs != 3 || !st.hasLastExit || st.lastExit != 78 {
			t.Errorf("got %+v known=%v, want loaded runs=3 lastExit=78", st, known)
		}
	})
	t.Run("job not loaded is a KNOWN answer", func(t *testing.T) {
		fakeLaunchdPrint(t, `Could not find service "com.jitpass.agent" in domain for user gui: 501`, errors.New("exit status 113"))
		st, known := queryLaunchdJobState()
		if !known || st.loaded {
			t.Errorf("got %+v known=%v, want known and not loaded", st, known)
		}
	})
	t.Run("any other failure is unknown, never a guess", func(t *testing.T) {
		fakeLaunchdPrint(t, "Bad request.", errors.New("exit status 5"))
		if _, known := queryLaunchdJobState(); known {
			t.Error("an unreadable state must report known=false")
		}
	})
}

// TestInstalledNotRunningPartsVariants pins each launchd state to its
// sentence — the vocabulary that replaced one "may have crashed or be
// mid-restart" for every state, which the 2026-08-17 incident showed being
// wrong on both halves (nothing crashed, nothing was mid-restart, and the
// advised restart couldn't work).
func TestInstalledNotRunningPartsVariants(t *testing.T) {
	cases := []struct {
		name, print string
		printErr    error
		wantDetail  string
	}{
		{"never started", "runs = 0\nlast exit code = (never exited)", nil,
			"the service is installed and launchd accepted it, but never started it."},
		{"stopped", "runs = 2\nlast exit code = 1", nil,
			"the service stopped (last exit code 1) and launchd has not brought it back."},
		{"dropped", `Could not find service "x"`, errors.New("exit status 113"),
			"the service is installed but launchd has dropped it."},
		{"unknown", "Bad request.", errors.New("exit status 5"),
			"the service is installed but not running."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fakeLaunchdPrint(t, tc.print, tc.printErr)
			detail, action := installedNotRunningParts("the service")
			if detail != tc.wantDetail {
				t.Errorf("detail = %q, want %q", detail, tc.wantDetail)
			}
			if !strings.Contains(action, "`jit service restart`") || !strings.Contains(action, "`jit service log`") {
				t.Errorf("action must carry the restart and the log command, got %q", action)
			}
		})
	}
}
