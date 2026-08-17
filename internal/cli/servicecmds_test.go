// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// These are servicecmds.go's command-level tests: the whole command run
// through cobra, asserting on its exit status and output rather than on a
// helper's return value. Both cases here are the 2026-08-17 incident's
// second half — a command that reported success over a service that was
// never going to come up.

// TestRestartTimeoutIsAFailure is the incident's second half as a test: a
// reload that launchd accepts but never spawns must make `jit service
// restart` FAIL — non-zero exit, an audit record of failure — not print
// "still starting up" and exit 0 (which audited success: true over a broker
// that stayed dead 71 minutes).
func TestRestartTimeoutIsAFailure(t *testing.T) {
	shortFixtureHome(t)

	restoreWait := agentStartWait
	agentStartWait = 50 * time.Millisecond
	t.Cleanup(func() { agentStartWait = restoreWait })

	restore := launchctlRun
	t.Cleanup(func() { launchctlRun = restore })
	launchctlRun = func(args ...string) ([]byte, error) {
		if args[0] == "print" {
			// The incident's state: job registered, spawn pended forever.
			return []byte("runs = 0\nlast exit code = (never exited)"), nil
		}
		return nil, nil // bootout/bootstrap/kickstart all "succeed"
	}

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"service", "restart"})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("a restart whose service never came up must fail, got exit 0")
	}
	if !strings.Contains(err.Error(), "never started") || !strings.Contains(err.Error(), "runs 0") {
		t.Errorf("the error must carry launchd's diagnosis, got %q", err)
	}
}

// TestLockIsHonestWhenServiceDown: a not-running service holds no session,
// so `jit lock` reports the already-true state instead of sending the user
// on a restart errand to lock a session that doesn't exist.
func TestLockIsHonestWhenServiceDown(t *testing.T) {
	shortFixtureHome(t)

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"lock"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("lock against a dead service must succeed (the state is already true), got %v", err)
	}
	if !strings.Contains(buf.String(), "Already locked") {
		t.Errorf("want the honest already-locked line, got %q", buf.String())
	}
}
