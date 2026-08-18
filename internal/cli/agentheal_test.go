// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/auditlog"
)

// These are healDeadService's tests: the client-side demand that revives an
// installed-but-not-running service on the first command that needs it,
// instead of failing with restart advice (design/service-reliability.md's
// addendum; the 2026-08-17 pended-spawn incident is why the demand exists).
// The launchctlRun seam plays launchd; a real agent.Server on a real socket
// plays the spawn it grants.

// healFixture installs the preconditions the heal keys on: a temp HOME, the
// launchd plist marker (agentInstalled must answer true), the vault root
// dir, and a fresh once-guard so tests don't observe each other's heal.
func healFixture(t *testing.T) (home, root string) {
	t.Helper()
	home = shortFixtureHome(t)
	plistDir := filepath.Join(home, "Library", "LaunchAgents")
	if err := os.MkdirAll(plistDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(plistDir, agentPlistLabel+".plist"), []byte("<plist/>"), 0o600); err != nil {
		t.Fatalf("writing plist marker: %v", err)
	}
	root = filepath.Join(home, "Library", "Application Support", "jitpass")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	agentHealOnce = sync.Once{}
	t.Cleanup(func() { agentHealOnce = sync.Once{} })
	return home, root
}

// TestAgentClientHealsDeadService is the whole feature end to end: the
// socket is dead, the plist is installed, and the SAME invocation that
// found it dead succeeds — one plain kickstart (never -k), the spawn it
// grants answered within the extended window, and the heal left its
// evidence in the application audit log rather than hiding the incident.
func TestAgentClientHealsDeadService(t *testing.T) {
	_, root := healFixture(t)

	mek := bytes.Repeat([]byte{0x24}, 32)
	ctx, cancel := context.WithCancel(context.Background())
	var server *agent.Server
	done := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		if server != nil {
			_ = server.Close()
			<-done
		}
	})

	var calls [][]string
	restore := launchctlRun
	t.Cleanup(func() { launchctlRun = restore })
	launchctlRun = func(args ...string) ([]byte, error) {
		calls = append(calls, args)
		if args[0] == "kickstart" {
			// launchd honoring the demand: the service comes up.
			server = agent.NewServer(agent.SocketPath(root), func() agent.MEKFetcher { return &fakeMEKFetcher{key: mek} }, time.Minute)
			if err := server.Listen(); err != nil {
				t.Errorf("Listen: %v", err)
			}
			go func() { _ = server.Serve(ctx); close(done) }()
		}
		return nil, nil
	}

	c, err := agentClient()
	if err != nil {
		t.Fatalf("agentClient: %v", err)
	}
	if _, err := c.Status(); err != nil {
		t.Fatalf("Status must succeed on the healing invocation itself, got: %v", err)
	}

	if len(calls) != 1 || calls[0][0] != "kickstart" {
		t.Fatalf("want exactly one kickstart, got %v", calls)
	}
	for _, a := range calls[0] {
		// -k would kill a process launchd may have just spawned; the heal
		// only ever starts, never restarts.
		if a == "-k" {
			t.Fatalf("heal kickstart must not use -k: %v", calls[0])
		}
	}
	if calls[0][len(calls[0])-1] != agentServiceTarget() {
		t.Errorf("kickstart must target the service, got %v", calls[0])
	}

	var healed bool
	for _, r := range auditlog.New(root, io.Discard).Load(0) {
		if r.Command == "jit service heal" {
			healed = true
		}
	}
	if !healed {
		t.Error("the heal must leave a 'jit service heal' record in the audit log")
	}
}

// TestHealDeadServiceOnceAndFailureAddsNothing: a kickstart launchd refuses
// (a dropped job) grants no extra wait — the command falls through to the
// existing advice — and the demand is one per process, not one per dial.
func TestHealDeadServiceOnceAndFailureAddsNothing(t *testing.T) {
	_, root := healFixture(t)

	var calls int
	restore := launchctlRun
	t.Cleanup(func() { launchctlRun = restore })
	launchctlRun = func(args ...string) ([]byte, error) {
		calls++
		return []byte(`Could not find service "com.jitpass.agent" in domain for user gui: 502`), errors.New("exit status 113")
	}

	if w := healDeadService(); w != 0 {
		t.Fatalf("a refused kickstart must grant no extra window, got %s", w)
	}
	if w := healDeadService(); w != 0 {
		t.Fatalf("second call must be a no-op, got %s", w)
	}
	if calls != 1 {
		t.Fatalf("want exactly one launchctl call across repeated heals, got %d", calls)
	}
	for _, r := range auditlog.New(root, io.Discard).Load(0) {
		if r.Command == "jit service heal" {
			t.Error("a failed demand must not be recorded as a heal")
		}
	}
}

// TestReportersAndReducersNeverHeal pins the needs-vs-probes line: the
// health reporter (`jit service status`) and the session reducer (`jit
// lock`) keep telling the truth about a dead service instead of quietly
// reviving it, and the prompt-free shim probe (SessionUnlocked) spawns
// nothing on a Tab press.
func TestReportersAndReducersNeverHeal(t *testing.T) {
	healFixture(t)

	var kickstarts int
	restore := launchctlRun
	t.Cleanup(func() { launchctlRun = restore })
	launchctlRun = func(args ...string) ([]byte, error) {
		if args[0] == "kickstart" {
			kickstarts++
		}
		// queryLaunchdJobState's "print" lands here too: a definitively
		// not-loaded job, so the advice paths have a state to phrase.
		return []byte(`Could not find service "com.jitpass.agent" in domain for user gui: 502`), errors.New("exit status 113")
	}

	if SessionUnlocked() {
		t.Fatal("SessionUnlocked must answer false against a dead socket")
	}

	agentStatusFormat = "text"
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs([]string{"service", "status"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("jit service status: %v", err)
	}

	out.Reset()
	rootCmd.SetArgs([]string{"lock"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("jit lock: %v", err)
	}
	if got := out.String(); !bytes.Contains([]byte(got), []byte("Already locked")) {
		t.Errorf("jit lock against a dead service must stay honest, got %q", got)
	}

	if kickstarts != 0 {
		t.Fatalf("reporters/reducers issued %d kickstarts, want 0", kickstarts)
	}
}
