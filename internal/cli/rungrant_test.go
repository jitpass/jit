// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/agent"
)

// grantTestServer is a real agent.Server on a short socket with the
// challenge faked (fakeMEKFetcher approves instantly, no UI) and
// OnRevealPID recording what arrives — requestRunGrantVia's counterpart.
func grantTestServer(t *testing.T) (*agent.Server, *agent.Client, *atomic.Value) {
	t.Helper()
	// Under /tmp directly, not t.TempDir(): sockaddr_un caps the path at
	// ~104 bytes and these test names blow straight past it (same
	// convention as internal/agent's shortSocketPath).
	socketPath := filepath.Join("/tmp", fmt.Sprintf("jit-grant-test-%d-%d.sock", os.Getpid(), time.Now().UnixNano()))
	t.Cleanup(func() { _ = os.Remove(socketPath) })
	mek := bytes.Repeat([]byte{0x24}, 32)
	server := agent.NewServer(socketPath, func() agent.MEKFetcher { return &fakeMEKFetcher{key: mek} }, time.Minute)

	var recorded atomic.Value // stores struct{ paths []string; pid int32 }
	server.OnRevealPID = func(mountPaths []string, pid int32, swap bool) error {
		recorded.Store(struct {
			paths []string
			pid   int32
		}{mountPaths, pid})
		return nil
	}

	if err := server.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = server.Serve(ctx); close(done) }()
	t.Cleanup(func() { cancel(); _ = server.Close(); <-done })

	return server, agent.NewClient(socketPath), &recorded
}

func TestRequestRunGrantSendsLayerMountsAndOwnPID(t *testing.T) {
	_, c, recorded := grantTestServer(t)
	if _, _, err := c.Unlock(); err != nil { // session unlocked, as after jit run's own resolve
		t.Fatalf("Unlock: %v", err)
	}

	var out bytes.Buffer
	mounts := []string{"/tmp/fixture/.env", "/tmp/fixture/.env.local"}
	requestRunCompatVia(c, &out, mounts, 4242, true)

	got, ok := recorded.Load().(struct {
		paths []string
		pid   int32
	})
	if !ok {
		t.Fatal("OnRevealPID never fired for an unlocked session")
	}
	if len(got.paths) != 2 || got.paths[0] != mounts[0] || got.paths[1] != mounts[1] || got.pid != 4242 {
		t.Errorf("OnRevealPID got %v pid %d, want %v pid 4242", got.paths, got.pid, mounts)
	}
	if !strings.Contains(out.String(), ".env, .env.local serving real values to this run") {
		t.Errorf("announce = %q, want the mounts named", out.String())
	}
}

// TestRequestRunGrantNeverPromptsALockedSession is the no-surprise-Touch-ID
// guard: with the session locked, the grant request must stop at the
// status check — OnRevealPID firing here would mean an ensureUnlocked
// challenge was triggered by a request the user's command didn't need.
func TestRequestRunGrantNeverPromptsALockedSession(t *testing.T) {
	_, c, recorded := grantTestServer(t)

	var out bytes.Buffer
	requestRunCompatVia(c, &out, []string{"/tmp/fixture/.env"}, 4242, true)

	if recorded.Load() != nil {
		t.Error("OnRevealPID fired against a locked session — the guard must skip, never challenge")
	}
	if out.Len() != 0 {
		t.Errorf("announce = %q, want silence on skip", out.String())
	}
}

func TestRequestRunGrantSilentWhenAgentUnreachableOrRefusing(t *testing.T) {
	// Unreachable: a client dialed at a socket nothing listens on.
	dead := agent.NewClient(filepath.Join(t.TempDir(), "dead.sock"))
	var out bytes.Buffer
	requestRunCompatVia(dead, &out, []string{"/tmp/fixture/.env"}, 4242, true)
	if out.Len() != 0 {
		t.Errorf("announce = %q with no agent, want silence", out.String())
	}

	// Refusing: OnRevealPID errors (e.g. nothing real to serve) — the run
	// proceeds without a grant and without noise.
	server, c, _ := grantTestServer(t)
	server.OnRevealPID = func([]string, int32, bool) error {
		return errFixtureRefused
	}
	if _, _, err := c.Unlock(); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	out.Reset()
	requestRunCompatVia(c, &out, []string{"/tmp/fixture/.env"}, 4242, true)
	if out.Len() != 0 {
		t.Errorf("announce = %q after an agent refusal, want silence", out.String())
	}
}

type fixtureError string

func (e fixtureError) Error() string { return string(e) }

const errFixtureRefused fixtureError = "no grant created: fixture refusal"

func TestRequestRunCompatDefaultSwapsAndAutodetectsLive(t *testing.T) {
	// Default (live=false): a SwapForPID request must arrive.
	server, c, _ := grantTestServer(t)
	var swapPID atomic.Int32
	var live atomic.Bool
	live.Store(true) // will be flipped false when Swap arrives
	server.OnRevealPID = func(paths []string, pid int32, swap bool) error {
		swapPID.Store(pid)
		live.Store(!swap)
		return nil
	}
	if _, _, err := c.Unlock(); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	var out bytes.Buffer
	requestRunCompatVia(c, &out, []string{"/tmp/fixture/.env"}, 7777, false)
	if swapPID.Load() != 7777 || live.Load() {
		t.Errorf("default compat did not send a swap for the run pid (pid=%d live=%v)", swapPID.Load(), live.Load())
	}
	if !strings.Contains(out.String(), "compatibility file") {
		t.Errorf("announce = %q, want the compatibility-file phrasing", out.String())
	}
}

func TestCommandReadsEnvFileAutodetect(t *testing.T) {
	for _, tc := range []struct {
		argv []string
		want bool
	}{
		{[]string{"docker", "compose", "up"}, true},
		{[]string{"/usr/local/bin/docker-compose", "up"}, true},
		{[]string{"podman", "run"}, true},
		{[]string{"npm", "run", "dev"}, false},
		{[]string{"./run_all_exports.sh"}, false},
		{[]string{"python3", "app.py"}, false},
		{nil, false},
	} {
		if got := commandReadsEnvFile(tc.argv); got != tc.want {
			t.Errorf("commandReadsEnvFile(%v) = %v, want %v", tc.argv, got, tc.want)
		}
	}
}
