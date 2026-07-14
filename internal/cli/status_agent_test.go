// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/mount"
)

// shortFixtureHome behaves like withFixtureHome but under /tmp directly
// instead of t.TempDir() — a real agent socket lives at
// $HOME/Library/Application Support/jitpass/agent.sock, and t.TempDir()'s
// test-name-based nesting easily pushes that past macOS's ~104-byte
// sockaddr_un limit (the same reason internal/agent's own tests use
// shortSocketPath instead of t.TempDir() for socket paths directly).
func shortFixtureHome(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "jit-status-test-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	original, wasSet := os.LookupEnv("HOME")
	if err := os.Setenv("HOME", dir); err != nil {
		t.Fatalf("os.Setenv(HOME): %v", err)
	}
	t.Cleanup(func() {
		if wasSet {
			_ = os.Setenv("HOME", original)
		} else {
			_ = os.Unsetenv("HOME")
		}
	})
	return dir
}

// TestStatusReflectsRealAgentRunningAndLocked drives jit status against a
// real agent.Server/Client (not a mock), the same pattern
// TestDecoyGateEndToEnd uses — confirming printAgentStatus's "running and
// unlocked"/"running and locked" branches actually work against the real
// RPC, not just a stubbed Reachable()/Status(). Also confirms GAPS.md
// #35's status wording: a mount is reported as served (decoy content)
// even while the agent is locked, never "not being served" — only
// ServingReal (real content potentially available) turns off on lock.
func TestStatusReflectsRealAgentRunningAndLocked(t *testing.T) {
	home := shortFixtureHome(t)
	withFixtureCwd(t)

	root := filepath.Join(home, "Library", "Application Support", "jitpass")
	socketPath := agent.SocketPath(root)
	mek := bytes.Repeat([]byte{0x24}, 32)
	server := agent.NewServer(socketPath, func() agent.MEKFetcher { return &fakeMEKFetcher{key: mek} }, time.Minute)

	var stdout, stderr bytes.Buffer
	mounts := &mountManager{root: root, keyWrapper: server, stdout: &stdout, stderr: &stderr}
	server.OnUnlock = mounts.start
	server.OnLock = mounts.stop
	server.OnRefresh = mounts.start
	server.OnReveal = mounts.revealMount
	server.OnMountStatus = mounts.mountRevealStatuses

	if err := server.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = server.Serve(ctx); close(done) }()
	defer func() { cancel(); _ = server.Close(); <-done }()

	if err := mount.AddMount(mount.RegistryPath(root), mount.Entry{MountPath: "/tmp/fixture/.env", ProfilePath: "/tmp/fixture/profile.yaml"}); err != nil {
		t.Fatalf("AddMount: %v", err)
	}

	client := agent.NewClient(socketPath)
	if _, _, err := client.Unlock(); err != nil {
		t.Fatalf("Client.Unlock: %v", err)
	}

	out, err := execStatus(t)
	if err != nil {
		t.Fatalf("jit status: %v", err)
	}
	if !strings.Contains(out, "Agent: running and unlocked") {
		t.Errorf("expected an unlocked agent summary, got:\n%s", out)
	}
	if !strings.Contains(out, "Mounts: 1 registered, agent unlocked — real content available") {
		t.Errorf("expected mounts to be reported as serving real content while unlocked, got:\n%s", out)
	}

	if err := client.Lock(); err != nil {
		t.Fatalf("Client.Lock: %v", err)
	}
	out, err = execStatus(t)
	if err != nil {
		t.Fatalf("jit status: %v", err)
	}
	if !strings.Contains(out, "Agent: running and locked.") {
		t.Errorf("expected a locked agent summary, got:\n%s", out)
	}
	if !strings.Contains(out, "Mounts: 1 registered, serving decoy content only (agent locked") {
		t.Errorf("expected mounts to be reported as still served (decoy-only) while locked, not fully unserved — GAPS.md #35, got:\n%s", out)
	}
}
