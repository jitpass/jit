// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"context"
	"net"
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
	if !strings.Contains(out, "service  ● running · unlocked") {
		t.Errorf("expected an unlocked agent summary, got:\n%s", out)
	}
	// The in-test server runs in this same process, so its version matches
	// this binary's — matching versions collapse to one entry rather than
	// being printed twice, and the headline carries the verdict, not builds.
	wantVersions := "jit      ● all clear · " + shortVersion(agent.Version())
	if !strings.Contains(out, wantVersions) {
		t.Errorf("expected %q, got:\n%s", wantVersions, out)
	}
	if !strings.Contains(out, "mounts   1 registered mount · unlocked, all decoy (real values flow through a jit run grant, or an approved consent prompt") {
		t.Errorf("expected mounts reported as decoy while unlocked, with real values flowing via a jit run grant or an approved consent prompt, got:\n%s", out)
	}

	if err := client.Lock(); err != nil {
		t.Fatalf("Client.Lock: %v", err)
	}
	out, err = execStatus(t)
	if err != nil {
		t.Fatalf("jit status: %v", err)
	}
	if !strings.Contains(out, "service  ● running · locked") {
		t.Errorf("expected a locked agent summary, got:\n%s", out)
	}
	if !strings.Contains(out, "mounts   ○ 1 registered mount · serving decoy content only (service locked") {
		t.Errorf("expected mounts to be reported as still served (decoy-only) while locked, not fully unserved, GAPS.md #35, got:\n%s", out)
	}
}

// TestStatusDegradesWhenAgentUnreachable drives status against a socket that
// accepts a connection and then hangs up without replying — a hung agent, a
// half-written socket, a protocol mismatch mid-upgrade. That is NOT the
// "not running" case (nothing answers at all), so it used to abort the whole
// command with an error, taking the vault, secrets and mount sections down
// with it. A sick service is precisely when the overview is worth reading,
// so it degrades to one reported section instead.
func TestStatusDegradesWhenAgentUnreachable(t *testing.T) {
	home := shortFixtureHome(t)
	withFixtureCwd(t)

	root := filepath.Join(home, "Library", "Application Support", "jitpass")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	ln, err := net.Listen("unix", agent.SocketPath(root))
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close() // accept, then say nothing
		}
	}()

	plantVaultSecret(t, home, "aws/key1")

	out, err := execStatus(t)
	if err != nil {
		t.Fatalf("jit status must survive an unreachable agent, got: %v", err)
	}
	if !strings.Contains(out, "service  ✗ unreachable") {
		t.Errorf("expected the service reported as unreachable, got:\n%s", out)
	}
	// The sections that don't depend on the agent must still be there.
	if !strings.Contains(out, "vault    1 secret stored") || !strings.Contains(out, "secrets  1 stored in 1 group") {
		t.Errorf("expected the agent-independent sections to still render, got:\n%s", out)
	}
}
