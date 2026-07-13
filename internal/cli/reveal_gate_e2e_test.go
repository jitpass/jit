// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

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
	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

// startRevealFixture wires the same Server/mountManager/Serve stack the other
// e2e tests here use (see TestDecoyGateEndToEnd), then — in exactly real
// jit migrate's ordering — calls seedSecrets (if non-nil) to write vault
// secrets through the server's own session FIRST, registers the mount
// AFTER, and finishes with an explicit Refresh. Registering before the
// secrets exist would let the Set-triggered OnUnlock resolve-and-fail the
// mount prematurely — the exact hazard TestDecoyGateEndToEnd's own
// comment documents.
func startRevealFixture(t *testing.T, root, profilePath, mountPath string, seedSecrets func(v *vault.Vault)) *agent.Client {
	t.Helper()

	if err := mount.CreateFIFO(mountPath); err != nil {
		t.Fatalf("CreateFIFO: %v", err)
	}

	// os.MkdirTemp, not t.TempDir(): a long test name pushes a t.TempDir()-
	// based socket path past macOS's ~104-byte sockaddr_un limit ("bind:
	// invalid argument") — same constraint as internal/agent's
	// shortSocketPath convention.
	sockDir, err := os.MkdirTemp("", "jit")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	socketPath := filepath.Join(sockDir, "a.sock")

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
	t.Cleanup(func() { cancel(); _ = server.Close(); <-done })

	if seedSecrets != nil {
		// RecipientID must match what mountManager.start() itself computes
		// (os.Hostname()) — it builds its own *vault.Vault internally.
		hostname, err := os.Hostname()
		if err != nil {
			t.Fatalf("os.Hostname: %v", err)
		}
		seedSecrets(&vault.Vault{Root: root, KeyWrapper: server, RecipientID: hostname})
	}

	if err := mount.AddMount(mount.RegistryPath(root), mount.Entry{MountPath: mountPath, ProfilePath: profilePath}); err != nil {
		t.Fatalf("AddMount: %v", err)
	}
	client := agent.NewClient(socketPath)
	if err := client.Refresh(); err != nil {
		t.Fatalf("Client.Refresh: %v", err)
	}
	waitForMountServing(t, mounts, mountPath)
	return client
}

// TestRevealWindowNaturalExpiryEndToEnd crosses the reveal-window expiry
// boundary through the real RPC/mount stack — the one transition
// TestDecoyGateEndToEnd doesn't cover (it hides explicitly). Expiry is
// lazy (nothing fires at the moment the window ends; the next reader
// connection re-decides), so this is the regression test for "real
// content within the window, decoy after it, status flips to hidden and
// reports when the window ended" (GAPS.md #48).
func TestRevealWindowNaturalExpiryEndToEnd(t *testing.T) {
	root := t.TempDir()
	profilePath := filepath.Join(root, "fixture-profile.yaml")
	writeYAML(t, profilePath, profile.Profile{"API_KEY": "fixture/API_KEY"})
	mountPath := filepath.Join(t.TempDir(), ".env")

	client := startRevealFixture(t, root, profilePath, mountPath, func(v *vault.Vault) {
		if err := v.Set("fixture/API_KEY", []byte("sk_live_REAL_SECRET")); err != nil {
			t.Fatalf("vault Set: %v", err)
		}
	})

	// `jit agent reveal <path> --for 2s`, over the real wire.
	if err := client.Reveal(mountPath, 2*time.Second); err != nil {
		t.Fatalf("Client.Reveal: %v", err)
	}

	got := readMountOnceWithTimeout(t, mountPath, 2*time.Second)
	if !bytes.Contains(got, []byte("sk_live_REAL_SECRET")) {
		t.Errorf("within the reveal window, mount = %q, want the real secret", got)
	}

	time.Sleep(2300 * time.Millisecond) // cross the expiry boundary

	got = readMountOnceWithTimeout(t, mountPath, 2*time.Second)
	if bytes.Contains(got, []byte("sk_live_REAL_SECRET")) {
		t.Errorf("after reveal expiry, mount still served the real secret: %q", got)
	}
	if !bytes.Contains(got, []byte("jit-hidden-API_KEY")) {
		t.Errorf("after reveal expiry, mount = %q, want decoy content", got)
	}

	_, _, mountStatuses, _, err := client.Status()
	if err != nil {
		t.Fatalf("Client.Status: %v", err)
	}
	found := false
	for _, ms := range mountStatuses {
		if ms.Path != mountPath {
			continue
		}
		found = true
		if ms.Revealed {
			t.Errorf("status still reports revealed (%ds remaining) after expiry", ms.RevealedForSeconds)
		}
		if ms.RevealEndedUnix == 0 {
			t.Error("status reports no RevealEndedUnix after a window expired — 'the timer ended' stays invisible (GAPS.md #48)")
		} else if since := time.Since(time.Unix(ms.RevealEndedUnix, 0)); since < 0 || since > time.Minute {
			t.Errorf("RevealEndedUnix says the window ended %v ago, want just now", since)
		}
	}
	if !found {
		t.Fatalf("Client.Status didn't include %s at all, got %+v", mountPath, mountStatuses)
	}
}

// TestRevealRefusedWhenNothingRealToServe is GAPS.md #46's regression test:
// a mount whose profile references a secret that does NOT exist in the
// vault can never serve real content, so an explicit reveal must FAIL with
// the resolve error in the message — it used to report "Revealed ... for
// 5m0s" and show a live status countdown while every read kept serving
// decoys, the failure visible only in the agent's own log file.
func TestRevealRefusedWhenNothingRealToServe(t *testing.T) {
	root := t.TempDir()
	profilePath := filepath.Join(root, "fixture-profile.yaml")
	writeYAML(t, profilePath, profile.Profile{"API_KEY": "fixture/MISSING_SECRET"})
	mountPath := filepath.Join(t.TempDir(), ".env")

	client := startRevealFixture(t, root, profilePath, mountPath, nil)

	err := client.Reveal(mountPath, 5*time.Minute)
	if err == nil {
		t.Fatal("Client.Reveal succeeded on a mount with nothing real to serve — 'Revealed for 5m0s' with every read still a decoy is exactly the silent failure GAPS.md #46 records")
	}
	if !strings.Contains(err.Error(), "nothing real to serve") {
		t.Errorf("Reveal error = %q, want it to say the mount has nothing real to serve", err)
	}
	if !strings.Contains(err.Error(), "MISSING_SECRET") {
		t.Errorf("Reveal error = %q, want the underlying resolve failure (mentioning MISSING_SECRET) included, not just a generic refusal", err)
	}

	// The refusal must leave the mount hidden — no countdown in status.
	_, _, mountStatuses, _, statusErr := client.Status()
	if statusErr != nil {
		t.Fatalf("Client.Status: %v", statusErr)
	}
	for _, ms := range mountStatuses {
		if ms.Path == mountPath && ms.Revealed {
			t.Errorf("status reports the mount revealed (%ds remaining) after a refused reveal", ms.RevealedForSeconds)
		}
	}

	// And reads keep resolving instantly to decoy, never hanging.
	got := readMountOnceWithTimeout(t, mountPath, 2*time.Second)
	if !bytes.Contains(got, []byte("jit-hidden-API_KEY")) {
		t.Errorf("mount = %q, want decoy content", got)
	}
}
