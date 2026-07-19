// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

// TestRunScopedGrantEndToEnd drives the whole grant mechanism through the
// real agent.Server/Client/mountManager/mount.Serve/internal-lineage code
// paths with REAL process trees — the fixture-level equivalent of the
// manual pass (jit run against a live agent) that can't be scripted
// because it needs a real Touch ID approval. Asserts the four behaviors
// the spike promised:
//
//  1. a reader inside the granted tree gets REAL content while the mount
//     is hidden (no reveal window);
//  2. a sibling process outside the tree gets decoys at the same moment;
//  3. Client.Status reports the live grant;
//  4. the grant dies with the target (NOTE_EXIT), after which reads are
//     decoys again and status shows no grant.
func TestRunScopedGrantEndToEnd(t *testing.T) {
	root := t.TempDir()

	profilePath := filepath.Join(root, "fixture-profile.yaml")
	writeYAML(t, profilePath, profile.Profile{"API_KEY": "fixture/API_KEY"})

	mountDir := t.TempDir()
	mountPath := filepath.Join(mountDir, ".env")
	if err := mount.CreateFIFO(mountPath); err != nil {
		t.Fatalf("CreateFIFO: %v", err)
	}

	socketPath := filepath.Join(t.TempDir(), "a.sock") // short path, sockaddr_un limit
	mek := bytes.Repeat([]byte{0x24}, 32)
	server := agent.NewServer(socketPath, func() agent.MEKFetcher { return &fakeMEKFetcher{key: mek} }, time.Minute)

	var stdout, stderr bytes.Buffer
	mounts := &mountManager{root: root, keyWrapper: server, stdout: &stdout, stderr: &stderr}
	server.OnUnlock = mounts.start
	server.OnUnlockForReveal = mounts.startForReveal
	server.OnLock = mounts.stop
	server.OnRefresh = mounts.start
	server.OnReveal = mounts.revealMount
	server.OnRevealPID = mounts.revealForPID
	server.OnMountStatus = mounts.mountRevealStatuses

	if err := server.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = server.Serve(ctx); close(done) }()
	defer func() { cancel(); _ = server.Close(); <-done }()

	hostname, err := os.Hostname()
	if err != nil {
		t.Fatalf("os.Hostname: %v", err)
	}
	v := &vault.Vault{Root: root, KeyWrapper: server, RecipientID: hostname}
	// Secret first, registry after, then Refresh — see
	// TestDecoyGateEndToEnd for the real ordering bug this mirrors.
	if err := v.Set("fixture/API_KEY", []byte("sk_live_REAL_SECRET")); err != nil {
		t.Fatalf("vault Set: %v", err)
	}
	if err := mount.AddMount(mount.RegistryPath(root), mount.Entry{MountPath: mountPath, ProfilePath: profilePath}); err != nil {
		t.Fatalf("AddMount: %v", err)
	}
	client := agent.NewClient(socketPath)
	if err := client.Refresh(); err != nil {
		t.Fatalf("Client.Refresh: %v", err)
	}
	waitForMountServing(t, mounts, mountPath)
	mounts.mu.Lock()
	sm := mounts.served[mountPath]
	mounts.mu.Unlock()
	sm.reveal.Hide() // no window: whatever real content flows must be grant-authorized

	// The "granted run": a live sh, executing one command per stdin line —
	// its children are real descendants, exactly jit run's post-exec shape.
	grantRoot := exec.Command("/bin/sh", "-s")
	grantStdin, err := grantRoot.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	var grantOut safeBuffer
	grantRoot.Stdout = &grantOut
	grantRoot.Stderr = io.Discard
	if err := grantRoot.Start(); err != nil {
		t.Fatalf("start grant root: %v", err)
	}
	defer func() { _ = grantStdin.Close(); _ = grantRoot.Wait() }()

	if err := client.RevealForPID([]string{mountPath}, int32(grantRoot.Process.Pid)); err != nil {
		t.Fatalf("Client.RevealForPID: %v", err)
	}

	// (3) status shows the live grant.
	st, err := client.Status()
	if err != nil {
		t.Fatalf("Client.Status: %v", err)
	}
	if len(st.Mounts) != 1 || len(st.Mounts[0].Grants) != 1 || st.Mounts[0].Grants[0].PID != int32(grantRoot.Process.Pid) {
		t.Fatalf("Status.Mounts = %+v, want one grant for pid %d", st.Mounts, grantRoot.Process.Pid)
	}

	// (1) in-tree reader (cat, a child of the granted sh) gets REAL content.
	if _, err := fmt.Fprintf(grantStdin, "/bin/cat %s\n", mountPath); err != nil {
		t.Fatalf("feeding grant root: %v", err)
	}
	waitFor(t, "in-tree cat to receive real content", func() bool {
		return bytes.Contains(grantOut.Bytes(), []byte("sk_live_REAL_SECRET"))
	})

	// (2) an out-of-tree sibling (spawned by the TEST, not the granted sh)
	// gets decoys at the same moment the grant is live.
	sibling, err := exec.Command("/bin/cat", mountPath).Output()
	if err != nil {
		t.Fatalf("sibling cat: %v", err)
	}
	if bytes.Contains(sibling, []byte("sk_live_REAL_SECRET")) {
		t.Fatalf("out-of-tree reader got the real secret: %q", sibling)
	}
	if !bytes.Contains(sibling, []byte("jit-hidden-API_KEY")) {
		t.Errorf("out-of-tree reader = %q, want decoy jit-hidden-API_KEY", sibling)
	}

	// (4) the grant dies with the run: end the sh, then the kqueue watcher
	// (or, failing that, the per-use liveness check) must retire the grant.
	_ = grantStdin.Close()
	_ = grantRoot.Wait()
	waitFor(t, "the grant to be retired after target exit", func() bool {
		st, err := client.Status()
		return err == nil && len(st.Mounts) == 1 && len(st.Mounts[0].Grants) == 0
	})
	after := readMountOnce(t, mountPath)
	if bytes.Contains(after, []byte("sk_live_REAL_SECRET")) {
		t.Fatalf("read after target exit got the real secret: %q", after)
	}
}

// waitFor polls cond up to a deadline — the e2e assertions above cross
// real process and goroutine boundaries, so "immediately" means "within a
// beat", never "on the very next line".
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// safeBuffer is a bytes.Buffer safe for the exec goroutine and the test
// to touch concurrently.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buf.Bytes()...)
}
