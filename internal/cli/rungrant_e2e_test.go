// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

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
	"strings"
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
	server.OnLock = mounts.stop
	server.OnRefresh = mounts.start
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
	// No reveal window exists: the mount serves decoys until a run-scoped
	// grant authorizes real reads for its process tree, which is what the
	// rest of this test exercises via RevealForPID.

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
	sibling := readMountFromSiblingProcess(t, mountPath, 5*time.Second)
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
	after := readMountOnceWithTimeout(t, mountPath, 5*time.Second)
	if bytes.Contains(after, []byte("sk_live_REAL_SECRET")) {
		t.Fatalf("read after target exit got the real secret: %q", after)
	}
}

// readMountFromSiblingProcess reads the mount from a process OUTSIDE the
// granted tree. A separate process is the whole assertion — the grant is
// keyed on process ancestry, so an in-process read
// (readMountOnceWithTimeout) sits in the test binary, whose own tree is not
// the granted one but is also not what a real out-of-tree reader looks like.
//
// The deadline is not politeness. This read used to be a bare
// exec.Command(...).Output(), which waits on the child with no bound of its
// own while the child parks in open(2) on a pipe nothing is writing to. That
// is not a failing test, it is a hung one: a repeat run of this package left
// it parked until the test binary died on its own 10-minute alarm and printed
// a goroutine dump in place of the one line naming the read that never
// resolved. CommandContext kills the child at the deadline so the failure
// arrives as a sentence.
func readMountFromSiblingProcess(t *testing.T, path string, timeout time.Duration) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/bin/cat", path).Output()
	if ctx.Err() != nil {
		t.Fatalf("an out-of-tree read of %s did not resolve within %s, nothing is serving the mount", path, timeout)
	}
	if err != nil {
		t.Fatalf("sibling cat: %v", err)
	}
	return out
}

// waitFor polls cond up to a deadline — the e2e assertions above cross
// real process and goroutine boundaries, so "immediately" means "within a
// beat", never "on the very next line".
// waitForBudget is a safety net, not an assertion about speed: a passing
// wait returns the moment its condition holds, so the ceiling costs nothing
// except on a genuine failure.
//
// It was 5s, which a loaded CI runner could not always meet. The restore this
// file waits on is driven by a kqueue NOTE_EXIT watch (see mountruns.go) and
// completes on an async goroutine, so the chain is process-death delivery,
// then the restore, then recreating the FIFO. Measured: 3 of 6 CI runs failed
// on "the FIFO to be restored after the run exits" with identical code that
// passed 10 consecutive local runs under -race, and the same job passed on
// other runs — timing, not logic. 30s keeps a hung restore a fast, clear
// failure while giving a slow runner room.
const waitForBudget = 30 * time.Second

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitForBudget)
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

// TestRunScopedSwapEndToEnd drives the compatibility swap through the real
// agent/mountManager/mount code with a live registry+FIFO+vault: a run's
// SwapForPID turns the FIFO into a regular inert pointer file (so [ -f ]
// passes and sourcing sets nothing), and the run's exit restores the FIFO.
func TestRunScopedSwapEndToEnd(t *testing.T) {
	root := t.TempDir()

	profilePath := filepath.Join(root, "fixture-profile.yaml")
	writeYAML(t, profilePath, profile.Profile{"API_KEY": "fixture/API_KEY"})

	mountDir := t.TempDir()
	mountPath := filepath.Join(mountDir, ".env")
	if err := mount.CreateFIFO(mountPath); err != nil {
		t.Fatalf("CreateFIFO: %v", err)
	}

	socketPath := filepath.Join(t.TempDir(), "a.sock")
	mek := bytes.Repeat([]byte{0x24}, 32)
	server := agent.NewServer(socketPath, func() agent.MEKFetcher { return &fakeMEKFetcher{key: mek} }, time.Minute)

	var stdout, stderr bytes.Buffer
	mounts := &mountManager{root: root, keyWrapper: server, stdout: &stdout, stderr: &stderr}
	server.OnUnlock = mounts.start
	server.OnLock = mounts.stop
	server.OnRefresh = mounts.start
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

	// The "granted run": a live sleep, standing in for jit run's target.
	runProc := exec.Command("/bin/sleep", "30")
	if err := runProc.Start(); err != nil {
		t.Fatalf("start run: %v", err)
	}
	defer func() { _ = runProc.Process.Kill(); _ = runProc.Wait() }()

	if err := client.SwapForPID([]string{mountPath}, int32(runProc.Process.Pid)); err != nil {
		t.Fatalf("Client.SwapForPID: %v", err)
	}

	// During the run: the mount is a regular inert file that passes [ -f ]
	// and sources to nothing, and never leaks the real secret.
	info, err := os.Lstat(mountPath)
	if err != nil {
		t.Fatalf("Lstat during swap: %v", err)
	}
	if info.Mode()&os.ModeNamedPipe != 0 {
		t.Fatal("mount is still a FIFO during a swap run")
	}
	out, err := exec.Command("/bin/sh", "-c",
		"[ -f "+mountPath+" ] && echo FILE_OK; set -a; . "+mountPath+"; set +a; echo \"API_KEY=[${API_KEY:-unset}]\"").CombinedOutput()
	if err != nil {
		t.Fatalf("guard/source check: %v (%s)", err, out)
	}
	if !strings.Contains(string(out), "FILE_OK") || !strings.Contains(string(out), "API_KEY=[unset]") {
		t.Errorf("swapped file failed guard/inertness: %q", out)
	}
	if bytes.Contains(out, []byte("sk_live_REAL_SECRET")) {
		t.Fatalf("swapped compatibility file leaked the real secret: %q", out)
	}

	// Status shows it swapped.
	st, err := client.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if len(st.Mounts) != 1 || !st.Mounts[0].Swapped {
		t.Fatalf("Status.Mounts = %+v, want the mount marked Swapped", st.Mounts)
	}

	// Run exits -> FIFO restored, back to decoy.
	_ = runProc.Process.Kill()
	_ = runProc.Wait()
	waitFor(t, "the FIFO to be restored after the run exits", func() bool {
		info, err := os.Lstat(mountPath)
		return err == nil && info.Mode()&os.ModeNamedPipe != 0
	})
	after := readMountOnceWithTimeout(t, mountPath, 5*time.Second)
	if bytes.Contains(after, []byte("sk_live_REAL_SECRET")) {
		t.Fatalf("restored mount served the real secret while hidden: %q", after)
	}
	if !bytes.Contains(after, []byte("jit-hidden-API_KEY")) {
		t.Errorf("restored mount = %q, want decoy content", after)
	}
}
