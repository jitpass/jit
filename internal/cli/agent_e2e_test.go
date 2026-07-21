// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

// fakeMEKFetcher stands in for a real Touch ID/passcode challenge — this
// project's established pattern (see internal/agent/server_test.go's
// fakeFetcher) for testing everything up to, but not including, the real
// interactive LocalAuthentication boundary, which can't be scripted.
type fakeMEKFetcher struct{ key []byte }

func (f *fakeMEKFetcher) FetchMEK(reason string) ([]byte, error) { return f.key, nil }

// TestMountNeverHangsRegardlessOfLockState is GAPS.md #35's end-to-end
// regression test for a real, reported incident: with the old design,
// mountManager.stop() (OnLock) cancelled every mount's Serve goroutine
// outright, so opening a mount while the agent was locked — or before it
// had ever been unlocked at all — had no writer behind the pipe and
// blocked on open() forever, hanging whatever tried to read it (one
// report: an editor's own crash-recovery step hung closing the window).
// Confirms three points in the lifecycle where a read must resolve
// immediately: (1) mounts.startDecoyOnly() alone, before any unlock ever
// happens; (2) after a real unlock+reveal, reading real content; (3) after
// an explicit stop() (OnLock), back to decoy — never a hang.
func TestMountNeverHangsRegardlessOfLockState(t *testing.T) {
	root := t.TempDir()

	profilePath := filepath.Join(root, "fixture-profile.yaml")
	writeYAML(t, profilePath, profile.Profile{"API_KEY": "fixture/API_KEY"})

	mountDir := t.TempDir()
	mountPath := filepath.Join(mountDir, ".env")
	if err := mount.CreateFIFO(mountPath); err != nil {
		t.Fatalf("CreateFIFO: %v", err)
	}
	if err := mount.AddMount(mount.RegistryPath(root), mount.Entry{MountPath: mountPath, ProfilePath: profilePath}); err != nil {
		t.Fatalf("AddMount: %v", err)
	}

	socketPath := filepath.Join(t.TempDir(), "a.sock")
	mek := bytes.Repeat([]byte{0x24}, 32)
	server := agent.NewServer(socketPath, func() agent.MEKFetcher { return &fakeMEKFetcher{key: mek} }, time.Minute)
	var stdout, stderr bytes.Buffer
	mounts := &mountManager{root: root, keyWrapper: server, stdout: &stdout, stderr: &stderr}
	server.OnUnlock = mounts.start
	server.OnLock = mounts.stop
	server.OnRefresh = mounts.start
	server.OnMountStatus = mounts.mountRevealStatuses

	// (1) No unlock has ever happened — startDecoyOnly is the only thing
	// that's run, exactly matching what agentRunCmd calls at raw process
	// startup, before Listen/Serve even begin accepting connections.
	mounts.startDecoyOnly()
	waitForMountServing(t, mounts, mountPath)
	got := readMountOnceWithTimeout(t, mountPath, 2*time.Second)
	if !bytes.Contains(got, []byte("jit-hidden-API_KEY")) {
		t.Fatalf("before any unlock, mount = %q, want decoy content (and, critically, a response at all, the read must never hang)", got)
	}

	// (2) Write the real secret, THEN trigger the same start() OnUnlock
	// would call (directly, not via v.Set's own incidental WrapKey call —
	// that would fire mid-Set, before the secret is actually written to
	// disk yet). Unlocking ARMS real content in memory but reveals nothing:
	// with no run-scoped grant, a bare read must STILL get decoys, never the
	// real secret.
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatalf("os.Hostname: %v", err)
	}
	v := &vault.Vault{Root: root, KeyWrapper: server, RecipientID: hostname}
	if err := v.Set("fixture/API_KEY", []byte("sk_live_REAL_SECRET")); err != nil {
		t.Fatalf("vault Set: %v", err)
	}
	mounts.start()
	mounts.mu.Lock()
	sm := mounts.served[mountPath]
	armed := string(sm.real)
	mounts.mu.Unlock()
	if !strings.Contains(armed, "sk_live_REAL_SECRET") {
		t.Fatalf("after unlock, sm.real = %q, want the real secret armed in memory", armed)
	}
	got = readMountOnceWithTimeout(t, mountPath, 2*time.Second)
	if bytes.Contains(got, []byte("sk_live_REAL_SECRET")) {
		t.Fatalf("after unlock with NO grant, mount leaked the real secret: %q (real content must serve only to a run-scoped grant)", got)
	}
	if !bytes.Contains(got, []byte("jit-hidden-API_KEY")) {
		t.Fatalf("after unlock with no grant, mount = %q, want decoy content", got)
	}

	// (3) Lock again — the actual regression. Must forget the armed real
	// content, keep serving decoy immediately, never hang, and the Serve
	// goroutine must still be the SAME one (never restarted) — confirmed by
	// checking the mount is still present in m.served without ever having
	// been removed.
	mounts.stop()
	mounts.mu.Lock()
	stillArmed := sm.real
	mounts.mu.Unlock()
	if stillArmed != nil {
		t.Errorf("after re-locking, sm.real = %q, want nil (real content forgotten on lock)", stillArmed)
	}
	got = readMountOnceWithTimeout(t, mountPath, 2*time.Second)
	if bytes.Contains(got, []byte("sk_live_REAL_SECRET")) {
		t.Fatalf("after re-locking, mount leaked the real secret: %q", got)
	}
	if !bytes.Contains(got, []byte("jit-hidden-API_KEY")) {
		t.Errorf("after re-locking, mount = %q, want decoy content", got)
	}
	mounts.mu.Lock()
	_, stillServed := mounts.served[mountPath]
	mounts.mu.Unlock()
	if !stillServed {
		t.Error("expected the mount to still be in m.served after stop(), locking must not tear down serving")
	}
}

// readMountOnceWithTimeout is readMountOnce, but fails loud on a timeout
// instead of hanging the test suite forever — the whole point of
// TestMountNeverHangsRegardlessOfLockState is to catch exactly the hang
// this guards against.
func readMountOnceWithTimeout(t *testing.T, path string, timeout time.Duration) []byte {
	t.Helper()
	type result struct {
		data []byte
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		f, err := os.Open(path)
		if err != nil {
			ch <- result{err: err}
			return
		}
		defer f.Close()
		data, err := io.ReadAll(f)
		ch <- result{data: data, err: err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("reading mount: %v", r.err)
		}
		return r.data
	case <-time.After(timeout):
		t.Fatalf("reading %s timed out after %s, the mount has no writer and is hanging", path, timeout)
		return nil
	}
}

func waitForMountServing(t *testing.T, m *mountManager, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		_, serving := m.served[path]
		m.mu.Unlock()
		if serving {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("mount never started serving")
}

func readMountOnce(t *testing.T, path string) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening mount for read: %v", err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("reading mount: %v", err)
	}
	return data
}

func writeYAML(t *testing.T, path string, v any) {
	t.Helper()
	data, err := yaml.Marshal(v)
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}
