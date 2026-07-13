// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
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

func (f *fakeMEKFetcher) FetchMEK() ([]byte, error) { return f.key, nil }

// TestDecoyGateEndToEnd drives the real GAPS.md #2 mechanism through the
// actual agent.Server/Client/mountManager/mount.Serve code paths — no
// stubs beyond the MEK fetch — and confirms: an hidden mount serves
// DecoyValues, an explicit `jit agent reveal`-equivalent RPC (agent.Client.Reveal)
// makes it serve real content, and internal/lineage's audit scan runs
// without disrupting either. This is the fixture-based verification for
// the flow the manual/real-hardware pass (agent install -> jit migrate ->
// jit agent reveal) can't be scripted for, since that needs a real Touch ID
// approval.
func TestDecoyGateEndToEnd(t *testing.T) {
	root := t.TempDir()

	profilePath := filepath.Join(root, "fixture-profile.yaml")
	writeYAML(t, profilePath, profile.Profile{"API_KEY": "fixture/API_KEY"})

	mountDir := t.TempDir()
	mountPath := filepath.Join(mountDir, ".env")
	if err := mount.CreateFIFO(mountPath); err != nil {
		t.Fatalf("CreateFIFO: %v", err)
	}

	socketPath := filepath.Join(t.TempDir(), "a.sock") // short path — see agent's shortSocketPath convention (sockaddr_un ~104 byte limit)
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

	// RecipientID must match what mountManager.start() itself computes
	// (os.Hostname()) — it builds its own *vault.Vault internally to
	// resolve a mount's profile.
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatalf("os.Hostname: %v", err)
	}
	v := &vault.Vault{Root: root, KeyWrapper: server, RecipientID: hostname}

	// Order matters here exactly as it does in real jit migrate
	// (internal/migrate.ApplyEnvFile then internal/cli/migrate.go's
	// mount.AddMount + Client.Refresh): write the secret(s) FIRST, only
	// register the mount in the registry AFTER. This first v.Set is what
	// triggers the very first OnUnlock — if the mount were already
	// registered at that point, mountManager.start() would attempt (and
	// fail) to resolve it before the secret exists, permanently mark it
	// "serving" in m.serving anyway, and then never retry on a later
	// Refresh even once the secret is written — reproduced once while
	// writing this test (registering the mount before Set caused exactly
	// this permanent-skip and a hung readMountOnce). Registering only once
	// the secret is safely in place, then explicitly Refresh-ing, is what
	// real migrate already does specifically to avoid this.
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
	sm.reveal.Hide()

	// Hidden: real value must never appear on the wire.
	got := readMountOnce(t, mountPath)
	if bytes.Contains(got, []byte("sk_live_REAL_SECRET")) {
		t.Fatalf("hidden mount leaked the real secret: %q", got)
	}
	if !bytes.Contains(got, []byte("jit-hidden-API_KEY")) {
		t.Errorf("hidden mount = %q, want decoy value jit-hidden-API_KEY", got)
	}

	// Explicit reveal via the real Client/OpReveal RPC — exactly what `jit agent
	// reveal` and migrate's injected hook command do over the wire.
	if err := client.Reveal(mountPath, 5*time.Second); err != nil {
		t.Fatalf("Client.Reveal: %v", err)
	}

	got = readMountOnce(t, mountPath)
	if !bytes.Contains(got, []byte("sk_live_REAL_SECRET")) {
		t.Errorf("revealed mount = %q, want the real secret", got)
	}

	// GAPS.md #37: Client.Status() (the real RPC, not mountManager's
	// in-process state directly) must report this mount as revealed — this
	// is what `jit status`/`jit agent status` actually call.
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
		if !ms.Revealed {
			t.Errorf("Client.Status reported %s as hidden right after a successful Client.Reveal", mountPath)
		}
		if ms.RevealedForSeconds <= 0 || ms.RevealedForSeconds > 5 {
			t.Errorf("Client.Status reported RevealedForSeconds=%d, want 0 < n <= 5 (revealed for 5s just now)", ms.RevealedForSeconds)
		}
	}
	if !found {
		t.Fatalf("Client.Status didn't include %s at all, got %+v", mountPath, mountStatuses)
	}

	// Audit logging ran alongside without influencing the above —
	// mountManager's onReaderConnected calls internal/lineage on every
	// cycle unconditionally. Expect "not identified" here specifically:
	// IdentifyFIFOReader deliberately skips its own PID (see its doc
	// comment), and this test's reader and the scan both run in this same
	// test binary process. internal/lineage's own tests (a genuinely
	// separate reader process) cover the scan's actual accuracy; this only
	// confirms wiring it into Serve never crashes or blocks a read.
	t.Logf("agent stderr (audit log lines expected here):\n%s", stderr.String())
}

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
	server.OnReveal = mounts.revealMount
	server.OnMountStatus = mounts.mountRevealStatuses

	// (1) No unlock has ever happened — startDecoyOnly is the only thing
	// that's run, exactly matching what agentRunCmd calls at raw process
	// startup, before Listen/Serve even begin accepting connections.
	mounts.startDecoyOnly()
	waitForMountServing(t, mounts, mountPath)
	got := readMountOnceWithTimeout(t, mountPath, 2*time.Second)
	if !bytes.Contains(got, []byte("jit-hidden-API_KEY")) {
		t.Fatalf("before any unlock, mount = %q, want decoy content (and, critically, a response at all — the read must never hang)", got)
	}

	// (2) Write the real secret, THEN trigger the same start() OnUnlock
	// would call (directly, not via v.Set's own incidental WrapKey call —
	// that would fire mid-Set, before the secret is actually written to
	// disk yet, the exact ordering hazard TestDecoyGateEndToEnd's own
	// comment already documents), then explicitly reveal.
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
	mounts.mu.Unlock()
	sm.reveal.Reveal(time.Minute)

	got = readMountOnceWithTimeout(t, mountPath, 2*time.Second)
	if !bytes.Contains(got, []byte("sk_live_REAL_SECRET")) {
		t.Fatalf("after unlock+reveal, mount = %q, want the real secret", got)
	}

	// (3) Lock again — the actual regression. Must fall back to decoy
	// immediately, never hang, and the Serve goroutine must still be the
	// SAME one (never restarted) — confirmed by checking the mount is
	// still present in m.served without ever having been removed.
	mounts.stop()
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
		t.Error("expected the mount to still be in m.served after stop() — locking must not tear down serving")
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
		t.Fatalf("reading %s timed out after %s — the mount has no writer and is hanging", path, timeout)
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
