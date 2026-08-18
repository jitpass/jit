// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package agent

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// hookSocketDir returns a /tmp-based dir for a test socket: t.TempDir() on
// macOS lives under /var/folders/... and can push a socket path past
// sun_path's 104-byte limit.
func hookSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "jit-hook-test-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// listenAndAccept keeps a test listener draining connections so a client
// dial completes; closed by the test via the returned listener.
func listenAndAccept(t *testing.T, sock string) net.Listener {
	t.Helper()
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	return ln
}

// TestDialFailedHookCausesTheSocketAndExtendsTheWindow pins the hook's
// contract: with NO retry window of its own, a failed dial fires the hook,
// and the window the hook returns is what lets the retry find the socket
// the hook just caused to exist — the CLI's service heal in miniature.
func TestDialFailedHookCausesTheSocketAndExtendsTheWindow(t *testing.T) {
	sock := filepath.Join(hookSocketDir(t), "agent.sock")

	fired := 0
	var ln net.Listener
	c := NewClient(sock).WithDialFailedHook(func() time.Duration {
		fired++
		ln = listenAndAccept(t, sock)
		return 2 * time.Second
	})
	defer func() {
		if ln != nil {
			_ = ln.Close()
		}
	}()

	if !c.Reachable() {
		t.Fatal("dial must succeed inside the hook-granted window")
	}
	if fired != 1 {
		t.Fatalf("hook fired %d times, want 1", fired)
	}
	// The socket is up now: further dials succeed without the hook, and the
	// hook must not fire again even if it were still armed.
	if !c.Reachable() {
		t.Fatal("second dial must succeed")
	}
	if fired != 1 {
		t.Fatalf("hook re-fired (%d times) after being consumed", fired)
	}
}

// TestDialFailedHookNeverFiresOnSuccess: a healthy socket means the hook is
// dead weight that must cost nothing.
func TestDialFailedHookNeverFiresOnSuccess(t *testing.T) {
	sock := filepath.Join(hookSocketDir(t), "agent.sock")
	ln := listenAndAccept(t, sock)
	defer func() { _ = ln.Close() }()

	fired := 0
	c := NewClient(sock).WithDialFailedHook(func() time.Duration {
		fired++
		return time.Second
	})
	if !c.Reachable() {
		t.Fatal("dial against a live listener must succeed")
	}
	if fired != 0 {
		t.Fatalf("hook fired %d times on a successful dial, want 0", fired)
	}
}

// TestDialFailedHookReturningZeroChangesNothing: a hook that could not act
// leaves the client exactly as configured — here, no retry window at all,
// so the failure is immediate.
func TestDialFailedHookReturningZeroChangesNothing(t *testing.T) {
	sock := filepath.Join(hookSocketDir(t), "agent.sock")

	fired := 0
	c := NewClient(sock).WithDialFailedHook(func() time.Duration {
		fired++
		return 0
	})
	start := time.Now()
	if c.Reachable() {
		t.Fatal("nothing listens; dial must fail")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("a zero-window hook must not delay the failure, took %s", elapsed)
	}
	if fired != 1 {
		t.Fatalf("hook fired %d times, want 1", fired)
	}
}
