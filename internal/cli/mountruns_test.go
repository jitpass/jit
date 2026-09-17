// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

// The run exit watcher's kqueue used to live for the process: fine in the
// daemon, a leaked fd and a blocked goroutine per manager everywhere else.
// A lock ends it, the next attachment arms a fresh one, shutdown ends that.
func TestRunWatchClosesOnLockAndShutdown(t *testing.T) {
	var out bytes.Buffer
	m := &mountManager{root: t.TempDir(), stdout: &out, stderr: &out}
	target := exec.Command("/bin/sleep", "30")
	if err := target.Start(); err != nil {
		t.Fatalf("start target: %v", err)
	}
	defer func() { _ = target.Process.Kill(); _ = target.Wait() }()
	pid := int32(target.Process.Pid) // #nosec G115 -- a fresh child's pid fits int32

	m.watchRunPID(pid, 1)
	kq := m.grantKq
	if kq <= 0 {
		t.Fatalf("grantKq = %d after arming, want an open kqueue (stderr: %q)", kq, out.String())
	}
	var st unix.Stat_t
	if err := unix.Fstat(kq, &st); err != nil {
		t.Fatalf("Fstat(kqueue) = %v, want open", err)
	}

	m.stop()
	if m.grantKq != 0 {
		t.Errorf("grantKq = %d after stop, want 0 (forgotten, re-armed on the next attachment)", m.grantKq)
	}
	waitFor(t, "the watch loop to close its kqueue", func() bool {
		return unix.Fstat(kq, &st) == unix.EBADF
	})

	m.watchRunPID(pid, 1)
	second := m.grantKq
	if second <= 0 {
		t.Fatalf("grantKq = %d after re-arming, want a fresh kqueue", second)
	}
	m.shutdown()
	waitFor(t, "shutdown to close the second kqueue", func() bool {
		return unix.Fstat(second, &st) == unix.EBADF
	})
}
