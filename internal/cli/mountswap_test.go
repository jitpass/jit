// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/profile"
)

// swapTestFixture builds a real registry + FIFO + profile so the swap
// lifecycle can be driven end to end at the mountManager level (the
// filesystem transitions are the point, so they aren't faked). The pid
// lookups are faked via grantStartFn — a live target with a stable stamp.
func swapTestFixture(t *testing.T) (*mountManager, string) {
	t.Helper()
	root := t.TempDir()
	proj := t.TempDir()
	mountPath := filepath.Join(proj, ".env")

	profilePath := filepath.Join(root, "p.yaml")
	writeYAML(t, profilePath, profile.Profile{"API_KEY": "fixture/API_KEY", "DB_URL": "fixture/DB_URL"})
	if err := mount.CreateFIFO(mountPath); err != nil {
		t.Fatalf("CreateFIFO: %v", err)
	}
	if err := mount.AddMount(mount.RegistryPath(root), mount.Entry{MountPath: mountPath, ProfilePath: profilePath}); err != nil {
		t.Fatalf("AddMount: %v", err)
	}

	m := &mountManager{
		root:    root,
		stdout:  &bytes.Buffer{},
		stderr:  &bytes.Buffer{},
		grantKq: -1,
		grantStartFn: func(pid int32) (int64, bool) {
			if pid == 100 || pid == 101 {
				return 1000 + int64(pid), true
			}
			return 0, false // any other pid is "gone"
		},
	}
	// Serve the mount so swapForPID has something to stop.
	m.ensureServing([]mount.Entry{{MountPath: mountPath, ProfilePath: profilePath}})
	return m, mountPath
}

func TestSwapForPIDSwapsAndRestores(t *testing.T) {
	m, path := swapTestFixture(t)

	if err := m.swapForPID([]string{path}, 100); err != nil {
		t.Fatalf("swapForPID: %v", err)
	}
	// The FIFO is now a regular comment-only pointer file.
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat after swap: %v", err)
	}
	if info.Mode()&os.ModeNamedPipe != 0 {
		t.Fatal("path is still a FIFO after swapForPID")
	}
	if !mount.IsSwapPointerFile(path) {
		t.Error("swapped file is not recognizable as jit's pointer file")
	}
	// It must list the variable names and be inert.
	body, _ := os.ReadFile(path)
	if !bytes.Contains(body, []byte("API_KEY")) || !bytes.Contains(body, []byte("DB_URL")) {
		t.Errorf("pointer file missing variable names:\n%s", body)
	}

	// Run exits -> FIFO restored.
	m.onRunExit(100, "process exited")
	if !isFIFOPath(t, path) {
		t.Error("FIFO not restored after the run exited")
	}
}

func TestSwapForPIDRefcountsConcurrentRuns(t *testing.T) {
	m, path := swapTestFixture(t)

	if err := m.swapForPID([]string{path}, 100); err != nil {
		t.Fatalf("swapForPID 100: %v", err)
	}
	if err := m.swapForPID([]string{path}, 101); err != nil {
		t.Fatalf("swapForPID 101: %v", err)
	}
	// First run exits — still swapped (101 holds it).
	m.onRunExit(100, "process exited")
	if isFIFOPath(t, path) {
		t.Fatal("FIFO restored while a second run still holds the swap")
	}
	// Last run exits — now restored.
	m.onRunExit(101, "process exited")
	if !isFIFOPath(t, path) {
		t.Error("FIFO not restored after the last run exited")
	}
}

func TestSwapForPIDUnknownMountFails(t *testing.T) {
	m, _ := swapTestFixture(t)
	if err := m.swapForPID([]string{"/tmp/not/a/mount/.env"}, 100); err == nil {
		t.Error("expected an error swapping an unregistered mount")
	}
}

func TestSwapClearedOnLock(t *testing.T) {
	m, path := swapTestFixture(t)
	if err := m.swapForPID([]string{path}, 100); err != nil {
		t.Fatalf("swapForPID: %v", err)
	}
	m.clearAllSwaps()
	if !isFIFOPath(t, path) {
		t.Error("FIFO not restored after clearAllSwaps (lock)")
	}
	// Status must no longer report it swapped.
	if got := m.swapStatuses(); len(got) != 0 {
		t.Errorf("swapStatuses = %v after clear, want empty", got)
	}
}

// TestSwapPrunesRecycledTarget: pruneStaleSwaps must restore the FIFO for a
// swap whose target pid is gone even if the exit watcher never fired.
func TestSwapPrunesDeadTarget(t *testing.T) {
	m, path := swapTestFixture(t)
	if err := m.swapForPID([]string{path}, 100); err != nil {
		t.Fatalf("swapForPID: %v", err)
	}
	// Make the target look gone, then let a status read prune it.
	m.grantStartFn = func(int32) (int64, bool) { return 0, false }
	m.pruneStaleSwaps()
	if !isFIFOPath(t, path) {
		t.Error("FIFO not restored after the target was pruned as gone")
	}
}

func TestSwapStatusesReportsHolder(t *testing.T) {
	m, path := swapTestFixture(t)
	if err := m.swapForPID([]string{path}, 100); err != nil {
		t.Fatalf("swapForPID: %v", err)
	}
	st := m.mountRevealStatuses()
	var found bool
	for _, s := range st {
		if s.Path == path {
			found = true
			if !s.Swapped {
				t.Error("mount status not marked Swapped")
			}
			if len(s.Grants) != 1 || s.Grants[0].PID != 100 {
				t.Errorf("swap status grants = %+v, want holder pid 100", s.Grants)
			}
		}
	}
	if !found {
		t.Errorf("swapped mount %s absent from status", path)
	}
}

func isFIFOPath(t *testing.T, path string) bool {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat %s: %v", path, err)
	}
	return info.Mode()&os.ModeNamedPipe != 0
}

// TestReconcileSwappedMountsRestoresJitFileNotUserFile is crash recovery:
// a leftover jit pointer file at a mount path (agent died mid-run) is
// restored to a FIFO on startup, while a file a user restored by hand is
// left intact.
func TestReconcileSwappedMountsRestoresJitFileNotUserFile(t *testing.T) {
	root := t.TempDir()
	proj := t.TempDir()

	jitPath := filepath.Join(proj, ".env")
	if err := os.WriteFile(jitPath, mount.SwapPointerContent([]string{"API_KEY"}, nil), 0o644); err != nil {
		t.Fatalf("write jit pointer file: %v", err)
	}
	userPath := filepath.Join(proj, "b.env")
	userContent := []byte("API_KEY=user_restored_by_hand\n")
	if err := os.WriteFile(userPath, userContent, 0o644); err != nil {
		t.Fatalf("write user file: %v", err)
	}

	m := &mountManager{root: root, stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, grantKq: -1}
	m.reconcileSwappedMounts([]mount.Entry{
		{MountPath: jitPath, ProfilePath: "p"},
		{MountPath: userPath, ProfilePath: "p"},
	})

	if !isFIFOPath(t, jitPath) {
		t.Error("jit's leftover pointer file was not reconciled to a FIFO")
	}
	got, _ := os.ReadFile(userPath)
	if string(got) != string(userContent) {
		t.Errorf("a user's hand-restored file was clobbered: %q", got)
	}
	if isFIFOPath(t, userPath) {
		t.Error("a user's file was turned into a FIFO — provenance gate failed")
	}
}
