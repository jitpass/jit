// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRotateAgentLogCopiesAsideAndTruncatesInPlace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.log")
	content := bytes.Repeat([]byte("a log line the agent wrote\n"), 100)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Hold an O_APPEND fd across the rotation — the launchd arrangement:
	// this fd is the running agent's stdout and must keep working, at the
	// start of the truncated file, afterwards.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer func() { _ = f.Close() }()

	if err := rotateAgentLog(path, 10); err != nil {
		t.Fatalf("rotateAgentLog: %v", err)
	}

	rotated, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatalf("reading rotated log: %v", err)
	}
	if !bytes.Equal(rotated, content) {
		t.Error("agent.log.1 does not carry the full previous log — rotation must never cost the recent past")
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if fi.Size() != 0 {
		t.Errorf("agent.log is %d bytes after rotation, want 0 (truncated in place)", fi.Size())
	}
	if perm, _ := os.Stat(path + ".1"); perm.Mode().Perm() != 0o600 {
		t.Errorf("agent.log.1 mode = %o, want 0600 — it carries the same reader lineage the live log does", perm.Mode().Perm())
	}

	// The held O_APPEND fd must land its next write at the new EOF —
	// offset 0 — not at its stale pre-truncate offset (which would leave a
	// NUL-hole the size of the old log).
	if _, err := f.WriteString("post-rotation line\n"); err != nil {
		t.Fatalf("write on held fd: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(after) != "post-rotation line\n" {
		t.Errorf("log after post-rotation write = %q, want just the new line at offset 0", after)
	}
}

func TestRotateAgentLogNoOpUnderCapAndWhenMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.log")

	if err := rotateAgentLog(path, 1024); err != nil {
		t.Fatalf("rotateAgentLog on a missing file: %v", err)
	}
	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Error("rotation of a missing log created agent.log.1")
	}

	if err := os.WriteFile(path, []byte("small\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := rotateAgentLog(path, 1024); err != nil {
		t.Fatalf("rotateAgentLog under cap: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "small\n" {
		t.Errorf("under-cap log was modified: %q", got)
	}
	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Error("under-cap rotation created agent.log.1")
	}
}
