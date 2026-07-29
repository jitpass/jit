// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/agent"
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
		t.Error("agent.log.1 does not carry the full previous log, rotation must never cost the recent past")
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if fi.Size() != 0 {
		t.Errorf("agent.log is %d bytes after rotation, want 0 (truncated in place)", fi.Size())
	}
	if perm, _ := os.Stat(path + ".1"); perm.Mode().Perm() != 0o600 {
		t.Errorf("agent.log.1 mode = %o, want 0600, it carries the same reader lineage the live log does", perm.Mode().Perm())
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

func TestValidateAgentTTL(t *testing.T) {
	for _, bad := range []time.Duration{0, -time.Minute} {
		if err := validateAgentTTL(bad); err == nil {
			t.Errorf("validateAgentTTL(%s) = nil, want an error, a non-positive TTL re-prompts Touch ID on every single use", bad)
		}
	}
	if err := validateAgentTTL(15 * time.Minute); err != nil {
		t.Errorf("validateAgentTTL(15m) = %v, want nil", err)
	}

	// Startup takes whatever an installed plist says. A plist written before
	// the session ceiling existed can carry a longer TTL, and refusing to boot
	// over it would leave the agent silently not running after an upgrade —
	// the run path clamps instead.
	if err := validateAgentTTL(agent.DefaultMaxSessionAge + time.Hour); err != nil {
		t.Errorf("validateAgentTTL(%s) = %v, want nil: startup clamps a too-long TTL rather than refusing to start", agent.DefaultMaxSessionAge+time.Hour, err)
	}
}

// The upper bound belongs where a human just typed the number — that is the
// only moment there is someone present to be told that a longer idle timeout
// than the session ceiling could never be reached.
func TestValidateAgentTTLSetting(t *testing.T) {
	if err := validateAgentTTLSetting(agent.DefaultMaxSessionAge + time.Hour); err == nil {
		t.Error("a TTL above the hard session ceiling should be rejected when someone sets it")
	}
	if err := validateAgentTTLSetting(agent.DefaultMaxSessionAge); err != nil {
		t.Errorf("validateAgentTTLSetting(%s) = %v, want nil at exactly the ceiling", agent.DefaultMaxSessionAge, err)
	}
	if err := validateAgentTTLSetting(0); err == nil {
		t.Error("a non-positive TTL should still be rejected when set")
	}
}

// TestAgentRunRejectsNonPositiveTTL drives the validation through the real
// command so a plist baked with --ttl 0s fails loudly at startup instead
// of silently re-prompting forever.
func TestAgentRunRejectsNonPositiveTTL(t *testing.T) {
	defer func() { agentTTL = 15 * time.Minute }() // package-level flag var; don't leak into other tests
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"service", "run", "--ttl", "0s"})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("jit agent run --ttl 0s succeeded, want a validation error")
	}
}

func TestTailLines(t *testing.T) {
	data := []byte("one\ntwo\nthree\n")
	if got := string(tailLines(data, 2)); got != "two\nthree\n" {
		t.Errorf("tailLines(n=2) = %q, want the last two lines", got)
	}
	if got := string(tailLines(data, 10)); got != "one\ntwo\nthree\n" {
		t.Errorf("tailLines(n=10) = %q, want the whole file when shorter than n", got)
	}
	if got := tailLines(nil, 5); got != nil {
		t.Errorf("tailLines(nil) = %q, want nil", got)
	}
	if got := tailLines(data, 0); got != nil {
		t.Errorf("tailLines(n=0) = %q, want nil", got)
	}
	// A file without a trailing newline still yields newline-terminated output.
	if got := string(tailLines([]byte("one\ntwo"), 1)); got != "two\n" {
		t.Errorf("tailLines(no trailing newline, n=1) = %q, want %q", got, "two\n")
	}
}

func execAgentLog(t *testing.T, args ...string) (string, error) {
	t.Helper()
	agentLogLines = 50
	agentLogFollow = false
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs(append([]string{"service", "log"}, args...))
	err := rootCmd.Execute()
	return buf.String(), err
}

func TestAgentLogCommandPrintsTail(t *testing.T) {
	home := shortFixtureHome(t)
	root := filepath.Join(home, "Library", "Application Support", "jitpass")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	content := "2026-07-16 10:00:00 line one\n2026-07-16 10:00:01 line two\n2026-07-16 10:00:02 line three\n"
	if err := os.WriteFile(filepath.Join(root, "agent.log"), []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out, err := execAgentLog(t, "-n", "2")
	if err != nil {
		t.Fatalf("jit agent log: %v", err)
	}
	if out != "2026-07-16 10:00:01 line two\n2026-07-16 10:00:02 line three\n" {
		t.Errorf("jit agent log -n 2 = %q, want exactly the last two lines", out)
	}
}

func TestAgentLogCommandExplainsMissingLog(t *testing.T) {
	shortFixtureHome(t)

	out, err := execAgentLog(t)
	if err != nil {
		t.Fatalf("jit agent log with no log file: %v, an absent log is a normal state, not an error", err)
	}
	if !strings.Contains(out, "No service log yet") || !strings.Contains(out, "jit service restart") {
		t.Errorf("output %q, want it to explain there's no log yet and how one comes to exist", out)
	}
}
