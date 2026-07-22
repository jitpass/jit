// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/auditlog"
)

// seedAuditFixtures plants a command record and an auth event under the fixture
// home's config root, the two durable files `jit audit` reads.
func seedAuditFixtures(t *testing.T, home string) {
	t.Helper()
	root := filepath.Join(home, "Library", "Application Support", "jitpass")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	auditlog.New(root, nil).Append(auditlog.Record{
		UnixNano:   1000,
		Command:    "jit vault get",
		Args:       []string{"vault", "get", "stripe/live-key"},
		User:       "alice",
		UID:        501,
		PID:        4242,
		LaunchedBy: "claude",
		DurationMS: 120,
		Success:    true,
	})
	newHistoryLog(root, nil).append(agent.SessionEvent{
		UnixTime:   2000,
		Kind:       agent.KindUnlock,
		Op:         agent.OpUnwrap,
		By:         "jit vault get stripe/live-key",
		LaunchedBy: "claude",
		Labels:     []string{"stripe/live-key"},
		AuthMethod: "Touch ID or device passcode",
	})
}

func execAudit(t *testing.T, args ...string) (string, error) {
	t.Helper()
	auditFormat = "text"
	auditLimit = 50
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetArgs(append([]string{"audit"}, args...))
	err := rootCmd.Execute()
	return buf.String(), err
}

func TestAuditCommandTextMergesCommandsAndAuth(t *testing.T) {
	home := withFixtureHome(t)
	seedAuditFixtures(t, home)

	out, err := execAudit(t)
	if err != nil {
		t.Fatalf("jit audit: %v", err)
	}

	if !strings.Contains(out, "Audit log (most recent first):") {
		t.Errorf("missing header, got:\n%s", out)
	}
	if !strings.Contains(out, "jit vault get stripe/live-key") {
		t.Errorf("command invocation not shown, got:\n%s", out)
	}
	if !strings.Contains(out, "ran by alice") {
		t.Errorf("command actor not shown, got:\n%s", out)
	}
	if !strings.Contains(out, "unlock via Touch ID or device passcode") {
		t.Errorf("auth event / method not shown, got:\n%s", out)
	}
	if !strings.Contains(out, "secrets (caller-reported): stripe/live-key") {
		t.Errorf("auth labels not shown, got:\n%s", out)
	}
	// The auth event (unix 2000) is newer than the command (unix nano 1000, ~epoch),
	// so it must sort ahead of the command line.
	if strings.Index(out, "unlock via") > strings.Index(out, "jit vault get") {
		t.Errorf("entries not sorted newest-first, got:\n%s", out)
	}
}

func TestAuditCommandJSONShape(t *testing.T) {
	home := withFixtureHome(t)
	seedAuditFixtures(t, home)

	out, err := execAudit(t, "--format", "json")
	if err != nil {
		t.Fatalf("jit audit --format json: %v", err)
	}
	var got auditJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if len(got.Commands) != 1 || got.Commands[0].Command != "jit vault get" {
		t.Errorf("commands array wrong: %+v", got.Commands)
	}
	if len(got.AuthEvents) != 1 || got.AuthEvents[0].AuthMethod != "Touch ID or device passcode" {
		t.Errorf("auth_events array wrong: %+v", got.AuthEvents)
	}
}

func TestAuditCommandEmptyIsFriendly(t *testing.T) {
	withFixtureHome(t) // nothing seeded
	out, err := execAudit(t)
	if err != nil {
		t.Fatalf("jit audit on empty: %v", err)
	}
	if !strings.Contains(out, "No audit log yet") {
		t.Errorf("expected a friendly empty message, got:\n%s", out)
	}
}

func TestAuditCommandRejectsUnknownFormat(t *testing.T) {
	withFixtureHome(t)
	_, err := execAudit(t, "--format", "yaml")
	if err == nil {
		t.Fatal("expected an error for an unrecognized --format value, got nil")
	}
	if !strings.Contains(err.Error(), `unknown --format "yaml"`) {
		t.Errorf("expected the error to name the bad format, got: %v", err)
	}
}

func TestAuditCommandLimitCapsEntries(t *testing.T) {
	home := withFixtureHome(t)
	root := filepath.Join(home, "Library", "Application Support", "jitpass")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	l := auditlog.New(root, nil)
	for i := 0; i < 10; i++ {
		l.Append(auditlog.Record{UnixNano: int64(i + 1), Command: "jit status", Args: []string{"status"}, User: "alice", Success: true})
	}

	out, err := execAudit(t, "--limit", "3")
	if err != nil {
		t.Fatalf("jit audit --limit: %v", err)
	}
	if n := strings.Count(out, "  • "); n != 3 {
		t.Errorf("--limit 3 showed %d bullets, want 3, got:\n%s", n, out)
	}
}
