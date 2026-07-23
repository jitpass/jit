// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// TestCommandEntrySurfacesFreshAuth: a command that forced its own fresh
// Touch ID/passcode (jit migrate undo/remove set Record.Auth) must show that
// in the audit line, so the trail proves a plaintext-restoring or
// destructive action was gated by a live fingerprint. A command with no
// fresh auth carries no auth= key.
func TestCommandEntrySurfacesFreshAuth(t *testing.T) {
	withAuth := commandEntry(auditlog.Record{
		UnixNano: 1000, Command: "jit migrate undo", Args: []string{"migrate", "undo", "~/proj/.env"},
		Success: true, Auth: freshUserPresenceMethod,
	})
	if !strings.Contains(withAuth.line, "auth="+freshUserPresenceMethod) {
		t.Errorf("expected the fresh-auth marker in the audit line, got:\n%s", withAuth.line)
	}

	noAuth := commandEntry(auditlog.Record{
		UnixNano: 1000, Command: "jit status", Args: []string{"status"}, Success: true,
	})
	if strings.Contains(noAuth.line, "auth=") {
		t.Errorf("expected no auth= key for a command that didn't force a challenge, got:\n%s", noAuth.line)
	}
}

func execAudit(t *testing.T, args ...string) (string, error) {
	t.Helper()
	// The audit flags are package-level vars cobra only overwrites when the
	// flag is passed, so reset every one to its default here or a filter from
	// one test leaks into the next.
	auditFormat = "text"
	auditLimit = 50
	auditFollow = false
	auditKinds = nil
	auditSince, auditUntil = "", ""
	auditStatus, auditUser, auditParent, auditSecret, auditGrep = "", "", "", "", ""
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

	if !strings.Contains(out, `cmd="jit vault get stripe/live-key"`) {
		t.Errorf("command invocation not shown, got:\n%s", out)
	}
	if !strings.Contains(out, "kind=cmd status=ok") || !strings.Contains(out, "user=alice") {
		t.Errorf("command line/actor not shown, got:\n%s", out)
	}
	if !strings.Contains(out, "kind=unlock") || !strings.Contains(out, "method=touchid-or-passcode") {
		t.Errorf("auth event / method not shown, got:\n%s", out)
	}
	if !strings.Contains(out, "secrets=stripe/live-key") {
		t.Errorf("auth labels not shown, got:\n%s", out)
	}
	// The auth event (unix 2000) is newer than the command (unix nano 1000, ~epoch),
	// so its unlock line must sort ahead of the command line.
	if strings.Index(out, "kind=unlock") > strings.Index(out, "kind=cmd") {
		t.Errorf("entries not sorted newest-first, got:\n%s", out)
	}
}

func TestAuditRecorderSkipsNonRunnableParent(t *testing.T) {
	home := withFixtureHome(t)
	// `jit service un` resolves to the non-runnable `service` parent: cobra accepts
	// the stray "un", prints service help, and exits 0. Recording that would log a
	// successful `jit service un` for a command that never existed. The recorder
	// must skip non-runnable commands, so nothing lands in the durable log.
	recordAuditEvent(serviceCmd, nil, 0)

	root := filepath.Join(home, "Library", "Application Support", "jitpass")
	if recs := auditlog.New(root, nil).Load(0); len(recs) != 0 {
		t.Errorf("non-runnable parent command was recorded, want none: %+v", recs)
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
	if n := strings.Count(out, "kind=cmd"); n != 3 {
		t.Errorf("--limit 3 showed %d entries, want 3, got:\n%s", n, out)
	}
}

// seedDeniedAndError adds a refused prompt and a rejected-peer error on top of
// seedAuditFixtures' ok unlock and command, so the filter tests have every kind
// and status to narrow among.
func seedDeniedAndError(t *testing.T, home string) {
	t.Helper()
	root := filepath.Join(home, "Library", "Application Support", "jitpass")
	h := newHistoryLog(root, nil)
	h.append(agent.SessionEvent{
		UnixTime: 3000, Kind: agent.KindDenied, Op: agent.OpUnwrap,
		By: "jit run --profile mcp-jamf", LaunchedBy: "claude",
		Cause: "prompt timed out", AuthMethod: "Touch ID or device passcode",
	})
	h.append(agent.SessionEvent{
		UnixTime: 4000, Kind: agent.KindError, Op: "reject",
		Cause: "rejected peer: peer uid 502 != 501", By: "/usr/bin/curl", ByPID: 8080, LaunchedBy: "bash",
	})
}

func TestAuditFilterByKind(t *testing.T) {
	home := withFixtureHome(t)
	seedAuditFixtures(t, home)

	out, err := execAudit(t, "--kind", "unlock")
	if err != nil {
		t.Fatalf("jit audit --kind: %v", err)
	}
	if !strings.Contains(out, "kind=unlock") {
		t.Errorf("--kind unlock dropped the unlock, got:\n%s", out)
	}
	if strings.Contains(out, "kind=cmd") {
		t.Errorf("--kind unlock leaked a command line, got:\n%s", out)
	}
}

func TestAuditFilterByStatusDenied(t *testing.T) {
	home := withFixtureHome(t)
	seedAuditFixtures(t, home)
	seedDeniedAndError(t, home)

	out, err := execAudit(t, "--status", "denied")
	if err != nil {
		t.Fatalf("jit audit --status: %v", err)
	}
	if !strings.Contains(out, "status=denied") {
		t.Errorf("--status denied dropped the denial, got:\n%s", out)
	}
	if strings.Contains(out, "status=ok") || strings.Contains(out, "kind=cmd") {
		t.Errorf("--status denied leaked non-denied entries, got:\n%s", out)
	}
}

func TestAuditFilterBySecret(t *testing.T) {
	home := withFixtureHome(t)
	seedAuditFixtures(t, home)

	out, err := execAudit(t, "--secret", "stripe")
	if err != nil {
		t.Fatalf("jit audit --secret: %v", err)
	}
	if !strings.Contains(out, "secrets=stripe/live-key") {
		t.Errorf("--secret stripe dropped the touching unlock, got:\n%s", out)
	}
	// A command record carries no labels, so a secret filter must exclude it.
	if strings.Contains(out, "kind=cmd") {
		t.Errorf("--secret leaked a command with no secret labels, got:\n%s", out)
	}
}

func TestAuditFilterByParent(t *testing.T) {
	home := withFixtureHome(t)
	seedAuditFixtures(t, home)
	seedDeniedAndError(t, home)

	// Only the error event was launched by bash; the rest are claude.
	out, err := execAudit(t, "--parent", "bash")
	if err != nil {
		t.Fatalf("jit audit --parent: %v", err)
	}
	if !strings.Contains(out, "kind=error") {
		t.Errorf("--parent bash dropped the bash-launched error, got:\n%s", out)
	}
	if strings.Contains(out, "kind=unlock") || strings.Contains(out, "kind=cmd") {
		t.Errorf("--parent bash leaked claude-launched entries, got:\n%s", out)
	}
}

func TestAuditFilterByGrep(t *testing.T) {
	home := withFixtureHome(t)
	seedAuditFixtures(t, home)

	out, err := execAudit(t, "--grep", "method=touchid")
	if err != nil {
		t.Fatalf("jit audit --grep: %v", err)
	}
	if !strings.Contains(out, "kind=unlock") {
		t.Errorf("--grep matched the unlock's method but dropped it, got:\n%s", out)
	}
	if strings.Contains(out, "kind=cmd") {
		t.Errorf("--grep leaked a line that doesn't match, got:\n%s", out)
	}
}

// A rejected peer is the socket event most worth a durable line; it must render
// as a kind=error line naming what was refused and who the peer was.
func TestAuditRendersRejectedPeer(t *testing.T) {
	home := withFixtureHome(t)
	seedDeniedAndError(t, home)

	out, err := execAudit(t)
	if err != nil {
		t.Fatalf("jit audit: %v", err)
	}
	for _, want := range []string{"kind=error", "op=reject", `reason="rejected peer: peer uid 502 != 501"`, "parent=bash"} {
		if !strings.Contains(out, want) {
			t.Errorf("rejected-peer line missing %q, got:\n%s", want, out)
		}
	}
}

func TestAuditRejectsBadFilters(t *testing.T) {
	withFixtureHome(t)
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"--kind", "bogus"}, "unknown --kind"},
		{[]string{"--status", "maybe"}, "unknown --status"},
		{[]string{"--since", "yesterday"}, "--since"},
		{[]string{"--grep", "("}, "--grep"},
		{[]string{"--follow", "--format", "json"}, "--follow"},
	}
	for _, c := range cases {
		if _, err := execAudit(t, c.args...); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("audit %v: want error containing %q, got %v", c.args, c.want, err)
		}
	}
}

func TestAuditEmptyMatchIsDistinctFromEmptyLog(t *testing.T) {
	home := withFixtureHome(t)
	seedAuditFixtures(t, home)

	// There are entries, just none of this kind: the message must say "no
	// match", not "no log yet", or a filter reads as an empty machine.
	out, err := execAudit(t, "--kind", "lock")
	if err != nil {
		t.Fatalf("jit audit --kind lock: %v", err)
	}
	if !strings.Contains(out, "No audit entries match") {
		t.Errorf("a filter that matches nothing must say so, got:\n%s", out)
	}
}

func TestParseAuditTime(t *testing.T) {
	for _, ok := range []string{"3d", "90m", "2h", "1w", "2026-07-23", "2026-07-23 09:00", "2026-07-23 09:00:05"} {
		if _, err := parseAuditTime(ok); err != nil {
			t.Errorf("parseAuditTime(%q) errored: %v", ok, err)
		}
	}
	if _, err := parseAuditTime("sometime"); err == nil {
		t.Error("parseAuditTime accepted a non-time string")
	}
	// A relative age resolves to that long ago, not a forward offset.
	got, err := parseAuditTime("1h")
	if err != nil {
		t.Fatalf("parseAuditTime(1h): %v", err)
	}
	if d := time.Since(got); d < 59*time.Minute || d > 61*time.Minute {
		t.Errorf("parseAuditTime(1h) resolved to %v ago, want ~1h", d)
	}
}

// keep's time bounds are the one predicate a wall-clock test pins directly,
// since the fixture timestamps are fixed at epoch and can't exercise "since".
func TestAuditFilterKeepsWithinTimeWindow(t *testing.T) {
	since, _ := parseAuditTime("30m")
	f := auditFilter{since: since}
	now := time.Now()
	if f.keep(auditEntry{t: now.Add(-2 * time.Hour)}) {
		t.Error("an entry older than --since must be dropped")
	}
	if !f.keep(auditEntry{t: now.Add(-time.Minute)}) {
		t.Error("an entry inside the window must be kept")
	}
}

// readNewEvents is the heart of --follow: each poll must return only the lines
// appended since the last offset, and nothing when the file is unchanged.
func TestReadNewEventsIsIncremental(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, historyFileName)
	h := newHistoryLog(dir, nil)

	h.append(agent.SessionEvent{UnixTime: 1, Kind: agent.KindUnlock})
	off, first := readNewEvents(path, 0)
	if len(first) != 1 || first[0].Kind != agent.KindUnlock {
		t.Fatalf("first read = %+v, want the one unlock", first)
	}

	h.append(agent.SessionEvent{UnixTime: 2, Kind: agent.KindLock})
	off2, second := readNewEvents(path, off)
	if len(second) != 1 || second[0].Kind != agent.KindLock {
		t.Fatalf("second read = %+v, want only the new lock", second)
	}

	if _, none := readNewEvents(path, off2); len(none) != 0 {
		t.Errorf("an unchanged file returned %d events, want 0", len(none))
	}
}

// With an already-cancelled context, follow must still print the initial
// matching tail before it returns, so `--follow` on an idle machine shows the
// recent history rather than a blank screen.
func TestFollowPrintsInitialTail(t *testing.T) {
	home := withFixtureHome(t)
	seedAuditFixtures(t, home)
	root := filepath.Join(home, "Library", "Application Support", "jitpass")
	commands := auditlog.New(root, io.Discard).Load(0)
	events := newHistoryLog(root, io.Discard).load(1 << 30)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var buf bytes.Buffer
	if err := followAuditLog(ctx, &buf, root, commands, events, auditFilter{}, 50); err != nil {
		t.Fatalf("followAuditLog: %v", err)
	}
	if !strings.Contains(buf.String(), "kind=unlock") {
		t.Errorf("follow printed no initial tail, got:\n%s", buf.String())
	}
}
