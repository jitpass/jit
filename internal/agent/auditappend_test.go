// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package agent

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/auditlog"
)

// shortRoot is a config root under /tmp rather than t.TempDir(). Same reason
// shortSocketPath exists: a unix socket path is capped at 104 bytes by
// sun_path, and the temp dir Go hands a test (which embeds the test's own
// name) blows straight past it — bind then fails with "invalid argument",
// which reads like a code bug rather than a path-length one.
func shortRoot(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("/tmp", fmt.Sprintf("jit-audit-%d-%d", os.Getpid(), time.Now().UnixNano()))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// auditServer stands up a server whose socket lives in its own config root,
// so the audit log the handler writes is this test's and not the developer's.
// Returns the root and a client.
func auditServer(t *testing.T) (root string, c *Client) {
	t.Helper()
	root = shortRoot(t)
	path := SocketPath(root)

	s := NewServer(path, func() MEKFetcher {
		return &fakeFetcher{key: bytes.Repeat([]byte{0x42}, 32)}
	}, time.Minute)
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Serve(ctx) }()
	t.Cleanup(func() { cancel(); _ = s.Close(); <-done })

	return root, NewClient(path)
}

// TestAuditAppendWritesThroughTheAgent is the point of the op: a caller that
// never touches the config directory still lands a record in the audit log,
// because the agent does the writing.
func TestAuditAppendWritesThroughTheAgent(t *testing.T) {
	root, c := auditServer(t)

	if err := c.AuditAppend(auditlog.Record{
		Command:    "jit vault get",
		Args:       []string{"vault", "get", "npm/token"},
		User:       "tester",
		DurationMS: 7,
		Success:    true,
	}); err != nil {
		t.Fatalf("AuditAppend: %v", err)
	}

	// Read it back the way `jit audit` does, from the path the CLI would use.
	recs := auditlog.New(root, os.Stderr).Load(0)
	if len(recs) != 1 {
		t.Fatalf("audit log holds %d records, want 1", len(recs))
	}
	got := recs[0]
	if got.Command != "jit vault get" {
		t.Errorf("Command = %q, want the caller's", got.Command)
	}
	if len(got.Args) != 3 || got.Args[2] != "npm/token" {
		t.Errorf("Args = %v, want the caller's", got.Args)
	}
	if got.User != "tester" || got.DurationMS != 7 || !got.Success {
		t.Errorf("the caller's own account of itself was not preserved: %+v", got)
	}

	// And it really went to the agent's root, by the socket's directory —
	// not to some path assembled a second way.
	if _, err := os.Stat(filepath.Join(root, auditlog.FileName)); err != nil {
		t.Errorf("audit log not at the root the socket lives in: %v", err)
	}
}

// TestAuditAppendStampsWhatTheKernelVouchesFor pins the trust boundary: the
// three fields the agent can verify are re-stamped over whatever the request
// claimed, and the rest is left alone. A caller that lies about its uid or pid
// must not get that lie into the trail.
func TestAuditAppendStampsWhatTheKernelVouchesFor(t *testing.T) {
	root, c := auditServer(t)

	before := time.Now().UnixNano()
	if err := c.AuditAppend(auditlog.Record{
		Command:  "jit run",
		UID:      31337,            // a lie
		PID:      999999,           // a lie
		UnixNano: 1,                // a lie
		PPID:     os.Getppid(),     // not verifiable, kept as sent
		Parent:   "definitely-zsh", // not verifiable, kept as sent
	}); err != nil {
		t.Fatalf("AuditAppend: %v", err)
	}
	after := time.Now().UnixNano()

	recs := auditlog.New(root, os.Stderr).Load(0)
	if len(recs) != 1 {
		t.Fatalf("audit log holds %d records, want 1", len(recs))
	}
	got := recs[0]

	if got.UID != os.Getuid() {
		t.Errorf("UID = %d, want the peercred-proved %d: a claimed uid must not reach the trail", got.UID, os.Getuid())
	}
	if got.PID != os.Getpid() {
		t.Errorf("PID = %d, want the socket peer's %d: a claimed pid must not reach the trail", got.PID, os.Getpid())
	}
	if got.UnixNano < before || got.UnixNano > after {
		t.Errorf("UnixNano = %d, want the agent's own receipt time in [%d,%d]", got.UnixNano, before, after)
	}

	// The unverifiable half is deliberately untouched — this op is about
	// reaching the log, not about trusting its contents more than the direct
	// write did.
	if got.PPID != os.Getppid() || got.Parent != "definitely-zsh" {
		t.Errorf("the caller's unverifiable fields were rewritten: %+v", got)
	}
}

// TestAuditAppendRefusesEmptyRecords keeps the op from making the trail worse
// than the dropped events it exists to prevent: a blank line in `jit audit` is
// not an improvement on a missing one.
func TestAuditAppendRefusesEmptyRecords(t *testing.T) {
	root, c := auditServer(t)

	if err := c.AuditAppend(auditlog.Record{}); err == nil {
		t.Error("AuditAppend with no command succeeded, want an error")
	}
	// The nil-record shape can't be sent through AuditAppend, which always
	// takes a value, so it goes over the wire directly.
	if _, err := c.call(Request{Op: OpAuditAppend}); err == nil {
		t.Error("audit_append with no record succeeded, want a refusal")
	}

	if recs := auditlog.New(root, os.Stderr).Load(0); len(recs) != 0 {
		t.Errorf("refused appends still wrote %d records, want 0", len(recs))
	}
}

// TestAuditAppendNeedsNoUnlock pins the property the op shares with history:
// recording that a command ran must never itself raise a Touch ID prompt. The
// fetcher counts challenges, so a handler that reached for the session would
// show up here as a non-zero count.
func TestAuditAppendNeedsNoUnlock(t *testing.T) {
	path := SocketPath(shortRoot(t))

	var calls int32
	s := NewServer(path, func() MEKFetcher {
		return &fakeFetcher{key: bytes.Repeat([]byte{0x42}, 32), calls: &calls}
	}, time.Minute)
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Serve(ctx) }()
	defer func() { cancel(); _ = s.Close(); <-done }()

	if err := NewClient(path).AuditAppend(auditlog.Record{Command: "jit status"}); err != nil {
		t.Fatalf("AuditAppend on a LOCKED agent: %v", err)
	}
	if n := atomic.LoadInt32(&calls); n != 0 {
		t.Errorf("audit_append raised %d challenges, want 0: logging a command must never prompt", n)
	}
}

// TestAuditAppendRedactsOnTheServer pins the defence-in-depth mask: a client
// that forgot to redact must not get a token into the trail through this op.
func TestAuditAppendRedactsOnTheServer(t *testing.T) {
	root, c := auditServer(t)

	const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	if err := c.AuditAppend(auditlog.Record{
		Command: "jit vault set",
		Args:    []string{"vault", "set", "gh/token", token},
		Error:   "rejected " + token,
	}); err != nil {
		t.Fatalf("AuditAppend: %v", err)
	}
	// The raw bytes for the leak check: json.Marshal escapes "<" to \u003c,
	// so the MARKER can't be grepped for here, but a token has no such
	// characters and a leak would be verbatim.
	raw, err := os.ReadFile(filepath.Join(root, auditlog.FileName))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if bytes.Contains(raw, []byte(token)) {
		t.Errorf("the token reached the audit log unmasked:\n%s", raw)
	}
	// The decoded record for the positive check.
	recs := auditlog.New(root, os.Stderr).Load(0)
	if len(recs) != 1 {
		t.Fatalf("audit log holds %d records, want 1", len(recs))
	}
	if got := recs[0].Args[3]; got != auditlog.RedactToken {
		t.Errorf("Args[3] = %q, want %q", got, auditlog.RedactToken)
	}
	if got := recs[0].Error; got != "rejected "+auditlog.RedactToken {
		t.Errorf("Error = %q, want the token masked", got)
	}
}
