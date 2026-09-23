// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/auditlog"
)

// auditTestRoot points vaultRootDir at a config root short enough for a unix
// socket path (sun_path caps at 104 bytes, and t.TempDir's name-derived path
// overruns it), returning the root.
func auditTestRoot(t *testing.T) string {
	t.Helper()
	home := filepath.Join("/tmp", fmt.Sprintf("jit-auditcli-%d-%d", os.Getpid(), time.Now().UnixNano()))
	root := filepath.Join(home, "Library", "Application Support", "jitpass")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	t.Setenv("HOME", home)
	return root
}

// startAuditService runs a real agent on root's socket for the test's life.
func startAuditService(t *testing.T, root string) {
	t.Helper()
	s := agent.NewServer(agent.SocketPath(root), func() agent.MEKFetcher {
		// Never called: nothing in these tests unlocks, which is itself part
		// of what they assert.
		t.Error("audit path reached for the master key, want no unlock")
		return nil
	}, time.Minute)
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Serve(ctx) }()
	t.Cleanup(func() { cancel(); _ = s.Close(); <-done })
}

// TestAuditGoesThroughTheServiceWhenItIsUp is the routing assertion: with a
// service listening, the record is written by IT rather than by this process
// — which is the whole point, since a sandboxed caller can reach the socket
// but not the config directory.
func TestAuditGoesThroughTheServiceWhenItIsUp(t *testing.T) {
	root := auditTestRoot(t)
	startAuditService(t, root)

	if !auditViaService(root, auditlog.Record{Command: "jit status", Success: true}) {
		t.Fatal("auditViaService = false with a service listening, want the record routed through it")
	}
	recs := auditlog.New(root, os.Stderr).Load(0)
	if len(recs) != 1 || recs[0].Command != "jit status" {
		t.Fatalf("audit log = %+v, want the one routed record", recs)
	}
}

// TestAuditFallsBackWhenTheServiceIsDown is the regression control that
// matters most: preferring the service must not LOSE records when there is no
// service. Every machine without one — and every command run while it is
// restarting — depends on this path.
func TestAuditFallsBackWhenTheServiceIsDown(t *testing.T) {
	root := auditTestRoot(t)
	// Deliberately no service.

	if auditViaService(root, auditlog.Record{Command: "jit status"}) {
		t.Error("auditViaService = true with nothing listening, want false")
	}

	appendAuditRecord(root, auditlog.Record{Command: "jit scan", Success: true})
	recs := auditlog.New(root, os.Stderr).Load(0)
	if len(recs) != 1 || recs[0].Command != "jit scan" {
		t.Fatalf("audit log = %+v, want the record written directly", recs)
	}
}

// TestAuditRecordIsWrittenExactlyOnce guards the double-write the two paths
// invite: a service that accepted the record must stop the direct write, or
// every command on a healthy machine lands in the trail twice.
func TestAuditRecordIsWrittenExactlyOnce(t *testing.T) {
	root := auditTestRoot(t)
	startAuditService(t, root)

	appendAuditRecord(root, auditlog.Record{Command: "jit vault get", Success: true})

	recs := auditlog.New(root, os.Stderr).Load(0)
	if len(recs) != 1 {
		t.Fatalf("audit log holds %d records after one append, want exactly 1: %+v", len(recs), recs)
	}
}

// TestServiceDoesNotAuditThroughItself pins the re-entrancy guard. The
// service's own invocation record must never become a request into the socket
// it owns and is closing; it takes the direct write like any other process
// would when no service is reachable.
func TestServiceDoesNotAuditThroughItself(t *testing.T) {
	root := auditTestRoot(t)
	startAuditService(t, root)

	// Both spellings: old launchd plists still exec the deprecated alias,
	// which delegates to the same body.
	for _, cmd := range []string{"jit service run", "jit agent run"} {
		if auditViaService(root, auditlog.Record{Command: cmd}) {
			t.Errorf("%q routed its record through the socket it owns, want the direct write", cmd)
		}
	}

	// And the record still reaches the log by the other path.
	appendAuditRecord(root, auditlog.Record{Command: "jit service run", Success: true})
	if recs := auditlog.New(root, os.Stderr).Load(0); len(recs) != 1 {
		t.Fatalf("audit log holds %d records, want the service's own record written directly", len(recs))
	}

	// The guard must be scoped to the service's OWN record, not to any
	// command run while a service happens to be listening — otherwise it
	// would quietly switch every invocation back to the direct write and
	// undo the whole change.
	if !auditViaService(root, auditlog.Record{Command: "jit status"}) {
		t.Error("an ordinary command was pushed onto the direct write by the self-write guard")
	}
}
