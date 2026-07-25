// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/agent"
)

// TestLivenessProbeLeavesNoAuditTrail wires the agent server to the SAME
// durable history sink agentRunCmd gives it (server.OnServeError ->
// historyLog.append) and then reads the result back through `jit audit`,
// covering the whole chain the running service uses: socket -> serve-error
// sink -> agent-history.jsonl -> the audit reader's own filters.
//
// The bug this pins: Client.Reachable() dials and closes without sending a
// byte, and the server logged that io.EOF as `level=error kind=error
// op=decode reason="bad request: EOF"`. Reachable() runs from a dozen CLI
// paths (run, undo, unmount, vault, migrate remove, rekey), so an ordinary
// `jit run` filed two of them. On a real machine EVERY error event in a
// day's log was this probe — which makes `jit audit --kind error`, the one
// view meant to surface "a process the kernel says isn't yours probed the
// agent", pure noise.
//
// The agent package has its own unit test for the sink call; this one exists
// because the sink is only half the story — what the user actually runs is
// `jit audit --kind error`, and that's what has to come back empty.
func TestLivenessProbeLeavesNoAuditTrail(t *testing.T) {
	home := withFixtureHome(t)
	root := filepath.Join(home, "Library", "Application Support", "jitpass")

	// Not t.TempDir(): it embeds the test's (long) name, and this test's name
	// pushes the path past sockaddr_un's ~104-byte limit — bind(2) then fails
	// with a bare "invalid argument".
	sockDir, err := os.MkdirTemp("", "jsk")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	socketPath := filepath.Join(sockDir, "a.sock")
	mek := bytes.Repeat([]byte{0x24}, 32)
	server := agent.NewServer(socketPath, func() agent.MEKFetcher { return &fakeMEKFetcher{key: mek} }, time.Minute)

	// Exactly agentRunCmd's wiring (see agent.go's OnServeError block).
	var stderr bytes.Buffer
	hist := newHistoryLog(root, &stderr)
	server.OnServeError = func(e agent.SessionEvent) {
		hist.append(e)
		stderr.WriteString("jit service: " + e.Cause + "\n")
	}

	if err := server.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = server.Serve(ctx); close(done) }()
	defer func() { cancel(); _ = server.Close(); <-done }()

	// The probe every `jit run` makes, several times over.
	c := agent.NewClient(socketPath)
	for i := 0; i < 3; i++ {
		if !c.Reachable() {
			t.Fatalf("Reachable() #%d returned false against a listening server", i)
		}
	}
	// Serve handles each connection in its own goroutine; give a stray
	// recordServeError time to land rather than passing on a race.
	time.Sleep(250 * time.Millisecond)

	out, err := execAudit(t, "--kind", "error", "--since", "1h")
	if err != nil {
		t.Fatalf("jit audit: %v", err)
	}
	if strings.Contains(out, "bad request: EOF") {
		t.Errorf("a liveness probe put a security error in the audit log:\n%s", out)
	}
	if strings.TrimSpace(out) != "" && strings.Contains(out, "kind=error") {
		t.Errorf("jit audit --kind error should be empty after only probes, got:\n%s", out)
	}
}
