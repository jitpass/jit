// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

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

// TestReportAgentStatusRefreshesForProducedMount locks the contract behind the
// loose-secret --mount hot-registration fix. `jit migrate <bare-token> --mount`
// registers a live FIFO mount, but the running service only starts serving it
// after an explicit Refresh RPC — its own unlock fires BEFORE the mount is
// registered. The bug: producedMount was recomputed downstream from a
// per-category length list that omitted the loose path, so the Refresh was
// never sent and every reader of the migrated file hung until a manual
// `jit service restart`. The fix sets producedMount at the addMount choke
// point (so no mount category can be missed); this test guards the reporting
// contract that value drives: producedMount=true tells the running service to
// serve now and says so, false does not claim a mount is being served.
//
// A real agent.Server/Client is used (only the Touch ID challenge is stubbed,
// this project's fakeMEKFetcher pattern), so the Refresh actually round-trips.
func TestReportAgentStatusRefreshesForProducedMount(t *testing.T) {
	home := shortFixtureHome(t)
	root := filepath.Join(home, "Library", "Application Support", "jitpass")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	socketPath := agent.SocketPath(root)
	mek := bytes.Repeat([]byte{0x24}, 32)
	server := agent.NewServer(socketPath, func() agent.MEKFetcher { return &fakeMEKFetcher{key: mek} }, time.Minute)
	if err := server.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = server.Serve(ctx); close(done) }()
	defer func() { cancel(); _ = server.Close(); <-done }()

	// OpRefresh serves only an unlocked session; unlock first so the Refresh
	// this exercises succeeds without a real challenge (fakeMEKFetcher).
	if _, _, err := agent.NewClient(socketPath).Unlock(); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	t.Run("producedMount true tells the running service to serve now", func(t *testing.T) {
		var buf bytes.Buffer
		reportAgentStatus(&buf, root, true)
		if !strings.Contains(buf.String(), "now serving the new mount(s)") {
			t.Errorf("a produced mount must be refreshed into the running service with a confirmation, got:\n%s", buf.String())
		}
	})

	t.Run("producedMount false does not claim a mount is being served", func(t *testing.T) {
		var buf bytes.Buffer
		reportAgentStatus(&buf, root, false)
		if strings.Contains(buf.String(), "serving the new mount(s)") {
			t.Errorf("no mount was produced, so nothing should claim to serve one, got:\n%s", buf.String())
		}
	})
}
