// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package agent

import (
	"net"
	"path/filepath"
	"testing"
)

// verifyPeerUID is the gate between another user's process and this agent's
// unlocked session, and it now refuses any xucred whose layout version it
// does not recognize. That check is only safe if the version the kernel
// actually stamps matches the constant — a mismatch would fail EVERY
// connection closed, wedging the agent completely, which is worse than the
// check not existing. So this drives a real unix socket rather than asserting
// the constant against itself: it would have caught the value being wrong,
// and it will catch a future x/sys struct layout that shifts the field.
func TestVerifyPeerUIDAcceptsARealPeer(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "s.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	errc := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		defer conn.Close()
		errc <- verifyPeerUID(conn)
	}()

	client, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	if err := <-errc; err != nil {
		t.Fatalf("verifyPeerUID rejected this process's own connection: %v", err)
	}
}
