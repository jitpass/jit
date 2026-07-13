// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package agent

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// verifyPeerUID confirms conn's peer is running as the same OS user as this
// process, using Darwin's LOCAL_PEERCRED socket option — the mechanism
// confirmed working in spike/unix-socket-peercred/. Rejecting anything
// else is the socket-level access-control boundary RFC.md Pillar II/III
// assumes jit-agent enforces before releasing anything from the session
// cache: a different user on a shared machine must never be able to reach
// this agent's socket at all, regardless of file permissions on the
// socket path (which are also restricted, but this is defense in depth,
// not the only check).
func verifyPeerUID(conn net.Conn) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("not a unix socket connection")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("getting raw connection: %w", err)
	}

	var xucred *unix.Xucred
	var xucredErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		xucred, xucredErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	})
	if ctrlErr != nil {
		return fmt.Errorf("reading peer credentials: %w", ctrlErr)
	}
	if xucredErr != nil {
		return fmt.Errorf("LOCAL_PEERCRED failed: %w", xucredErr)
	}

	if int(xucred.Uid) != os.Getuid() {
		return fmt.Errorf("peer uid %d does not match this agent's uid %d", xucred.Uid, os.Getuid())
	}
	return nil
}
