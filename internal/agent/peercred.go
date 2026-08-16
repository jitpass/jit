// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

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
// xucredVersion is XUCRED_VERSION from <sys/ucred.h>, the layout version the
// kernel stamps into every xucred it fills (cru2x sets it unconditionally).
// Written out here because golang.org/x/sys/unix defines the STRUCT but
// exports no constant for its version, and TestVerifyPeerUIDAcceptsARealPeer
// proves the value against a live socket rather than trusting this comment —
// a wrong constant here would fail every connection closed, which is the one
// failure mode worse than the check being absent.
const xucredVersion = 0

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

	// Check the struct version BEFORE trusting any field in it. The kernel
	// fills Xucred per its own layout, and this code reads Uid at whatever
	// offset the Go definition puts it; a future layout the runtime does not
	// match would have us comparing some other word against our uid and
	// possibly liking the answer. The uid gate is the one thing standing
	// between another user's process and this agent's unlocked session, so
	// it fails closed on a struct it does not recognize rather than
	// interpreting bytes whose meaning it cannot vouch for.
	if xucred.Version != xucredVersion {
		return fmt.Errorf("peer credentials have version %d, want %d", xucred.Version, xucredVersion)
	}
	if int(xucred.Uid) != os.Getuid() {
		return fmt.Errorf("peer uid %d does not match this agent's uid %d", xucred.Uid, os.Getuid())
	}
	return nil
}

// peerPID returns the pid of conn's peer, via LOCAL_PEERPID — the same
// getsockopt family verifyPeerUID above already uses, on the same fd, one
// option number over.
//
// Strictly for explaining and auditing (who asked for this unlock, so the
// Touch ID prompt and `jit agent status` can say), NEVER for deciding.
// LOCAL_PEERPID is captured at connect time, but a process can exec a
// different program afterwards, and pids get reused — so "the caller looked
// like jit run" is an observation, not a guarantee, and any check built on
// it would be trivially defeated. verifyPeerUID (uid, an actual security
// boundary) remains the only thing that gates access to this socket.
func peerPID(conn net.Conn) (int32, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("not a unix socket connection")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("getting raw connection: %w", err)
	}

	var pid int
	var sockErr error
	if ctrlErr := raw.Control(func(fd uintptr) {
		pid, sockErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	}); ctrlErr != nil {
		return 0, fmt.Errorf("reading peer pid: %w", ctrlErr)
	}
	if sockErr != nil {
		return 0, fmt.Errorf("LOCAL_PEERPID failed: %w", sockErr)
	}
	return int32(pid), nil // #nosec G115 -- LOCAL_PEERPID returns a pid_t, which is int32 on darwin; GetsockoptInt merely widened it, so narrowing back cannot lose bits
}
