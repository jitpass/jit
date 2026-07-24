// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// Command unix-socket-peercred-spike confirms that jit-agent can verify which
// process/user is on the other end of its Unix domain socket before releasing
// anything from the session cache (RFC.md Pillar II/III's socket-level security
// boundary). Darwin doesn't have Linux's SO_PEERCRED/ucred (uid+gid+pid in one
// call) — it splits this into LOCAL_PEERCRED (uid/gid via a struct xucred) and
// the separate, Darwin-only LOCAL_PEERPID (pid). This spike proves both work
// from Go via golang.org/x/sys/unix and that the reported values are correct.
//
// Not production code — throwaway or to be promoted into internal/agent later.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func main() {
	mode := flag.String("mode", "", "server|client")
	path := flag.String("path", "", "unix socket path")
	flag.Parse()

	switch *mode {
	case "server":
		runServer(*path)
	case "client":
		runClient(*path)
	default:
		fmt.Fprintln(os.Stderr, "usage: -mode server|client -path <path>")
		os.Exit(2)
	}
}

func runServer(path string) {
	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[server] listen failed: %v\n", err)
		os.Exit(1)
	}
	defer l.Close()
	defer os.Remove(path)

	if err := os.Chmod(path, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "[server] chmod failed: %v\n", err)
	}

	fmt.Printf("[server] listening on %s (own uid=%d, own pid=%d)\n", path, os.Getuid(), os.Getpid())

	conn, err := l.Accept()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[server] accept failed: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		fmt.Fprintln(os.Stderr, "[server] not a unix conn")
		os.Exit(1)
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[server] SyscallConn failed: %v\n", err)
		os.Exit(1)
	}

	var xucred *unix.Xucred
	var xucredErr error
	var peerPID int
	var peerPIDErr error

	err = raw.Control(func(fd uintptr) {
		xucred, xucredErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		peerPID, peerPIDErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[server] raw.Control failed: %v\n", err)
		os.Exit(1)
	}

	if xucredErr != nil {
		fmt.Printf("[server] LOCAL_PEERCRED FAILED: %v\n", xucredErr)
	} else {
		fmt.Printf("[server] LOCAL_PEERCRED OK: peer uid=%d (version=%d)\n", xucred.Uid, xucred.Version)
	}

	if peerPIDErr != nil {
		fmt.Printf("[server] LOCAL_PEERPID FAILED: %v\n", peerPIDErr)
	} else {
		fmt.Printf("[server] LOCAL_PEERPID OK: peer pid=%d\n", peerPID)
	}

	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	fmt.Printf("[server] client self-reported: %s\n", string(buf[:n]))

	if peerPIDErr == nil {
		claimed := string(buf[:n])
		fmt.Printf("[server] cross-check: does LOCAL_PEERPID (%d) match what the client claims? see above\n", peerPID)
		_ = claimed
	}
}

func runClient(path string) {
	// Give the server a moment to start listening.
	var conn net.Conn
	var err error
	for i := 0; i < 20; i++ {
		conn, err = net.Dial("unix", path)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[client] dial failed: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	self := fmt.Sprintf("client pid=%d uid=%d", os.Getpid(), os.Getuid())
	fmt.Printf("[client] connected, reporting: %s\n", self)
	_, _ = conn.Write([]byte(self))
	time.Sleep(200 * time.Millisecond) // give server time to read before we exit
}