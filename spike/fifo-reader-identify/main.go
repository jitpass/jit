// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// Command fifo-reader-identify-spike investigates GAPS.md #2 / RFC.md B10: can
// jit identify, from userspace and *without root or a special entitlement*,
// which process just opened a live-mounted FIFO for reading? If so, that PID
// (and its parent-process ancestry) could feed the same trusted/unrecognized
// classification RFC.md §5.1 already describes for jit run (Tier 1), giving
// Tier 3 a cheap partial answer without waiting on Apple's Endpoint Security
// entitlement (see spike/fifo-reader-identify/FINDINGS.md's ES section).
//
// Mechanism under test: libproc(3) — proc_listpids -> proc_pidinfo(PROC_PIDLISTFDS)
// -> proc_pidfdinfo(PROC_PIDFDVNODEPATHINFO), scanning every same-user process's
// open vnode fds for one whose path matches the FIFO and whose type is VFIFO.
//
// Not production code — throwaway.
package main

/*
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/vnode.h>
#include <errno.h>

static int list_all_pids(pid_t *buf, int bufsize) {
	return proc_listpids(PROC_ALL_PIDS, 0, buf, bufsize);
}

static int list_fds(pid_t pid, struct proc_fdinfo *buf, int bufsize) {
	return proc_pidinfo(pid, PROC_PIDLISTFDS, 0, buf, bufsize);
}

static int get_vnode_info(pid_t pid, int32_t fd, struct vnode_fdinfowithpath *out) {
	return proc_pidfdinfo(pid, fd, PROC_PIDFDVNODEPATHINFO, out, sizeof(*out));
}

static int is_vnode_type(uint32_t fdtype) {
	return fdtype == PROX_FDTYPE_VNODE;
}

static int is_fifo_vtype(int vtype) {
	return vtype == VFIFO;
}
*/
import "C"

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"
)

func main() {
	mode := flag.String("mode", "", "server|reader|noread-reader")
	path := flag.String("path", "", "FIFO path")
	iterations := flag.Int("iterations", 1, "server: how many re-open cycles to serve")
	scanDelayMs := flag.Int("scan-delay-ms", 0, "server: artificial delay before scanning, to widen the race window")
	flag.Parse()

	switch *mode {
	case "server":
		runServer(*path, *iterations, *scanDelayMs)
	case "reader":
		runReader(*path, true)
	case "noread-reader":
		// Opens and immediately closes without reading — the adversarial
		// race case: does the reader's fd disappear before we can scan it?
		runReader(*path, false)
	default:
		fmt.Fprintln(os.Stderr, "usage: -mode server|reader|noread-reader -path <fifo>")
		os.Exit(2)
	}
}

func runServer(path string, iterations, scanDelayMs int) {
	if _, err := os.Stat(path); err == nil {
		_ = os.Remove(path)
	}
	if err := syscall.Mkfifo(path, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "[server] mkfifo failed: %v\n", err)
		os.Exit(1)
	}
	defer os.Remove(path)

	fmt.Printf("[server] serving %s, own pid=%d, %d iteration(s)\n", path, os.Getpid(), iterations)

	for i := 0; i < iterations; i++ {
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[server] iter %d: open for write failed: %v\n", i, err)
			os.Exit(1)
		}
		opened := time.Now()

		if scanDelayMs > 0 {
			time.Sleep(time.Duration(scanDelayMs) * time.Millisecond)
		}

		pid, openFlags, scanErr := findReaderPID(path)
		elapsed := time.Since(opened)
		if scanErr != nil {
			fmt.Printf("[server] iter %d: reader NOT IDENTIFIED after %v: %v\n", i, elapsed, scanErr)
		} else {
			fmt.Printf("[server] iter %d: identified reader pid=%d openflags=0x%x after %v\n", i, pid, openFlags, elapsed)
		}

		payload := fmt.Sprintf("iteration-%d-payload\n", i)
		if _, err := f.WriteString(payload); err != nil {
			fmt.Fprintf(os.Stderr, "[server] iter %d: write failed (non-fatal, matches internal/mount's onError convention): %v\n", i, err)
		}
		if err := f.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "[server] iter %d: close failed (non-fatal): %v\n", i, err)
		}
	}
}

func runReader(path string, doRead bool) {
	fmt.Printf("[reader] self pid=%d, doRead=%v\n", os.Getpid(), doRead)
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[reader] open failed: %v\n", err)
		os.Exit(1)
	}
	if doRead {
		buf := make([]byte, 4096)
		n, _ := f.Read(buf)
		fmt.Printf("[reader] read %q\n", string(buf[:n]))
	}
	f.Close()
}

// findReaderPID scans every other same-privilege process's open vnode file
// descriptors for one matching path with vnode type VFIFO, returning its PID
// and the raw fi_openflags value (informational — used to sanity-check that
// the match really is the read side, not some unrelated fd).
func findReaderPID(path string) (int32, uint32, error) {
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		target = path
	}
	target, err = filepath.Abs(target)
	if err != nil {
		target = path
	}

	pids, err := listAllPIDs()
	if err != nil {
		return 0, 0, fmt.Errorf("proc_listpids: %w", err)
	}

	self := int32(os.Getpid())
	var scannedCount int
	errnoTally := map[syscall.Errno]int{}

	for _, pid := range pids {
		if pid == self || pid <= 0 {
			continue
		}
		fds, errno, err := listVnodeFDs(pid)
		if err != nil {
			errnoTally[errno]++
			continue
		}
		scannedCount++
		for _, fd := range fds {
			p, vtype, openFlags, err := vnodeInfo(pid, fd)
			if err != nil {
				continue
			}
			if vtype != C.VFIFO {
				continue
			}
			if p == target {
				return pid, openFlags, nil
			}
		}
	}
	return 0, 0, fmt.Errorf("no matching FIFO reader found among %d scannable processes (errno tally: %v)", scannedCount, errnoTally)
}

func listAllPIDs() ([]int32, error) {
	const maxPIDs = 8192
	buf := make([]C.pid_t, maxPIDs)
	n := C.list_all_pids(&buf[0], C.int(len(buf))*C.int(unsafe.Sizeof(buf[0])))
	if n <= 0 {
		return nil, errors.New("proc_listpids returned 0")
	}
	count := int(n) / int(unsafe.Sizeof(buf[0]))
	if count > len(buf) {
		count = len(buf)
	}
	out := make([]int32, 0, count)
	for i := 0; i < count; i++ {
		if buf[i] != 0 {
			out = append(out, int32(buf[i]))
		}
	}
	return out, nil
}

func listVnodeFDs(pid int32) ([]int32, syscall.Errno, error) {
	const maxFDs = 4096
	buf := make([]C.struct_proc_fdinfo, maxFDs)
	n, errno := C.list_fds(C.pid_t(pid), &buf[0], C.int(len(buf))*C.int(unsafe.Sizeof(buf[0])))
	if n <= 0 {
		e, _ := errno.(syscall.Errno)
		return nil, e, fmt.Errorf("proc_pidinfo(PROC_PIDLISTFDS) failed for pid %d (errno=%v)", pid, errno)
	}
	count := int(n) / int(unsafe.Sizeof(buf[0]))
	if count > len(buf) {
		count = len(buf)
	}
	out := make([]int32, 0, count)
	for i := 0; i < count; i++ {
		if C.is_vnode_type(buf[i].proc_fdtype) != 0 {
			out = append(out, int32(buf[i].proc_fd))
		}
	}
	return out, 0, nil
}

func vnodeInfo(pid, fd int32) (path string, vtype int32, openFlags uint32, err error) {
	var info C.struct_vnode_fdinfowithpath
	n := C.get_vnode_info(C.pid_t(pid), C.int32_t(fd), &info)
	if n <= 0 {
		return "", 0, 0, fmt.Errorf("proc_pidfdinfo failed")
	}
	path = C.GoString(&info.pvip.vip_path[0])
	vtype = int32(info.pvip.vip_vi.vi_type)
	openFlags = uint32(info.pfi.fi_openflags)
	return path, vtype, openFlags, nil
}