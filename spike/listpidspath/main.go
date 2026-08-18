// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// Spike: is proc_listpidspath(3) a cheaper way to answer "which pids hold
// this FIFO open" than internal/lineage's own pid-table walk?
//
// The hope (from the audit-attribution work, PRs #83-#85): a single libproc
// call that the kernel answers directly would shrink the reader scan from
// milliseconds to microseconds, letting the serve path relax its 2s
// per-mount rate limit. The doubt: Apple's Libc source suggests
// proc_listpidspath is implemented in USERSPACE as the very same
// enumerate-all-pids + per-pid-fd walk, in which case it saves nothing but
// the Go-side loop. This spike settles it with numbers: correctness on a
// real FIFO reader, then wall-clock over N iterations of both approaches.
//
// Usage:
//
//	go build -o spike . && ./spike -iterations 50
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
	"unsafe"
)

/*
#include <libproc.h>
#include <stdlib.h>
#include <sys/proc_info.h>
#include <sys/vnode.h>

static int list_pids_with_path(const char *path, pid_t *buf, int bufsize) {
	return proc_listpidspath(PROC_ALL_PIDS, 0, path, 0, buf, bufsize);
}

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

static int is_fifo(uint32_t vtype) {
	return vtype == VFIFO;
}
*/
import "C"

// viaListPidsPath asks proc_listpidspath directly.
func viaListPidsPath(path string) []int32 {
	buf := make([]C.pid_t, 4096)
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	n := C.list_pids_with_path(cpath, &buf[0], C.int(len(buf))*C.int(unsafe.Sizeof(buf[0])))
	if n <= 0 {
		return nil
	}
	count := int(n) / int(unsafe.Sizeof(buf[0]))
	out := make([]int32, 0, count)
	for i := 0; i < count; i++ {
		if buf[i] != 0 {
			out = append(out, int32(buf[i]))
		}
	}
	return out
}

// viaFullWalk is internal/lineage's IdentifyFIFOReader shape: every pid,
// every vnode fd, match resolved path + VFIFO.
func viaFullWalk(path string) []int32 {
	pids := make([]C.pid_t, 8192)
	n := C.list_all_pids(&pids[0], C.int(len(pids))*C.int(unsafe.Sizeof(pids[0])))
	if n <= 0 {
		return nil
	}
	count := int(n) / int(unsafe.Sizeof(pids[0]))
	var out []int32
	fdbuf := make([]C.struct_proc_fdinfo, 4096)
	for i := 0; i < count; i++ {
		pid := pids[i]
		if pid <= 0 {
			continue
		}
		fn := C.list_fds(pid, &fdbuf[0], C.int(len(fdbuf))*C.int(unsafe.Sizeof(fdbuf[0])))
		if fn <= 0 {
			continue
		}
		fdcount := int(fn) / int(unsafe.Sizeof(fdbuf[0]))
		for j := 0; j < fdcount; j++ {
			if C.is_vnode_type(fdbuf[j].proc_fdtype) == 0 {
				continue
			}
			var info C.struct_vnode_fdinfowithpath
			if C.get_vnode_info(pid, C.int32_t(fdbuf[j].proc_fd), &info) <= 0 {
				continue
			}
			if C.is_fifo(C.uint32_t(info.pvip.vip_vi.vi_type)) == 0 {
				continue
			}
			if C.GoString(&info.pvip.vip_path[0]) == path {
				out = append(out, int32(pid))
			}
		}
	}
	return out
}

func contains(pids []int32, want int32) bool {
	for _, p := range pids {
		if p == want {
			return true
		}
	}
	return false
}

func main() {
	iterations := flag.Int("iterations", 50, "timing iterations per approach")
	flag.Parse()

	dir, err := os.MkdirTemp("", "listpidspath-spike")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	// Resolve /var -> /private/var the way internal/lineage's resolveTarget
	// does: the fd table reports the resolved spelling, and comparing the
	// unresolved one concludes nothing matches.
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}
	fifo := filepath.Join(dir, "test.fifo")
	if err := exec.Command("mkfifo", fifo).Run(); err != nil {
		panic(err)
	}

	// A real reader: cat blocks in read() once our write-open completes.
	reader := exec.Command("cat", fifo)
	if err := reader.Start(); err != nil {
		panic(err)
	}
	defer func() {
		_ = reader.Process.Kill()
		_, _ = reader.Process.Wait()
	}()
	readerPID := int32(reader.Process.Pid)

	f, err := os.OpenFile(fifo, os.O_WRONLY, 0)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// Let the reader's fd land in the table (the visibility lag the real
	// tests poll around).
	time.Sleep(200 * time.Millisecond)

	// Correctness first.
	lp := viaListPidsPath(fifo)
	fw := viaFullWalk(fifo)
	fmt.Printf("reader pid: %d\n", readerPID)
	fmt.Printf("proc_listpidspath found: %v (reader found: %v)\n", lp, contains(lp, readerPID))
	fmt.Printf("full walk found:         %v (reader found: %v)\n", fw, contains(fw, readerPID))

	// Timing.
	start := time.Now()
	for i := 0; i < *iterations; i++ {
		viaListPidsPath(fifo)
	}
	lpDur := time.Since(start) / time.Duration(*iterations)

	start = time.Now()
	for i := 0; i < *iterations; i++ {
		viaFullWalk(fifo)
	}
	fwDur := time.Since(start) / time.Duration(*iterations)

	fmt.Printf("\nper-scan average over %d iterations:\n", *iterations)
	fmt.Printf("proc_listpidspath: %v\n", lpDur)
	fmt.Printf("full walk:         %v\n", fwDur)
	if lpDur > 0 {
		fmt.Printf("ratio (walk/listpidspath): %.1fx\n", float64(fwDur)/float64(lpDur))
	}
}
