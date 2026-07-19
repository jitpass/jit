// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

// Command run-scoped-grant-spike validates the mechanism behind "run-scoped
// reveal": jit run tells the agent to serve REAL mount content only to a
// specific PID's process tree, for the lifetime of that process. Before
// building it, four questions need empirical answers on macOS:
//
//  1. WATCH: does a kqueue EVFILT_PROC/NOTE_EXIT watch registered on a PID
//     *before* that process execve()s survive the exec and fire exactly once
//     at exit? (jit run registers the grant pre-exec; execve keeps the PID.)
//     And is the process's start time (proc_bsdinfo pbi_start_tvsec) stable
//     across exec — usable as a PID-reuse tiebreaker recorded at grant time?
//
//  2. GATE/ancestry: at a FIFO rendezvous, can the writer identify EVERY
//     current reader (not just one) and classify each by walking its ppid
//     ancestry toward the granted root — including a depth-3 chain
//     (sh -c 'sh -c "cat fifo"') under the grant root?
//
//  3. GATE/fail-closed: with an out-of-tree reader holding the FIFO
//     concurrently with an in-tree reader, does the "ALL holders must be
//     in-tree, else decoy" rule actually trigger (i.e. does one rendezvous
//     see both holders)?
//
//  4. GATE/orphan: a granted tree spawning a background reader whose parent
//     exits (reparented to launchd) breaks the ppid chain — confirm it
//     classifies out-of-tree (accepted limitation, fail closed), and record
//     the orphan's pgid vs the grant root's pgid to evaluate a possible
//     process-group fallback signal.
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

static int get_bsd_info(pid_t pid, struct proc_bsdinfo *out) {
	return proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, out, sizeof(*out));
}

static int is_vnode_type(uint32_t fdtype) {
	return fdtype == PROX_FDTYPE_VNODE;
}
*/
import "C"

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func main() {
	mode := flag.String("mode", "", "watch|gate")
	flag.Parse()

	switch *mode {
	case "watch":
		runWatch()
	case "gate":
		runGate()
	default:
		fmt.Fprintln(os.Stderr, "usage: -mode watch|gate")
		os.Exit(2)
	}
}

// ---------- Question 1: EVFILT_PROC across execve + start-time stability ----------

func runWatch() {
	// The child mirrors jit run's shape: a process that will execve() and
	// keep its PID. `sh -c 'exec sleep 0.4'` — sh execs sleep in place.
	cmd := exec.Command("/bin/sh", "-c", "exec /bin/sleep 0.4")
	if err := cmd.Start(); err != nil {
		fatal("start child: %v", err)
	}
	pid := cmd.Process.Pid
	fmt.Printf("[watch] child pid=%d (starts as /bin/sh, will exec /bin/sleep)\n", pid)

	startBefore, comm, err := bsdInfo(int32(pid))
	if err != nil {
		fatal("bsdinfo before exec: %v", err)
	}
	fmt.Printf("[watch] pre-exec:  comm=%q start=%d.%06d\n", comm, startBefore.sec, startBefore.usec)

	kq, err := unix.Kqueue()
	if err != nil {
		fatal("kqueue: %v", err)
	}
	defer unix.Close(kq)

	// Register BEFORE the child execs (racy by construction: the child may
	// have exec'd already — both orders must work, and NOTE_EXEC tells us
	// which one we got).
	registered := time.Now()
	change := unix.Kevent_t{
		Ident:  uint64(pid),
		Filter: unix.EVFILT_PROC,
		Flags:  unix.EV_ADD | unix.EV_ENABLE,
		Fflags: unix.NOTE_EXIT | unix.NOTE_EXEC,
	}
	if _, err := unix.Kevent(kq, []unix.Kevent_t{change}, nil, nil); err != nil {
		fatal("kevent register: %v", err)
	}

	sawExec, sawExit := false, false
	for !sawExit {
		events := make([]unix.Kevent_t, 4)
		n, err := unix.Kevent(kq, nil, events, &unix.Timespec{Sec: 5})
		if err != nil {
			fatal("kevent wait: %v", err)
		}
		if n == 0 {
			fatal("timed out waiting for EVFILT_PROC events (exit never delivered?)")
		}
		for _, ev := range events[:n] {
			if ev.Filter != unix.EVFILT_PROC || ev.Ident != uint64(pid) {
				continue
			}
			if ev.Fflags&unix.NOTE_EXEC != 0 {
				sawExec = true
				startAfter, commAfter, err := bsdInfo(int32(pid))
				if err != nil {
					fmt.Printf("[watch] NOTE_EXEC at +%v (bsdinfo after exec failed: %v)\n", time.Since(registered), err)
				} else {
					fmt.Printf("[watch] NOTE_EXEC at +%v: comm=%q start=%d.%06d (stable=%v)\n",
						time.Since(registered), commAfter, startAfter.sec, startAfter.usec,
						startAfter == startBefore)
				}
			}
			if ev.Fflags&unix.NOTE_EXIT != 0 {
				sawExit = true
				fmt.Printf("[watch] NOTE_EXIT at +%v (exit status in ev.Data: %d)\n", time.Since(registered), ev.Data)
			}
		}
	}
	_ = cmd.Wait()
	fmt.Printf("[watch] RESULT: NOTE_EXEC seen=%v, NOTE_EXIT delivered=%v (watch registered pre-exec survived the exec)\n",
		sawExec, sawExit)

	// Second half: registering AFTER the exec must work too (jit run's RPC
	// lands pre-exec, but the agent may process it after — both orders real).
	cmd2 := exec.Command("/bin/sleep", "0.2")
	if err := cmd2.Start(); err != nil {
		fatal("start child2: %v", err)
	}
	pid2 := cmd2.Process.Pid
	change2 := unix.Kevent_t{
		Ident:  uint64(pid2),
		Filter: unix.EVFILT_PROC,
		Flags:  unix.EV_ADD | unix.EV_ENABLE,
		Fflags: unix.NOTE_EXIT,
	}
	if _, err := unix.Kevent(kq, []unix.Kevent_t{change2}, nil, nil); err != nil {
		fatal("kevent register post-exec: %v", err)
	}
	events := make([]unix.Kevent_t, 2)
	n, err := unix.Kevent(kq, nil, events, &unix.Timespec{Sec: 5})
	if err != nil || n == 0 {
		fatal("post-exec-registration NOTE_EXIT not delivered (n=%d err=%v)", n, err)
	}
	fmt.Printf("[watch] RESULT: registration on an already-exec'd pid also delivers NOTE_EXIT (pid=%d)\n", pid2)
	_ = cmd2.Wait()
}

// ---------- Questions 2-4: the per-rendezvous ancestry gate ----------

const (
	realPayload  = "REAL_SECRET_VALUE\n"
	decoyPayload = "jit-hidden-DECOY\n"
)

type verdict struct {
	scenario string
	served   string // "REAL" or "DECOY"
	expect   string
	holders  []holderInfo
	scanTime time.Duration
}

type holderInfo struct {
	pid    int32
	comm   string
	inTree bool
	pgid   int32
}

func runGate() {
	dir, err := os.MkdirTemp("", "grant-spike")
	if err != nil {
		fatal("mktemp: %v", err)
	}
	defer os.RemoveAll(dir)
	fifo := filepath.Join(dir, "grant.env")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		fatal("mkfifo: %v", err)
	}

	// The "granted run": a long-lived sh standing in for jit run's
	// post-exec target. It executes one command per stdin line, so each
	// scenario's readers are its real children/grandchildren.
	feeder := newLineFeeder()
	grant := exec.Command("/bin/sh", "-s")
	grant.Stdin = feeder
	grant.Stdout = os.Stdout
	grant.Stderr = os.Stderr
	if err := grant.Start(); err != nil {
		fatal("start grant root: %v", err)
	}
	grantRoot := int32(grant.Process.Pid)
	fmt.Printf("[gate] fifo=%s spike pid=%d(pgid %d) grant root pid=%d(pgid %d)\n",
		fifo, os.Getpid(), mustPgid(int32(os.Getpid())), grantRoot, mustPgid(grantRoot))

	var results []verdict

	// Scenario 1: depth-1 in-tree reader (cat is a direct child of the root).
	feeder.feed("/bin/cat " + fifo + "\n")
	results = append(results, serveOnce(fifo, grantRoot, "depth-1 child", "REAL"))

	// Scenario 2: depth-3 in-tree chain (root -> sh -> sh -> cat).
	feeder.feed("/bin/sh -c '/bin/sh -c \"/bin/cat " + fifo + "\"'\n")
	results = append(results, serveOnce(fifo, grantRoot, "depth-3 descendant", "REAL"))

	// Scenario 3: out-of-tree stranger — direct child of the SPIKE process
	// (the grant root's parent), so its ancestry passes beside the root,
	// never through it.
	stranger := exec.Command("/bin/cat", fifo)
	if err := stranger.Start(); err != nil {
		fatal("start stranger: %v", err)
	}
	results = append(results, serveOnce(fifo, grantRoot, "out-of-tree stranger", "DECOY"))
	_ = stranger.Wait()

	// Scenario 4: orphaned descendant — the grant tree backgrounds a cat
	// inside a subshell that exits immediately; the cat reparents away.
	feeder.feed("( /bin/cat " + fifo + " & )\n")
	time.Sleep(200 * time.Millisecond) // let the subshell exit so reparenting happens
	results = append(results, serveOnce(fifo, grantRoot, "orphaned descendant", "DECOY"))

	// Scenario 5: concurrent mixed holders — a stranger AND an in-tree
	// reader both attached at one rendezvous. Fail-closed rule requires the
	// scan to see both and serve DECOY.
	stranger2 := exec.Command("/bin/cat", fifo)
	if err := stranger2.Start(); err != nil {
		fatal("start stranger2: %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	feeder.feed("/bin/cat " + fifo + " &\n") // in-tree, parent (the root sh) stays alive
	time.Sleep(150 * time.Millisecond)
	results = append(results, serveOnce(fifo, grantRoot, "mixed concurrent holders", "DECOY"))
	_ = stranger2.Wait()
	// Drain the possibly-still-blocked second reader with one more serve.
	time.Sleep(100 * time.Millisecond)
	if holders := findAllHolders(fifo); len(holders) > 0 {
		results = append(results, serveOnce(fifo, grantRoot, "drain leftover reader", "REAL"))
	}

	feeder.close()
	_ = grant.Wait()

	fmt.Println("\n[gate] ---- summary ----")
	pass := true
	for _, r := range results {
		ok := r.served == r.expect
		if r.scenario == "drain leftover reader" {
			ok = true // outcome depends on which reader was left; informational only
		}
		if !ok {
			pass = false
		}
		fmt.Printf("[gate] %-26s served=%-5s expect=%-5s ok=%-5v scan=%v\n", r.scenario, r.served, r.expect, ok, r.scanTime)
		for _, h := range r.holders {
			fmt.Printf("[gate]     pid=%d comm=%q inTree=%v pgid=%d\n", h.pid, h.comm, h.inTree, h.pgid)
		}
	}
	if pass {
		fmt.Println("[gate] ALL SCENARIOS BEHAVED AS EXPECTED")
	} else {
		fmt.Println("[gate] MISMATCHES PRESENT — see above")
	}
}

// serveOnce performs one writer-side rendezvous: blocking open, enumerate
// ALL processes holding the FIFO, classify each by ancestry against
// grantRoot, apply the fail-closed rule (at least one holder and every
// holder in-tree => REAL), write the chosen payload, close.
func serveOnce(fifo string, grantRoot int32, scenario, expect string) verdict {
	f, err := os.OpenFile(fifo, os.O_WRONLY, 0)
	if err != nil {
		fatal("[%s] open for write: %v", scenario, err)
	}
	scanStart := time.Now()
	holders := findAllHolders(fifo)
	for i := range holders {
		holders[i].inTree = ancestryContains(holders[i].pid, grantRoot)
	}
	scanTime := time.Since(scanStart)

	payload := decoyPayload
	if len(holders) > 0 {
		allIn := true
		for _, h := range holders {
			if !h.inTree {
				allIn = false
				break
			}
		}
		if allIn {
			payload = realPayload
		}
	}
	served := "DECOY"
	if payload == realPayload {
		served = "REAL"
	}
	fmt.Printf("[gate] %-26s -> %s (%d holder(s), scan+classify %v)\n", scenario, served, len(holders), scanTime)
	if _, err := f.WriteString(payload); err != nil {
		fmt.Printf("[gate] %-26s write error (non-fatal): %v\n", scenario, err)
	}
	_ = f.Close()
	return verdict{scenario: scenario, served: served, expect: expect, holders: holders, scanTime: scanTime}
}

// findAllHolders returns EVERY same-user process holding fifo open — the
// enumeration the fail-closed rule depends on (the prior spike stopped at
// the first match; this one must not).
func findAllHolders(fifo string) []holderInfo {
	target, err := filepath.EvalSymlinks(fifo)
	if err != nil {
		target = fifo
	}
	pids := listAllPIDs()
	self := int32(os.Getpid())
	var out []holderInfo
	for _, pid := range pids {
		if pid == self || pid <= 0 {
			continue
		}
		for _, fd := range listVnodeFDs(pid) {
			p, vtype, err := vnodeInfo(pid, fd)
			if err != nil || vtype != int32(C.VFIFO) || p != target {
				continue
			}
			_, comm, _ := bsdInfo(pid)
			out = append(out, holderInfo{pid: pid, comm: comm, pgid: mustPgid(pid)})
			break
		}
	}
	return out
}

// ancestryContains walks pid's ppid chain (proc_bsdinfo.pbi_ppid) toward
// launchd, reporting whether root appears. Capped: a cycle or an absurd
// depth means something is wrong — fail closed by returning false.
func ancestryContains(pid, root int32) bool {
	cur := pid
	for depth := 0; depth < 64; depth++ {
		if cur == root {
			return true
		}
		if cur <= 1 {
			return false
		}
		var info C.struct_proc_bsdinfo
		if C.get_bsd_info(C.pid_t(cur), &info) <= 0 {
			return false // can't verify => out of tree
		}
		cur = int32(info.pbi_ppid)
	}
	return false
}

// ---------- shared helpers ----------

type startTime struct{ sec, usec int64 }

func bsdInfo(pid int32) (startTime, string, error) {
	var info C.struct_proc_bsdinfo
	if C.get_bsd_info(C.pid_t(pid), &info) <= 0 {
		return startTime{}, "", fmt.Errorf("proc_pidinfo(PROC_PIDTBSDINFO) failed for pid %d", pid)
	}
	return startTime{sec: int64(info.pbi_start_tvsec), usec: int64(info.pbi_start_tvusec)},
		C.GoString(&info.pbi_comm[0]), nil
}

func mustPgid(pid int32) int32 {
	var info C.struct_proc_bsdinfo
	if C.get_bsd_info(C.pid_t(pid), &info) <= 0 {
		return -1
	}
	return int32(info.pbi_pgid)
}

func listAllPIDs() []int32 {
	const maxPIDs = 8192
	buf := make([]C.pid_t, maxPIDs)
	n := C.list_all_pids(&buf[0], C.int(len(buf))*C.int(unsafe.Sizeof(buf[0])))
	if n <= 0 {
		return nil
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
	return out
}

func listVnodeFDs(pid int32) []int32 {
	const maxFDs = 4096
	buf := make([]C.struct_proc_fdinfo, maxFDs)
	n := C.list_fds(C.pid_t(pid), &buf[0], C.int(len(buf))*C.int(unsafe.Sizeof(buf[0])))
	if n <= 0 {
		return nil
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
	return out
}

func vnodeInfo(pid, fd int32) (path string, vtype int32, err error) {
	var info C.struct_vnode_fdinfowithpath
	if C.get_vnode_info(C.pid_t(pid), C.int32_t(fd), &info) <= 0 {
		return "", 0, fmt.Errorf("proc_pidfdinfo failed")
	}
	return C.GoString(&info.pvip.vip_path[0]), int32(info.pvip.vip_vi.vi_type), nil
}

// lineFeeder hands the grant-root shell one command line at a time: Read
// blocks until feed() supplies the next line, and close() delivers EOF so
// the shell exits cleanly.
type lineFeeder struct {
	lines chan string
	buf   []byte
	done  bool
}

func newLineFeeder() *lineFeeder {
	return &lineFeeder{lines: make(chan string, 8)}
}

func (l *lineFeeder) feed(line string) { l.lines <- line }
func (l *lineFeeder) close()           { close(l.lines) }

func (l *lineFeeder) Read(p []byte) (int, error) {
	if l.done {
		return 0, io.EOF
	}
	if len(l.buf) == 0 {
		line, ok := <-l.lines
		if !ok {
			l.done = true
			return 0, io.EOF
		}
		l.buf = []byte(line)
	}
	n := copy(p, l.buf)
	l.buf = l.buf[n:]
	return n, nil
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FATAL: "+format+"\n", args...)
	os.Exit(1)
}
