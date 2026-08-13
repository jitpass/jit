// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package lineage

/*
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/vnode.h>

static int list_all_pids(pid_t *buf, int bufsize) {
	return proc_listpids(PROC_ALL_PIDS, 0, buf, bufsize);
}

static int list_fds(pid_t pid, struct proc_fdinfo *buf, int bufsize) {
	return proc_pidinfo(pid, PROC_PIDLISTFDS, 0, buf, bufsize);
}

static int get_vnode_info(pid_t pid, int32_t fd, struct vnode_fdinfowithpath *out) {
	return proc_pidfdinfo(pid, fd, PROC_PIDFDVNODEPATHINFO, out, sizeof(*out));
}

static int get_pid_path(pid_t pid, char *buf, uint32_t bufsize) {
	return proc_pidpath(pid, buf, bufsize);
}

static int get_pid_cwd(pid_t pid, struct proc_vnodepathinfo *out) {
	return proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, out, sizeof(*out));
}

static int is_vnode_type(uint32_t fdtype) {
	return fdtype == PROX_FDTYPE_VNODE;
}
*/
import "C"

import (
	"os"
	"path/filepath"
	"unsafe"
)

// IdentifyFIFOReader is a best-effort scan (see this package's doc comment
// for why "best-effort," never a gate) for whichever process currently
// holds path open for reading as a FIFO. Confirmed in
// spike/fifo-reader-identify/FINDINGS.md: unprivileged, same-UID-only
// (proc_pidinfo/proc_pidfdinfo fail with EPERM for other users'/root's
// processes — exactly the boundary jit's threat model needs), sub-
// millisecond in the common case, but a reader that opens and closes fast
// enough (before this scan completes) will not be found. ok is false
// whenever no matching reader is currently identifiable, which includes
// both "no reader is there" and "a reader is there but too fast to catch."
func IdentifyFIFOReader(path string) (pid int32, execPath string, ok bool) {
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
		return 0, "", false
	}

	self := int32(os.Getpid())
	for _, candidate := range pids {
		if candidate == self || candidate <= 0 {
			continue
		}
		fds, err := listVnodeFDs(candidate)
		if err != nil {
			continue // typically EPERM (a different user's/root's process) or ESRCH (exited mid-scan) — expected, not logged
		}
		for _, fd := range fds {
			p, vtype, err := vnodeInfo(candidate, fd)
			if err != nil || vtype != C.VFIFO || p != target {
				continue
			}
			return candidate, pidExecPath(candidate), true
		}
	}
	return 0, "", false
}

// PathHeldOpen reports whether ANY currently-visible process (including
// this one) holds an open fd on path as a FIFO. Unlike IdentifyFIFOReader,
// this is allowed to gate one narrow decision in internal/mount's serve
// loop: whether a just-served pipe needs the stale-reader isolation
// rename, or can be reused as-is (GAPS.md #47 — every needless rename is
// a filesystem event that feeds a file watcher's re-read loop). That is
// NOT the identity-gating the spike ruled out, because the failure
// direction inverts: the spike's fatal race is a reader that closes too
// fast to identify — but a reader that has closed is exactly a reader the
// isolation rename no longer needs to protect against. To still be
// holding the pipe when the next cycle starts (the only state the rename
// guards), a reader must hold its fd across this scan, and an open fd in
// a same-user process's fd table is what this scan reads directly — there
// is no "too fast" evasion that leaves the hazard in place.
//
// Known blind spot, deliberate: another user's or root's process is
// invisible (proc_pidinfo fails with EPERM — see the spike). Another user
// can't open the 0600 mount at all, so the blind spot is root-only, and
// root is outside RFC.md's threat model entirely. Every STRUCTURAL
// uncertainty — pid/fd listing failure, possible buffer truncation —
// returns held=true, so the caller falls back to the always-isolate
// behavior rather than ever reusing on a guess.
func PathHeldOpen(path string) bool {
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		target = path
	}
	target, err = filepath.Abs(target)
	if err != nil {
		target = path
	}

	pids, truncated, err := listAllPIDsChecked()
	if err != nil || truncated {
		return true // can't enumerate reliably — never reuse on a guess
	}
	// Unlike IdentifyFIFOReader, our OWN pid is NOT skipped: a stray fd of
	// ours would be a real holder too, and (unlike audit attribution)
	// there's no reason to exclude ourselves from a safety check.
	for _, candidate := range pids {
		if candidate <= 0 {
			continue
		}
		fds, truncated, err := listVnodeFDsChecked(candidate)
		if err != nil {
			continue // typically EPERM (another user's/root's process) or ESRCH (exited mid-scan)
		}
		if truncated {
			return true // this pid's fd table may extend past our buffer — assume a holder rather than reuse on a guess
		}
		for _, fd := range fds {
			p, vtype, err := vnodeInfo(candidate, fd)
			if err != nil || vtype != C.VFIFO || p != target {
				continue
			}
			return true
		}
	}
	return false
}

// vfifoType mirrors C.VFIFO for the non-CGo files in this package
// (grant.go compares vnode types without needing its own CGo preamble).
var vfifoType = int32(C.VFIFO)

// resolveTarget normalizes a mount path the way every scan in this package
// compares it: symlinks resolved, absolute — falling back to the raw path
// when resolution fails, matching the scans' historical behavior.
func resolveTarget(path string) string {
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		target = path
	}
	target, err = filepath.Abs(target)
	if err != nil {
		target = path
	}
	return target
}

func listAllPIDs() ([]int32, error) {
	pids, _, err := listAllPIDsChecked()
	return pids, err
}

func listAllPIDsChecked() (pids []int32, truncated bool, err error) {
	const maxPIDs = 8192
	buf := make([]C.pid_t, maxPIDs)
	n, err := C.list_all_pids(&buf[0], C.int(len(buf))*C.int(unsafe.Sizeof(buf[0])))
	if n <= 0 {
		return nil, false, err
	}
	count := int(n) / int(unsafe.Sizeof(buf[0]))
	if count >= len(buf) {
		count = len(buf)
		truncated = true // a full buffer can't prove there wasn't more
	}
	out := make([]int32, 0, count)
	for i := 0; i < count; i++ {
		if buf[i] != 0 {
			out = append(out, int32(buf[i]))
		}
	}
	return out, truncated, nil
}

func listVnodeFDs(pid int32) ([]int32, error) {
	fds, _, err := listVnodeFDsChecked(pid)
	return fds, err
}

func listVnodeFDsChecked(pid int32) (fds []int32, truncated bool, err error) {
	const maxFDs = 4096
	buf := make([]C.struct_proc_fdinfo, maxFDs)
	n, err := C.list_fds(C.pid_t(pid), &buf[0], C.int(len(buf))*C.int(unsafe.Sizeof(buf[0])))
	if n <= 0 {
		return nil, false, err
	}
	count := int(n) / int(unsafe.Sizeof(buf[0]))
	if count >= len(buf) {
		count = len(buf)
		truncated = true // a full buffer can't prove there wasn't more
	}
	out := make([]int32, 0, count)
	for i := 0; i < count; i++ {
		if C.is_vnode_type(buf[i].proc_fdtype) != 0 {
			out = append(out, int32(buf[i].proc_fd))
		}
	}
	return out, truncated, nil
}

func vnodeInfo(pid, fd int32) (path string, vtype int32, err error) {
	var info C.struct_vnode_fdinfowithpath
	n := C.get_vnode_info(C.pid_t(pid), C.int32_t(fd), &info)
	if n <= 0 {
		return "", 0, errNotFound
	}
	path = C.GoString(&info.pvip.vip_path[0])
	vtype = int32(info.pvip.vip_vi.vi_type)
	return path, vtype, nil
}

// ProcessCWD returns pid's current working directory, or "" if unavailable
// (the process exited, is another user's, or the kernel has no vnode path
// for it). Display only, pidExecPath's exact posture: it annotates the
// `jit grant --pid` completion so seven identical "claude" rows become
// tellable apart by the project each one sits in — it never gates.
func ProcessCWD(pid int32) string {
	if pid <= 0 {
		return ""
	}
	var info C.struct_proc_vnodepathinfo
	n := C.get_pid_cwd(C.pid_t(pid), &info)
	if n <= 0 {
		return ""
	}
	return C.GoString(&info.pvi_cdir.vip_path[0])
}

// pidExecPath returns pid's executable path, or "" if unavailable — purely
// cosmetic for the audit log, never load-bearing, so a failure here is
// silently swallowed rather than surfaced.
func pidExecPath(pid int32) string {
	buf := make([]byte, C.PROC_PIDPATHINFO_MAXSIZE)
	n := C.get_pid_path(C.pid_t(pid), (*C.char)(unsafe.Pointer(&buf[0])), C.uint32_t(len(buf)))
	if n <= 0 {
		return ""
	}
	return string(buf[:n])
}

type simpleError string

func (e simpleError) Error() string { return string(e) }

const errNotFound simpleError = "no vnode info for this fd"
