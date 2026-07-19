// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package lineage

import (
	"os"

	"golang.org/x/sys/unix"
)

// This file is the run-scoped reveal grant's kernel primitives
// (spike/run-scoped-grant/FINDINGS.md). Unlike IdentifyFIFOReader — which is
// audit-only by doctrine — these three are allowed to feed a gating
// decision, for the same reason PathHeldOpen is: the failure direction is
// what matters. Every structural uncertainty here reports "can't verify",
// and the gate's only possible response to that is serving decoy content —
// a grant can only ever NARROW an exposure the reveal-window baseline
// already grants to every process, never widen one.

// grantAncestryCap bounds AncestryContainsPID's ppid walk. Deliberately
// larger than caller.go's maxAncestry (which serves display, where 8 hops
// is already past anyone's interest): a granted run's reader can
// legitimately sit under jit run → sh → make → sh → tool → interpreter
// chains, and a too-short cap here turns a legitimate deep descendant into
// a decoy-served mystery. A cycle guard makes the cap a formality.
const grantAncestryCap = 64

// FIFOHolders returns every same-user process currently holding path open
// as a FIFO, EXCLUDING the calling process (the agent holds the write side
// of its own mount at scan time). ok is false whenever the enumeration
// cannot be trusted to be complete — the pid table or any pid's fd table
// may have been truncated — in which case the caller must fail closed:
// an unverifiable holder set and a hostile one are indistinguishable.
//
// Per-pid errors (EPERM for another user's/root's process, ESRCH for one
// that exited mid-scan) skip that pid without poisoning ok, same doctrine
// as PathHeldOpen: another user can't open the 0600 mount at all, and root
// is outside RFC.md's threat model entirely.
func FIFOHolders(path string) (pids []int32, ok bool) {
	target := resolveTarget(path)

	all, truncated, err := listAllPIDsChecked()
	if err != nil || truncated {
		return nil, false
	}
	self := int32(os.Getpid())
	for _, candidate := range all {
		if candidate == self || candidate <= 0 {
			continue
		}
		fds, truncated, err := listVnodeFDsChecked(candidate)
		if err != nil {
			continue // EPERM/ESRCH — see doc comment
		}
		if truncated {
			return nil, false // this pid's fd table may extend past our buffer — can't rule it in or out
		}
		for _, fd := range fds {
			p, vtype, err := vnodeInfo(candidate, fd)
			if err != nil || vtype != vfifoType || p != target {
				continue
			}
			pids = append(pids, candidate)
			break
		}
	}
	return pids, true
}

// AncestryContainsPID walks pid's parent chain toward launchd, reporting
// whether root appears in it (pid == root counts). Any unreadable link,
// self-parent cycle, or cap overrun answers false — the gate treats
// "can't verify the lineage" exactly like "not in the tree".
//
// Known, deliberate limitation (spike-confirmed): a descendant whose
// intermediate parent exited has been reparented to launchd and its chain
// no longer passes through root — it fails closed to decoys. A granted
// run's synchronous children keep their chain intact; a double-forked
// daemon that outlives the run is exactly what a run-scoped grant should
// NOT cover.
func AncestryContainsPID(pid, root int32) bool {
	if pid <= 0 || root <= 0 {
		return false
	}
	cur := pid
	for depth := 0; depth < grantAncestryCap; depth++ {
		if cur == root {
			return true
		}
		if cur <= 1 {
			return false
		}
		kp, err := unix.SysctlKinfoProc("kern.proc.pid", int(cur))
		if err != nil {
			return false
		}
		ppid := int32(kp.Eproc.Ppid)
		if ppid == cur {
			return false // self-parent: impossible, but never loop on it
		}
		cur = ppid
	}
	return false
}

// ProcessStartTime returns pid's fork-time stamp in microseconds since the
// epoch, ok=false when the process is gone or unreadable. The stamp is
// stable across execve (spike-verified through a double exec), which is
// the property the grant machinery leans on: recorded at grant creation
// while jit run is provably alive (it's mid-RPC), and re-checked before
// every use, so a recycled pid — same number, different fork time — can
// never inherit a dead run's grant.
func ProcessStartTime(pid int32) (unixMicro int64, ok bool) {
	if pid <= 0 {
		return 0, false
	}
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", int(pid))
	if err != nil {
		return 0, false
	}
	return int64(kp.Proc.P_starttime.Sec)*1_000_000 + int64(kp.Proc.P_starttime.Usec), true
}
