// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

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
	self := int32(os.Getpid()) // #nosec G115 -- getpid always fits int32 on darwin
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

// AncestryNamedWithin walks pid's parent chain toward launchd and reports
// whether the chain passes through a process whose display Name() is name at
// or below root, and then reaches root itself. It is AncestryContainsPID
// with one extra condition, and the same fail-closed posture: any unreadable
// link, cycle, or cap overrun answers false.
//
// This is the serve gate for a tree-scoped process grant ("claude under
// iTerm2"). The two conditions carry very different weight, and the design
// leans on the strong one: reaching root is a kernel fact no process can
// arrange for itself, while the name is self-chosen (argv/exec path) and
// trivially claimed. The name therefore only NARROWS which descendants of
// the human-approved root are served — a process outside root's tree gains
// nothing by renaming itself, and a hostile process already inside the tree
// was already inside the perimeter the human approved. The decision is the
// disclosed challenge bound to root at creation; this walk only routes to it.
func AncestryNamedWithin(pid, root int32, name string) bool {
	// root <= 1 answers false outright: everything descends from launchd, so
	// a launchd-rooted walk would let the self-chosen name decide alone —
	// creation refuses to mint such a grant, and this is the serve-side belt.
	if pid <= 0 || root <= 1 || name == "" {
		return false
	}
	cur := pid
	nameSeen := false
	for depth := 0; depth < grantAncestryCap; depth++ {
		if !nameSeen {
			if p, ok := Describe(cur); ok && p.Name() == name {
				nameSeen = true
			}
		}
		if cur == root {
			return nameSeen
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

// SessionRoot returns the topmost ancestor of pid below launchd — the
// terminal app, tmux server, or SSH connection that owns pid's session —
// which is what a tree-scoped grant anchors to. ok is false when pid has no
// such ancestor to speak of: it is launchd's own child (a daemon has no
// session), or the chain was unreadable from the first hop. A chain that
// becomes unreadable partway returns the topmost ancestor that could be
// read: a narrower anchor is the safe direction, never a wider one.
func SessionRoot(pid int32) (Process, bool) {
	if pid <= 0 {
		return Process{}, false
	}
	top := int32(0) // topmost ancestor read so far, strictly above pid
	cur := pid
	for depth := 0; depth < grantAncestryCap; depth++ {
		kp, err := unix.SysctlKinfoProc("kern.proc.pid", int(cur))
		if err != nil {
			break // unreadable from here up: top is the narrowest safe anchor
		}
		ppid := int32(kp.Eproc.Ppid)
		if ppid <= 1 || ppid == cur {
			break // cur is launchd's child: the session root (or the cycle guard fired)
		}
		top = ppid
		cur = ppid
	}
	if top == 0 {
		return Process{}, false
	}
	p, ok := Describe(top)
	if !ok {
		return Process{}, false
	}
	return p, true
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
