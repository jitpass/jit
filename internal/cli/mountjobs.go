// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"path/filepath"
	"sync/atomic"

	"github.com/jitpass/jit/internal/mount"
)

// This file is how a project's .env mount treats an AI job
// (design/agent-jobs.md). A job's real values are injected into its
// environment, like `jit run`'s, so the mount has nothing to add; but a
// script that loads its .env anyway (the notion script's load_dotenv) used to
// get the DECOY, and the service reported every such read as "decoy served":
// an alert on every ordinary run, which is how people learn to ignore alerts.
//
// A job reader gets what `jit run` swaps in instead, the inert pointer file,
// and no serve is recorded, when BOTH hold:
//
//   - the mount is the .env of the job's OWN folder: its directory IS the
//     job's folder. A mount in a nested project, or in another job's
//     folder, does not qualify;
//   - every process holding the mount descends from THAT job's process
//     (registered the moment it starts). Another job, or anything else the
//     service started, does not qualify.
//
// A read that lands before the registration (microseconds after the start)
// falls through to the decoy and the alert: the safe direction to be wrong
// in. Identification is lineage's best effort and never widens anything:
// when the holders cannot be named, or any one of them is outside the job's
// tree, the read gets the ordinary decision (decoy, alert).

// beginJobRun records a running job's process and folder until the
// returned function is called.
func (m *mountManager) beginJobRun(dir string, pid int32) (end func()) {
	dir = filepath.Clean(dir)
	m.jobMu.Lock()
	if m.jobProcs == nil {
		m.jobProcs = map[int32]string{}
	}
	m.jobProcs[pid] = dir
	m.jobMu.Unlock()
	atomic.AddInt32(&m.jobRuns, 1)
	return func() {
		m.jobMu.Lock()
		delete(m.jobProcs, pid)
		m.jobMu.Unlock()
		atomic.AddInt32(&m.jobRuns, -1)
	}
}

// jobReaderContent returns the inert pointer for path when the read is a
// running job's read of its own folder's mount, and ok=false otherwise.
func (m *mountManager) jobReaderContent(path string) ([]byte, bool) {
	if atomic.LoadInt32(&m.jobRuns) == 0 {
		return nil, false
	}
	parent := filepath.Dir(path)
	var jobPID int32
	m.jobMu.Lock()
	for pid, dir := range m.jobProcs {
		if dir == parent {
			jobPID = pid
			break
		}
	}
	m.jobMu.Unlock()
	if jobPID == 0 {
		return nil, false
	}
	holders, ok := m.grantHolders(path)
	if !ok || len(holders) == 0 {
		return nil, false
	}
	for _, h := range holders {
		if h != jobPID && !m.grantAncestry(h, jobPID) {
			return nil, false
		}
	}
	return m.pointerContent(path)
}

// pointerContent is the comment-only file `jit run` swaps in for path,
// naming the variables the mount carries and nothing else.
func (m *mountManager) pointerContent(path string) ([]byte, bool) {
	if m.pointerFn != nil {
		return m.pointerFn(path)
	}
	entry, ok := m.registryEntryForPath(path)
	if !ok {
		return nil, false
	}
	names, order, err := m.mountVarNames(entry)
	if err != nil {
		return nil, false
	}
	return mount.SwapPointerContent(names, order), true
}
