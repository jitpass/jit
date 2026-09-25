// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"os"
	"path/filepath"
	"strings"
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
//   - every process holding the mount descends from this service process.
//     Every job is the service's own child, so this needs no registration of
//     the child's pid, and so has no window between the child starting and a
//     registration landing, the race jit run avoids by registering before
//     its exec. Any other child of the service would also get only the inert
//     file, never a value;
//   - the mount is inside the folder of a job running right now. A job that
//     reads ANOTHER project's .env still gets the decoy and still raises the
//     alert, because that is exactly the read worth knowing about.
//
// Identification is lineage's best effort and never widens anything: when
// the holders cannot be named, or any one of them is not the service's, the
// read falls through to the ordinary decision (decoy, alert).

// beginJobRun marks dir as the folder of a running job until the returned
// function is called.
func (m *mountManager) beginJobRun(dir string) (end func()) {
	dir = filepath.Clean(dir)
	m.jobMu.Lock()
	if m.jobDirs == nil {
		m.jobDirs = map[string]int{}
	}
	m.jobDirs[dir]++
	m.jobMu.Unlock()
	atomic.AddInt32(&m.jobRuns, 1)
	return func() {
		m.jobMu.Lock()
		if m.jobDirs[dir]--; m.jobDirs[dir] <= 0 {
			delete(m.jobDirs, dir)
		}
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
	m.jobMu.Lock()
	covered := false
	for dir := range m.jobDirs {
		if path == dir || strings.HasPrefix(path, dir+string(filepath.Separator)) {
			covered = true
			break
		}
	}
	m.jobMu.Unlock()
	if !covered {
		return nil, false
	}
	holders, ok := m.grantHolders(path)
	if !ok || len(holders) == 0 {
		return nil, false
	}
	self := m.servicePID
	if self == 0 {
		self = int32(os.Getpid()) // #nosec G115 -- a pid always fits int32 on darwin
	}
	for _, h := range holders {
		if h == self || !m.grantAncestry(h, self) {
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
