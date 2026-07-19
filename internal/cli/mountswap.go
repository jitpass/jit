// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/jitpass/jit/internal/lineage"
	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

// This file is mountManager's compatibility swap (the jit run DEFAULT):
// while a run executes, each of its mounts is a plain regular comment-only
// pointer file instead of the decoy FIFO, so a script's `[ -f ]`/is_file()
// guard passes and a `source`/dotenv re-read parses to nothing (real values
// still arrive via jit run's env injection). The FIFO is restored the
// instant the run's process tree exits. Nothing secret is ever on disk.
//
// Swap vs grant (mountgrants.go): both are triggered by jit run and share
// the same pid-lifetime teardown (onRunExit, the kqueue NOTE_EXIT watcher,
// the hard cap). The difference is what the mount IS during the run — a
// regular file (swap, compatible with every guard and loader) vs a gated
// FIFO (grant, for tools that read real values from the file itself, jit
// run --live). Swap is mutually exclusive with the FIFO on a path, so a
// swapped mount cannot also be grant-gated; the two shouldn't target the
// same mount at once, and if they do, whichever swapped it wins until it
// restores.

// mountSwap tracks one mount's active swap: the set of run pids currently
// holding it as a pointer file, refcounted so the FIFO returns only after
// the LAST run exits (spike-verified balanced). Each pid carries the same
// fork-time stamp + hard cap protections a grant does.
type mountSwap struct {
	pids map[int32]swapAttach
}

type swapAttach struct {
	startMicro int64
	command    string
	since      time.Time
	hardCap    time.Time
}

// swapForPID is revealForPID's swap-mode handler. For each mount currently
// served, it replaces the FIFO with a comment-only pointer file (once, on
// the first run to hold it) and records pid in the refcount. Mounts that
// aren't served are skipped with a logged reason; the RPC fails only when
// NO mount could be swapped. Every filesystem transition happens under
// swapMu so a swap-in and a concurrent restore for the same path can never
// interleave.
func (m *mountManager) swapForPID(mountPaths []string, pid int32) error {
	startMicro, ok := m.grantStart(pid)
	if !ok {
		return fmt.Errorf("reveal_pid: target pid %d not found", pid)
	}
	command := ""
	if p, ok := lineage.Describe(pid); ok {
		command = p.Command()
	}
	now := time.Now()
	attach := swapAttach{startMicro: startMicro, command: command, since: now, hardCap: now.Add(grantHardCap)}

	m.swapMu.Lock()
	defer m.swapMu.Unlock()

	var swapped, problems []string
	for _, path := range mountPaths {
		entry, ok := m.registryEntryForPath(path)
		if !ok {
			problems = append(problems, fmt.Sprintf("no such mount: %s", path))
			continue
		}
		if m.swaps == nil {
			m.swaps = map[string]*mountSwap{}
		}
		s := m.swaps[path]
		firstForThisMount := s == nil || len(s.pids) == 0
		if firstForThisMount {
			// Actually perform the swap: stop the Serve goroutine (so it
			// can't write decoy into the pointer file), then atomically
			// replace the FIFO with the pointer content.
			if err := m.performSwapIn(path, entry); err != nil {
				problems = append(problems, fmt.Sprintf("%s: %v", path, err))
				continue
			}
			s = &mountSwap{pids: map[int32]swapAttach{}}
			m.swaps[path] = s
		}
		s.pids[pid] = attach
		swapped = append(swapped, path)
		fmt.Fprintf(m.stdout, "jit agent: mount %s: swapped to a compatibility file for pid %d's run (%s) until it exits\n", path, pid, command)
	}
	for _, p := range problems {
		fmt.Fprintf(m.stderr, "jit agent: reveal_pid (swap) skipped: %s\n", p)
	}
	if len(swapped) == 0 {
		return fmt.Errorf("reveal_pid: no mount swapped: %s", strings.Join(problems, "; "))
	}
	m.watchGrantPID(pid)
	return nil
}

// performSwapIn stops serving path's FIFO and replaces it with the
// comment-only pointer file. Caller holds swapMu.
func (m *mountManager) performSwapIn(path string, entry mount.Entry) error {
	names, err := m.mountVarNames(entry)
	if err != nil {
		return err
	}
	content := mount.SwapPointerContent(names.vars, names.order)
	// stopMount cancels the Serve goroutine and waits for its in-flight
	// cycle to finish (sm.done) — exactly the race-safety SwapToPointer
	// needs, the same guarantee jit unmount relies on before it replaces a
	// mount's file.
	m.stopMount(path)
	if err := mount.SwapToPointer(path, content); err != nil {
		// Best-effort recovery: put the FIFO back and resume serving, so a
		// failed swap doesn't leave the mount dead.
		_ = mount.RestoreFIFO(path)
		m.resumeServing(entry)
		return err
	}
	return nil
}

// onRunExit is the shared teardown for a finished run pid: drop any grants
// it held (mountgrants.go) AND release any swaps it held, restoring the
// FIFO for each mount whose last run just ended. Called from the kqueue
// NOTE_EXIT watcher and the already-exited registration path.
func (m *mountManager) onRunExit(pid int32, why string) {
	m.dropGrantsForPID(pid, why)
	m.releaseSwapsForPID(pid, why)
}

// releaseSwapsForPID removes pid from every mount's swap refcount and, for
// any mount whose count reaches zero, restores the FIFO and resumes
// serving. Under swapMu so restore can't race a concurrent swap-in.
func (m *mountManager) releaseSwapsForPID(pid int32, why string) {
	m.swapMu.Lock()
	defer m.swapMu.Unlock()
	for path, s := range m.swaps {
		if _, held := s.pids[pid]; !held {
			continue
		}
		delete(s.pids, pid)
		if len(s.pids) > 0 {
			continue // other runs still hold it swapped
		}
		delete(m.swaps, path)
		if entry, ok := m.registryEntryForPath(path); ok {
			if err := mount.RestoreFIFO(path); err != nil {
				fmt.Fprintf(m.stderr, "jit agent: mount %s: restoring FIFO after run exit failed: %v\n", path, err)
				continue
			}
			m.resumeServing(entry)
			fmt.Fprintf(m.stdout, "jit agent: mount %s: run-scoped compatibility file ended (%s), decoy mount restored\n", path, why)
		}
	}
}

// pruneStaleSwaps drops swap attachments whose target exited or whose pid
// was recycled (fork-time stamp mismatch) or that outlived the hard cap —
// the lazy backstop to the event-driven watcher, mirroring liveGrants.
// Runs on status reads and returns the surviving attachments per path.
func (m *mountManager) pruneStaleSwaps() {
	m.swapMu.Lock()
	type dead struct {
		pid int32
		why string
	}
	var restored []string
	var deadPIDs []dead
	now := time.Now()
	for path, s := range m.swaps {
		for pid, a := range s.pids {
			switch start, ok := m.grantStart(pid); {
			case now.After(a.hardCap):
				deadPIDs = append(deadPIDs, dead{pid, "hard cap reached"})
				delete(s.pids, pid)
			case !ok:
				deadPIDs = append(deadPIDs, dead{pid, "process exited"})
				delete(s.pids, pid)
			case start != a.startMicro:
				deadPIDs = append(deadPIDs, dead{pid, "pid recycled"})
				delete(s.pids, pid)
			}
		}
		if len(s.pids) == 0 {
			delete(m.swaps, path)
			if entry, ok := m.registryEntryForPath(path); ok {
				if err := mount.RestoreFIFO(path); err == nil {
					m.resumeServing(entry)
					restored = append(restored, path)
				}
			}
		}
	}
	m.swapMu.Unlock()
	_ = deadPIDs // per-pid reasons are implied by the restore line below
	for _, path := range restored {
		fmt.Fprintf(m.stdout, "jit agent: mount %s: compatibility file ended (run gone), decoy mount restored\n", path)
	}
}

// clearAllSwaps restores every swapped mount — OnLock's path. A lock means
// the session dropped; the run may still be alive, but the agent can't
// resolve anything for it, and leaving a mount as a pointer file past a
// lock would misreport state. The run's own next read gets the restored
// decoy FIFO (jit run already injected its env, so the run keeps working).
func (m *mountManager) clearAllSwaps() {
	m.swapMu.Lock()
	defer m.swapMu.Unlock()
	restored := 0
	for path, s := range m.swaps {
		_ = s
		delete(m.swaps, path)
		if entry, ok := m.registryEntryForPath(path); ok {
			if err := mount.RestoreFIFO(path); err == nil {
				m.resumeServing(entry)
				restored++
			}
		}
	}
	if restored > 0 {
		fmt.Fprintf(m.stdout, "jit agent: %d compatibility file(s) restored to decoy mounts (session locked)\n", restored)
	}
}

// resumeServing re-establishes decoy serving for one entry after its FIFO
// was restored, and resolves real content if the session is unlocked so a
// reveal window or a subsequent grant has something to serve. Best-effort:
// a resolve failure just leaves the mount decoy-only, exactly as a locked
// agent would. Caller holds swapMu; ensureServing/resolveReal take m.mu,
// never swapMu, so there's no lock inversion.
func (m *mountManager) resumeServing(entry mount.Entry) {
	m.ensureServing([]mount.Entry{entry})
	deviceID, err := vault.EnsureDeviceID(m.root)
	if err != nil {
		return
	}
	v := &vault.Vault{Root: m.root, KeyWrapper: m.keyWrapper, RecipientID: deviceID}
	// floorReveal=false: restoring a mount after a run must not light up a
	// fresh 60s reveal window on it — that would serve real content to
	// anything, the opposite of the decoy-by-default posture we're
	// returning to.
	m.resolveReal([]mount.Entry{entry}, v, false)
}

// mountVarNames loads entry's profile for the variable NAMES the pointer
// file lists (never values — this needs no vault access, same as the decoy
// path).
type mountVarNames struct {
	vars  []string
	order []string
}

func (m *mountManager) mountVarNames(entry mount.Entry) (mountVarNames, error) {
	p, order, err := profile.LoadFileOrdered(entry.ProfilePath)
	if err != nil {
		return mountVarNames{}, fmt.Errorf("loading profile for swap: %w", err)
	}
	names := make([]string, 0, len(p))
	for name := range p {
		names = append(names, name)
	}
	return mountVarNames{vars: names, order: order}, nil
}

// registryEntryForPath finds the registry entry for a mount path — needed
// to re-serve and to render pointer content, since the servedMount record
// is torn down by the swap. Best-effort: a read failure yields ok=false.
func (m *mountManager) registryEntryForPath(path string) (mount.Entry, bool) {
	entries, ok := m.loadRegistry()
	if !ok {
		return mount.Entry{}, false
	}
	for _, e := range entries {
		if e.MountPath == path {
			return e, true
		}
	}
	return mount.Entry{}, false
}

// swapHolder is one run holding a mount swapped, for status reporting.
type swapHolder struct {
	pid     int32
	command string
	since   time.Time
}

// swapStatuses reports each swapped mount's holding run(s) so `jit status`/
// `jit agent status` show "compatibility file for pid N" the same way they
// show a grant. Prunes stale attachments first.
func (m *mountManager) swapStatuses() map[string][]swapHolder {
	m.pruneStaleSwaps()
	m.swapMu.Lock()
	defer m.swapMu.Unlock()
	out := make(map[string][]swapHolder, len(m.swaps))
	for path, s := range m.swaps {
		for pid, a := range s.pids {
			out[path] = append(out[path], swapHolder{pid: pid, command: a.command, since: a.since})
		}
	}
	return out
}
