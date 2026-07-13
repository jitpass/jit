// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package mount

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// RetireFIFO clears path so a regular file can take its place, and — when
// the occupant is a pipe — returns a release function the caller MUST
// invoke once the replacement file is in place. The release rescues any
// reader currently blocked in open(2) on the old pipe: such a reader
// resolved the path to the pipe's vnode before the swap and would
// otherwise block forever on a writer that can never arrive. A real
// incident (GAPS.md #57): a file watcher re-reading a mount ~7×/sec was
// mid-open() at the instant `jit migrate undo` replaced the pipe — the
// on-disk restore succeeded, but VS Code sat on an empty,
// perpetually-loading tab until its whole window was reloaded, because a
// blocked open() holds no fd yet (invisible to lsof) and survives the
// unlink of the very pipe it's waiting on.
//
// Mechanism: the pipe is renamed to a sibling ".jit-prev" name (never
// removed in place — the rename keeps its vnode reachable for the rescue
// below, and the set of blocked openers is frozen at rename time, since
// new opens of path no longer resolve to it). After the caller writes the
// real file at path, release opens the renamed pipe O_WRONLY|O_NONBLOCK:
// success means at least one reader was waiting — the open itself
// completes every pending rendezvous — and the pipe is then unlinked
// BEFORE any byte moves, so nothing new can ever reach it. handoff (the
// same bytes the caller just wrote at path) is written best-effort so the
// rescued read observes the real replacement content rather than a bare
// EOF; ENXIO means nobody was waiting and there's nothing to do but
// remove the renamed pipe.
//
// Serve's rule that a pipe probe "must stay passive" (see its doc
// comment) does not apply here, and this must not be
// "fixed" to comply with it: that rule protects a pipe still being served
// at its path, where a probe's rendezvous steals a brand-new reader from
// the next real cycle. This pipe is already off its path and unlinked
// before the write — completing the rendezvous is the entire point.
//
// If path holds a regular file it is simply removed; if it holds nothing,
// nothing happens. Both return a no-op release so callers can invoke this
// unconditionally in place of a bare os.Remove.
func RetireFIFO(path string) (release func(handoff []byte) error, err error) {
	noop := func([]byte) error { return nil }

	info, lerr := os.Lstat(path)
	switch {
	case os.IsNotExist(lerr):
		return noop, nil
	case lerr != nil:
		return nil, fmt.Errorf("inspecting %s: %w", path, lerr)
	case info.Mode()&os.ModeNamedPipe == 0:
		if rerr := os.Remove(path); rerr != nil {
			return nil, fmt.Errorf("removing %s: %w", path, rerr)
		}
		return noop, nil
	}

	tmp := path + ".jit-prev"
	// A leftover from a crashed earlier attempt — it's a pipe nothing can
	// be blocked on anymore (its own release never ran, but its openers
	// died with whatever session they belonged to; keeping it only risks
	// the rename below failing).
	if rerr := os.Remove(tmp); rerr != nil && !os.IsNotExist(rerr) {
		return nil, fmt.Errorf("removing stale %s: %w", tmp, rerr)
	}
	if rerr := os.Rename(path, tmp); rerr != nil {
		return nil, fmt.Errorf("moving pipe %s aside: %w", path, rerr)
	}

	return func(handoff []byte) error {
		fd, oerr := unix.Open(tmp, unix.O_WRONLY|unix.O_NONBLOCK, 0)
		if oerr != nil {
			rmErr := os.Remove(tmp)
			if errors.Is(oerr, unix.ENXIO) {
				// No reader was waiting — the common case.
				return rmErr
			}
			return fmt.Errorf("probing retired pipe %s for blocked readers: %w", tmp, oerr)
		}
		// Unlink before writing: from here nothing new can reach this
		// pipe, and everything already rendezvoused is being rescued.
		rmErr := os.Remove(tmp)
		// Best-effort: the open above already woke every blocked reader;
		// the handoff just upgrades their wake-up from a bare EOF to the
		// real replacement content. A full pipe buffer or a reader that
		// vanished mid-write changes nothing about the rescue.
		_, _ = unix.Write(fd, handoff)
		_ = unix.Close(fd)
		return rmErr
	}, nil
}
