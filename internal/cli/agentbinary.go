// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"context"
	"os"
	"syscall"
	"time"
)

// This file is the agent's stale-binary self-retirement (the automatic
// half of what `jit service restart` does by hand). launchd's KeepAlive
// keeps an agent process alive across rebuilds and reinstalls
// indefinitely, which made "the running agent predates the binary on
// disk" a whole class of investigation trap — a just-built fix that looks
// unfixed, with only a status warning (GAPS.md #49) saying why. Detection
// alone still left the fix manual; now the agent notices its own
// executable changed and exits cleanly, and launchd restarts it on the
// current build.
//
// Two gates keep this from ever costing anyone anything:
//   - Server.Quiescent(): only while the session is locked with no
//     challenge on screen. A lock has already hidden every mount, and the
//     next use re-prompts either way, so a quiescent restart is
//     invisible; killing a live session or an in-flight prompt is not.
//   - launchd parenthood (getppid == 1): a foreground `jit service run` has
//     no KeepAlive behind it — self-exiting would just stop the agent the
//     user deliberately started.

// agentBinaryCheckInterval paces the stat. One stat per 30s is nothing,
// and a rebuild waits at most one interval past quiescence to be picked
// up.
const agentBinaryCheckInterval = 30 * time.Second

// binaryFingerprint identifies one on-disk build of the executable.
// Inode + size + mtime: `go build` (and any install) replaces the file
// wholesale via rename, so a new build is a new inode — size/mtime cover
// the exotic in-place overwrite too.
type binaryFingerprint struct {
	ino     uint64
	size    int64
	mtimeNS int64
}

func fingerprintBinary(path string) (binaryFingerprint, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return binaryFingerprint{}, false
	}
	fp := binaryFingerprint{size: fi.Size(), mtimeNS: fi.ModTime().UnixNano()}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		fp.ino = st.Ino
	}
	return fp, true
}

// watchOwnBinary polls path until it no longer matches the fingerprint it
// had at call time, then calls restart() exactly once — but only after the
// NEW fingerprint has held steady for two consecutive checks (a build
// still being written isn't a build worth restarting onto; rename makes
// that near-atomic, but steadiness is free) and only while quiescent()
// holds. A vanished file (mid-swap, or the binary was deleted outright)
// counts as "no change yet": exiting because the binary is GONE would
// have launchd respawn-looping a nonexistent program.
func watchOwnBinary(ctx context.Context, path string, interval time.Duration, quiescent func() bool, restart func()) {
	orig, ok := fingerprintBinary(path)
	if !ok {
		return
	}
	var pending binaryFingerprint
	havePending := false
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		cur, ok := fingerprintBinary(path)
		if !ok || cur == orig {
			havePending = false
			continue
		}
		if !havePending || cur != pending {
			pending, havePending = cur, true
			continue
		}
		if !quiescent() {
			continue // stays pending; retried next tick
		}
		restart()
		return
	}
}
