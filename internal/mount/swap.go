// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package mount

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

// This file is the compatibility swap (spike/run-compat-swap/FINDINGS.md):
// while a `jit run` executes, a mount is temporarily a plain regular file
// of comment-only pointers instead of the decoy FIFO, so a script's
// `[ -f .env ]` / `Path.is_file()` guard passes and a `source .env` /
// dotenv re-read parses to nothing (real values still arrive via jit run's
// env injection). The FIFO is restored the instant the run exits. No secret
// is ever written to disk — the swapped-in file holds vault PATHS only, as
// comments — so even a crash mid-run leaves something harmless.
//
// The two directions use different primitives for a reason the spike pinned
// down empirically: swap-IN must both (a) never leave the path absent — a
// `[ -f ]` landing in an absent window fails "not found", the very trap
// this removes, reintroduced — and (b) rescue a reader blocked in open() on
// the FIFO at the swap instant. Neither obvious ordering gives both; the
// hardlink-rescue swap does. Restore is a plain atomic rename-over (a
// regular file has no blocked-open case).

// swapMarkerPrefix is the first line of every swapped-in pointer file, and
// the provenance gate for crash reconciliation: the agent may recreate a
// FIFO over a leftover regular file at a mount path ONLY when it starts
// with this, i.e. is jit's own swap artifact — NEVER over a file a user
// restored by hand (jit unmount, manual recovery), which must be left
// intact and surfaced. Distinct from migrate's pointerFileHeaderPrefix
// (`# jit pointer file`): that file's body is parseable `KEY=jit://…`
// lines; a swap file is comment-only so sourcing it is inert.
const swapMarkerPrefix = "# jit: secrets live in the vault, not in this file"

// SwapPointerContent renders varNames as the comment-only body a swapped-in
// mount serves — every line a comment, so `[ -f ]`/`is_file()` see a real
// file while `source`/dotenv parse nothing out of it (both traps closed by
// one format, spike-verified). Names are listed in the given order first,
// then any remainder sorted, matching FormatDotenv's ordering contract.
func SwapPointerContent(varNames []string, order []string) []byte {
	ordered := orderedNames(varNames, order)

	var b strings.Builder
	b.WriteString(swapMarkerPrefix + ".\n")
	b.WriteString("# This project is running under `jit run`, which injects the real values\n")
	b.WriteString("# into the environment. This file is intentionally inert: reading it sets\n")
	b.WriteString("# nothing. Outside `jit run` it is a decoy mount. Safe to open or commit.\n")
	for _, name := range ordered {
		fmt.Fprintf(&b, "#   %s\n", name)
	}
	return []byte(b.String())
}

// orderedNames returns names with those in order first (deduplicated, only
// if present), then the rest sorted — the same discipline FormatDotenv and
// pointerFileContent share.
func orderedNames(names []string, order []string) []string {
	present := make(map[string]bool, len(names))
	for _, n := range names {
		present[n] = true
	}
	out := make([]string, 0, len(names))
	seen := make(map[string]bool, len(names))
	for _, n := range order {
		if present[n] && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	rest := make([]string, 0, len(names))
	for _, n := range names {
		if !seen[n] {
			rest = append(rest, n)
		}
	}
	sort.Strings(rest)
	return append(out, rest...)
}

// SwapToPointer replaces the FIFO at path with a regular file containing
// content, atomically and with no absent-path window, rescuing any reader
// blocked in open() on the FIFO at the swap instant. The mechanism
// (spike/run-compat-swap/FINDINGS.md, swapHardlinkRescue):
//
//  1. hardlink the FIFO to a sibling ".jit-swap-prev" — a second name for
//     the same vnode, so it stays reachable after step 2 unlinks the path.
//  2. write content to ".jit-swap-tmp" and rename(2) it OVER path. rename
//     is atomic: the path resolves to the FIFO, then to the regular file,
//     never to nothing.
//  3. open the sibling O_WRONLY|O_NONBLOCK — this completes any reader
//     blocked in open() on the now-unlinked FIFO (reachable only via the
//     hardlink), hands it content instead of a bare EOF, then drops it.
//
// Caller MUST have stopped serving the FIFO first (the agent's stopMount):
// an in-flight Serve write cycle racing this swap is the same clobber
// hazard recreateFIFO guards against. If path is not a FIFO (already
// swapped, or a leftover), this is a no-op returning nil, so it's safe to
// call idempotently.
func SwapToPointer(path string, content []byte) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspecting %s: %w", path, err)
	}
	if info.Mode()&os.ModeNamedPipe == 0 {
		return nil // not a FIFO — nothing to swap (idempotent)
	}

	prev := path + ".jit-swap-prev"
	tmp := path + ".jit-swap-tmp"
	// Clear leftovers from a crashed earlier attempt; a stale prev is a
	// pipe nothing can still be blocked on (its openers died with their
	// session), keeping it only risks the Link below failing.
	_ = os.Remove(prev)
	_ = os.Remove(tmp)

	if err := os.Link(path, prev); err != nil {
		return fmt.Errorf("hardlinking %s aside for swap: %w", path, err)
	}
	if err := os.WriteFile(tmp, content, 0o644); err != nil { // #nosec G306 -- comment-only pointers, no secret; meant to be readable/committable like a .pointers file
		_ = os.Remove(prev)
		return fmt.Errorf("writing swap pointer file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(prev)
		_ = os.Remove(tmp)
		return fmt.Errorf("swapping pointer file over %s: %w", path, err)
	}

	// Rescue a reader blocked in open() on the retired FIFO, reachable via
	// prev. Success means one was waiting — the open completes its
	// rendezvous; write the same content so it observes the pointer file,
	// not a bare EOF. ENXIO means nobody waited: the common case. Either
	// way the retired pipe is then unlinked.
	if fd, oerr := unix.Open(prev, unix.O_WRONLY|unix.O_NONBLOCK, 0); oerr == nil {
		_, _ = unix.Write(fd, content)
		_ = unix.Close(fd)
	}
	if err := os.Remove(prev); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing retired pipe %s after swap: %w", prev, err)
	}
	return nil
}

// RestoreFIFO reverses SwapToPointer: replaces the regular pointer file at
// path with a fresh FIFO, atomically (mkfifo at a sibling temp, rename(2)
// over path) so the path is never absent — the spike confirmed a plain
// remove-then-mkfifo leaves a ~34%-of-samples absent window. A regular file
// has no blocked-open case (open of a regular file never blocks on a
// writer), so no rescue step is needed on this side.
//
// If path is already a FIFO this is a no-op (idempotent). If path holds a
// file that is NOT jit's swap artifact, the caller (crash reconciliation)
// must gate on IsSwapPointerFile FIRST — RestoreFIFO itself does not check
// provenance, so callers that could be pointing at user content must.
func RestoreFIFO(path string) error {
	info, err := os.Lstat(path)
	switch {
	case os.IsNotExist(err):
		// Nothing there — just create the FIFO directly.
		return CreateFIFO(path)
	case err != nil:
		return fmt.Errorf("inspecting %s: %w", path, err)
	case info.Mode()&os.ModeNamedPipe != 0:
		return nil // already a FIFO (idempotent)
	}

	tmp := path + ".jit-swap-tmp"
	_ = os.Remove(tmp)
	if err := unix.Mkfifo(tmp, 0o600); err != nil {
		return fmt.Errorf("creating replacement FIFO for %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("restoring FIFO over %s: %w", path, err)
	}
	return nil
}

// IsSwapPointerFile reports whether path is a regular file jit itself
// swapped in (identified by swapMarkerPrefix on its first line) — the
// provenance gate crash reconciliation uses before RestoreFIFO, so it
// recreates a FIFO over its OWN artifact but never over content a user
// restored by hand. Reads only the first line. A FIFO, a missing file, or
// any file not starting with the marker returns false.
func IsSwapPointerFile(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeNamedPipe != 0 || !info.Mode().IsRegular() {
		return false
	}
	f, err := os.Open(path) // #nosec G304 -- a mount path from jit's own registry, already confirmed a regular file above
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, len(swapMarkerPrefix))
	n, _ := f.Read(buf)
	return string(buf[:n]) == swapMarkerPrefix
}
