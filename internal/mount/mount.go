// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package mount

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// CreateFIFO replaces whatever is at path (a regular file, or nothing) with
// a named pipe — the literal "replaces the physical .env with a named pipe
// at the same path" step RFC.md Pillar III Tier 3 describes. Removing an
// existing file first is required: Mkfifo fails if path already exists.
func CreateFIFO(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing existing file at %s: %w", path, err)
	}
	if err := unix.Mkfifo(path, 0o600); err != nil {
		return fmt.Errorf("creating FIFO at %s: %w", path, err)
	}
	return nil
}

// Serve re-opens a FIFO at path: opens it for writing (blocking until a
// reader appears), writes content, closes, and immediately loops back to
// serve the next reader — the pattern validated in spike/named-pipe/ so
// standard dotenv loaders "just work" across repeated reads/hot-reloads
// (RFC.md B4). Runs until ctx is cancelled (a session TTL is the caller's
// responsibility: pass a context.WithTimeout).
//
// A stale reader must never see the next cycle's content (GAPS.md #24):
// opening for write only blocks when *zero* readers are attached, so if
// the previous cycle's reader hadn't yet processed EOF and closed its fd
// by the time the loop re-opened, the new open succeeded immediately
// against that same stale reader and the new cycle's content got appended
// onto whatever it was still reading — reproduced via `go test -race`
// (TestServeSequentialReaders occasionally read two iterations
// concatenated). recreateFIFO's atomic rename-over (see its own doc
// comment) makes that structurally impossible — but ONLY because of
// exactly where it's called: right after this cycle's write, while this
// cycle's writer fd is still open, never before the next open() is
// already waiting. Swapping any earlier (e.g. at the top of the loop,
// before the *next* open) can strand a reader that got there early: it
// binds to the fifo that's about to be orphaned and then blocks forever
// on a writer that will never come — a real, reproduced deadlock found
// while building this fix, worse than the bug it replaced. Calling it
// here instead means a reader arriving any time after this point already
// finds the new fifo in place and rendezvous with the *next* open()
// normally; a stale reader from *this* cycle just keeps talking to the
// old, now-unlinked pipe once f.Close() below delivers its EOF.
//
// Two cases skip the recreate (GAPS.md #47) — this matters because the
// rename is a filesystem event, and a file watcher that re-reads on every
// change (VS Code with the project open — a completely normal dev setup)
// turned the unconditional per-cycle rename into a self-sustaining
// feedback loop — serve → rename → watcher re-reads → serve → rename →
// ... — a real incident: ~30 reads/sec for hours, 635k log lines and 63
// CPU-minutes in one afternoon, plus manual reads racing the watcher for
// pipe cycles, which made revealing look flaky:
//
//  1. A write that failed with EPIPE. EPIPE on a pipe means zero
//     processes held the read end at that moment, which proves no reader
//     received any of this cycle's content — no stale reader can exist.
//  2. A drained write whose reader has since let go: when
//     hasLingeringReader is non-nil, the cycle's writer is closed FIRST
//     (delivering the reader its EOF so it can finish and close), and the
//     isolation rename runs only if the callback still finds someone
//     holding the pipe open. The callback must be a PASSIVE check
//     (internal/lineage.PathHeldOpen — an fd-table scan), never an
//     open(2)-based probe of the pipe: a non-blocking write-end open
//     can't tell a lingering stale reader from a brand-new one already
//     blocked in open(2) — the probe open itself completes that reader's
//     rendezvous, and stranding it with an instant EOF was a real,
//     reproduced empty-read regression while building this. A reader
//     blocked in open(2) holds no fd yet, so the passive scan correctly
//     ignores it and it rendezvouses safely with the next cycle on the
//     reused pipe. When the callback IS uncertain it must err toward
//     "held" — the isolation rename is always safe, reuse on a guess
//     never is. hasLingeringReader == nil preserves the unconditional
//     rename for every drained cycle (the portable default: the real
//     check is darwin-only).
//
// A drained cycle with a confirmed lingering holder still gets the full
// rename-over isolation, exactly as before.
//
// provideContent is called fresh on every re-open cycle, AFTER a reader has
// connected but BEFORE anything is written — not a fixed byte slice —
// specifically so a caller can gate on live state (is this read inside a
// run-scoped grant's process tree?) and choose real values or DecoyValues
// per cycle (RFC.md B10, GAPS.md #2) without restarting Serve. Calling it
// after the reader connects, not
// before, matters: spike/fifo-reader-identify/FINDINGS.md confirmed a
// reader that's genuinely waiting on data can't receive anything until
// this function decides to write, so the decoy gate can never be raced by
// a reader that gets classified/served before the decision is made.
//
// onReaderConnected, if non-nil, is called at that same moment (reader
// connected, before provideContent/write) purely for best-effort audit
// logging (RFC.md §5.1 Process Lineage Logging via internal/lineage) — it
// never influences what gets served. Kept as its own hook, separate from
// provideContent, so this package never needs to know what "identify a
// reader" means; the caller supplies that entirely.
//
// onError, if non-nil, is called with any write/close error for a single
// reader cycle — but never stops the loop. A real incident during manual
// verification showed why this has to be non-fatal: a reader (`cat`) that
// opens and closes quickly can race the write, producing a transient
// "broken pipe." An earlier version of this function returned on that
// error, silently killing the whole mount after serving exactly one
// reader — a regression from spike/named-pipe/'s own reference loop, which
// only logs a write/close failure and continues. Only a failure to OPEN
// the FIFO at all (path gone, disk error — something structurally wrong,
// not a reader race) ends the loop.
func Serve(ctx context.Context, path string, provideContent func() []byte, onError func(error), onReaderConnected func(), hasLingeringReader func() bool) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		f, err := openForWriteOrCancel(ctx, path)
		if err != nil {
			return err
		}
		if f == nil {
			// Cancelled while waiting for a reader.
			return ctx.Err()
		}

		if onReaderConnected != nil {
			onReaderConnected()
		}

		_, writeErr := f.Write(provideContent())

		var recreateErr error
		var closeErr error
		switch {
		case errors.Is(writeErr, syscall.EPIPE):
			// Zero readers held the pipe — nothing to isolate, reuse.
			closeErr = f.Close()
		case hasLingeringReader == nil:
			// Portable default: swap in a fresh pipe object for the *next*
			// cycle now, while f (this cycle's writer) is still open — see
			// recreateFIFO's doc comment for why this ordering, relative to
			// f.Close() below, is exactly what makes stale-reader isolation
			// deadlock-free.
			recreateErr = recreateFIFO(path)
			closeErr = f.Close()
		default:
			// Close FIRST — the drained reader can't see its EOF (and
			// therefore can't finish and close) until the writer is gone —
			// then isolate only if someone still holds the pipe open. See
			// the function doc comment for why the check must be passive
			// and err toward "held."
			closeErr = f.Close()
			if hasLingeringReader() {
				recreateErr = isolateHeldPipe(path)
			}
		}

		if writeErr != nil && onError != nil {
			onError(fmt.Errorf("writing to %s: %w", path, writeErr))
		}
		if closeErr != nil && onError != nil {
			onError(fmt.Errorf("closing %s: %w", path, closeErr))
		}
		if recreateErr != nil {
			return recreateErr
		}
	}
}

// isolateHeldPipe runs the stale-reader isolation for a pipe whose cycle
// writer is already closed and that a passive check just confirmed is
// still held open. recreateFIFO's deadlock-safety needs SOME writer fd
// open on the old pipe across the rename (a reader attached to it must
// end with EOF, never block forever on a writer that will never come), so
// one is opened non-blocking here: it succeeds precisely because a holder
// is attached. ENXIO instead means the holder let go between the check
// and now — the pipe is unheld, so reuse is safe and no rename is needed
// after all. The close after the rename delivers EOF to everything still
// on the old pipe; a brand-new reader that raced into this narrow window
// gets an empty read it can retry (rare — it requires a confirmed
// lingering holder AND a new reader in the same few milliseconds), never
// a hang.
func isolateHeldPipe(path string) error {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ENXIO) {
			return nil
		}
		return fmt.Errorf("reopening %s to isolate its lingering reader: %w", path, err)
	}
	recreateErr := recreateFIFO(path)
	_ = unix.Close(fd)
	return recreateErr
}

// recreateFIFO atomically replaces the FIFO at path with a brand-new pipe
// object, so a fresh reader can never end up attached to the same kernel
// pipe a previous cycle's reader might still be lingering on (GAPS.md #24).
// mkfifo happens at a sibling temp path first, then rename(2) swaps it into
// place — path never observably disappears the way a plain remove-then-
// mkfifo would (spike/named-pipe/FINDINGS.md already flags a bare ENOENT
// window as a real hazard for a fast-polling reader), and any fd a slow-
// to-close previous reader still holds keeps working against the now-
// unlinked old pipe, fully isolated from whatever gets written next.
//
// Callers must invoke this while the current cycle's writer fd is still
// open, never after it's closed and never before the current cycle's
// open() has already succeeded — see the call site in Serve for why that
// specific ordering is what keeps this deadlock-free. The rename is also
// a filesystem event a file watcher will react to, which is why Serve
// skips this entirely when EPIPE proved there's nothing to isolate.
func recreateFIFO(path string) error {
	tmp := path + ".jit-next"
	if err := os.Remove(tmp); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing stale %s: %w", tmp, err)
	}
	if err := unix.Mkfifo(tmp, 0o600); err != nil {
		return fmt.Errorf("creating replacement FIFO at %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("renaming %s to %s: %w", tmp, path, err)
	}
	return nil
}

// openForWriteOrCancel opens path for writing, blocking until a reader
// connects — exactly like os.OpenFile(path, os.O_WRONLY, 0) — but returns
// (nil, nil) if ctx is cancelled first. Since a blocking open can't be
// interrupted directly, cancellation is delivered by opening the read end
// ourselves once (as a throwaway, non-blocking reader) to unblock whatever
// real open() is pending; the goroutine's own result is then discarded.
func openForWriteOrCancel(ctx context.Context, path string) (*os.File, error) {
	type result struct {
		f   *os.File
		err error
	}
	ch := make(chan result, 1)
	go func() {
		f, err := os.OpenFile(path, os.O_WRONLY, 0) // #nosec G304 -- path is the mount path jit itself created (CreateFIFO), not external input
		ch <- result{f, err}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			return nil, fmt.Errorf("opening %s for write: %w", path, r.err)
		}
		return r.f, nil
	case <-ctx.Done():
		if rf, err := os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK, 0); err == nil { // #nosec G304 -- same path as above, just unblocking our own pending open
			_ = rf.Close()
		}
		go func() {
			r := <-ch
			if r.f != nil {
				_ = r.f.Close()
			}
		}()
		return nil, nil
	}
}
