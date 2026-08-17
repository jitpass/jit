// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// This file is the socket boundary: binding and tightening the listener,
// accepting connections, bounding and decoding one request per connection,
// and recording the failures that happen out here (a rejected peer, a
// malformed request, a dying accept loop). Everything in it runs BEFORE any
// session decision — peer verification lives in peercred.go and is called
// from handleConn below — which is why it is worth reading apart from the
// session state machine in session.go.

// Listen opens the Unix socket, replacing any stale one left behind by a
// previous run that didn't shut down cleanly.
func (s *Server) Listen() error {
	if err := os.Remove(s.socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing stale socket %s: %w", s.socketPath, err)
	}
	dir := filepath.Dir(s.socketPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	tightenSocketDir(dir)
	l, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", s.socketPath, err)
	}
	if err := os.Chmod(s.socketPath, 0o600); err != nil {
		_ = l.Close()
		return fmt.Errorf("chmod %s: %w", s.socketPath, err)
	}
	if fi, err := os.Lstat(s.socketPath); err == nil {
		s.socketInfo = fi
	}
	s.listener = l
	return nil
}

// tightenSocketDir narrows the socket's parent directory to 0700 when it is
// ours and currently wider.
//
// It exists because net.Listen creates the socket at whatever the umask
// allows (0755 under the common 022), and the chmod that fixes that runs one
// syscall later — a window in which the socket is connectable by anyone. A
// 0700 parent closes the window outright, and MkdirAll can't be relied on for
// it: MkdirAll applies its mode only when it CREATES the directory, so a
// jitpass dir left at 0755 by an older build keeps those permissions forever.
//
// Deliberately narrow and deliberately quiet:
//
//   - Only a directory THIS user owns is touched. A socket path under a shared
//     directory (/tmp, as the tests use) belongs to the system, and chmodding
//     it would be both futile and rude.
//   - Failure is not fatal. This is the outer of two layers; verifyPeerUID is
//     the one that actually decides, on every single connection, and an agent
//     that refuses to start over a directory mode would trade a hardening
//     measure for an outage.
func tightenSocketDir(dir string) {
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm()&0o077 == 0 {
		return // unreadable, or already tight enough
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Getuid() {
		return // not ours to narrow
	}
	_ = os.Chmod(dir, 0o700) // #nosec G302 -- a DIRECTORY, not a file: 0700 is the tightest mode that is still traversable by its owner, and G302's 0600 ceiling assumes a regular file. Matches the MkdirAll above.
}

// Serve accepts connections until ctx is cancelled or the listener fails.
// Call Listen first.
func (s *Server) Serve(ctx context.Context) error {
	// The watcher ends when Serve does, not only when ctx is cancelled: a
	// listener that fails for its own reason returns below, and a watcher
	// still parked on ctx.Done() would outlive the Serve call that started
	// it. The daemon's deferred cancel covers that today; a library embedding
	// this Server need not have one.
	served := make(chan struct{})
	defer close(served)
	go func() {
		select {
		case <-ctx.Done():
			_ = s.listener.Close()
		case <-served:
		}
	}()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			s.recordServeError("accept", fmt.Sprintf("accept: %v", err), nil)
			return fmt.Errorf("accept: %w", err)
		}
		go s.handleConn(conn)
	}
}

// Close shuts down the listener and removes the socket file — but only if
// the path still holds the socket this server bound. A later agent may have
// claimed the path (Listen replaces stale sockets); removing ITS live socket
// on our way out is how a briefly-run second agent used to strand the real
// one behind an unlinked inode.
func (s *Server) Close() error {
	var err error
	if s.listener != nil {
		err = s.listener.Close()
	}
	if fi, statErr := os.Lstat(s.socketPath); statErr == nil && s.socketInfo != nil && os.SameFile(fi, s.socketInfo) {
		_ = os.Remove(s.socketPath)
	}
	return err
}

// maxRequestBytes bounds one request. The largest legitimate one is a
// reveal_pid carrying a handful of mount paths, or a wrap/unwrap whose Data is
// a single base64'd 32-byte DEK plus nonce and tag — kilobytes, and this is a
// megabyte. The bound exists because the decoder read straight from the
// connection with no limit: a peer had the whole read deadline to stream
// arbitrary JSON into the agent's heap, and this process is meant to live for
// weeks. Same-user code execution is conceded in the threat model, but the
// concession is that such code reaches the unlocked agent — not that it gets
// to take the service down for everything else on the machine.
const maxRequestBytes = 1 << 20

func (s *Server) handleConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	// Covers verifyPeerUID's syscalls, the error-path responses, and
	// reading the request itself — everything up to the point real
	// handling (which may wait on a human) starts.
	_ = conn.SetDeadline(time.Now().Add(s.readTimeout))

	if err := verifyPeerUID(conn); err != nil {
		// A peer the kernel says isn't this user is the one socket event most
		// worth a durable record: someone else's process probing the agent.
		// Enrich with its lineage while it's still connected — that identity
		// is exactly what the audit trail is for.
		s.recordServeError("reject", fmt.Sprintf("rejected peer: %v", err), s.identify(conn))
		_ = json.NewEncoder(conn).Encode(Response{OK: false, Error: fmt.Sprintf("rejected: %v", err), Protocol: Protocol})
		return
	}

	var req Request
	if err := json.NewDecoder(io.LimitReader(conn, maxRequestBytes)).Decode(&req); err != nil {
		// A peer that closed without sending a single byte is a liveness
		// probe, not a malformed request: Client.Reachable() dials and
		// closes exactly like this, and it runs from a dozen CLI paths
		// (run, undo, unmount, vault, migrate remove, rekey), so recording
		// it would file two KindError events per `jit run`. That noise
		// lands in the durable audit log next to the events kind=error
		// exists for — a peer the kernel says isn't this user, probing the
		// agent — and drowns them. json.Decode reports this exact case as
		// a bare io.EOF; a peer that sent SOME bytes and then died gives
		// io.ErrUnexpectedEOF (or a syntax error) and is still recorded.
		// There's nothing to reply to either way — the peer is gone.
		if errors.Is(err, io.EOF) {
			return
		}
		s.recordServeError("decode", fmt.Sprintf("bad request: %v", err), s.identify(conn))
		_ = json.NewEncoder(conn).Encode(Response{OK: false, Error: fmt.Sprintf("bad request: %v", err), Protocol: Protocol})
		return
	}

	// Identify the peer BEFORE handling: a `jit run` that execs its child
	// (which is what jit run does) has already replaced its own argv by the
	// time a slow interactive challenge finishes, so asking the kernel
	// afterwards would describe the wrong program. nil is fine and expected
	// (peer already gone) — handling never depends on it.
	c := s.identify(conn)

	// Handling can block on an interactive challenge far longer than the
	// request-read bound — clear the deadline for it, then re-bound just
	// the response write.
	_ = conn.SetDeadline(time.Time{})
	resp := s.handle(req, c)
	// Stamped on EVERY response, not just status: it is how a client learns
	// what this agent is able to enforce, and a client that has to make a
	// second round trip to find out would be tempted to skip the check.
	resp.Protocol = Protocol
	_ = conn.SetWriteDeadline(time.Now().Add(s.readTimeout))
	_ = json.NewEncoder(conn).Encode(resp)
}

// serveErrNote is one (op, cause) pair's rate-limit state.
type serveErrNote struct {
	last       time.Time
	suppressed int
}

// serveErrorMinGap spaces identical socket-boundary failures in the durable
// trail. One minute keeps a sustained flood at a bounded one line per
// minute per distinct failure — visible, timestamped, countable — instead
// of one line per connection.
const serveErrorMinGap = time.Minute

// recordServeError hands a socket-boundary failure to OnServeError as a
// KindError event: op names which failure ("reject", "decode", "accept"),
// cause carries the detail, and c (when the kernel still named the peer)
// stamps the same By/ByPID/LaunchedBy provenance an unlock would carry — for a
// rejected peer that provenance is the whole point of recording it. No-op when
// no sink is wired (a test server, or the KeyWrapper embedding with no socket).
//
// Identical (op, cause) pairs are rate-limited: a misbehaving peer can hit
// the same failure at connection rate for weeks, and each event used to
// become its own durable line — recordRejectedClass defends the in-memory
// ring against exactly that caller-minted eviction, but the FILE had no
// equivalent, so a flood could push real unlock/denial history out by byte
// pressure. Repeats within serveErrorMinGap fold into the next recorded
// event's Count (total occurrences), the same ×N motif mount serves carry.
func (s *Server) recordServeError(op, cause string, c *caller) {
	if s.OnServeError == nil {
		return
	}
	// Keyed on the OP ALONE, never on the cause. The cause embeds the
	// decoder's own error text, which quotes bytes the caller chose — so a
	// prober that varies one digit ("min_protocol":1<N>0) mints a fresh key
	// per request and every request earns its own durable line. Measured at
	// ~1200 lines/sec, which evicts the real unlock/denial/grant history from
	// agent-history.jsonl (trim keeps the newest half) in seconds: exactly
	// the eviction this limit exists to prevent, walked straight through the
	// middle of it. A caller-influenced value can never be part of a
	// rate-limit key.
	//
	// The cost is real and accepted: several genuinely different decode
	// failures inside one gap now fold into one event carrying the FIRST
	// cause and the total Count. An investigator loses the variety, which is
	// the lesser loss — the raw prose still lands in agent.log, and an
	// unbounded durable trail loses everything.
	key := op
	now := time.Now()
	s.serveErrMu.Lock()
	if s.serveErrSeen == nil {
		s.serveErrSeen = map[string]*serveErrNote{}
	}
	n := s.serveErrSeen[key]
	if n != nil && now.Sub(n.last) < serveErrorMinGap {
		n.suppressed++
		s.serveErrMu.Unlock()
		return
	}
	var suppressed int
	if n != nil {
		suppressed = n.suppressed
	}
	s.serveErrSeen[key] = &serveErrNote{last: now}
	s.serveErrMu.Unlock()

	e := SessionEvent{UnixTime: now.Unix(), Kind: KindError, Op: op, Cause: cause}
	if suppressed > 0 {
		e.Count = int64(suppressed) + 1
	}
	if c != nil {
		e.By = c.command()
		e.ByPID = c.pid
		e.LaunchedBy = c.launchedBy()
	}
	s.OnServeError(e)
}
