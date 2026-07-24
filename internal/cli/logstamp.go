// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"io"
	"sync"
	"time"
)

// stampedWriter prefixes every output line with a wall-clock timestamp —
// wired around `jit service run`'s stdout/stderr only (GAPS.md #48). The
// agent process runs for weeks and everything it prints lands in one
// agent.log; without timestamps a 635k-line log couldn't answer WHEN
// anything happened, which made correlating reads against grants and
// lock events impossible during a real investigation. Interactive
// commands don't want this — their output is read at the moment it's
// printed.
//
// Concurrency-safe: mountManager's Serve goroutines and the RPC handlers
// write to the same streams. Each Write is stamped at line starts only,
// tracking whether the previous Write ended mid-line, so a multi-Write
// line isn't stamped twice (in practice every call site writes whole
// lines via Fprintf).
type stampedWriter struct {
	mu      sync.Mutex
	w       io.Writer
	midline bool
}

func newStampedWriter(w io.Writer) *stampedWriter {
	return &stampedWriter{w: w}
}

func (s *stampedWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var buf bytes.Buffer
	rest := p
	for len(rest) > 0 {
		if !s.midline {
			buf.WriteString(time.Now().Format("2006-01-02 15:04:05 "))
			s.midline = true
		}
		i := bytes.IndexByte(rest, '\n')
		if i < 0 {
			buf.Write(rest)
			break
		}
		buf.Write(rest[:i+1])
		s.midline = false
		rest = rest[i+1:]
	}
	if _, err := s.w.Write(buf.Bytes()); err != nil {
		return 0, err
	}
	return len(p), nil
}
