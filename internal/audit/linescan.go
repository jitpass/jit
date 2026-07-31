// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"bufio"
	"bytes"
	"errors"
	"io"
)

// newLineScanner returns a line scanner that never stops early on account of
// one long line: lines past maxContentLineSize (1 MiB, content.go's own
// existing ceiling) are truncated to it and the rest of the line discarded,
// and scanning CONTINUES with the next line.
//
// bufio's 64 KiB default is not a safe choice for anything reading a config
// file a developer wrote. A .env whose first line is a base64'd GCP
// service-account JSON, a long JWT, a data URI, or a minified blob crosses it
// routinely — and a stock Scanner that hits its limit STOPS, reporting
// bufio.ErrTooLong, so every line after the long one goes unread. Two of this
// package's scanners then turned that error into "no findings for this file"
// (see lineScanErr), which is how a .env holding a live sk_live_ key came back
// from `jit scan` as a clean machine, exit 0, with the file absent from the
// report entirely. The threshold was exact: 60 KB of blob reported the key,
// 66 KB reported nothing.
//
// Truncate-and-continue, rather than a merely larger limit, is what actually
// closes that: a bigger number moves the cliff instead of removing it, and a
// scanner for a security tool must not have a file size above which it goes
// quiet. A secret in the first 1 MiB of a long line is still found, and every
// later line is scanned normally.
//
// Line NUMBERING is preserved (one token per newline, always), which the
// callers that map findings back to line numbers and character spans depend
// on — those span loops already bound their indices by the line's own length,
// so a truncated line blanks correctly rather than reaching past its end.
func newLineScanner(r io.Reader) *bufio.Scanner {
	s := bufio.NewScanner(r)
	// The split function below never emits a token larger than
	// maxContentLineSize, so this ceiling exists only to bound how far the
	// buffer can grow while a line is still being accumulated — ErrTooLong is
	// structurally unreachable through it.
	s.Buffer(make([]byte, 0, 64*1024), 2*maxContentLineSize)
	s.Split(scanLinesTruncating(maxContentLineSize))
	return s
}

// scanLinesTruncating is bufio.ScanLines with over-long lines truncated to
// limit and their remainder skipped, instead of ending the scan. The head of
// an over-long line is emitted as its own token; everything up to that line's
// newline is then consumed without producing a second token, so the line count
// stays honest.
func scanLinesTruncating(limit int) bufio.SplitFunc {
	// discarding is set while skipping the tail of a line whose head has
	// already been emitted, and cleared by that line's newline.
	discarding := false
	return func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if discarding {
			if i := bytes.IndexByte(data, '\n'); i >= 0 {
				discarding = false
				// Consume through the newline WITHOUT a token: this tail
				// belongs to the line whose head already went out.
				return i + 1, nil, nil
			}
			if atEOF && len(data) == 0 {
				return 0, nil, nil
			}
			return len(data), nil, nil
		}

		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			return i + 1, truncate(dropCR(data[:i]), limit), nil
		}
		if atEOF {
			if len(data) == 0 {
				return 0, nil, nil
			}
			return len(data), truncate(dropCR(data), limit), nil
		}
		// No newline in view yet. Once more than limit bytes have piled up,
		// this line is over-long: emit its head and start skipping the rest
		// rather than buffering (and ultimately erroring on) all of it.
		if len(data) >= limit {
			discarding = true
			return limit, data[:limit], nil
		}
		return 0, nil, nil // need more data
	}
}

func truncate(line []byte, limit int) []byte {
	if len(line) > limit {
		return line[:limit]
	}
	return line
}

func dropCR(data []byte) []byte {
	if len(data) > 0 && data[len(data)-1] == '\r' {
		return data[:len(data)-1]
	}
	return data
}

// lineScanErr is a scanner's terminal error with a too-long line downgraded to
// "stop reading here", not "this file produced nothing".
//
// newLineScanner's split function makes bufio.ErrTooLong unreachable, so this
// is belt-and-braces for any scanner built some other way — but the downgrade
// is the behaviour that matters and it is cheap to keep stated. Every caller
// accumulates findings as it scans, so returning ErrTooLong upward discards the
// credentials already found ABOVE the long line: the scan saw them, then threw
// them away. A partial answer is always better than a false clean bill of
// health, and for a tool whose only job is telling you where your secrets are,
// silently reporting zero is the worst failure available.
//
// Every OTHER error (a read failure, a vanished file) still propagates: those
// mean the scan could not do its job, which is a fact the caller — and, via
// scan.go's degraded-scanner reporting, the user — needs.
//
// Callers must return whatever they accumulated alongside this, never a zero
// value, or the downgrade buys nothing.
func lineScanErr(s *bufio.Scanner) error {
	if err := s.Err(); err != nil && !errors.Is(err, bufio.ErrTooLong) {
		return err
	}
	return nil
}
