// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"path/filepath"
	"strings"
	"testing"
)

// A single over-long line must never hide the rest of its file.
//
// This is a regression test for a silent false-clean: every scanner here used
// bufio's 64 KiB default token limit, a Scanner that hits that limit STOPS,
// and buildEnvFileFinding turned the resulting bufio.ErrTooLong into "this
// file has no findings" (classifyEnvFile discards the error). A .env whose
// first line was a 66 KB base64 blob — an entirely ordinary thing to find in
// one — therefore vanished from the report, and `jit scan` announced a clean
// machine with exit 0 while a live sk_live_ key sat on line 2.
//
// The sizes here are deliberately spread ACROSS the old cliff (60 KB scanned
// fine, 66 KB reported nothing) and far past the 1 MiB truncation ceiling, so
// this fails if anyone reintroduces a hard stop at any size at all rather than
// just moving the number.
func TestLongLineDoesNotHideLaterSecrets(t *testing.T) {
	var secretLine = "STRIPE_KEY=sk_live_" + strings.Repeat("x", 24) + "\n"

	for _, blob := range []int{
		1_000,      // control: comfortably under every limit
		60_000,     // just under bufio's 64 KiB default
		66_000,     // just over it — the exact case that reported zero
		2_000_000,  // past the 1 MiB truncation ceiling
		20_000_000, // far past it: the tail must still be scanned
	} {
		t.Run(strings.TrimSpace(byteLabel(blob)), func(t *testing.T) {
			home := t.TempDir()
			dir := filepath.Join(home, "project")
			mkdirAll(t, dir)
			envPath := filepath.Join(dir, ".env")
			writeFile(t, envPath, "BLOB="+strings.Repeat("A", blob)+"\n"+secretLine)

			findings, _, err := Scan(Config{HomeDir: home, RunID: "test", ScannerVersion: "test"})
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			for _, f := range findings {
				if f.FilePath == envPath {
					return // the file was reported, which is the whole contract
				}
			}
			t.Fatalf("a %d-byte first line hid the whole file: %s is absent from %d findings "+
				"(scan reported a clean machine while it held a live-looking key)", blob, envPath, len(findings))
		})
	}
}

// Line numbering must survive truncation: callers map findings back to line
// numbers and character spans, so an over-long line has to consume exactly one
// line's worth of the count, not zero and not two.
func TestTruncatedLineKeepsLineNumbering(t *testing.T) {
	long := strings.Repeat("A", 2_000_000)
	input := "one\n" + long + "\nthree\nfour\n"

	s := newLineScanner(strings.NewReader(input))
	var got []string
	for s.Scan() {
		got = append(got, s.Text())
	}
	if err := lineScanErr(s); err != nil {
		t.Fatalf("lineScanErr: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("got %d lines, want 4 (an over-long line must yield exactly one token): %q", len(got), firstBytes(got))
	}
	if got[0] != "one" || got[2] != "three" || got[3] != "four" {
		t.Errorf("lines around the truncated one are wrong: %q, %q, %q", got[0], got[2], got[3])
	}
	if len(got[1]) != maxContentLineSize {
		t.Errorf("over-long line truncated to %d bytes, want %d", len(got[1]), maxContentLineSize)
	}
}

// A CRLF file must not carry its \r into the parsed line — the scanners match
// values with anchored patterns, and a trailing \r silently breaks them.
func TestLineScannerDropsCR(t *testing.T) {
	s := newLineScanner(strings.NewReader("A=1\r\nB=2\r\n"))
	var got []string
	for s.Scan() {
		got = append(got, s.Text())
	}
	if len(got) != 2 || got[0] != "A=1" || got[1] != "B=2" {
		t.Fatalf("CRLF not stripped: %q", got)
	}
}

func byteLabel(n int) string {
	switch {
	case n >= 1_000_000:
		return "MB" + itoa(n/1_000_000)
	case n >= 1_000:
		return "KB" + itoa(n/1_000)
	default:
		return "B" + itoa(n)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// firstBytes keeps a failure message readable when one of the lines is
// megabytes long.
func firstBytes(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if len(l) > 40 {
			l = l[:40] + "…"
		}
		out = append(out, l)
	}
	return out
}
