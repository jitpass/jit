// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package ui

import (
	"bytes"
	"strings"
	"testing"
)

// A disabled tracker must be byte-for-byte invisible: this is what guarantees
// piped/CI/--quiet runs behave exactly as if progress didn't exist.
func TestDisabledTrackerWritesNothing(t *testing.T) {
	var buf bytes.Buffer
	tr := New(&buf, false, false)
	tr.Step("Scanning .env files…", "Scanned .env files")
	tr.Update("3/9")
	tr.Step("Scanning MCP configs…", "Scanned MCP configs")
	tr.Stop()
	if buf.Len() != 0 {
		t.Fatalf("disabled tracker wrote %q, want nothing", buf.String())
	}
}

// The dumb-terminal fallback (enabled, not animate) prints one plain line per
// step in order, with no ANSI escapes or carriage returns.
func TestPlainModePrintsOneLinePerStep(t *testing.T) {
	var buf bytes.Buffer
	tr := New(&buf, true, false)
	tr.Step("Scanning .env files…", "Scanned .env files")
	tr.Update("ignored in plain mode")
	tr.Step("Scanning MCP configs…", "Scanned MCP configs")
	tr.Stop()

	got := buf.String()
	want := "Scanning .env files…\nScanning MCP configs…\n"
	if got != want {
		t.Fatalf("plain mode output = %q, want %q", got, want)
	}
	if strings.ContainsAny(got, "\r\033") {
		t.Fatalf("plain mode emitted control characters: %q", got)
	}
}

// In animate mode the final settle must leave a persistent past-tense line and
// end on a newline so the caller's next output starts clean. (color.NoColor is
// on under `go test` since stdout isn't a TTY, so the check mark is bare.)
func TestAnimateModeSettlesToDoneLine(t *testing.T) {
	var buf bytes.Buffer
	tr := New(&buf, true, true)
	tr.Step("Scanning .env files…", "Scanned .env files")
	tr.Step("Scanning MCP configs…", "Scanned MCP configs")
	tr.Stop()

	got := buf.String()
	if !strings.Contains(got, "Scanned .env files") || !strings.Contains(got, "Scanned MCP configs") {
		t.Fatalf("animate mode missing settled done lines: %q", got)
	}
	if !strings.HasSuffix(got, "\n") {
		t.Fatalf("animate mode did not end on a newline: %q", got)
	}
}

// Stop with no steps, and a double Stop, must both be safe no-ops.
func TestStopIsIdempotentAndSafeWithoutSteps(t *testing.T) {
	var buf bytes.Buffer
	tr := New(&buf, true, true)
	tr.Stop()
	tr.Stop()
	if buf.Len() != 0 {
		t.Fatalf("Stop without steps wrote %q, want nothing", buf.String())
	}
}
