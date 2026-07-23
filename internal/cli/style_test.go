// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"bytes"
	"strings"
	"testing"
)

// TestFlowNamesPacksColumns confirms the column-flow helper lays several
// names onto one row (the whole point — a long list becomes a few tidy rows,
// not one item per line) and pads every name but the last in a row so they
// align. Width is the non-terminal fallback (defaultWidth) here, which keeps
// the layout deterministic.
func TestFlowNamesPacksColumns(t *testing.T) {
	var buf bytes.Buffer
	names := []string{"AAA", "BBB", "CCC", "DDD", "EEE"}
	flowNames(&buf, names, "    ")
	out := buf.String()

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) >= len(names) {
		t.Fatalf("flow should pack names onto fewer lines than there are names, got %d lines for %d names:\n%s", len(lines), len(names), out)
	}
	// Every name must survive the layout.
	for _, n := range names {
		if !strings.Contains(out, n) {
			t.Errorf("output missing name %q:\n%s", n, out)
		}
	}
	// The first row leads with the requested indent.
	if !strings.HasPrefix(lines[0], "    AAA") {
		t.Errorf("first row should start with the indent then the first name, got %q", lines[0])
	}
}

// TestFlowNamesEmpty is a no-op guard: nothing to lay out, nothing printed.
func TestFlowNamesEmpty(t *testing.T) {
	var buf bytes.Buffer
	flowNames(&buf, nil, "  ")
	if buf.Len() != 0 {
		t.Errorf("empty input should print nothing, got %q", buf.String())
	}
}
