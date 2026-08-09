// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/migrate"
)

// The result renderer must name the agent, count copies by cache area, and
// never lean on a raw path — the whole point of the origin-forward design.
func TestRenderAgentCleanupResult(t *testing.T) {
	c := migrate.AgentCacheCleanup{
		Edited: []migrate.AgentCacheEdit{
			{Path: "/h/.claude/file-history/s/a@v1", Agent: "Claude Code", Area: "edit history", Occurrences: 1},
			{Path: "/h/.claude/file-history/s/b@v2", Agent: "Claude Code", Area: "edit history", Occurrences: 1},
			{Path: "/h/.claude/projects/p/t.jsonl", Agent: "Claude Code", Area: "transcripts", Occurrences: 3},
		},
		Skipped: []migrate.AgentCacheSkip{
			{Path: "/h/.local/share/opencode/db", Agent: "OpenCode", Reason: "a binary store; rewriting it would corrupt the file"},
		},
	}
	var b bytes.Buffer
	renderAgentCleanupResult(&b, "/h", c)
	out := b.String()

	for _, want := range []string{
		"Cleared 5 copies",  // 1+1+3 occurrences
		"Claude Code",       // agent named
		"2 in edit history", // two files under that area
		"1 in transcripts",  // one file under that area
		"OpenCode",          // the skip
		"binary store",      // the reason, verbatim
		"jit migrate undo",  // the recovery path
	} {
		if !strings.Contains(out, want) {
			t.Errorf("result missing %q:\n%s", want, out)
		}
	}
	// A copy left in place is a real exposure; it must not hide inside the
	// green "cleared" line.
	if !strings.Contains(out, "left in place") {
		t.Errorf("skips not surfaced:\n%s", out)
	}
}

// The plan renderer feeds both the confirm gate and --dry-run, so it must
// state what WOULD happen without claiming anything was done.
func TestRenderAgentCleanupPlan(t *testing.T) {
	c := migrate.AgentCacheCleanup{
		Edited: []migrate.AgentCacheEdit{
			{Path: "/h/.claude/file-history/s/a@v1", Agent: "Claude Code", Area: "edit history"},
		},
	}
	var b bytes.Buffer
	renderAgentCleanupPlan(&b, "/h", c)
	out := b.String()
	if !strings.Contains(out, "will redact") {
		t.Errorf("plan should describe intent, got:\n%s", out)
	}
	if strings.Contains(out, "Cleared") {
		t.Errorf("plan must not claim work was done:\n%s", out)
	}
}

// TestAgentCleanupUndoCommandNamesTheFiles pins the fix for a real gap: the
// sweep rewrites files OUTSIDE the path the user migrated, and
// `jit migrate undo <that path>` restores only what it is pointed at. The old
// line read "`jit migrate undo` restores the file", which a reader reasonably
// took as covering these; it did not, and ten redacted spans survived an undo
// the user believed was complete.
func TestAgentCleanupUndoCommandNamesTheFiles(t *testing.T) {
	const home = "/Users/alex"

	t.Run("a few files are named outright", func(t *testing.T) {
		cmd := agentCleanupUndoCommand(home, []migrate.AgentCacheEdit{
			{Path: home + "/.claude/projects/p/a.jsonl"},
			{Path: home + "/.claude/history.jsonl"},
		})
		for _, want := range []string{"jit migrate undo", "~/.claude/history.jsonl", "~/.claude/projects/p/a.jsonl"} {
			if !strings.Contains(cmd, want) {
				t.Errorf("command %q missing %q", cmd, want)
			}
		}
	})

	t.Run("many files collapse to the agent directories, still covering them", func(t *testing.T) {
		var edits []migrate.AgentCacheEdit
		for _, n := range []string{"a", "b", "c", "d", "e"} {
			edits = append(edits, migrate.AgentCacheEdit{Path: home + "/.claude/projects/p/" + n + ".jsonl"})
		}
		edits = append(edits, migrate.AgentCacheEdit{Path: home + "/.cursor/cache/x.json"})
		cmd := agentCleanupUndoCommand(home, edits)
		for _, want := range []string{"~/.claude", "~/.cursor"} {
			if !strings.Contains(cmd, want) {
				t.Errorf("command %q does not cover %q", cmd, want)
			}
		}
		// The point of collapsing is brevity; a per-file list defeats it.
		if strings.Contains(cmd, "a.jsonl") {
			t.Errorf("command still enumerates every file: %q", cmd)
		}
	})

	t.Run("duplicate paths are named once", func(t *testing.T) {
		cmd := agentCleanupUndoCommand(home, []migrate.AgentCacheEdit{
			{Path: home + "/.claude/history.jsonl"},
			{Path: home + "/.claude/history.jsonl"},
		})
		if strings.Count(cmd, "history.jsonl") != 1 {
			t.Errorf("path repeated: %q", cmd)
		}
	})
}
