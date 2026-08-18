// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/lineage"
)

// TestAgentStatusExplainsAnUnexplainedPrompt is GAPS.md #75 from the user's
// side of the screen. The report that motivated it: a Touch ID prompt
// appeared while the user was doing something unrelated, and `jit agent
// status` — the one command you'd run to ask why — said only "jit agent is
// running and locked."
//
// The three facts it now has to surface are exactly the three the user had to
// reconstruct by hand from the agent log and their shell history: WHAT asked
// (a jit run for a named profile), WHY it was running at all (Claude Code
// started it), and WHY the session had lapsed in the first place (the idle
// timeout, not anything they did).
func TestAgentStatusExplainsAnUnexplainedPrompt(t *testing.T) {
	now := time.Now()
	var buf bytes.Buffer

	printSessionProvenance(&buf, agent.Status{
		Unlocked: false,
		LastUnlock: &agent.SessionEvent{
			UnixTime:   now.Add(-63 * time.Minute).Unix(),
			Op:         agent.OpUnwrap,
			By:         "jit run --profile mcp-jamf -- uv --directory /Users/menit/Documents/ai_security_workspace/ai_tooling/mcp_servers/jamf run jamf-mcp",
			ByPID:      41233,
			LaunchedBy: "claude",
		},
		LastLock: &agent.SessionEvent{UnixTime: now.Add(-48 * time.Minute).Unix(), Cause: "15m0s idle timeout"},
	})
	got := buf.String()

	for _, want := range []string{
		"mcp-jamf",           // what set of secrets was handed out
		"launched by claude", // why it happened when it did
		"idle timeout",       // why a re-prompt was needed at all
	} {
		if !strings.Contains(got, want) {
			t.Errorf("status output is missing %q, that's one of the three facts a surprise prompt raises:\n%s", want, got)
		}
	}

	for _, line := range strings.Split(strings.TrimRight(got, "\n"), "\n") {
		if len([]rune(line)) > 120 {
			t.Errorf("status line is %d chars, too wide to read in a terminal without wrapping:\n%s", len([]rune(line)), line)
		}
	}
}

// TestAgentStatusStatesItsOwnOrdering is a readability regression test, from
// a real complaint about the first version of this output: an unlock and the
// lock that ended it can land in the SAME second, so two timestamped lines
// both reading "2m ago", in an order nothing declared, left a reader unable
// to tell which had happened last. The section must say which end is newest,
// and be in that order.
func TestAgentStatusStatesItsOwnOrdering(t *testing.T) {
	now := time.Now()
	var buf bytes.Buffer

	// Both events in the same second — the case that made the old output
	// ambiguous, not a contrived one.
	sameSecond := now.Add(-2 * time.Minute).Unix()
	printSessionProvenance(&buf, agent.Status{
		Unlocked:   false,
		LastUnlock: &agent.SessionEvent{UnixTime: sameSecond, Op: agent.OpUnwrap, By: "jit run --profile mcp-jamf -- /usr/bin/true", LaunchedBy: "claude"},
		LastLock:   &agent.SessionEvent{UnixTime: sameSecond, Cause: "explicit lock, launched by claude"},
	})
	got := buf.String()

	if !strings.Contains(got, "most recent first") {
		t.Errorf("session section doesn't declare its ordering, so two same-second events are unreadable:\n%s", got)
	}
	locked, unlocked := strings.Index(got, "locked "), strings.Index(got, "unlocked ")
	if locked < 0 || unlocked < 0 {
		t.Fatalf("want both a locked and an unlocked bullet:\n%s", got)
	}
	if locked > unlocked {
		t.Errorf("the lock is the more recent event but is printed below the unlock, contradicting the stated order:\n%s", got)
	}
}

// While the session is unlocked, the headline already says when it will lock.
// A "Locked ..." line from the PREVIOUS cycle would sit directly under it,
// flatly contradicting it.
func TestAgentStatusOmitsStaleLockLineWhileUnlocked(t *testing.T) {
	now := time.Now()
	var buf bytes.Buffer

	printSessionProvenance(&buf, agent.Status{
		Unlocked:   true,
		Remaining:  12 * time.Minute,
		LastUnlock: &agent.SessionEvent{UnixTime: now.Add(-3 * time.Minute).Unix(), Op: agent.OpUnwrap, By: "jit run --profile aws-admin -- terraform plan", LaunchedBy: "Code"},
		LastLock:   &agent.SessionEvent{UnixTime: now.Add(-30 * time.Minute).Unix(), Cause: "15m0s idle timeout"},
	})
	got := buf.String()

	// Deliberately matched as a whole bullet, not as the substring "locked":
	// every "unlocked" bullet contains that, so the naive check passes even
	// when the bug is present. (It briefly did — the bullets used to be
	// capitalised, and lowercasing them turned this assertion vacuous without
	// failing.)
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "• locked") {
			t.Errorf("unlocked agent printed a lock bullet from a previous cycle, contradicting the headline:\n%s", got)
		}
	}
	if !strings.Contains(got, "launched by Code") {
		t.Errorf("want the launching editor named while unlocked too:\n%s", got)
	}
}

// A fresh agent that has never unlocked has nothing to explain. Printing
// blanks ("unlocked by  at ") would be worse than printing nothing.
func TestAgentStatusSaysNothingWhenThereIsNoHistory(t *testing.T) {
	var buf bytes.Buffer
	printSessionProvenance(&buf, agent.Status{Unlocked: false})
	if buf.Len() != 0 {
		t.Errorf("want no provenance output for an agent that never unlocked, got:\n%s", buf.String())
	}
}

// The long-command case, pinned: $HOME collapses to ~, the line gets cut, and
// what survives the cut is jit's OWN arguments — the profile name is the
// whole reason the line exists, so it must never be what gets truncated away.
func TestShortenCommandKeepsTheProfileAndDropsTheChildArgs(t *testing.T) {
	got := shortenCommand("/Users/menit",
		"jit run --profile mcp-jamf -- uv --directory /Users/menit/Documents/ai_security_workspace/ai_tooling/mcp_servers/jamf run jamf-mcp")

	if !strings.Contains(got, "--profile mcp-jamf") {
		t.Errorf("shortened command lost the profile: %q", got)
	}
	if strings.Contains(got, "/Users/menit") {
		t.Errorf("shortened command didn't collapse $HOME to ~: %q", got)
	}
	if len([]rune(got)) > maxCommandLen() {
		t.Errorf("shortened command is %d chars, want <= %d: %q", len([]rune(got)), maxCommandLen(), got)
	}
}

// The unlock/lock provenance the agent's log must carry — every unlock named
// with what asked and what launched it, every lock named with its cause — is
// now rendered by `jit audit` (logfmt), and pinned by
// TestAuditCommandTextMergesCommandsAndAuth in audit_test.go. The prose
// renderer these once tested (logSessionEvent) was retired when session events
// stopped being double-written into agent.log: `jit audit` is the one place
// the events are read.

// TestDescribeReaderStatesItsConfidence pins the three honest tiers. The
// motivating output: a mount in an editor's watcher loop alternated between
// naming the editor and saying "an unidentified process" — the same editor
// both times. A carried-over identity fixes that, but must never be presented
// as certainty: it's an inference, and an audit line that overstates itself is
// worse than one that admits doubt.
func TestDescribeReaderStatesItsConfidence(t *testing.T) {
	scanned := describeReader(&agent.MountServeEvent{ReaderPath: "/Applications/Visual Studio Code.app/Contents/MacOS/Code", ReaderPID: 57346})
	if scanned != "Code (pid 57346)" {
		t.Errorf("a directly-scanned reader = %q, want it named flatly with no hedging", scanned)
	}

	carried := describeReader(&agent.MountServeEvent{ReaderPath: "/usr/bin/python3", ReaderPID: 900, ReaderLikely: true, ReaderLaunchedBy: "claude"})
	if !strings.HasPrefix(carried, "likely ") {
		t.Errorf("a carried-over reader = %q, want it hedged as \"likely\", it's an inference, not an observation", carried)
	}
	if !strings.Contains(carried, "launched by claude") {
		t.Errorf("reader = %q, want the launcher named: \"python3 read your credentials\" is not actionable, \"launched by claude\" is", carried)
	}

	if unknown := describeReader(&agent.MountServeEvent{}); unknown != "an unidentified process" {
		t.Errorf("a genuinely unseen reader = %q, want the honest fallback", unknown)
	}
}

// The carried-over identity is only safe because of the pid-reuse guard: a
// remembered pid that now runs a DIFFERENT binary must be dropped, never
// re-attributed. Without this, jit would eventually blame one program for
// another program's read — an audit log that lies.
func TestIdentifyReaderRejectsAReusedPID(t *testing.T) {
	// A path nothing holds open, so the live scan is guaranteed to miss and
	// the fallback is what's under test.
	unread := filepath.Join(t.TempDir(), "nobody-reads-this")
	m := &mountManager{stdout: io.Discard, stderr: io.Discard}

	stale := readerIdentity{pid: 999999, execPath: "/usr/bin/python3", identified: true}
	if got := m.identifyReader(unread, stale); got.identified {
		t.Errorf("carried forward a reader whose pid is dead or now runs another binary: %+v", got)
	}

	// This test process, on the other hand, IS alive and IS its own executable
	// — the case the fallback exists to serve.
	//
	// The remembered path comes from lineage.Describe, not os.Executable, and
	// that's the contract, not a convenience: both sides of stillRunning's
	// comparison must come from the same kernel accessor. os.Executable reports
	// /var/folders/... where proc_pidpath reports /private/var/folders/... for
	// the same binary (macOS symlinks /var into /private), so mixing the two
	// sources compares two spellings of one path and concludes they're
	// different programs. In production both sides are proc_pidpath, via
	// IdentifyFIFOReader and Describe respectively.
	self, ok := lineage.Describe(int32(os.Getpid()))
	if !ok {
		t.Fatal("lineage.Describe couldn't identify this test process")
	}
	live := readerIdentity{pid: self.PID, execPath: self.ExecPath, identified: true}
	got := m.identifyReader(unread, live)
	if !got.identified || !got.likely {
		t.Errorf("dropped a live, still-running reader instead of carrying it forward as likely: %+v", got)
	}
}
