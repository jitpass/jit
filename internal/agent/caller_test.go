// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package agent

import (
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/lineage"
)

// callerFor builds a *caller with a hand-written process chain, standing in
// for what the kernel would have reported — the identification syscalls
// themselves are covered in internal/lineage; what's under test here is the
// phrasing built ON TOP of them, which is the part a human actually reads.
func callerFor(argv []string, ancestors ...string) *caller {
	c := &caller{pid: 4242, self: lineage.Process{PID: 4242, ExecPath: "/Users/x/go/bin/jit", Argv: argv}}
	for i, name := range ancestors {
		c.ancestors = append(c.ancestors, lineage.Process{PID: int32(100 + i), ExecPath: "/usr/bin/" + name})
	}
	return c
}

// TestChallengeReasonNamesTheProfileNotTheFlag is the whole point of the
// reason string, in one assertion. The real report: an MCP server launched by
// Claude Code as `jit run --profile mcp-jamf -- uv --directory /very/long/...`
// triggered a Touch ID prompt that said only "jit is trying to unlock jit
// agent", and working out why took cross-referencing the agent log against
// shell history.
//
// The prompt must name the PROFILE ("mcp-jamf" — the user's own label for a
// set of secrets, and the thing they're actually being asked to authorize),
// never the flag: "--profile" in the dialog invites the reading that jit has
// some notion of "mcp", which it does not. And it must stay short enough to
// read inside a modal, which the raw argv is not.
func TestChallengeReasonNamesTheProfileNotTheFlag(t *testing.T) {
	c := callerFor(
		[]string{"jit", "run", "--profile", "mcp-jamf", "--", "uv", "--directory", "/Users/x/Documents/ai_security_workspace/ai_tooling/mcp_servers/jamf", "run", "jamf-mcp"},
		"claude", "zsh",
	)

	got := challengeReason(OpUnwrap, c)

	if !strings.Contains(got, `"mcp-jamf"`) {
		t.Errorf("reason = %q, want it to name the profile mcp-jamf — that's the secret set being authorized", got)
	}
	if strings.Contains(got, "--profile") {
		t.Errorf("reason = %q, must not contain the raw flag: a dialog saying --profile implies jit understands an \"mcp\" concept it has none of", got)
	}
	if !strings.Contains(got, "launched by claude") {
		t.Errorf("reason = %q, want the launching process named — \"why is this happening right now\" is the question the prompt has to answer", got)
	}
	if strings.Contains(got, "/Users/") {
		t.Errorf("reason = %q, must not carry absolute paths from the child command into a modal dialog", got)
	}
	if len(got) > maxReasonLen {
		t.Errorf("reason is %d chars (%q), want <= %d — macOS renders it as one sentence in a small modal", len(got), got, maxReasonLen)
	}
}

// A human at a shell prompt already knows why the prompt appeared: they just
// typed the command. Attributing it to "zsh" is technically true and tells
// them nothing, so the shells in the chain must be skipped — and when the
// chain is nothing BUT shells, the reason says nothing about provenance at
// all rather than reaching for a filler.
func TestChallengeReasonSkipsShellsInTheChain(t *testing.T) {
	c := callerFor([]string{"jit", "vault", "set", "API_KEY"}, "-zsh", "login")

	got := challengeReason(OpWrap, c)

	if strings.Contains(got, "launched by") {
		t.Errorf("reason = %q, want no attribution when only shells launched it — the human typed it themselves", got)
	}
	if !strings.Contains(got, "store a secret") {
		t.Errorf("reason = %q, want the op named (a wrap is storing a secret)", got)
	}
}

// An editor that spawns jit is exactly the case attribution exists for, and
// it must survive the shell that sits between them.
func TestChallengeReasonReachesPastRelaysToTheRealLauncher(t *testing.T) {
	c := callerFor([]string{"jit", "run", "--profile=aws-admin", "--", "terraform", "plan"}, "sh", "Code", "launchd")

	got := challengeReason(OpUnwrap, c)

	if !strings.Contains(got, `"aws-admin"`) {
		t.Errorf("reason = %q, want --profile=name (equals form) parsed too", got)
	}
	if !strings.Contains(got, "launched by Code") {
		t.Errorf("reason = %q, want the shell relay skipped and the editor named", got)
	}
}

// A --profile flag belonging to the CHILD command (after --) is not jit's,
// and must never be reported as though jit were unlocking that profile — the
// dialog would name a set of secrets that has nothing to do with the request.
func TestCallerProfileStopsAtDoubleDash(t *testing.T) {
	c := callerFor([]string{"jit", "run", "--", "some-tool", "--profile", "not-jits-profile"})

	if got := c.profile(); got != "" {
		t.Errorf("profile() = %q, want empty — everything after -- belongs to the child command", got)
	}
}

// The in-process case: mountManager resolving a mount's real content unlocks
// the agent through Server-as-KeyWrapper, with no socket and therefore no
// peer to identify. A nil caller must degrade to a truthful, op-only reason
// rather than panicking or inventing a launcher.
func TestChallengeReasonHandlesNilCaller(t *testing.T) {
	got := challengeReason(opServeMounts, nil)

	if got == "" || strings.Contains(got, "launched by") {
		t.Errorf("reason = %q, want a plain op-only reason for an unidentifiable/in-process caller", got)
	}
	if !strings.Contains(got, "mounted files") {
		t.Errorf("reason = %q, want the mount-serving unlock named as itself, not disguised as a wrap/unwrap", got)
	}
}

// The dialog is small; a pathological profile name must not be what makes the
// reason unreadable.
func TestChallengeReasonTruncatesRunawayNames(t *testing.T) {
	c := callerFor([]string{"jit", "run", "--profile", strings.Repeat("x", 300)})

	if got := challengeReason(OpUnwrap, c); len(got) > maxReasonLen {
		t.Errorf("reason is %d chars, want <= %d even with an absurd profile name", len(got), maxReasonLen)
	}
}
