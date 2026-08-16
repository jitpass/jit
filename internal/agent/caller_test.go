// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package agent

import (
	"strings"
	"testing"
	"unicode/utf8"

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
		t.Errorf("reason = %q, want it to name the profile mcp-jamf, that's the secret set being authorized", got)
	}
	if strings.Contains(got, "--profile") {
		t.Errorf("reason = %q, must not contain the raw flag: a dialog saying --profile implies jit understands an \"mcp\" concept it has none of", got)
	}
	if !strings.Contains(got, "launched by claude") {
		t.Errorf("reason = %q, want the launching process named, \"why is this happening right now\" is the question the prompt has to answer", got)
	}
	if strings.Contains(got, "/Users/") {
		t.Errorf("reason = %q, must not carry absolute paths from the child command into a modal dialog", got)
	}
	if n := utf8.RuneCountInString(got); n > maxReasonLen {
		t.Errorf("reason is %d chars (%q), want <= %d, macOS renders it as one sentence in a small modal", n, got, maxReasonLen)
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
		t.Errorf("reason = %q, want no attribution when only shells launched it, the human typed it themselves", got)
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
		t.Errorf("profile() = %q, want empty, everything after -- belongs to the child command", got)
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

	if got := challengeReason(OpUnwrap, c); utf8.RuneCountInString(got) > maxReasonLen {
		t.Errorf("reason is %d chars, want <= %d even with an absurd profile name", utf8.RuneCountInString(got), maxReasonLen)
	}
}

// A profile name is user-written text and can be non-ASCII. Truncation
// used to slice by byte index, so a cut landing inside a multi-byte
// character put literally invalid UTF-8 into the one string whose entire
// job is to be read by a human on the Touch ID dialog.
func TestChallengeReasonTruncationNeverSplitsARune(t *testing.T) {
	c := callerFor([]string{"jit", "run", "--profile", strings.Repeat("日本語の秘密", 20)})

	got := challengeReason(OpUnwrap, c)
	if !utf8.ValidString(got) {
		t.Errorf("reason = %q is not valid UTF-8, truncation split a multi-byte character", got)
	}
	if utf8.RuneCountInString(got) > maxReasonLen {
		t.Errorf("reason is %d runes, want <= %d", utf8.RuneCountInString(got), maxReasonLen)
	}
}

// The session history is durable (agent-history.jsonl, rendered back by `jit
// audit` and `jit agent history`), and By is the caller's own argv — so a
// secret the caller carried on its command line must be masked BEFORE the
// event exists. The application audit log promises it "records that a command
// RAN, not the secret it may have carried" (internal/auditlog); the agent's
// half of the merged timeline has to keep the same promise, or `jit run --
// tool --token=…` upgrades a transient argv into a durable plaintext copy —
// precisely the shell-history exposure jit exists to eliminate.
func TestUnlockEventNeverRecordsACredentialFromTheCallersArgv(t *testing.T) {
	secret := "sk_FAKEfixture_notARealKeyXYZ0123"
	c := callerFor([]string{"jit", "run", "--profile", "deploy", "--", "curl", "-H", "Authorization=" + secret}, "claude")

	e := unlockEvent(OpUnwrap, c)

	if strings.Contains(e.By, secret) {
		t.Fatalf("By = %q carries the caller's raw credential into the durable history", e.By)
	}
	if !strings.Contains(e.By, "jit run --profile deploy") {
		t.Errorf("By = %q, want the non-secret part of the command kept legible", e.By)
	}
}

// A weak value ("hunter2") is not credential-shaped, so the entropy pass alone
// would record it — the vault-set positional mask has to catch it, the same
// way cli/auditrecord.go masks the identical position in jit's own os.Args.
// The PATH stays legible: it is the one part of the line an investigation
// needs, and it is not a secret.
func TestUnlockEventMasksAVaultSetValueTooWeakForTheEntropyTest(t *testing.T) {
	c := callerFor([]string{"jit", "vault", "set", "stripe/live-key", "hunter2"})

	e := unlockEvent(OpWrap, c)

	if strings.Contains(e.By, "hunter2") {
		t.Fatalf("By = %q records the vault-set value in the clear", e.By)
	}
	if !strings.Contains(e.By, "stripe/live-key") {
		t.Errorf("By = %q, want the secret's path kept, it is not a secret", e.By)
	}
}

// The path-only form carries no value (it came from the prompt or --stdin),
// and masking the last positional then would redact the path itself.
func TestUnlockEventKeepsVaultSetPathWhenValueCameFromPrompt(t *testing.T) {
	c := callerFor([]string{"jit", "vault", "set", "stripe/live-key", "--stdin"})

	e := unlockEvent(OpWrap, c)

	if !strings.Contains(e.By, "stripe/live-key") {
		t.Errorf("By = %q, want the path kept when no value was on the line", e.By)
	}
}

// recordServeError stamps the same By provenance an unlock would, for peers
// that were REJECTED — and a rejected peer's argv is even less trustworthy
// than an accepted one's, so it gets the same redaction.
func TestRecordServeErrorRedactsTheRejectedPeersArgv(t *testing.T) {
	secret := "sk_FAKEfixture_notARealKeyXYZ0123"
	var got SessionEvent
	s := &Server{OnServeError: func(e SessionEvent) { got = e }}
	c := callerFor([]string{"some-tool", "--token=" + secret})

	s.recordServeError("reject", "peer uid mismatch", c)

	if strings.Contains(got.By, secret) {
		t.Fatalf("By = %q carries a rejected peer's raw credential into the history", got.By)
	}
	if got.ByPID != c.pid {
		t.Errorf("ByPID = %d, want %d: redaction must not cost the provenance", got.ByPID, c.pid)
	}
}
