// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package agent

import (
	"fmt"
	"net"
	"strings"

	"github.com/jitpass/jit/internal/lineage"
)

// caller is who asked the agent to do something, as the KERNEL describes
// them — never as they describe themselves. handleConn builds one per
// connection from the peer pid (see peerPID) and internal/lineage.
//
// This exists because the agent used to be amnesiac about its own prompts.
// A Touch ID/passcode dialog would appear with no way, anywhere, to find out
// what had triggered it: the real answer in one reported case ("Claude Code
// started, which booted MCP servers, two of which are `jit run --profile ...`")
// took cross-referencing the agent log against shell history to reconstruct.
// The agent had every fact needed to just SAY that, and threw them away.
//
// Kernel-derived, and therefore not spoofable by a caller filling in an RPC
// field — but still NOT an authorization mechanism, and nothing here may
// ever become one: a process can exec something else after connecting, and
// pids get reused. RFC.md B6/GAPS.md #1/#4 already concede that an attacker
// with code execution as this user reaches the unlocked agent anyway. This
// is for explaining and auditing, exactly like internal/lineage's reader
// identification. A nil *caller (identification failed, or an in-process
// call that never touched the socket) must always stay legal.
type caller struct {
	pid int32
	// self is the connecting process, ancestors are its parents (nearest
	// first). Both come from lineage.Ancestry.
	self      lineage.Process
	ancestors []lineage.Process
}

// callerFromConn identifies conn's peer, or returns nil if the kernel won't
// say (the peer already exited, say). Never an error: not knowing who called
// is a degraded status line, never a refused request.
func callerFromConn(conn net.Conn) *caller {
	pid, err := peerPID(conn)
	if err != nil || pid <= 0 {
		return nil
	}
	chain := lineage.Ancestry(pid)
	if len(chain) == 0 {
		return &caller{pid: pid}
	}
	return &caller{pid: pid, self: chain[0], ancestors: chain[1:]}
}

// command is the caller's full invocation for a status line or a log: a wide
// terminal can take the whole argv, and when investigating you want the
// literal command back.
func (c *caller) command() string {
	if c == nil {
		return ""
	}
	if cmd := c.self.Command(); cmd != "" {
		return cmd
	}
	return fmt.Sprintf("pid %d", c.pid)
}

// launchedBy names the nearest ancestor that actually EXPLAINS the call. The
// rule (skip the shells that merely relayed it) lives in internal/lineage,
// because the mount manager asks the same question of a different process:
// "who launched the thing that just READ this secret file".
func (c *caller) launchedBy() string {
	if c == nil {
		return ""
	}
	return lineage.LaunchedBy(c.ancestors)
}

// profile extracts the profile name when the caller is a `jit run --profile
// <name>` (or `--profile=<name>`), which is the single most explanatory fact
// available about a jit invocation — "for profile mcp-jamf" tells you which
// secrets are about to be handed out, which is precisely the decision the
// Touch ID prompt is asking you to make. Empty for every other invocation.
//
// Parsing stops at "--": everything after it is the child command's own
// arguments, and a child that happens to take a --profile flag of its own
// must never be mistaken for jit's.
func (c *caller) profile() string {
	if c == nil {
		return ""
	}
	argv := c.self.Argv
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if arg == "--" {
			return ""
		}
		if name, ok := strings.CutPrefix(arg, "--profile="); ok {
			return name
		}
		if arg == "--profile" && i+1 < len(argv) {
			return argv[i+1]
		}
	}
	return ""
}

// maxReasonLen caps what goes into the LocalAuthentication dialog. macOS
// renders the reason as one sentence inside a small modal ("jit is trying to
// <reason>."), and Apple's own guidance is a short phrase — the raw argv of a
// jit-launched MCP server runs past 120 characters of absolute paths and is
// unreadable there. The full command line is still recorded for `jit agent
// status`, which has a whole terminal to print it in.
const maxReasonLen = 90

// challengeReason is what the human actually reads on the Touch ID/passcode
// prompt, phrased to complete macOS's own sentence: "jit is trying to ___."
//
// It answers two questions, in the order a startled user asks them: WHAT is
// about to happen to my secrets, and WHY now. The "why now" half (launchedBy)
// is the one the old fixed string "unlock jit agent" could never answer.
//
// op is the RPC that forced the unlock; c may be nil (an in-process unlock,
// or a caller the kernel wouldn't identify), in which case the reason degrades
// to the op alone rather than inventing an explanation.
func challengeReason(op string, c *caller) string {
	reason := intent(op, c)
	if by := c.launchedBy(); by != "" {
		reason = fmt.Sprintf("%s, launched by %s", reason, by)
	}
	return truncate(reason, maxReasonLen)
}

// intent is the "what" half of challengeReason: what this unlock is FOR,
// named in the user's own vocabulary (a profile they wrote, a file they
// mounted) rather than jit's internal op names.
func intent(op string, c *caller) string {
	if p := c.profile(); p != "" {
		// The profile name is the user's own label — never a flag, never a
		// path. `--profile mcp-jamf` in a config file means nothing to jit
		// beyond "the profile named mcp-jamf"; showing the flag would imply
		// jit understands an "mcp" concept it has no notion of.
		return fmt.Sprintf("unlock the vault for profile %q", truncate(p, 40))
	}
	switch op {
	case OpWrap:
		return "unlock the vault to store a secret"
	case OpUnwrap:
		return "unlock the vault to read a secret"
	case OpReveal:
		return "unlock the vault to reveal a mounted file"
	case opServeMounts:
		return "unlock the vault to serve this project's mounted files"
	default: // OpUnlock, OpRefresh, and anything added later
		return "unlock the vault"
	}
}

// opServeMounts is not a wire op — it is the reason the agent unlocks ITSELF,
// in-process, when mountManager resolves a mount's real content through
// Server-as-KeyWrapper (no socket, therefore no peer pid, therefore no
// caller). Naming it keeps that unlock from having to masquerade as a
// wrap/unwrap it isn't.
const opServeMounts = "serve_mounts"

// truncate cuts s to at most max RUNES. Runes, not bytes: profile names
// are user-written and can be non-ASCII, and a byte-index cut through the
// middle of a multi-byte character puts invalid UTF-8 into the one string
// whose entire job is to be read by a human on a Touch ID dialog.
func truncate(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max <= 1 {
		return string(r[:max])
	}
	return string(r[:max-1]) + "…"
}
