// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/auditlog"
	"github.com/jitpass/jit/internal/lineage"
)

// auditExcludedCommands are the invocations the application audit log
// deliberately does NOT record: shell-completion plumbing (cobra runs
// __complete on every Tab), the help command, and docs generation. None of
// these are a user "doing" something on their secrets, and logging them would
// bury the real trail under Tab-key noise. Everything else, including the
// credential-process helpers other tools invoke, IS recorded: those hand out
// secrets and are exactly what an audit trail is for.
var auditExcludedCommands = map[string]bool{
	"__complete":       true,
	"__completeNoDesc": true,
	"completion":       true,
	"help":             true,
	"docs-gen":         true,
}

// secretValueCommands take a raw secret value as their final positional
// argument (`jit vault set <path> <value>`). auditlog.Redact already masks
// anything credential-SHAPED, but a weak secret ("hunter2") isn't, so for
// these commands the final positional is masked unconditionally, the only
// place it could be is the secret.
var secretValueCommands = map[string]bool{
	"jit vault set": true,
}

func init() {
	recordInvocation = recordAuditEvent
}

// recordAuditEvent writes one finished invocation to the application audit
// log. Every failure here is swallowed: an audit trail is a nicety, and
// nothing about recording that a command ran may make the command itself
// appear to have failed.
func recordAuditEvent(cmd *cobra.Command, cmdErr error, elapsed time.Duration) {
	if cmd == nil {
		return
	}
	if auditExcludedCommands[cmd.Name()] {
		return
	}
	// A command that only printed its help never touched the user's secrets,
	// so it isn't an audit event. Two shapes reach here:
	//
	//   - a genuinely non-runnable command (no RunE at all), and
	//   - a command GROUP (`jit service`, `jit vault`), which carries a RunE
	//     only so a mistyped subcommand can be rejected — see runCommandGroup.
	//     Invoked bare it prints help and returns nil, exactly like the first
	//     case, so a nil error is what distinguishes "printed help" from work.
	//
	// A MISTYPED subcommand (`jit service un`) is deliberately NOT skipped
	// any more: it now fails with "unknown command", and a failed invocation
	// is precisely the kind of thing the log should carry — the same way
	// `jit bogus` has always been recorded as status=failed.
	if !cmd.Runnable() || (isCommandGroup(cmd) && cmdErr == nil) {
		return
	}
	root, err := vaultRootDir()
	if err != nil {
		return
	}

	cmdPath := cmd.CommandPath() // e.g. "jit vault get"
	rec := auditlog.Record{
		UnixNano:   time.Now().UnixNano(),
		Command:    cmdPath,
		Args:       sanitizeInvocationArgs(cmdPath, os.Args[1:]),
		UID:        os.Getuid(),
		PID:        os.Getpid(),
		PPID:       os.Getppid(),
		DurationMS: elapsed.Milliseconds(),
		Success:    cmdErr == nil,
		Auth:       invocationAuth, // set only when the command forced a fresh Touch ID/passcode challenge
	}
	if u, uerr := user.Current(); uerr == nil {
		rec.User = u.Username
	} else {
		rec.User = strconv.Itoa(rec.UID)
	}
	rec.Parent, rec.LaunchedBy = resolveInvoker()
	if cmdErr != nil {
		rec.Error = redactText(cmdErr.Error())
	}

	logger := auditlog.New(root, os.Stderr)
	logger.Trim()
	logger.Append(rec)
}

// resolveInvoker names this jit process's parent and the nearest ancestor that
// actually explains the call, "claude", "Code", a shell, reusing the exact
// lineage the agent records for its own Touch ID prompts, so a command's
// "launched by" in the audit log and the matching unlock's "launched by" in
// the session history read the same. Best-effort: an empty pair just means the
// kernel wouldn't say (a parent that already exited, another user's process).
func resolveInvoker() (parent, launchedBy string) {
	chain := lineage.Ancestry(int32(os.Getpid())) // #nosec G115 -- getpid always fits int32
	if len(chain) < 2 {
		return "", ""
	}
	ancestors := chain[1:]
	return ancestors[0].Name(), lineage.LaunchedBy(ancestors)
}

// sanitizeInvocationArgs redacts the recorded arguments. auditlog.Redact
// handles credential-shaped tokens generically; on top of that, for commands
// whose grammar puts a raw secret in a known position, that position is masked
// unconditionally so a low-entropy secret can't slip through.
func sanitizeInvocationArgs(cmdPath string, rawArgs []string) []string {
	args := auditlog.Redact(rawArgs)
	if secretValueCommands[cmdPath] {
		// Mask the last non-flag token: `jit vault set <path> <value>`, the
		// value is the only thing it can be, and Redact may have left a weak
		// one untouched.
		for i := len(args) - 1; i >= 0; i-- {
			if strings.HasPrefix(args[i], "-") {
				continue
			}
			args[i] = "<redacted>"
			break
		}
	}
	return args
}

// redactText masks any secret-looking substring in a free-form string (a
// command's error summary) before it is persisted, then truncates it, jit's
// own errors never echo a secret value by design, but the audit log must not
// depend on that holding for every error path forever, and an error that
// quotes an argument back ("no secret stored at \"sk_live_…\"") would slip a
// raw token past a token-by-token pass.
func redactText(s string) string {
	s = auditlog.RedactText(s)
	const max = 300
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
