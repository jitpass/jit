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

// auditExcludedPaths excludes by full command path, for a name too generic to
// key on ("check" could belong to any future command).
//
// `jit guard check` is the shell history guard's classification helper: the
// zsh hook forks it for every command line that passes its cheap admit test,
// so it runs constantly at the interactive prompt. Recording it would be
// wrong twice over. It is on the critical path of the user's keystrokes, and
// an audit append (open, lock, write) is real latency there. And it does not
// belong in the trail on its own terms: it hands out nothing, stores nothing,
// and reads a line the user is in the middle of typing — logging it would
// build a timestamped record of WHEN someone typed credential-shaped
// commands, which is not what an audit log of secret access is for.
var auditExcludedPaths = map[string]bool{
	"jit guard check": true,
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
	if auditExcludedCommands[cmd.Name()] || auditExcludedPaths[cmd.CommandPath()] {
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
		Args:       sanitizeInvocationArgs(cmdPath, os.Args[1:], cmd.Flags().Args(), cmdErr == nil),
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

// recordSideEffect appends an audit record for a persistent change a command
// made BEYOND its own name — work the user consented to as part of a plan
// rather than by typing that command.
//
// The trail is meant to answer "what has jit done to this machine", and the
// per-invocation record answers it only for commands whose name IS the change.
// Bare `jit migrate` can install the shell history guard, which writes a hook
// and a line into the user's ~/.zshrc that then runs on every command they
// type. Recorded as only `cmd="jit migrate"`, that persistent change would be
// invisible: someone auditing later would see a migration and have no way to
// learn where the hook in their rc file came from.
//
// cmdPath is the command the change is equivalent to (so `jit audit --grep
// guard` finds it), and args render the line, including who really did it.
// Failures are swallowed exactly as recordAuditEvent's are: an audit trail is
// a nicety, and nothing about recording a change may make the change itself
// appear to have failed.
func recordSideEffect(cmdPath string, args []string, byCommand string) {
	root, err := vaultRootDir()
	if err != nil {
		return
	}
	rec := auditlog.Record{
		UnixNano: time.Now().UnixNano(),
		Command:  cmdPath,
		Args:     append(args, "(by "+byCommand+")"),
		UID:      os.Getuid(),
		PID:      os.Getpid(),
		PPID:     os.Getppid(),
		Success:  true,
	}
	if u, uerr := user.Current(); uerr == nil {
		rec.User = u.Username
	} else {
		rec.User = strconv.Itoa(rec.UID)
	}
	rec.Parent, rec.LaunchedBy = resolveInvoker()
	auditlog.New(root, os.Stderr).Append(rec)
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
// so a low-entropy secret can't slip through. positionals is the command's
// parsed positional arguments (cobra's Flags().Args()) and parsedOK reports
// whether flag parsing succeeded — together they tell a value that was passed
// on the command line from one that wasn't.
func sanitizeInvocationArgs(cmdPath string, rawArgs, positionals []string, parsedOK bool) []string {
	args := auditlog.Redact(rawArgs)
	if !secretValueCommands[cmdPath] {
		return args
	}
	// Skip the value mask ONLY when we are certain no value was on the command
	// line: a clean parse that yielded exactly the one <path> positional (the
	// value came from the prompt or --stdin). Then masking the last token would
	// redact the secret's PATH — a non-secret the log should keep.
	//
	// On a parse ERROR the positional count is unreliable — cobra returns none
	// even when a value is present (`jit vault set --stdim path secret`, a
	// mistyped flag) — so we must NOT infer "no value" from an empty slice, or a
	// weak value would be logged in the clear. Fall back to masking in every
	// case but the confirmed single-positional one.
	if parsedOK && len(positionals) == 1 {
		return args
	}
	// The SAME grammar the agent's By redaction applies (one implementation,
	// auditlog.MaskVaultSetValues, so the two halves of the merged `jit
	// audit` timeline can never disagree): every element past the path is
	// masked, including a value that starts with "-" or a mis-pasted extra
	// argument. The grammar wants argv[0]; os.Args[1:] lacks it, so lend it
	// one.
	if masked, changed := auditlog.MaskVaultSetValues(append([]string{"jit"}, args...)); changed {
		return masked[1:]
	}
	// The grammar saw nothing past the path, but on a failed parse the one
	// positional present may itself be a mistyped value sitting in the path
	// slot — keep the old conservative fallback and mask the last non-flag
	// token rather than trust it.
	for i := len(args) - 1; i >= 0; i-- {
		if strings.HasPrefix(args[i], "-") {
			continue
		}
		args[i] = auditlog.RedactToken
		break
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
