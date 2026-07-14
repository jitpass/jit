// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package lineage

import (
	"encoding/binary"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// maxAncestry bounds how far Ancestry walks up. Nothing jit cares about is
// more than a few hops from the caller (a `jit run` an editor spawned is
// two), and a bounded walk is also what keeps a corrupted/cyclic parent
// chain — pid reuse can, in principle, produce one — from looping forever.
const maxAncestry = 8

// Process is one process's kernel-reported identity: what it is (ExecPath),
// how it was invoked (Argv), and who started it (PPID). Every field is read
// from the kernel, never accepted from the process itself — see Describe.
//
// Argv is nil when the kernel wouldn't answer (another user's process, or
// one that exited between the peer-pid read and this call). Callers must
// treat every field as best-effort and cosmetic; this package's doc comment
// explains why none of it may ever become a gate.
type Process struct {
	PID      int32
	ExecPath string
	Argv     []string
	PPID     int32
}

// Name is what a human should call this process ("claude", "jit", "Code") —
// what a Touch ID prompt or a status line says, with the full path left in
// ExecPath for anyone who wants it.
//
// Usually the executable's base name, but not always, and the exception is
// not exotic: Claude Code installs as
//
//	~/.local/bin/claude -> ~/.local/share/claude/versions/2.1.209
//
// so the file the kernel reports executing is NAMED "2.1.209", and a prompt
// built from the base name said "launched by 2.1.209" — found by running the
// real thing, since a unit test would only ever have been fed a name someone
// already believed. When the base name carries no information (a bare version
// string), the closest meaningful path component is the program's real name;
// walking up to it keeps this kernel-derived rather than trusting argv[0],
// which the process itself chooses and could set to anything.
func (p Process) Name() string {
	if p.ExecPath == "" {
		return ""
	}
	parts := strings.Split(filepath.Clean(p.ExecPath), string(filepath.Separator))
	for i := len(parts) - 1; i >= 0; i-- {
		if name := parts[i]; name != "" && !isVersionLike(name) && !isPathNoise(name) {
			return name
		}
	}
	return filepath.Base(p.ExecPath)
}

// isVersionLike reports whether a path component is nothing but a version
// ("2.1.209", "v3", "1.0.0-rc2") — a name that identifies a release, never a
// program.
func isVersionLike(s string) bool {
	s = strings.TrimPrefix(s, "v")
	if s == "" || !strings.ContainsFunc(s, func(r rune) bool { return r >= '0' && r <= '9' }) {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r == '.', r == '-', r == '_':
		case r >= 'a' && r <= 'z': // "1.0.0-rc2", "2.1.209-beta"
		default:
			return false
		}
	}
	// A component that is ONLY letters ("claude") is a name, not a version;
	// requiring a digit AND a separator keeps "beta" or "node" out of here.
	return strings.ContainsAny(s, ".-_") || isAllDigits(s)
}

func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

// isPathNoise reports whether a component is packaging scaffolding rather
// than a program name — the directories a version-named binary tends to sit
// under, and the ones inside a macOS .app bundle.
func isPathNoise(s string) bool {
	switch s {
	case "bin", "sbin", "libexec", "versions", "current", "latest",
		"Contents", "MacOS", "Resources", "Helpers", "share", "local":
		return true
	}
	return false
}

// Command is the full invocation, argv joined — for a wide terminal (jit
// agent status) rather than a modal dialog. Falls back to the exec path
// when the kernel wouldn't give up argv.
func (p Process) Command() string {
	if len(p.Argv) == 0 {
		return p.ExecPath
	}
	return strings.Join(p.Argv, " ")
}

// Describe reads pid's identity from the kernel: exec path via libproc
// (pidExecPath), argv and parent pid via sysctl. ok is false when pid is
// gone or belongs to another user — both are ordinary, not errors.
//
// Nothing here trusts the described process. That distinction is the whole
// point: a caller could claim anything about itself in an RPC field, so the
// agent asks the kernel instead. It still isn't an authorization mechanism
// (a process can exec something else after connecting, and pids get reused)
// — it is an audit and explanation mechanism, exactly like the rest of this
// package.
func Describe(pid int32) (Process, bool) {
	if pid <= 0 {
		return Process{}, false
	}
	p := Process{PID: pid, ExecPath: pidExecPath(pid)}

	if kp, err := unix.SysctlKinfoProc("kern.proc.pid", int(pid)); err == nil {
		p.PPID = int32(kp.Eproc.Ppid)
	}
	p.Argv = procArgs(pid)

	if p.ExecPath == "" && len(p.Argv) == 0 && p.PPID == 0 {
		return Process{}, false // nothing at all: pid is gone or not ours
	}
	return p, true
}

// Ancestry is pid and its parents, nearest first, stopping at launchd/init
// (pid 1), at an unreadable process, or at maxAncestry — whichever comes
// first. The chain is what turns "a jit process asked for the key" into
// "...because Claude Code started it", which is the question a surprise
// Touch ID prompt actually raises.
func Ancestry(pid int32) []Process {
	var chain []Process
	for p := pid; p > 1 && len(chain) < maxAncestry; {
		proc, ok := Describe(p)
		if !ok {
			break
		}
		chain = append(chain, proc)
		if proc.PPID == p { // self-parent: impossible, but never loop on it
			break
		}
		p = proc.PPID
	}
	return chain
}

// LaunchedBy names the nearest ancestor that actually EXPLAINS a process,
// skipping the shells and wrappers that merely relay it — a `jit run` typed by
// a human has a shell parent, and "launched by zsh" is technically true and
// completely uninformative. Empty when the chain is all relays: for something
// a human ran at a prompt, the honest answer is "you did", and saying nothing
// is how that gets said.
//
// ancestors is the chain WITHOUT the process itself (Ancestry(pid)[1:]).
// Shared by the agent (who unlocked the vault) and the mount manager (who
// read a secret file), which ask the same question of different processes.
func LaunchedBy(ancestors []Process) string {
	for _, p := range ancestors {
		if name := p.Name(); name != "" && !isRelay(name) {
			return name
		}
	}
	return ""
}

// isRelay reports whether name is a process that passes work along rather than
// being the reason for it. Shells dominate, but the login/exec wrappers belong
// here too — none of them is ever the interesting answer to "why is this
// happening".
func isRelay(name string) bool {
	switch strings.TrimPrefix(name, "-") { // login shells appear as "-zsh"
	case "zsh", "bash", "sh", "dash", "fish", "tcsh", "csh", "ksh",
		"login", "env", "sudo", "xargs", "time":
		return true
	}
	return false
}

// procArgs reads pid's argv from the kernel via sysctl kern.procargs2,
// whose layout is: int32 argc, the exec path, NUL padding, then argc
// NUL-terminated argv strings (the environment follows, which we
// deliberately stop before — a caller's environment is exactly the kind of
// thing that tends to hold secrets, and jit has no business copying it into
// its own logs).
func procArgs(pid int32) []string {
	buf, err := unix.SysctlRaw("kern.procargs2", int(pid))
	if err != nil || len(buf) < 4 {
		return nil
	}
	argc := int(int32(binary.LittleEndian.Uint32(buf[:4]))) // #nosec G115 -- deliberate: kern.procargs2's argc field IS an int32; reinterpreting the raw uint32 as signed is the decode, and the <=0 check below rejects any wrapped/garbage value
	if argc <= 0 {
		return nil
	}

	// Skip the exec path and the NUL padding after it, leaving the cursor
	// on the first argv string.
	rest := buf[4:]
	end := 0
	for end < len(rest) && rest[end] != 0 {
		end++
	}
	rest = rest[end:]
	for len(rest) > 0 && rest[0] == 0 {
		rest = rest[1:]
	}

	argv := make([]string, 0, argc)
	for len(rest) > 0 && len(argv) < argc {
		end := 0
		for end < len(rest) && rest[end] != 0 {
			end++
		}
		argv = append(argv, string(rest[:end]))
		if end == len(rest) {
			break
		}
		rest = rest[end+1:]
	}
	return argv
}
