// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package wrap

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// This file is the per-invocation hot path — it runs on every wrapped CLI
// call before the target starts — so it stays stdlib-only and does no
// parsing or vault work of its own; all of that belongs to the jit run
// process it execs into (docs/internal/WRAP-PLAN.md §4).

// ShimInvocation reports which wrapped tool this process was invoked as, if
// any: argv[0]'s basename isn't "jit" AND the invoked executable lives in
// the shim directory. The second condition keeps a manually renamed jit
// binary elsewhere on disk behaving as plain jit instead of surprising its
// caller with shim dispatch.
func ShimInvocation() (tool string, ok bool) {
	tool = filepath.Base(os.Args[0])
	if tool == "jit" {
		return "", false
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", false
	}
	exe, err := os.Executable() // the symlink's own path, not its target (darwin returns the exec'd path)
	if err != nil {
		return "", false
	}
	if !samePath(filepath.Dir(exe), ShimDir(home)) {
		return "", false
	}
	return tool, true
}

// ShimExec replaces this process with
// `jit run --profile wrap-<tool> -- <real-tool> <args...>`. It returns only
// on failure; the caller prints the error and exits 127 — loudly, never
// silently degrading to an unwrapped run (docs/internal/WRAP-PLAN.md §3.1).
func ShimExec(tool string, args []string) error {
	// Belt-and-braces recursion guard: even if real-binary resolution is
	// somehow defeated (the PATH skip below is the primary defense), the
	// second pass through the shim for the same tool aborts instead of
	// fork-looping.
	guard := guardVar(tool)
	if os.Getenv(guard) != "" {
		return fmt.Errorf("recursion detected, shim invoked twice for the same tool, refusing to loop")
	}
	if err := os.Setenv(guard, "1"); err != nil {
		return err
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	realTool, err := lookPathSkipping(os.Getenv("PATH"), tool, ShimDir(home))
	if err != nil {
		return fmt.Errorf("real %q not found in PATH beyond the shim directory, `jit wrap undo %s` removes the shim", tool, tool)
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	jitBinary, err := filepath.EvalSymlinks(exe) // resolve the shim symlink back to the jit binary itself
	if err != nil {
		return err
	}

	// A grant-wrap runs `jit run --with <name>`; an env-wrap runs
	// `jit run --profile wrap-<tool>`. The manifest is the one place that
	// distinction lives; reading it here (a small JSON file under $HOME)
	// keeps the shim mode-agnostic apart from this branch.
	manifest, err := LoadManifest(home)
	if err != nil {
		return err
	}

	// syscall.Exec never returns on success — same contract as jit run's
	// own exec, which this process is about to become.
	return syscall.Exec(jitBinary, shimArgv(tool, realTool, manifest.Tools[tool], args), os.Environ()) // #nosec G204 -- tool comes from the shim symlink's own name, installed by `jit wrap add`; args are the user's own command line
}

// shimArgv builds the jit run invocation a shim execs into. argv[0] is
// "jit" so the re-exec'd binary takes its normal CLI path, not shim mode.
// A grant-wrap (entry.With set) grants a global mount; an env-wrap injects
// a profile.
func shimArgv(tool, realTool string, entry Entry, args []string) []string {
	if entry.IsGrant() {
		return append([]string{"jit", "run", "--with", entry.With, "--", realTool}, args...)
	}
	return append([]string{"jit", "run", "--profile", ProfileName(tool), "--", realTool}, args...)
}

// guardVar maps a tool name onto its recursion-guard environment variable:
// alphanumerics uppercased, everything else flattened to '_'.
func guardVar(tool string) string {
	mapped := strings.Map(func(r rune) rune {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r >= 'a' && r <= 'z':
			return r - 'a' + 'A'
		default:
			return '_'
		}
	}, tool)
	return "JIT_SHIM_GUARD_" + mapped
}

// lookPathSkipping finds tool in pathEnv like exec.LookPath would, except
// it skips every PATH entry that resolves to skipDir — that skip is what
// breaks the recursion that "shim dir first on PATH, shim named after the
// tool" would otherwise guarantee. Spike-verified against symlinked
// duplicate PATH entries (spike/cli-shim-wrap).
func lookPathSkipping(pathEnv, tool, skipDir string) (string, error) {
	for _, dir := range filepath.SplitList(pathEnv) {
		if dir == "" {
			dir = "."
		}
		if samePath(dir, skipDir) {
			continue
		}
		candidate := filepath.Join(dir, tool)
		info, err := os.Stat(candidate) // #nosec G703 -- candidate is the user's own PATH entries joined with the wrapped tool's name; walking them is what PATH lookup is
		if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
			continue
		}
		return candidate, nil
	}
	return "", fmt.Errorf("%s not found in PATH", tool)
}

// samePath reports whether two paths name the same directory once symlinks
// are resolved; a path that fails to resolve is compared literally.
func samePath(a, b string) bool {
	ra, err := filepath.EvalSymlinks(a)
	if err != nil {
		ra = a
	}
	rb, err := filepath.EvalSymlinks(b)
	if err != nil {
		rb = b
	}
	return ra == rb
}
