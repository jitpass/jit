// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

// Spike: a PATH shim for a hypothetical `jit wrap <cli>` feature.
//
// One binary, hardlinked/copied into a shim directory under each wrapped
// CLI's name (like asdf/mise shims). When invoked as `fakecli`, it finds
// the real fakecli further down PATH (skipping its own directory) and
// execs `jit run --profile wrap-fakecli -- <real> <args...>`, so the
// credential exists only in the target process's environment.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "jitshim: "+format+"\n", args...)
	os.Exit(127)
}

func main() {
	tool := filepath.Base(os.Args[0])

	// Belt-and-braces recursion guard: even if real-binary resolution is
	// somehow defeated (shim dir appearing twice in PATH via symlinks,
	// the real tool re-invoking itself by name), the second pass through
	// the shim for the same tool aborts instead of looping.
	guard := "JIT_SHIM_GUARD_" + strings.Map(func(r rune) rune {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		if r >= 'a' && r <= 'z' {
			return r - 'a' + 'A'
		}
		return '_'
	}, tool)
	if os.Getenv(guard) != "" {
		fail("recursion detected for %q — shim invoked twice, refusing to loop", tool)
	}
	os.Setenv(guard, "1")

	self, err := os.Executable()
	if err != nil {
		fail("cannot determine own path: %v", err)
	}
	selfDir, err := filepath.EvalSymlinks(filepath.Dir(self))
	if err != nil {
		selfDir = filepath.Dir(self)
	}

	real, err := findReal(tool, selfDir)
	if err != nil {
		fail("%v", err)
	}

	// JIT_SHIM_JIT lets the experiments substitute a stub injector to
	// measure the shim's own overhead in isolation; default is the real
	// jit from PATH.
	jitPath := os.Getenv("JIT_SHIM_JIT")
	if jitPath == "" {
		jitPath, err = lookPathSkipping("jit", selfDir)
		if err != nil {
			fail("cannot find jit in PATH: %v", err)
		}
	}

	argv := append([]string{jitPath, "run", "--profile", "wrap-" + tool, "--", real}, os.Args[1:]...)
	if err := syscall.Exec(jitPath, argv, os.Environ()); err != nil {
		fail("exec %s: %v", jitPath, err)
	}
}

// findReal locates tool in PATH, skipping any PATH entry that resolves to
// the shim's own directory — that skip is what breaks the recursion that
// "shim dir first in PATH, shim named after the tool" would otherwise
// guarantee.
func findReal(tool, selfDir string) (string, error) {
	p, err := lookPathSkipping(tool, selfDir)
	if err != nil {
		return "", fmt.Errorf("real %q not found in PATH beyond the shim directory (%s)", tool, selfDir)
	}
	return p, nil
}

func lookPathSkipping(tool, skipDir string) (string, error) {
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			dir = "."
		}
		resolved, err := filepath.EvalSymlinks(dir)
		if err != nil {
			resolved = dir
		}
		if resolved == skipDir {
			continue
		}
		candidate := filepath.Join(dir, tool)
		info, err := os.Stat(candidate)
		if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
			continue
		}
		return candidate, nil
	}
	return "", fmt.Errorf("%s not found", tool)
}
