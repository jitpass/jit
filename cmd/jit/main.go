// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

// Command jit is the local-first developer secret runtime CLI.
// See RFC.md for the architecture and README.md for why this exists.
package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/jitpass/jit/internal/cli"
	"github.com/jitpass/jit/internal/wrap"
)

func init() {
	// Keep the main goroutine on the main OS thread. `jit agent run` hands
	// that thread to internal/screenlock.RunMain — macOS delivers
	// distributed notifications (the screen-lock signal the agent locks
	// its session on) to the MAIN run loop only, so the thread must still
	// be the main one when RunE executes. Free for every other command:
	// the main goroutine simply runs where it started.
	runtime.LockOSThread()
}

func main() {
	// Shim dispatch (docs/internal/WRAP-PLAN.md §3.1): invoked through a
	// ~/.jit/shims symlink named after a wrapped tool, this process
	// becomes `jit run --profile wrap-<tool> -- <real-tool> ...`.
	// ShimExec returns only on failure, and failure is loud (exit 127) —
	// never a silent unwrapped run of the target.
	if tool, ok := wrap.ShimInvocation(); ok {
		err := wrap.ShimExec(tool, os.Args[1:])
		fmt.Fprintf(os.Stderr, "jit shim %s: %v\n", tool, err)
		os.Exit(127)
	}

	if err := cli.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
