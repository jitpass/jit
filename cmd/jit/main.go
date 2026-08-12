// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// Command jit is the local-first developer secret runtime CLI.
// See RFC.md for the architecture and README.md for why this exists.
package main

import (
	"errors"
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
		// cli.FormatError, not the bare error: a remedy printed as "run `jit
		// service restart`" is the one line the reader is meant to act on, and
		// it was the only place in jit that showed its own backticks.
		fmt.Fprintln(os.Stderr, cli.FormatError(err))
		// A command whose non-zero exit is a RESULT (jit scan --fail-on
		// tripping) carries its own status, so CI can tell "secrets found"
		// apart from "the scan itself broke". Everything else is exit 1.
		var exitErr *cli.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.Code)
		}
		os.Exit(1)
	}
}
