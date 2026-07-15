// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

// Command jit is the local-first developer secret runtime CLI.
// See RFC.md for the architecture and README.md for why this exists.
package main

import (
	"fmt"
	"os"

	"github.com/jitpass/jit/internal/cli"
	"github.com/jitpass/jit/internal/wrap"
)

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
