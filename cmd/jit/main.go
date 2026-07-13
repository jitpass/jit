// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

// Command jit is the local-first developer secret runtime CLI.
// See RFC.md for the architecture and README.md for why this exists.
package main

import (
	"fmt"
	"os"

	"github.com/jitpass/jit/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
