// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// Command named-pipe-spike prototypes the "re-opened FIFO" pattern RFC.md
// Pillar III Tier 3 depends on: serve a live .env file at a conventional path
// via a named pipe, reopening for each new reader so dotenv loaders "just
// work" unmodified across repeated reads/hot-reloads (RFC.md B4).
//
// Not production code — throwaway or to be promoted into internal/mount later.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func main() {
	path := flag.String("path", "", "path to serve the FIFO at")
	count := flag.Int("count", 5, "number of reader cycles to serve before exiting")
	flag.Parse()

	if *path == "" {
		fmt.Fprintln(os.Stderr, "usage: named-pipe-spike -path <path> [-count N]")
		os.Exit(2)
	}

	_ = os.Remove(*path)
	if err := unix.Mkfifo(*path, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "mkfifo failed: %v\n", err)
		os.Exit(1)
	}
	defer os.Remove(*path)

	content := []byte("STRIPE_KEY=sk_test_spike_12345\nDB_URL=postgres://spike\n")

	for i := 1; i <= *count; i++ {
		fmt.Printf("[server] cycle %d: waiting for a reader to open %s ...\n", i, *path)
		start := time.Now()

		// Opening for write blocks until a reader opens the other end — this is
		// exactly the "re-open" behavior: each loop iteration is a fresh serve.
		f, err := os.OpenFile(*path, os.O_WRONLY, 0600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[server] open for write failed: %v\n", err)
			os.Exit(1)
		}

		waited := time.Since(start)
		n, err := f.Write(content)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[server] write failed: %v\n", err)
		}
		if err := f.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "[server] close failed: %v\n", err)
		}
		fmt.Printf("[server] cycle %d: served %d bytes (waited %v for reader)\n", i, n, waited)
	}

	fmt.Println("[server] done serving all cycles, exiting cleanly")
}