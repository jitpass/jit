// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

// This file is `jit service log`: reading the raw operational log, tailing it,
// and following it. The RENDERING lives in agentlogview.go — this is the
// command, its flags, and its file handling; that is the house-style view of
// the bytes.

// agentLogLines and agentLogFollow are `jit service log`'s flags.
var agentLogLines int
var agentLogFollow bool

// agentLogRaw prints the log file's bytes exactly as written, skipping the
// human rendering. The formatted view drops repeated prefixes and shortens
// paths, which is what makes it readable and also what would break a grep or
// a pasted bug report — so the untouched bytes stay one flag away.
var agentLogRaw bool

// agentLogPollInterval paces --follow's growth checks — comfortably
// under a human's "is it live?" threshold without hammering stat.
const agentLogPollInterval = 500 * time.Millisecond

var agentLogCmd = &cobra.Command{
	Use:   "log",
	Short: "Show the service's raw operational output (startup, mount notes, serve errors)",
	Long: "Prints the tail of the service's raw output log: the timestamped operational\n" +
		"lines the daemon prints as it runs, startup and shutdown, mount notes (with\n" +
		"who read them), serve-error detail, and anything a crash leaves behind.\n\n" +
		"This is the low-level debug view, not the audit trail. The session events\n" +
		"themselves, every unlock, denial, lock, use, and refused peer, live in the\n" +
		"structured trail that `jit audit` reads, filters, and follows; they are no\n" +
		"longer duplicated as prose here. Reach for `jit audit` for \"what happened and\n" +
		"who did it\", and for this when a serve error or a startup problem needs its\n" +
		"raw context.\n\n" +
		"The file lives alongside the vault as agent.log (the previous generation\n" +
		"is kept as agent.log.1 after rotation). This command exists because the\n" +
		"investigations that need the log are exactly the ones where hunting down\n" +
		"its path is one obstacle too many.",
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		root, err := vaultRootDir()
		if err != nil {
			return fmt.Errorf("jit service log: %w", err)
		}
		logPath := filepath.Join(root, "agent.log")
		out := cmd.OutOrStdout()

		data, err := os.ReadFile(logPath) // #nosec G304 -- jit's own log file under its config root
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("jit service log: %w", err)
		}
		if os.IsNotExist(err) && !agentLogFollow {
			// Not an error: an empty history is a normal state on a machine
			// where the service hasn't run, and the useful output is what
			// would make one exist.
			fmt.Fprint(out, hlCmds(fmt.Sprintf("No service log yet at %s, it's written once the service runs; it starts on its own the first time you use jit, or run `jit service restart`.\n", displayLogPath(logPath))))
			return nil
		}
		if !agentLogFollow {
			// A static read pages like `jit audit` does; --follow keeps the
			// terminal, since a poll loop must never sit behind a pager.
			var donePaging func()
			out, donePaging = pageableOutput(cmd)
			defer donePaging()
		}
		// One renderer for the tail AND every --follow chunk, so the day
		// header prints on day changes rather than once per polled chunk.
		home, herr := os.UserHomeDir()
		if herr != nil {
			home = ""
		}
		renderer := &agentLogRenderer{home: home}
		render := func(b []byte) {
			if agentLogRaw {
				_, _ = out.Write(b)
				return
			}
			renderer.write(out, b)
		}
		render(tailLines(data, agentLogLines))

		if !agentLogFollow {
			return nil
		}
		// Follow by polling for growth. A rotation truncates in place (see
		// rotateAgentLog), which reads as the file shrinking — restart from
		// the top of the now-small file rather than waiting for it to grow
		// past a stale offset that may be megabytes away.
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		offset := int64(len(data))
		ticker := time.NewTicker(agentLogPollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
			}
			fi, err := os.Stat(logPath)
			if err != nil {
				continue // mid-rotation or not yet created; try again next tick
			}
			if fi.Size() < offset {
				offset = 0
			}
			if fi.Size() == offset {
				continue
			}
			f, err := os.Open(logPath) // #nosec G304 -- jit's own log file under its config root
			if err != nil {
				continue
			}
			if _, err := f.Seek(offset, io.SeekStart); err == nil {
				// --follow renders each appended chunk through the same
				// formatter (and the same renderer state) as the initial
				// tail, so a live stream and a static read look identical.
				// Consume only complete lines: a chunk read mid-write used
				// to split a line across two polls, and each half rendered
				// as an unparseable raw fragment. The remainder stays
				// unconsumed — offset advances only past the last newline —
				// and comes back whole on the next poll (audit's
				// readAppended makes the same cut).
				chunk, _ := io.ReadAll(f)
				if i := bytes.LastIndexByte(chunk, '\n'); i >= 0 {
					render(chunk[:i+1])
					offset += int64(i + 1)
				}
			}
			_ = f.Close()
		}
	},
}

// tailLines returns the last n lines of data, newline-terminated — the
// whole file when it has fewer, or when n is 0: `-n 0` means everything,
// the same convention `jit audit --limit 0` teaches.
func tailLines(data []byte, n int) []byte {
	trimmed := bytes.TrimSuffix(data, []byte("\n"))
	if len(trimmed) == 0 {
		return nil
	}
	lines := bytes.Split(trimmed, []byte("\n"))
	if n > 0 && len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return append(bytes.Join(lines, []byte("\n")), '\n')
}

// displayLogPath ~-shortens the log path for a message, same courtesy as
// every other path this file prints.
func displayLogPath(logPath string) string {
	home, _ := os.UserHomeDir()
	return displayPath(home, logPath)
}
