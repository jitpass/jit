// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// jit pages its long reports (`jit audit`, `jit scan`) through the user's
// pager, git-style: only when stdout is the real terminal, resolved from
// $JIT_PAGER then $PAGER then less, with -F so output that fits one screen
// prints inline as if no pager existed. Everything else about the report is
// deliberately untouched — the pager writer wraps only the command's output
// stream, never os.Stdout itself, so fatih/color still sees a terminal (color
// survives into `less -R`) and termtext.Width() still reads the real window
// (no collapse to the 80-column pipe fallback).
//
// The pager is spawned LAZILY, on the first byte of report output. `jit scan`
// runs a progress trail on stderr for many seconds before its report starts;
// a pager started up front would sit as a blank alternate screen over that
// trail the whole time.

// pagerOff is --no-pager on the commands that page. One var shared by both
// registrations: only one command runs per process, and a shared var is what
// keeps the flag's meaning identical everywhere it appears.
var pagerOff bool

// registerPagerFlag adds --no-pager to a command that pages its output.
func registerPagerFlag(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&pagerOff, "no-pager", false, "print straight to the terminal instead of paging through $PAGER")
}

// resolvePager picks the pager command line: $JIT_PAGER wins, then $PAGER,
// then less. A variable set to the empty string or to "cat" disables paging —
// the same convention git honors, and the escape hatch for a shell where
// --no-pager can't be typed (an alias, a wrapper script).
func resolvePager() string {
	for _, k := range []string{"JIT_PAGER", "PAGER"} {
		if v, ok := os.LookupEnv(k); ok {
			v = strings.TrimSpace(v)
			if v == "cat" {
				return ""
			}
			return v
		}
	}
	return "less"
}

// pageableOutput returns the writer a long report should print to, plus a
// done func the caller must invoke (defer is fine) after the last write —
// it closes the pager's stdin and waits for the user to quit it, so the
// command's exit still marks "the user is finished reading".
//
// Paging engages only when every one of these holds: the command's output is
// the process's real stdout (tests substitute buffers, and a future caller
// may substitute a file), that stdout is a terminal (piping to grep or
// redirecting to a file must behave exactly as before), --no-pager wasn't
// given, and the resolved pager is non-empty. Otherwise the caller's writer
// comes back unchanged with a no-op done.
func pageableOutput(cmd *cobra.Command) (io.Writer, func()) {
	out := cmd.OutOrStdout()
	if pagerOff {
		return out, func() {}
	}
	stdout, ok := out.(*os.File)
	if !ok || stdout != os.Stdout || !term.IsTerminal(int(stdout.Fd())) {
		return out, func() {}
	}
	pager := resolvePager()
	if pager == "" {
		return out, func() {}
	}
	p := &pagerWriter{cmdline: pager, dst: stdout}
	return p, p.close
}

// pagerWriter lazily spawns the pager on the first write and streams into
// its stdin. If the spawn fails (pager not installed, /bin/sh missing) it
// degrades silently to writing straight through — a missing pager must never
// cost the report itself.
type pagerWriter struct {
	cmdline string
	dst     *os.File

	started bool
	proc    *exec.Cmd
	pipe    io.WriteCloser
}

func (p *pagerWriter) Write(b []byte) (int, error) {
	if !p.started {
		p.started = true
		p.start()
	}
	if p.pipe == nil {
		return p.dst.Write(b)
	}
	if _, err := p.pipe.Write(b); err != nil {
		// The user quit the pager before the report finished streaming.
		// That is them saying "seen enough", not a failure: claim the write
		// succeeded so the report code upstream never surfaces an EPIPE for
		// a deliberate q keystroke.
		return len(b), nil
	}
	return len(b), nil
}

func (p *pagerWriter) start() {
	// Catch a typo'd $PAGER before the shell does: sh itself starts fine,
	// dies with "command not found", and every report byte would then vanish
	// into the broken pipe. Only checkable when the value is a plain command
	// (possibly with flags) — anything with shell syntax is the shell's to
	// judge.
	if name, ok := simplePagerName(p.cmdline); ok {
		if _, err := exec.LookPath(name); err != nil {
			fmt.Fprintf(os.Stderr, "jit: pager %q not found; printing without it\n", name)
			return
		}
	}
	// Through the shell, so PAGER="less -S" and any other value a user's
	// dotfiles export works verbatim. The command line comes from the user's
	// own environment and runs as them, with their terminal — the exact
	// contract $PAGER has had since forever.
	cmd := exec.Command("/bin/sh", "-c", p.cmdline) // #nosec G204 -- $PAGER/$JIT_PAGER is the user's own choice of program, the flag's entire purpose
	cmd.Stdout = p.dst
	cmd.Stderr = os.Stderr
	env := os.Environ()
	// Defaults for a bare `less`, only when the user hasn't set their own:
	// -F quit inline if it fits one screen, -R pass color through, -X skip
	// the alternate screen so short output stays in scrollback. Env rather
	// than argv so a user's exported LESS wins wholesale, exactly as git
	// does it.
	if _, ok := os.LookupEnv("LESS"); !ok {
		env = append(env, "LESS=FRX")
	}
	cmd.Env = env
	pipe, err := cmd.StdinPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		_ = pipe.Close()
		return
	}
	// While the pager owns the terminal, ctrl-C belongs to it (less uses it
	// to interrupt a search). The keyboard SIGINT goes to the whole
	// foreground process group, so without this jit would die and orphan the
	// pager mid-display. Restored in close.
	signal.Ignore(syscall.SIGINT)
	p.proc, p.pipe = cmd, pipe
}

// simplePagerName returns the command a pager value names, when the value is
// a bare command with optional flags ("less", "less -S", "more"). A value
// carrying shell syntax — a pipeline, a variable, quoting — reports !ok and
// is left for the shell to interpret.
func simplePagerName(cmdline string) (string, bool) {
	if strings.ContainsAny(cmdline, "|&;<>()$`\\\"'*?[]{}~#") {
		return "", false
	}
	fields := strings.Fields(cmdline)
	if len(fields) == 0 {
		return "", false
	}
	return fields[0], true
}

func (p *pagerWriter) close() {
	if p.pipe != nil {
		_ = p.pipe.Close()
	}
	if p.proc != nil {
		_ = p.proc.Wait()
		signal.Reset(syscall.SIGINT)
	}
}
