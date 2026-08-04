// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/audit"
	"github.com/jitpass/jit/internal/guard"
)

var guardHistoryRemove bool

var guardCmd = &cobra.Command{
	Use:     "guard",
	GroupID: groupWorkflow,
	Short:   "Prevention hooks that keep credentials from being recorded in the first place",
	Long: "jit guard installs prevention hooks: where jit scan finds credentials that\n" +
		"were already recorded and jit migrate cleans them up, a guard stops the\n" +
		"recording from happening at all.\n\n" +
		"The first guard is the shell history guard (`jit guard history`).",
}

var guardHistoryCmd = &cobra.Command{
	Use:   "history",
	Short: "Keep typed credentials out of your shell history file (zsh)",
	Long: "jit guard history installs a zsh hook that checks every command line for a\n" +
		"known credential format before zsh writes it to the history file. A command\n" +
		"carrying one stays on the SESSION's history list, so up-arrow keeps working,\n" +
		"but is never written to $HISTFILE. It cannot end up in a Time Machine backup\n" +
		"or a dotfiles repo, and `jit scan` never has to find it.\n\n" +
		"The check is two-stage, so most commands cost nothing measurable: a\n" +
		"pure-zsh test (the same admit conditions jit scan's history prefilter\n" +
		"uses) settles a line in about 15 microseconds without launching anything.\n" +
		"Only a line that could hold a credential runs the real vendor patterns via\n" +
		"jit itself, which costs about 33 milliseconds. On a real 592-command\n" +
		"history that second path takes 14% of lines, mostly because any address\n" +
		"with an @ and any ten-character word qualify.\n\n" +
		"That check reads the line over stdin, never argv, so the value never\n" +
		"appears in ps output. It is also bounded: if jit is missing, errors, or\n" +
		"takes longer than two seconds, the hook fails OPEN and the line saves\n" +
		"normally. Silently eating your history would be a worse bug than missing\n" +
		"a token, and a hook that can hang is a hook that can freeze your shell.\n\n" +
		"zsh only, deliberately: zsh is macOS's default shell and the only one with\n" +
		"a clean pre-write hook (zshaddhistory). What it installs: ~/.jit/guard.zsh\n" +
		"plus one source line in ~/.zshrc (or $ZDOTDIR/.zshrc when that is set);\n" +
		"--remove reverses both exactly.",
	Example: "  jit guard history            # install the hook\n" +
		"  jit guard history --remove   # remove it",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("jit guard history: %w", err)
		}
		out := cmd.OutOrStdout()
		// Every prose line goes through wrapBody at the indent that owns it
		// (design/output-style.md rule 6): hard-wrapping at a source-file
		// width leaves the terminal to break these at column 0 in a narrow
		// window, which drops each continuation to the left of the glyph it
		// belongs under.
		if guardHistoryRemove {
			changed, rcEdited, err := guard.Remove(home)
			if err != nil {
				return fmt.Errorf("jit guard history: %w", err)
			}
			if !changed {
				wrapBody(out, 0, "", "The history guard is not installed, nothing to remove.")
				return nil
			}
			_, _ = cOK.Fprintf(out, "%s ", glyphDone)
			if rcEdited {
				wrapBody(out, 2, "  ", fmt.Sprintf("history guard removed: %s deleted, the source line taken out of %s.",
					displayPath(home, guard.HookPath(home)), displayPath(home, guard.RcPath(home))))
			} else {
				// Say only what happened. The rc file was left alone because it
				// never carried jit's own line — the user sources the hook their
				// own way, and rewriting someone's hand-edited rc on the strength
				// of a guess is not this command's job. Worth naming, because an
				// unguarded hand-written source line now points at a deleted file
				// and will error in every new shell.
				wrapBody(out, 2, "  ", fmt.Sprintf("history guard removed: %s deleted.", displayPath(home, guard.HookPath(home))))
				wrapBody(out, 0, "  ", cWarn.Sprintf("  %s sources the hook by a line jit did not write, so it was left alone. Remove it by hand, or new shells will report a missing file.",
					displayPath(home, guard.RcPath(home))))
			}
			wrapBody(out, 0, "  ", cDim.Sprint("  Shells that are already open keep the hook they loaded until they exit."))
			return nil
		}

		changed, err := guard.Install(home)
		if err != nil {
			return fmt.Errorf("jit guard history: %w", err)
		}
		if !changed {
			_, _ = cOK.Fprintf(out, "%s ", glyphDone)
			wrapBody(out, 2, "  ", fmt.Sprintf("history guard already installed (%s, sourced from %s). Nothing to do.",
				displayPath(home, guard.HookPath(home)), displayPath(home, guard.RcPath(home))))
			return nil
		}
		_, _ = cOK.Fprintf(out, "%s ", glyphDone)
		wrapBody(out, 2, "  ", "history guard installed for zsh")
		fmt.Fprintf(out, "  hook: %s\n", displayPath(home, guard.HookPath(home)))
		_, _ = cDim.Fprintf(out, "  %s now sources it: %s\n", displayPath(home, guard.RcPath(home)), guard.RcLine())
		wrapBody(out, 0, "  ", cDim.Sprint("  From now on, a command carrying a recognized credential stays usable in "+
			"that session (up-arrow works) but is never written to your history file."))
		fmt.Fprintln(out)
		_, _ = cPath.Fprint(out, "→ ")
		wrapBody(out, 2, "  ", hlCmds("`source ~/.jit/guard.zsh`   to activate it in shells that are already open"))
		return nil
	},
}

// guardCheckCmd is the hook's plumbing half: it reads command line(s) from
// stdin and reports whether any carries a value matching a known vendor
// credential format. Exit 0 with the vendor names on stdout when found, exit
// 1 when clean. Stdin rather than an argument, always — the whole point is
// that the credential must not become another process's visible argv. It
// never prints the value and never writes it anywhere.
//
// "Clean" is quiet on STDOUT, which is what the hook reads, but not silent
// overall: cmd/jit/main.go prints every returned error to stderr, so a clean
// line emits "no credential found" there. The hook discards its stderr, so
// this is invisible in use; it is documented rather than suppressed because
// the alternative (an exit path that bypasses main's error printing) would
// make this one command's failure handling differ from every other.
var guardCheckCmd = &cobra.Command{
	Use:    "check",
	Hidden: true,
	Short:  "Read a command line from stdin and report recognized credential formats (used by the history guard hook)",
	Args:   cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		vendors, err := guardCheckStdin(cmd.InOrStdin())
		if err != nil {
			return fmt.Errorf("jit guard check: %w", err)
		}
		if len(vendors) == 0 {
			// Silent, structured "clean": the hook branches on the exit code.
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			return errExitClean
		}
		fmt.Fprintln(cmd.OutOrStdout(), strings.Join(vendors, ", "))
		return nil
	},
}

// errExitClean is guard check's "no credential found" result: exit code 1
// with no output, distinguished from a real failure only by silence. Mapped
// to a plain error so cobra's RunE contract still drives the exit code.
var errExitClean = fmt.Errorf("no credential found")

// guardCheckStdin scans r line by line with the same detection the history
// scanner uses (audit.HistoryLineTokens on a bare command line runs the full
// vendor-pattern set) and returns the unique vendor names found, sorted.
// Input is capped: the hook hands over one interactive command line, so
// anything beyond a small bound is not a command line and is not worth
// scanning at the prompt.
func guardCheckStdin(r io.Reader) ([]string, error) {
	// 4 MiB, not 1: the cap exists to bound memory on absurd input, and a
	// pasted command line carrying a credential can genuinely run to a few
	// megabytes (a base64 blob, a heredoc). Anything past the cap is not
	// scanned, and the hook reads that as "clean" and saves the line — so the
	// bound is set well above any real command rather than at a round number.
	const maxCheckInput = 4 << 20
	// Read and split by hand rather than with bufio.Scanner. Scanner fails the
	// whole read with "token too long" on a single line past its buffer, and
	// the hook treats any failure as "clean" — so pasting a 3 MB command that
	// happened to carry a credential got it recorded, with a raw Go error on
	// stderr. Truncating at the bound instead still checks the first megabyte,
	// which is where a credential in a pasted blob will be.
	data, err := io.ReadAll(io.LimitReader(r, maxCheckInput))
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var vendors []string
	for _, line := range strings.Split(string(data), "\n") {
		for _, tk := range audit.HistoryLineTokens(strings.TrimSuffix(line, "\r")) {
			if !seen[tk.Vendor] {
				seen[tk.Vendor] = true
				vendors = append(vendors, tk.Vendor)
			}
		}
	}
	sort.Strings(vendors)
	return vendors, nil
}

func init() {
	guardHistoryCmd.Flags().BoolVar(&guardHistoryRemove, "remove", false, "remove the guard: delete the hook file and take the source line out of ~/.zshrc")
	guardCmd.AddCommand(guardHistoryCmd)
	guardCmd.AddCommand(guardCheckCmd)
	rootCmd.AddCommand(guardCmd)
}
