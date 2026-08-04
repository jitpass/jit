// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bufio"
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
		"carrying one stays on the SESSION's history list — up-arrow keeps working —\n" +
		"but is never written to $HISTFILE, so it cannot end up in Time Machine\n" +
		"backups or a dotfiles repo, and `jit scan` never has to find it.\n\n" +
		"The check is two-stage so it costs nothing at the prompt: a pure-zsh test\n" +
		"(the same admit conditions jit scan's history prefilter uses) passes ~95%\n" +
		"of commands untouched, and only a line that could hold a credential runs\n" +
		"the real vendor patterns via jit itself — over stdin, never argv, so the\n" +
		"value never appears in ps output. If jit is missing or errors, the hook\n" +
		"fails OPEN and the line saves normally: eating history would be worse.\n\n" +
		"zsh only, deliberately: zsh is macOS's default shell and the only one with\n" +
		"a clean pre-write hook (zshaddhistory). What it installs: ~/.jit/guard.zsh\n" +
		"plus one source line in ~/.zshrc; --remove reverses both exactly.",
	Example: "  jit guard history            # install the hook\n" +
		"  jit guard history --remove   # remove it",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("jit guard history: %w", err)
		}
		out := cmd.OutOrStdout()
		if guardHistoryRemove {
			changed, err := guard.Remove(home)
			if err != nil {
				return fmt.Errorf("jit guard history: %w", err)
			}
			if !changed {
				fmt.Fprintln(out, "The history guard is not installed; nothing to remove.")
				return nil
			}
			fmt.Fprintf(out, "%s history guard removed: %s deleted, the source line taken out of ~/.zshrc.\n", glyphDone, displayPath(home, guard.HookPath(home)))
			fmt.Fprintln(out, "  Open shells keep their loaded hook until they exit.")
			return nil
		}

		changed, err := guard.Install(home)
		if err != nil {
			return fmt.Errorf("jit guard history: %w", err)
		}
		if !changed {
			fmt.Fprintf(out, "%s history guard already installed (%s, sourced from ~/.zshrc). Nothing to do.\n", glyphDone, displayPath(home, guard.HookPath(home)))
			return nil
		}
		fmt.Fprintf(out, "%s history guard installed for zsh\n", glyphDone)
		fmt.Fprintf(out, "  hook: %s\n", displayPath(home, guard.HookPath(home)))
		fmt.Fprintf(out, "  ~/.zshrc now sources it: %s\n", guard.RcLine())
		fmt.Fprint(out, hlCmds("  activate it in shells that are already open: `source ~/.jit/guard.zsh`\n"))
		fmt.Fprintln(out, "  From then on, a command carrying a recognized credential stays usable in that")
		fmt.Fprintln(out, "  session (up-arrow works) but is never written to your history file.")
		return nil
	},
}

// guardCheckCmd is the hook's plumbing half: it reads command line(s) from
// stdin and reports whether any carries a value matching a known vendor
// credential format. Exit 0 with the vendor names on stdout when found,
// exit 1 silently when clean. Stdin rather than an argument, always — the
// whole point is that the credential must not become another process's
// visible argv. Never prints the value, never logs.
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
	const maxCheckInput = 1 << 20
	scanner := bufio.NewScanner(io.LimitReader(r, maxCheckInput))
	scanner.Buffer(make([]byte, 0, 64*1024), maxCheckInput)
	seen := map[string]bool{}
	var vendors []string
	for scanner.Scan() {
		for _, tk := range audit.HistoryLineTokens(scanner.Text()) {
			if !seen[tk.Vendor] {
				seen[tk.Vendor] = true
				vendors = append(vendors, tk.Vendor)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
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
