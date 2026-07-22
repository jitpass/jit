// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/audit"
	"github.com/jitpass/jit/internal/keychainwrap"
	"github.com/jitpass/jit/internal/mount"
)

// playgroundMarker is the file the jitpass-playground repo ships at its root
// so `jit` can recognize a sandbox checkout. Detection here is cosmetic: it
// only softens the copy ("these are synthetic") and forces the project-scoped
// reveal, so a missing marker just falls back to generic project handling,
// never to anything unsafe. Aliased to audit.PlaygroundMarkerFile so the CLI
// and the audit scanner (which excludes playground findings from the score)
// can never disagree on the filename.
const playgroundMarker = audit.PlaygroundMarkerFile

// firstRunDeps are the seams the first-run flow is exercised through. The real
// root command wires them to production implementations in prodFirstRunDeps;
// tests inject fakes so the whole decision tree runs without a keychain, an
// interactive terminal, or spawning jit subprocesses.
type firstRunDeps struct {
	vaultReady   func() bool            // is jit already set up? (prompt-free)
	isTTY        func() bool            // interactive stdin AND stdout?
	cwd          func() (string, error) // current directory
	homeDir      func() (string, error) // $HOME
	isPlayground func(dir string) bool  // a jitpass-playground checkout?
	scan         func(root string) ([]audit.Finding, audit.ScanSummary, error)
	render       func(w io.Writer, findings []audit.Finding, summary audit.ScanSummary)
	confirm      func(prompt string) bool   // y/N gate
	runStep      func(args ...string) error // re-exec jit <args>
}

// runFirstRun backs the root command's RunE: bare `jit` with no subcommand.
func runFirstRun(cmd *cobra.Command) error {
	return firstRun(cmd, prodFirstRunDeps(cmd))
}

// firstRun decides what bare `jit` does. Returning users and non-interactive
// callers get exactly today's behavior (cobra's help); the guided onboarding
// only ever engages on a fresh machine with a human on the other end.
func firstRun(cmd *cobra.Command, d firstRunDeps) error {
	// Cheap, side-effect-free check first. A non-interactive bare `jit`
	// (piped, CI, a script) must fall through to help without ever touching
	// the keychain: vaultReady() reads the keychain, which can block on an
	// OS permission prompt, so it's only reachable once we know a human is
	// here to answer both it and the y/N that follows.
	if !d.isTTY() || d.vaultReady() {
		return cmd.Help()
	}

	out := cmd.OutOrStdout()
	cwd, _ := d.cwd()
	playground := cwd != "" && d.isPlayground(cwd)

	// Cwd-aware reveal: scope to the project you're standing in first (safe
	// and on-message in the playground), and fall back to a machine-wide scan
	// only when the current directory isn't itself a project with exposed
	// secrets. The chosen scan result is reused for rendering, never
	// re-scanned, so the scary machine-wide walk happens at most once.
	var (
		findings    []audit.Finding
		summary     audit.ScanSummary
		projectMode bool
	)
	if cwd != "" {
		cf, cs, err := d.scan(cwd)
		if err != nil {
			return err
		}
		if len(cf) > 0 || playground {
			findings, summary, projectMode = cf, cs, true
		}
	}
	if !projectMode {
		home, _ := d.homeDir()
		if home != "" {
			hf, hs, err := d.scan(home)
			if err != nil {
				return err
			}
			findings, summary = hf, hs
		}
	}

	migrateArg, scopeWord := "home", "your machine"
	if projectMode {
		migrateArg, scopeWord = "local", "this project"
	}

	fmt.Fprintln(out)
	switch {
	case playground:
		fmt.Fprintln(out, "You're in the jitpass playground. Every secret here is synthetic, so")
		fmt.Fprintln(out, "it's safe to run the whole flow. Here's what this project exposes")
		fmt.Fprintln(out, "(read-only, nothing is changed):")
	case projectMode:
		fmt.Fprintln(out, "Welcome to jit. Here's what's exposed in this project (read-only),")
		fmt.Fprintln(out, "nothing is changed:")
	default:
		fmt.Fprintln(out, "Welcome to jit. Here's what's exposed on this machine (read-only),")
		fmt.Fprintln(out, "nothing is changed:")
	}
	fmt.Fprintln(out)
	d.render(out, findings, summary)
	fmt.Fprintln(out)

	if len(findings) == 0 {
		if playground {
			fmt.Fprintln(out, "Nothing exposed here yet. Add a secret and run `jit` again, or follow")
			fmt.Fprintln(out, "the tour in the playground README.")
		} else {
			fmt.Fprintln(out, "No plaintext secrets found. Nice.")
			fmt.Fprintln(out, "Want to see the whole flow risk-free? github.com/jitpass/jitpass-playground")
		}
		return nil
	}

	fmt.Fprintln(out, "jit can move these into an encrypted vault gated by Touch ID and rewrite")
	fmt.Fprintln(out, "the files so your tools keep working. Every change is backed up first and")
	fmt.Fprintln(out, "reversible with `jit migrate undo`.")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "Set up jit and fix %s now? This runs, in order:\n", scopeWord)
	fmt.Fprintln(out, "  1. jit vault init      (creates the vault, one Touch ID prompt)")
	fmt.Fprintln(out, "  2. jit agent install   (unlock once per session, not once per command)")
	fmt.Fprintf(out, "  3. %-20s(shows the fix plan, asks again before any change)\n", "jit migrate "+migrateArg)

	if !d.confirm("Set up the vault now? [y/N] ") {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "No problem, nothing was changed. When you're ready, run these yourself:")
		fmt.Fprintln(out, "  jit vault init")
		fmt.Fprintln(out, "  jit agent install")
		fmt.Fprintf(out, "  jit migrate %s\n", migrateArg)
		return nil
	}

	// Guided auto-chain. Each step keeps its own consent gate: vault init is
	// non-destructive, agent install is skipped past its own prompt (--yes,
	// the user just consented to it), and migrate still prints its plan and
	// asks "Proceed? [y/N]" before rewriting a single file.
	for _, step := range [][]string{
		{"vault", "init"},
		{"agent", "install", "--yes"},
		{"migrate", migrateArg},
	} {
		if err := d.runStep(step...); err != nil {
			return err
		}
	}
	return nil
}

func prodFirstRunDeps(cmd *cobra.Command) firstRunDeps {
	return firstRunDeps{
		vaultReady: func() bool { return keychainwrap.New().HasMEK() },
		isTTY: func() bool {
			// Both ends must be a terminal: stdout so the reveal is worth
			// printing, stdin so the y/N prompt can actually be answered. A
			// piped or CI invocation of bare `jit` must fall through to help,
			// never block waiting on input.
			return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
		},
		cwd:          os.Getwd,
		homeDir:      os.UserHomeDir,
		isPlayground: isPlaygroundDir,
		scan:         scanRoot,
		render: func(w io.Writer, f []audit.Finding, s audit.ScanSummary) {
			home, _ := os.UserHomeDir() // display-only "~"-shortening
			audit.WriteHumanReport(w, f, s, home)
		},
		confirm: func(prompt string) bool { return confirmPrompt(cmd, prompt) },
		runStep: func(args ...string) error { return execSelf(args...) },
	}
}

// scanRoot runs the audit rooted at root instead of $HOME. HomeDir is the
// scan root for every scanner (internal/audit/finding.go), so pointing it at
// the current directory yields a project-scoped report from the exact same
// engine and renderer `jit scan` uses.
func scanRoot(root string) ([]audit.Finding, audit.ScanSummary, error) {
	cfg, err := audit.NewConfig(agent.Version())
	if err != nil {
		return nil, audit.ScanSummary{}, err
	}
	cfg.HomeDir = root
	if vroot, e := vaultRootDir(); e == nil {
		cfg.MountRegistryPath = mount.RegistryPath(vroot)
	}
	return audit.Scan(cfg)
}

// isPlaygroundDir reports whether dir or any ancestor holds the playground
// marker file. Walking up lets it fire from a subdirectory of the checkout too.
func isPlaygroundDir(dir string) bool {
	for {
		if _, err := os.Stat(filepath.Join(dir, playgroundMarker)); err == nil {
			return true
		}
		parent := filepath.Dir(dir)
		if parent == dir { // reached the filesystem root
			return false
		}
		dir = parent
	}
}

// execSelf re-runs jit itself with args, inheriting the real terminal, so each
// guided-setup step behaves exactly as if the user had typed it: its own
// prompts, its own Touch ID challenge, its own exit behavior. Only ever called
// from the interactive first-run path, so os.Std* is the user's terminal.
func execSelf(args ...string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("jit: locating own binary: %w", err)
	}
	c := exec.Command(exe, args...) // #nosec G204 -- re-execs jit's own binary (os.Executable) with a fixed set of internal subcommands ({"vault","init"}, ...), never attacker-controlled input
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	return c.Run()
}
