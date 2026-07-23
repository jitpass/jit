// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/audit"
	"github.com/jitpass/jit/internal/mount"
)

var (
	scanFormat string
	scanOutput string
	scanScore  bool
)

var scanCmd = &cobra.Command{
	Use:     "scan [path...]",
	GroupID: groupWorkflow,
	Short:   "Scan for plaintext secrets exposed on this machine (read-only)",
	Long: "jit scan scans shell configs, .env files, credential files, MCP/AI-tool " +
		"configs, private keys, IaC variable files, and suspicious filenames for " +
		"plaintext secrets. Default behavior is strictly read-only: it never " +
		"touches, encrypts, or rewrites a single file on disk. No real secret " +
		"value is ever printed, only a masked preview.\n\n" +
		"Scanning specific paths\n\n" +
		"Pass one or more files or directories to scan only those, instead of the " +
		"whole machine: `jit scan ./project token.txt`. A directory is walked with " +
		"the same name-based rules as the full scan. A file you name explicitly is " +
		"classified regardless of its name — a shell/env/MCP/IaC file is routed to " +
		"its scanner, and anything else is swept for known vendor tokens and JWTs, " +
		"so `jit scan token.txt` catches a bare token the full scan's naming rules " +
		"would miss. Named paths never pull in the fixed machine-wide credential " +
		"stores (~/.aws, ~/.ssh, …); symlinks are not followed.\n\n" +
		"Exposure score\n\n" +
		"jit reports a 0-100 exposure score (EXPOSURE:) next to the categorical " +
		"RISK LEVEL. It is computed entirely locally and deterministically:\n\n" +
		"  1. Sum a severity-weighted load over all findings: critical 30, high " +
		"15, medium 6, low 2, info 0. (info is detection-only, not an at-rest " +
		"secret, so it adds nothing.)\n" +
		"  2. Add 40 for each finding that carries a production indicator (a " +
		"\"prod\"/\"production\" token) or a public IP address, the same signals " +
		"that escalate the whole scan to CRITICAL.\n" +
		"  3. Cap the total at 100.\n" +
		"  4. Clamp into the band of the scan's RISK LEVEL, so the number and the " +
		"label can never disagree: clean 0, low 10-39, medium 40-64, high 65-84, " +
		"critical 85-100.\n\n" +
		"Run with --score to print just the score line and exit.",
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Validate before touching the filesystem or doing any scanning —
		// otherwise a bad --output path can mask a bad --format value (or
		// vice versa) behind the wrong error.
		if err := validateScanFormat(scanFormat); err != nil {
			return fmt.Errorf("jit scan: %w", err)
		}

		cfg, err := audit.NewConfig(agent.Version())
		if err != nil {
			return fmt.Errorf("jit scan: %w", err)
		}
		// Best-effort: lets the scan report registered live mounts as an
		// "already protected" count instead of them silently vanishing from
		// the findings (scanners skip named pipes regardless — see
		// audit.Config.MountRegistryPath). An unresolvable root just means
		// no count.
		if root, rootErr := vaultRootDir(); rootErr == nil {
			cfg.MountRegistryPath = mount.RegistryPath(root)
		}

		// A live status trail on stderr so a full home-directory scan (nine
		// filesystem walks) doesn't look hung. Silenced automatically for the
		// machine-readable formats and --output (where even stderr chatter is
		// unwanted), for --quiet, and whenever stderr isn't a terminal — see
		// newProgress. --score deliberately gets it too: it runs the entire
		// scan before printing its one line, so it's just as silent otherwise.
		machineScan := scanFormat == "ndjson" || scanFormat == "markdown" || scanFormat == "md" || scanOutput != ""
		progress := newProgress(cmd, machineScan)
		cfg.Progress = func(category string) {
			progress.Step("Scanning "+category+"…", "Scanned "+category)
		}

		var findings []audit.Finding
		var summary audit.ScanSummary
		if len(args) > 0 {
			targets, resolveErr := resolveScanTargets(args)
			if resolveErr != nil {
				progress.Stop()
				return fmt.Errorf("jit scan: %w", resolveErr)
			}
			findings, summary, err = audit.TargetedScan(cfg, targets)
		} else {
			findings, summary, err = audit.Scan(cfg)
		}
		// Stop before any result is written — the trail lives on stderr, but
		// the spinner's in-place line must be settled before stdout output (or
		// the confirm-free score line) begins.
		progress.Stop()
		if err != nil {
			return fmt.Errorf("jit scan: %w", err)
		}

		if scanScore {
			// Terse mode: just the score line, no report. --format/--output
			// don't apply here — this is for scripts, badges, and a quick
			// "how bad is it" without the full dump.
			fmt.Fprintf(cmd.OutOrStdout(), "Exposure: %d/100 (%s)\n", summary.ExposureScore, strings.ToUpper(summary.RiskLevel))
			return nil
		}

		out := cmd.OutOrStdout()
		home, _ := os.UserHomeDir() // display-only "~"-shortening; "" (no shortening) if unresolvable
		var outFile *os.File
		if scanOutput != "" {
			// scanOutput is a path the user typed themselves via --output —
			// this is the intended use of the flag (like `curl -o` or `gcc
			// -o`), not attacker-controlled input.
			outFile, err = os.Create(scanOutput) // #nosec G304 -- user-specified output destination, the flag's entire purpose
			if err != nil {
				return fmt.Errorf("jit scan: %w", err)
			}
			out = outFile
			// Never write raw ANSI escape codes into a saved file — color's
			// NoColor default is based on whether the process's real stdout
			// is a terminal, not on whichever io.Writer a caller happens to
			// pass to Fprintf, so redirecting to a file needs this explicit.
			color.NoColor = true
			// Same reasoning for "~"-shortening: a saved report is re-read
			// later, often by a tool that can't expand "~" — keep the
			// absolute file:line locations a terminal reader doesn't need.
			home = ""
		}

		if err := writeScanReport(out, scanFormat, findings, summary, home); err != nil {
			if outFile != nil {
				_ = outFile.Close()
			}
			return fmt.Errorf("jit scan: %w", err)
		}

		if outFile != nil {
			// Close explicitly, not deferred: a close error (e.g. a full
			// disk flushing the tail of the report) must fail the command
			// instead of printing "Report written" over a truncated file.
			if err := outFile.Close(); err != nil {
				return fmt.Errorf("jit scan: writing %s: %w", scanOutput, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Report written to %s\n", scanOutput)
		}
		return nil
	},
}

// resolveScanTargets turns the path arguments to `jit scan <path>...` into
// absolute paths, failing loud on any that don't exist — a mistyped path
// should be an error, not a silently empty scan (the same choice `jit migrate
// <path>` makes). Absolute paths keep the findings' file_path locations
// unambiguous regardless of the process's working directory.
func resolveScanTargets(args []string) ([]string, error) {
	targets := make([]string, 0, len(args))
	for _, arg := range args {
		abs, err := filepath.Abs(arg)
		if err != nil {
			return nil, fmt.Errorf("resolving %q: %w", arg, err)
		}
		if _, err := os.Lstat(abs); err != nil {
			if os.IsNotExist(err) {
				return nil, fmt.Errorf("no such file or directory: %s", arg)
			}
			return nil, fmt.Errorf("%s: %w", arg, err)
		}
		targets = append(targets, abs)
	}
	return targets, nil
}

func validateScanFormat(format string) error {
	switch format {
	case "", "text", "markdown", "md", "ndjson":
		return nil
	default:
		return fmt.Errorf("unknown --format %q (want \"text\", \"markdown\", or \"ndjson\")", format)
	}
}

// writeScanReport assumes format has already been validated. home is
// only consulted by the human format (display-only "~"-shortening, "" to
// disable); markdown/NDJSON always keep full absolute paths for machines.
func writeScanReport(w io.Writer, format string, findings []audit.Finding, summary audit.ScanSummary, home string) error {
	switch format {
	case "", "text":
		audit.WriteHumanReport(w, findings, summary, home)
	case "markdown", "md":
		audit.WriteMarkdownReport(w, findings, summary)
	case "ndjson":
		return audit.WriteNDJSON(w, findings, summary)
	}
	return nil
}

func init() {
	scanCmd.Flags().StringVar(&scanFormat, "format", "text", `output format: "text" (default), "markdown"/"md", or "ndjson"`)
	scanCmd.Flags().StringVarP(&scanOutput, "output", "o", "", "write the report to this file instead of stdout")
	scanCmd.Flags().BoolVar(&scanScore, "score", false, `print only the exposure score (e.g. "Exposure: 92/100 (CRITICAL)") and exit`)
	rootCmd.AddCommand(scanCmd)
}
