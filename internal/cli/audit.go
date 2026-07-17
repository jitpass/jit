// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/audit"
	"github.com/jitpass/jit/internal/mount"
)

var (
	auditFormat string
	auditOutput string
	auditScore  bool
)

var auditCmd = &cobra.Command{
	Use:     "audit",
	GroupID: groupWorkflow,
	Short:   "Scan for plaintext secrets exposed on this machine (read-only)",
	Long: "jit audit scans shell configs, .env files, credential files, MCP/AI-tool " +
		"configs, private keys, IaC variable files, and suspicious filenames for " +
		"plaintext secrets. Default behavior is strictly read-only: it never " +
		"touches, encrypts, or rewrites a single file on disk. No real secret " +
		"value is ever printed, only a masked preview.\n\n" +
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
		"Findings inside a jitpass playground checkout crossed during the scan are " +
		"synthetic demo secrets, so they are excluded from every count and from the " +
		"score (the report states how many were excluded and where). " +
		"Run with --score to print just the score line and exit.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Validate before touching the filesystem or doing any scanning —
		// otherwise a bad --output path can mask a bad --format value (or
		// vice versa) behind the wrong error.
		if err := validateAuditFormat(auditFormat); err != nil {
			return fmt.Errorf("jit audit: %w", err)
		}

		cfg, err := audit.NewConfig(agent.Version())
		if err != nil {
			return fmt.Errorf("jit audit: %w", err)
		}
		// Best-effort: lets the scan report registered live mounts as an
		// "already protected" count instead of them silently vanishing from
		// the findings (scanners skip named pipes regardless — see
		// audit.Config.MountRegistryPath). An unresolvable root just means
		// no count.
		if root, rootErr := vaultRootDir(); rootErr == nil {
			cfg.MountRegistryPath = mount.RegistryPath(root)
		}

		findings, summary, err := audit.Scan(cfg)
		if err != nil {
			return fmt.Errorf("jit audit: %w", err)
		}

		if auditScore {
			// Terse mode: just the score line, no report. --format/--output
			// don't apply here — this is for scripts, badges, and a quick
			// "how bad is it" without the full dump.
			fmt.Fprintf(cmd.OutOrStdout(), "Exposure: %d/100 (%s)\n", summary.ExposureScore, strings.ToUpper(summary.RiskLevel))
			return nil
		}

		out := cmd.OutOrStdout()
		home, _ := os.UserHomeDir() // display-only "~"-shortening; "" (no shortening) if unresolvable
		var outFile *os.File
		if auditOutput != "" {
			// auditOutput is a path the user typed themselves via --output —
			// this is the intended use of the flag (like `curl -o` or `gcc
			// -o`), not attacker-controlled input.
			outFile, err = os.Create(auditOutput) // #nosec G304 -- user-specified output destination, the flag's entire purpose
			if err != nil {
				return fmt.Errorf("jit audit: %w", err)
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

		if err := writeAuditReport(out, auditFormat, findings, summary, home); err != nil {
			if outFile != nil {
				_ = outFile.Close()
			}
			return fmt.Errorf("jit audit: %w", err)
		}

		if outFile != nil {
			// Close explicitly, not deferred: a close error (e.g. a full
			// disk flushing the tail of the report) must fail the command
			// instead of printing "Report written" over a truncated file.
			if err := outFile.Close(); err != nil {
				return fmt.Errorf("jit audit: writing %s: %w", auditOutput, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Report written to %s\n", auditOutput)
		}
		return nil
	},
}

func validateAuditFormat(format string) error {
	switch format {
	case "", "text", "markdown", "md", "ndjson":
		return nil
	default:
		return fmt.Errorf("unknown --format %q (want \"text\", \"markdown\", or \"ndjson\")", format)
	}
}

// writeAuditReport assumes format has already been validated. home is
// only consulted by the human format (display-only "~"-shortening, "" to
// disable); markdown/NDJSON always keep full absolute paths for machines.
func writeAuditReport(w io.Writer, format string, findings []audit.Finding, summary audit.ScanSummary, home string) error {
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
	auditCmd.Flags().StringVar(&auditFormat, "format", "text", `output format: "text" (default), "markdown"/"md", or "ndjson"`)
	auditCmd.Flags().StringVarP(&auditOutput, "output", "o", "", "write the report to this file instead of stdout")
	auditCmd.Flags().BoolVar(&auditScore, "score", false, `print only the exposure score (e.g. "Exposure: 92/100 (CRITICAL)") and exit`)
	rootCmd.AddCommand(auditCmd)
}
