// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

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
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/mount"
)

var (
	scanFormat     string
	scanOutput     string
	scanScore      bool
	scanUnfiltered bool
	scanFull       bool
	scanFailOn     string
)

// newAuditConfig builds the audit Config every CLI scan surface shares
// (scan, bare migrate's protect plan, first-run), with the cross-package
// hooks wired. audit cannot import migrate (migrate imports audit), so
// the classifier arrives as a hook — the vault.KeyWrapper pattern; see
// audit.Config.K8sMigratable.
func newAuditConfig() (audit.Config, error) {
	cfg, err := audit.NewConfig(agent.Version())
	if err != nil {
		return cfg, err
	}
	cfg.K8sMigratable = k8sMigratableForScan
	return cfg, nil
}

// k8sMigratableForScan answers the hook with migrate's own classifier, so
// scan and migrate can never disagree about a manifest. Read-only and
// prompt-free, as the hook's contract requires.
func k8sMigratableForScan(path string) (reason string, ok bool) {
	plan, reason, err := migrate.ClassifyK8sSecretManifest(path)
	switch {
	case err != nil:
		// Unreadable where audit could read it moments ago (racing edit,
		// permissions): don't promise a migrate that will error.
		return err.Error(), false
	case plan != nil:
		return "", true
	case reason != "":
		return reason, false
	default:
		// Recognized but with nothing migrate can move (fully
		// SOPS-encrypted, an empty scaffold).
		return "no plaintext Secret values migrate can move", false
	}
}

// riskRank orders the aggregate RISK LEVEL vocabulary so --fail-on can ask
// "at or above". Kept local to the flag: it is a CLI comparison, not a
// property of the finding schema.
var riskRank = map[string]int{
	audit.RiskLevelClean:    0,
	audit.RiskLevelLow:      1,
	audit.RiskLevelMedium:   2,
	audit.RiskLevelHigh:     3,
	audit.RiskLevelCritical: 4,
}

// failOnThreshold resolves a --fail-on value to the rank at or above which the
// scan should exit non-zero. "any" means "anything that isn't clean", which is
// the threshold a pre-commit hook usually wants. "clean" is rejected rather
// than accepted as a synonym for "any": it would read as "fail when clean".
func failOnThreshold(level string) (int, error) {
	if level == "any" {
		return riskRank[audit.RiskLevelLow], nil
	}
	rank, ok := riskRank[level]
	if !ok || level == audit.RiskLevelClean {
		return 0, fmt.Errorf("--fail-on %q: expected one of critical, high, medium, low, any", level)
	}
	return rank, nil
}

// failOnResult returns the ExitError for a scan whose risk level reached the
// --fail-on threshold, or nil when it didn't (or the flag wasn't used).
func failOnResult(level, riskLevel string, score, degraded int) error {
	if level == "" {
		return nil
	}
	threshold, err := failOnThreshold(level)
	if err != nil {
		return fmt.Errorf("jit scan: %w", err)
	}
	// A degraded scan couldn't read one or more categories, so it cannot
	// certify the machine is below the threshold: a partial scan must never
	// pass a gate a complete one might have failed (audit/triage.go makes the
	// same promise to the human reader with its INCOMPLETE SCAN banner). Trip
	// on the incompleteness itself, whatever risk the readable categories
	// produced, so a CI gate can't read a can't-be-sure as all-clear.
	if degraded > 0 {
		return &ExitError{
			Code: scanFailOnExitCode,
			Msg: fmt.Sprintf("jit scan: an incomplete scan cannot pass --fail-on %s: %s could not be read (exit %d)",
				level, countWord(degraded, "category", "categories"), scanFailOnExitCode),
		}
	}
	if riskRank[riskLevel] < threshold {
		return nil
	}
	return &ExitError{
		Code: scanFailOnExitCode,
		Msg: fmt.Sprintf("jit scan: risk level %s at or above --fail-on %s (exposure %d/100) — exit %d",
			strings.ToUpper(riskLevel), level, score, scanFailOnExitCode),
	}
}

// scanFailOnExitCode is deliberately not 1: exit 1 is "the command failed",
// and a tripped threshold must be distinguishable from a scan that couldn't
// run at all.
const scanFailOnExitCode = 2

var scanCmd = &cobra.Command{
	Use:     "scan [path...]",
	GroupID: groupWorkflow,
	Short:   "Scan for plaintext secrets exposed on this machine (read-only)",
	Long: "jit scan scans shell configs, .env files, credential files, MCP/AI-tool " +
		"configs, private keys, IaC variable files, and shell history for " +
		"plaintext secrets. Default behavior is strictly read-only: it never " +
		"touches, encrypts, or rewrites a single file on disk. No real secret " +
		"value is ever printed, only a masked preview.\n\n" +
		"Shell history is the surface the others miss by construction: a " +
		"credential gets there by being typed, so it never sits in a file whose " +
		"name announces it. ~/.zsh_history, ~/.bash_history, ~/.sh_history, " +
		"~/.history, fish history and $HISTFILE are all swept.\n\n" +
		"Scanning specific paths\n\n" +
		"Pass one or more files or directories to scan only those, instead of the " +
		"whole machine: `jit scan ./project token.txt`. A directory is walked with " +
		"the same name-based rules as the full scan. A file you name explicitly is " +
		"classified regardless of its name — a shell/env/MCP/IaC/history file is " +
		"routed to its own scanner (so a named history file still reports line " +
		"numbers), and anything else is swept for known vendor tokens and JWTs, " +
		"so `jit scan token.txt` catches a bare token the full scan's naming rules " +
		"would miss. Named paths never pull in the fixed machine-wide credential " +
		"stores (~/.aws, ~/.ssh, …); symlinks are not followed.\n\n" +
		"Exposure score\n\n" +
		"jit reports a 0-100 exposure score next to the categorical risk level " +
		"(the report's `" + glyphRisk + " CRITICAL — exposure 85/100` banner). It is computed " +
		"entirely locally and deterministically:\n\n" +
		"  1. Sum a severity-weighted load over all findings: critical 30, high " +
		"15, medium 6, low 2, info 0. (info is detection-only, not an at-rest " +
		"secret, so it adds nothing.)\n" +
		"  2. Add 40 for each finding that carries a production indicator (a " +
		"\"prod\"/\"production\" token) or a public IP address, the same signals " +
		"that escalate the whole scan to CRITICAL.\n" +
		"  3. Cap the total at 100.\n" +
		"  4. Clamp into the band of the scan's risk level, so the number and the " +
		"label can never disagree: clean 0, low 10-39, medium 40-64, high 65-84, " +
		"critical 85-100.\n\n" +
		"Run with --score to print just the score line and exit.\n\n" +
		"Exit status\n\n" +
		"By default jit scan always exits 0: finding secrets is its job, not an " +
		"error, and a read-only report shouldn't fail a shell. To use it as a " +
		"GATE (a pre-commit hook, a CI step), give it a threshold with --fail-on " +
		"<level>: the scan exits 2 when its risk level is at or above that " +
		"level, e.g. `jit scan --fail-on high`. --fail-on any trips on anything " +
		"that isn't clean.\n\n" +
		"The status is 2, never 1, so a tripped gate is distinguishable from the " +
		"scan itself failing (a bad flag, an unreadable path), which stays 1. " +
		"The report is always written in full first — the gate never costs you " +
		"the findings that explain it. --fail-on works with --score too.",
	// The pathless form is the one to start with, and the Use line's
	// "[path...]" cannot say that a named path is scanned MORE closely (it
	// bypasses the name gate and sweeps contents).
	Example: "  jit scan                       # the whole machine, read-only\n" +
		"  jit scan ~/proj                # just this folder\n" +
		"  jit scan token.txt             # a file no name rule would flag\n" +
		"  jit scan --full                # every finding, not the triage view",
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Validate before touching the filesystem or doing any scanning —
		// otherwise a bad --output path can mask a bad --format value (or
		// vice versa) behind the wrong error.
		if err := validateScanFormat(scanFormat); err != nil {
			return fmt.Errorf("jit scan: %w", err)
		}
		// Validate --fail-on up front too: a typo'd threshold must fail
		// before the scan runs, not after several minutes of walking $HOME.
		if scanFailOn != "" {
			if _, err := failOnThreshold(scanFailOn); err != nil {
				return fmt.Errorf("jit scan: %w", err)
			}
		}

		cfg, err := newAuditConfig()
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

		// A live status trail on stderr so a full home-directory scan doesn't
		// look hung. Its first step is the one shared filesystem walk that
		// feeds every discovery category at once (audit.discoverByWalk) and
		// accounts for effectively all of a scan's runtime; the known-location
		// categories that follow are each a handful of stats. Silenced
		// automatically for the
		// machine-readable formats and --output (where even stderr chatter is
		// unwanted), for --quiet, and whenever stderr isn't a terminal — see
		// newProgress. --score deliberately gets it too: it runs the entire
		// scan before printing its one line, so it's just as silent otherwise.
		cfg.Unfiltered = scanUnfiltered

		machineScan := scanFormat == "ndjson" || scanFormat == "markdown" || scanFormat == "md" || scanOutput != ""
		progress := newProgress(cmd, machineScan)
		// The trail is scaffolding for either view, not part of the result: a
		// scan report is a page the reader works down, and sixteen settled
		// "✓ Scanned …" lines pushed its top off a short window. They still
		// animate while the scan runs — a ten-second home walk must not look
		// hung — and collapse to one line the moment it finishes.
		//
		// --full used to keep its trail, on the reasoning that per-category
		// lines above an inventory read as a table of contents. They don't:
		// the actual table of contents is the category count table three lines
		// below the header, which carries the same sixteen names AND their
		// counts. So the trail was sixteen lines of duplication at the top of
		// the longest view in the tool, and it was the largest remaining
		// difference between the two views of one command.
		progress.Collapse()
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
		progress.StopCollapsed(fmt.Sprintf("%s scanned",
			countWord(progress.Steps(), "category", "categories")))
		if err != nil {
			return fmt.Errorf("jit scan: %w", err)
		}

		if scanScore {
			// Terse mode: just the score line, no report. --format/--output
			// don't apply here — this is for scripts, badges, and a quick
			// "how bad is it" without the full dump.
			fmt.Fprintf(cmd.OutOrStdout(), "Exposure: %d/100 (%s)\n", summary.ExposureScore, strings.ToUpper(summary.RiskLevel))
			// --score is the shape a CI badge step uses, so it honours
			// --fail-on too; the score still prints before the gate trips.
			return failOnResult(scanFailOn, summary.RiskLevel, summary.ExposureScore, len(summary.DegradedScanners))
		}

		var out io.Writer
		home, _ := os.UserHomeDir() // display-only "~"-shortening; "" (no shortening) if unresolvable
		var outFile *os.File
		if scanOutput != "" {
			// scanOutput is a path the user typed themselves via --output —
			// this is the intended use of the flag (like `curl -o` or `gcc
			// -o`), not attacker-controlled input.
			//
			// 0600, not os.Create's 0666-minus-umask: the report holds only
			// masked previews (first 4 characters), key names and paths, but
			// an inventory of exactly where this machine keeps its
			// credentials is worth reading on its own, and every other file
			// jit writes is owner-only. A report the user then chooses to
			// share is a chmod away; one written world-readable by default
			// cannot be un-read.
			outFile, err = os.OpenFile(scanOutput, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- user-specified output destination, the flag's entire purpose
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
		} else {
			// On a terminal, page the report: a machine-wide scan runs well
			// past one screen. Lazy spawn (see pageableOutput) keeps the
			// progress trail above visible while the scan itself runs.
			var donePaging func()
			out, donePaging = pageableOutput(cmd)
			defer donePaging()
		}

		// The triage view is the default for a machine-wide text scan: the
		// coverage-first, action-first summary designed in review 2026-07-28.
		// Targeted scans (`jit scan <path>`) keep the detailed report — a
		// scan the user aimed at one file IS a request for its inventory —
		// as do --full, markdown, and NDJSON. --unfiltered forces the full
		// report too: it is an audit of the suppression gates, whose extra
		// findings bare `jit migrate` (a filtered scan) will never act on —
		// feeding them into the coverage ledger would promise protection the
		// recommended command can't deliver.
		triage := (scanFormat == "" || scanFormat == "text") && len(args) == 0 && !scanFull && !scanUnfiltered
		if err := writeScanReport(out, scanFormat, findings, summary, home, triage); err != nil {
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
		// Last, so the full report is always written and flushed first: the
		// gate tripping must never cost the user the findings that explain it.
		return failOnResult(scanFailOn, summary.RiskLevel, summary.ExposureScore, len(summary.DegradedScanners))
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
// only consulted by the human formats (display-only "~"-shortening, "" to
// disable); markdown/NDJSON always keep full absolute paths for machines.
func writeScanReport(w io.Writer, format string, findings []audit.Finding, summary audit.ScanSummary, home string, triage bool) error {
	switch format {
	case "", "text":
		if triage {
			cov := audit.Coverage{
				Protected:  summary.SecretsProtected,
				Exposed:    summary.SecretsTotal - summary.SecretsProtected,
				Migratable: summary.SecretsMigratable,
			}
			audit.WriteTriageReport(w, findings, summary, home, cov)
			return nil
		}
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
	scanCmd.Flags().BoolVar(&scanUnfiltered, "unfiltered", false, "show findings jit normally judges to be settings, paths, browser-public build variables or unfilled template values; each is tagged [unfiltered] with the rule that hid it, so one run audits what the filters are hiding")
	scanCmd.Flags().BoolVar(&scanScore, "score", false, `print only the exposure score (e.g. "Exposure: 92/100 (CRITICAL)") and exit`)
	scanCmd.Flags().BoolVar(&scanFull, "full", false, "print the full finding inventory (categories, severities, every file and line) instead of the coverage summary")
	scanCmd.Flags().StringVar(&scanFailOn, "fail-on", "", "exit 2 when the scan's risk level is at or above this: critical, high, medium, low, or any (default: always exit 0)")
	registerPagerFlag(scanCmd)
	_ = scanCmd.RegisterFlagCompletionFunc("fail-on", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return []string{audit.RiskLevelCritical, audit.RiskLevelHigh, audit.RiskLevelMedium, audit.RiskLevelLow, "any"}, cobra.ShellCompDirectiveNoFileComp
	})
	// Not the shared completeOutputFormat: scan reports a list of findings,
	// so its vocabulary is markdown/ndjson rather than one JSON snapshot
	// (validateScanFormat, which TestScanFormatCompletionMatchesValidator
	// pins this to). "md" is accepted as an alias but not offered — two
	// spellings of one format read as two formats.
	_ = scanCmd.RegisterFlagCompletionFunc("format", completeValues(
		"text\thuman-readable (default)",
		"markdown\ta report to paste into a document",
		"ndjson\tone JSON finding per line"))
	rootCmd.AddCommand(scanCmd)
}
