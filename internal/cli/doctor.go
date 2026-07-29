// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"fmt"
	"github.com/fatih/color"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

var (
	doctorProfile string
	doctorFormat  string
	doctorVerbose bool
	doctorOrphans bool
)

// doctorResult is jit doctor's --format json shape. Problems and Warnings
// carry the SAME structured checkFinding objects the text path renders — a
// change from the old flat []string, made deliberately (GAPS.md #22 chose
// strings; leveling doctor up reverses that): a CI health check can now
// filter on {kind, profile, variable, path} instead of regexing an English
// sentence back apart. ok reflects hard Problems only — a missing/corrupt/
// unparseable profile secret. Every other finding (orphan, shadowed profile,
// agent/backup/wrap health) is a Warning and never flips ok, so a pipeline
// that only cares whether its profiles resolve keeps passing.
//
// --verbose affects the TEXT report only (it lists each clean reference);
// the JSON shape is stable regardless, so a consumer never has to strip an
// unexpected field back out.
type doctorResult struct {
	ProfilesChecked int            `json:"profiles_checked"`
	SecretsChecked  int            `json:"secrets_checked"`
	OK              bool           `json:"ok"`
	Problems        []checkFinding `json:"problems"`
	Warnings        []checkFinding `json:"warnings"`
}

var doctorCmd = &cobra.Command{
	Use:     "doctor",
	GroupID: groupWorkflow,
	Short:   "One-shot health check: profiles, secrets, service, backup, and wrap shims",
	Long: "jit doctor is the single \"what's wrong\" rollup for a jit setup. Its core\n" +
		"job: verify that every secret path a profile references actually exists in\n" +
		"the vault AND that its envelope is one this build of jit can read, failing\n" +
		"fast with a named problem instead of letting an app crash later on an empty\n" +
		"environment variable or a value that won't decrypt. It never decrypts a\n" +
		"value (existence and envelope structure are both plaintext on disk), so it\n" +
		"never needs local authentication and is safe to run often.\n\n" +
		"By default it checks every profile visible from the current directory: both\n" +
		"project-local ones under .jit/profiles/ and the home-rooted global ones\n" +
		"jit migrate writes for shell-config/MCP/AWS/kubeconfig/npmrc secrets,\n" +
		"the same set `jit status --secrets` reconciles. It also folds in the health checks\n" +
		"that used to take `jit status` and `jit wrap doctor` to see: the background\n" +
		"service, your vault backup, and any wrapped-tool shims.\n\n" +
		"It exits non-zero only when a profile's secret is missing, corrupt, or\n" +
		"unparseable. Everything else it reports is an advisory warning, never a\n" +
		"failure: an orphaned secret (with --orphans), a profile name shadowed\n" +
		"across scopes, a stopped service, a stale or missing vault backup, a broken\n" +
		"shim. Use --profile to narrow the run to a single profile (the system-\n" +
		"health sections are skipped then), --verbose to list every reference it\n" +
		"cleared, and --format json for a machine-readable snapshot.",
	Args: cobra.NoArgs,
	// A "problems found" exit is a normal, expected outcome here, not a
	// usage mistake — cobra's default of dumping the usage string to
	// stdout on any RunE error would otherwise land right after (and
	// corrupt) a --format json snapshot on exactly the run a script most
	// needs to parse cleanly: the failing one.
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateOutputFormat(doctorFormat); err != nil {
			return fmt.Errorf("jit doctor: %w", err)
		}

		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("jit doctor: %w", err)
		}
		root, err := vaultRootDir()
		if err != nil {
			return fmt.Errorf("jit doctor: %w", err)
		}
		v, err := openVaultReadOnly()
		if err != nil {
			return fmt.Errorf("jit doctor: %w", err)
		}

		// Integrity is always on: it is auth-free (envelope structure is
		// plaintext) and cheap, and a "doctor" that couldn't tell a
		// truncated secret from a healthy one would be missing the failure
		// most likely to look like a jit bug at runtime.
		outcome, err := runProfileCheck(cwd, v, checkOptions{
			Profile:   doctorProfile,
			Integrity: true,
			Orphans:   doctorOrphans,
		})
		if err != nil {
			return fmt.Errorf("jit doctor: %w", err)
		}

		// The absorbed system-health sections run on the full sweep only. A
		// --profile run is a narrow "does THIS profile resolve" query; folding
		// agent/backup/wrap warnings into it would be surprising noise.
		if doctorProfile == "" {
			outcome.Findings = append(outcome.Findings, gatherSystemFindings(root, v)...)
		}

		problems := outcome.Problems()
		warnings := outcome.Warnings()

		if doctorFormat == "json" {
			if problems == nil {
				problems = []checkFinding{}
			}
			if warnings == nil {
				warnings = []checkFinding{}
			}
			if err := writeJSON(cmd.OutOrStdout(), doctorResult{
				ProfilesChecked: outcome.ProfilesChecked,
				SecretsChecked:  outcome.SecretsChecked,
				OK:              len(problems) == 0,
				Problems:        problems,
				Warnings:        warnings,
			}); err != nil {
				return fmt.Errorf("jit doctor: %w", err)
			}
			if len(problems) > 0 {
				return fmt.Errorf("jit doctor: %s found", countWord(len(problems), "problem", "problems"))
			}
			return nil
		}

		return renderDoctorText(cmd.OutOrStdout(), outcome, problems, warnings)
	},
}

// renderDoctorText prints the human report and returns the non-zero-exit
// error when there are hard problems. Order is: problems (red, the reason
// you ran this), then warnings (yellow, advisory), then the profile summary
// line, then — under --verbose — the per-reference detail, then the standing
// global-mount reminders.
func renderDoctorText(out io.Writer, outcome checkOutcome, problems, warnings []checkFinding) error {
	for _, f := range problems {
		writeDoctorFinding(out, glyphRisk, cRisk, f)
	}
	for _, f := range warnings {
		writeDoctorFinding(out, glyphWarn, cWarn, f)
	}

	// The verdict lines wrap like every other line here: at 44 columns the
	// clean-bill-of-health line was the one thing still running past the edge,
	// which is a poor look on the line that says everything is fine.
	switch {
	case outcome.ProfilesChecked == 0:
		wrapBody(out, 0, "  ", cDim.Sprint("No profiles found under .jit/profiles/ or the global store."))
	case len(problems) == 0:
		_, _ = cOK.Fprintf(out, "%s ", glyphDone)
		wrapBody(out, 2, "  ", cOKBold.Sprintf(
			"%s, %s all resolve cleanly",
			countWord(outcome.ProfilesChecked, "profile", "profiles"),
			countWord(outcome.SecretsChecked, "secret reference", "secret references")))
	}

	// --verbose lists the individual references so a passing run can still
	// answer "did it actually see my profile?" — a bare count can't.
	if doctorVerbose && len(outcome.OKRefs) > 0 {
		_, _ = cBold.Fprintln(out, "\nChecked")
		for _, r := range outcome.OKRefs {
			_, _ = cOK.Fprintf(out, "  %s ", glyphDone)
			fmt.Fprintf(out, "%s (%s): %s → %s\n", r.Profile, r.Scope, r.Variable, r.Path)
		}
	}

	printGlobalMountReminders(out)

	if len(problems) > 0 {
		return fmt.Errorf("jit doctor: %s found", countWord(len(problems), "problem", "problems"))
	}
	return nil
}

// doctorActionRe lifts a trailing "run `cmd` …" clause out of a finding's
// prose. Doctor's findings were single lines that ran to 190 columns with the
// fix buried mid-sentence — exactly the shape design/output-style.md's action
// rule exists to prevent. The commands are already backtick-delimited for
// hlCmds, so the clause is machine-findable rather than guessed at.
//
// Case-insensitive on the verb: these sentences are written by a dozen
// different call sites, and half of them start the clause after a full stop
// with a capital "Run".
var doctorActionRe = regexp.MustCompile("(?i)(?:[,;]| —|\\.)\\s+run (`[^`]+`.*)$")

// writeDoctorFinding renders one finding: the state glyph, the bracketed kind,
// then the prose wrapped so continuations hang under the prose rather than
// resuming at column 0 beneath the glyph. A fix the finding names moves to its
// own cyan arrow line, so the thing to type is the last thing on screen.
func writeDoctorFinding(out io.Writer, glyph string, c *color.Color, f checkFinding) {
	label := findingLabel(f)
	_, _ = c.Fprintf(out, "%s ", glyph)
	fmt.Fprintf(out, "%s ", label)
	used := 2 + len(label) + 1
	indent := strings.Repeat(" ", used)

	body := formatFinding(f)
	body = strings.TrimPrefix(body, label+" ")
	action := ""
	if m := doctorActionRe.FindStringSubmatch(body); m != nil {
		action = m[1]
		body = strings.TrimRight(body[:len(body)-len(m[0])], " ,;—.") + "."
	}
	wrapBody(out, used, indent, hlCmds(body))
	if action == "" {
		return
	}
	// The arrow sits two columns left of the prose it resolves, the same
	// relationship `jit status` uses between a note and its action.
	arrowIndent := strings.Repeat(" ", used-2)
	fmt.Fprint(out, arrowIndent)
	_, _ = cPath.Fprint(out, "→ ")
	wrapBody(out, used, arrowIndent+"  ", hlCmds(action))
}

// findingLabel is the bracketed kind tag that opens a finding line.
func findingLabel(f checkFinding) string {
	switch f.Kind {
	case kindParse:
		return "[parse]"
	case kindMissing:
		return "[missing]"
	case kindCorrupt:
		return "[corrupt]"
	case kindVaultError:
		return "[vault error]"
	case kindOrphan:
		return "[orphan]"
	case kindShadowed:
		return "[shadowed]"
	case kindService:
		return "[service]"
	case kindBackup:
		return "[backup]"
	case kindWrap:
		return "[wrap]"
	default:
		return ""
	}
}

// formatFinding renders one finding as a single human-readable line, tagged
// by kind. kindMissing keeps its full remediation hint (the fix command by
// name) — the line users act on most. writeDoctorFinding is what breaks the
// result across the window and lifts the fix onto its own arrow line.
func formatFinding(f checkFinding) string {
	switch f.Kind {
	case kindParse:
		return fmt.Sprintf("[parse] %s", f.Detail)
	case kindMissing:
		// Backticks, not escaped double quotes: hlCmds turns them into the
		// house cyan and drops the delimiters, so this line stops being the
		// one place doctor prints a command as quoted prose.
		return fmt.Sprintf(
			"[missing] profile %q: %s -> %s (not in the vault). run `jit vault set %s` to add it, or `jit migrate <path>` to convert the file it came from",
			f.Profile, f.Variable, f.Path, f.Path)
	case kindCorrupt:
		return fmt.Sprintf("[corrupt] profile %q: %s -> %s: %s", f.Profile, f.Variable, f.Path, f.Detail)
	case kindVaultError:
		if f.Profile == "" {
			return fmt.Sprintf("[vault error] %s", f.Detail)
		}
		return fmt.Sprintf("[vault error] profile %q: checking %s (%s): %s", f.Profile, f.Variable, f.Path, f.Detail)
	case kindOrphan:
		return fmt.Sprintf("[orphan] %s (%s)", f.Path, f.Detail)
	case kindShadowed:
		return fmt.Sprintf("[shadowed] profile %q: %s", f.Profile, f.Detail)
	case kindService:
		return fmt.Sprintf("[service] %s", f.Detail)
	case kindBackup:
		return fmt.Sprintf("[backup] %s", f.Detail)
	case kindWrap:
		return fmt.Sprintf("[wrap] %s", f.Detail)
	default:
		return f.Detail
	}
}

func init() {
	doctorCmd.Flags().StringVar(&doctorProfile, "profile", "", "check only this profile, and skip the service/backup/wrap health sections")
	_ = doctorCmd.RegisterFlagCompletionFunc("profile", completeProfileNames)
	doctorCmd.Flags().StringVar(&doctorFormat, "format", "text", `output format: "text" (default) or "json"`)
	doctorCmd.Flags().BoolVar(&doctorVerbose, "verbose", false, "on success, list every variable→path reference that was checked")
	doctorCmd.Flags().BoolVar(&doctorOrphans, "orphans", false, "also warn about vault secrets no profile references (advisory, never a failure)")
	rootCmd.AddCommand(doctorCmd)
}
