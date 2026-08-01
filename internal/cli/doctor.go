// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	doctorProfile string
	doctorFormat  string
	doctorVerbose bool
	doctorOrphans bool
	doctorWrap    bool
)

// doctorResult is jit doctor's --format json shape. Problems and Warnings
// carry the SAME structured checkFinding objects the text path renders — a
// change from the old flat []string, made deliberately (GAPS.md #22 chose
// strings; leveling doctor up reverses that): a CI health check can now
// filter on {kind, profile, variable, path} instead of regexing an English
// sentence back apart. ok reflects hard Problems only: a secret that cannot
// be read (missing, corrupt, unparseable, or the whole vault locked out of
// its master key) and a wrapped-tool installation that is actually damaged.
// Everything else — an orphan, a shadowed profile, a stopped agent, a stale
// backup, a mount whose manifest vanished, a shim dir absent from THIS
// shell's PATH — is a Warning and never flips ok, so a pipeline that only
// cares whether its secrets resolve keeps passing.
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
		"plus the profile behind every registered mount — which may live in a project\n" +
		"tree this directory never walks into, yet is being served right now. That is\n" +
		"the same set `jit status --secrets` and `jit vault orphans` reconcile. It also\n" +
		"folds in the health checks that used to take `jit status` and the retired\n" +
		"`jit wrap doctor` to see: the background service, your vault backup, and\n" +
		"every wrapped tool's shim, PATH entry and profile.\n\n" +
		"It exits non-zero when something this setup depends on is actually broken:\n" +
		"a secret missing, corrupt, or unparseable; the whole vault unreadable\n" +
		"because this Mac's master key is gone from the keychain or a master-key\n" +
		"rotation never finished; or a wrapped tool's installation damaged, which\n" +
		"means that tool now runs unwrapped or not at all. Everything else it\n" +
		"reports is an advisory warning: an orphaned secret (with --orphans), a\n" +
		"profile name shadowed across scopes, a mount whose profile won't load, a\n" +
		"stopped service, a stale or missing vault backup, and any shim complaint\n" +
		"that is only true of the shell you happen to be in — a CI job that doesn't\n" +
		"put the shim dir on PATH is not a broken machine.\n\n" +
		"Use --profile to narrow the run to a single profile. The service, backup and\n" +
		"shim sections are skipped then; the whole-vault key checks are not, because\n" +
		"with no master key no profile resolves and saying otherwise would be false.\n" +
		"Use --wrap for the shim check on its own — it never opens the vault, so it\n" +
		"still works when the vault is the thing that's broken. --verbose lists every\n" +
		"check that passed, not just the ones that failed, and --format json prints a\n" +
		"machine-readable snapshot.",
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

		var outcome checkOutcome

		// --wrap is the shim-only run that used to be `jit wrap doctor`. It
		// never opens the vault — not as an optimisation, but because the
		// state you most often want it in is one where the vault itself is
		// the problem, and a shim check that can't run until the vault opens
		// is no use debugging a shim.
		if doctorWrap {
			findings, okChecks := wrapFindings()
			outcome.Findings = findings
			outcome.OKChecks = okChecks
			outcome.WrapOnly = true
			return renderDoctorOutcome(cmd, outcome)
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
		outcome, err = runProfileCheck(cwd, v, checkOptions{
			Root:      root,
			Profile:   doctorProfile,
			Integrity: true,
			Orphans:   doctorOrphans,
		})
		if err != nil {
			return fmt.Errorf("jit doctor: %w", err)
		}

		// Whole-vault integrity runs on EVERY invocation, --profile included:
		// a missing master key or an unfinished rekey makes the named
		// profile's secrets just as unreadable as everyone else's, so
		// "resolves cleanly" would be false. See gatherVaultIntegrityFindings.
		outcome.Findings = append(outcome.Findings, gatherVaultIntegrityFindings(root, v)...)

		// The absorbed system-health sections run on the full sweep only. A
		// --profile run is a narrow "does THIS profile resolve" query; folding
		// agent/backup/wrap warnings into it would be surprising noise.
		if doctorProfile == "" {
			systemFindings, wrapOK := gatherSystemFindings(root, v)
			outcome.Findings = append(outcome.Findings, systemFindings...)
			outcome.OKChecks = wrapOK
		}

		return renderDoctorOutcome(cmd, outcome)
	},
}

// renderDoctorOutcome is the single exit path both the full run and the
// --wrap run take, so the two can't drift in exit code or JSON shape.
func renderDoctorOutcome(cmd *cobra.Command, outcome checkOutcome) error {
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
}

// renderDoctorText prints the human report and returns the non-zero-exit
// error when there are hard problems.
//
// The layout is design/output-style.md's REPORT shape — a `[Category] count`
// header, then its items — not the dashboard shape that document used to file
// doctor under. Doctor's data is a findings list, the same shape `jit scan`
// and `jit migrate` carry; `jit status` is the dashboard. Grouping is what
// finally lets rule 5 hold here: twelve missing references in one profile used
// to repeat the identical remediation sentence twelve times, and now state it
// once under the group that shares it.
//
// Grouping also fixes the column. Each finding previously indented its own
// continuation and arrow by its own label width, so `[missing]`, `[mount]` and
// `[rekey]` lines hung at three different depths down the same report. Under a
// header the label is out of the item line entirely and every item, wrap and
// arrow sits at one fixed indent.
func renderDoctorText(out io.Writer, outcome checkOutcome, problems, warnings []checkFinding) error {
	wrote := writeFindingGroups(out, glyphRisk, cRisk, problems, false)
	wrote = writeFindingGroups(out, glyphWarn, cWarn, warnings, wrote)

	// The verdict lines wrap like every other line here: at 44 columns the
	// clean-bill-of-health line was the one thing still running past the edge,
	// which is a poor look on the line that says everything is fine.
	switch {
	case outcome.WrapOnly:
		// A --wrap run has nothing to say about profiles. When it also has
		// nothing to say about shims, say THAT rather than printing an empty
		// report and leaving the reader to guess whether it ran.
		if len(problems)+len(warnings) == 0 {
			_, _ = cOK.Fprintf(out, "%s ", glyphDone)
			wrapBody(out, 2, "  ", cOKBold.Sprintf("%s %s",
				countWord(len(outcome.OKChecks), "wrap check", "wrap checks"),
				pluralWord(len(outcome.OKChecks), "passes", "pass")))
		}
	case outcome.ProfilesChecked == 0:
		wrapBody(out, 0, "  ", cDim.Sprint("No profiles found under .jit/profiles/ or the global store."))
	case len(problems) == 0:
		if wrote {
			fmt.Fprintln(out)
		}
		_, _ = cOK.Fprintf(out, "%s ", glyphDone)
		// Scoped deliberately to the references, and carrying the warning
		// count when there is one. Unqualified "all resolve cleanly" printed
		// directly beneath a [mount] or [backup] warning read as a global
		// all-clear contradicting the lines above it — the summary is only
		// ever speaking for the secret references it actually checked.
		summary := fmt.Sprintf("%s, %s resolve cleanly",
			countWord(outcome.ProfilesChecked, "profile", "profiles"),
			countWord(outcome.SecretsChecked, "secret reference", "secret references"))
		if len(warnings) > 0 {
			summary += fmt.Sprintf(" · %s above", countWord(len(warnings), "warning", "warnings"))
		}
		wrapBody(out, 2, "  ", cOKBold.Sprint(summary))
	}

	// --verbose lists the individual references so a passing run can still
	// answer "did it actually see my profile?" — a bare count can't.
	if passing := len(outcome.OKRefs) + len(outcome.OKChecks); doctorVerbose && passing > 0 {
		// Same `[Name]  count` header as every finding group, so the report
		// has one header shape rather than a bare bold word here and
		// bracketed tags above it (rule 1).
		fmt.Fprintln(out)
		_, _ = cBold.Fprint(out, "[checked]")
		_, _ = cDim.Fprintf(out, "  %d\n", passing)
		body := strings.Repeat(" ", findingIndent)
		for _, r := range outcome.OKRefs {
			_, _ = cOK.Fprintf(out, "  %s ", glyphOK)
			wrapBody(out, findingIndent, body,
				fmt.Sprintf("%s: %s → %s", profileRef(checkFinding{Profile: r.Profile, Scope: r.Scope}), r.Variable, r.Path))
		}
		for _, c := range outcome.OKChecks {
			_, _ = cOK.Fprintf(out, "  %s ", glyphOK)
			wrapBody(out, findingIndent, body, hlCmds(shortHome(c)))
		}
	}

	printGlobalMountReminders(out)

	if len(problems) > 0 {
		return fmt.Errorf("jit doctor: %s found", countWord(len(problems), "problem", "problems"))
	}
	return nil
}

// The report's two fixed columns. Items hang under their `[Category]` header
// at findingIndent; an action arrow sits two columns left of the prose it
// resolves, the same relationship `jit status` uses. Both are constants
// precisely because they used to be arithmetic on the label's own width,
// which is how one report grew three different left edges.
const (
	findingIndent = 4
	findingArrow  = findingIndent - 2
)

// writeFindingGroups renders findings grouped by kind, each group under a
// `[Category] count` header (rule 1), in the order the kinds were first seen
// so the most important finding a run produced still leads.
// precededBy is whether anything has already been printed, so groups are
// separated by a blank line without the report opening on one.
func writeFindingGroups(out io.Writer, glyph string, c *color.Color, findings []checkFinding, precededBy bool) bool {
	if len(findings) == 0 {
		return precededBy
	}
	var order []checkKind
	groups := map[checkKind][]checkFinding{}
	for _, f := range findings {
		if _, ok := groups[f.Kind]; !ok {
			order = append(order, f.Kind)
		}
		groups[f.Kind] = append(groups[f.Kind], f)
	}

	body := strings.Repeat(" ", findingIndent)
	arrow := strings.Repeat(" ", findingArrow)
	for _, kind := range order {
		group := groups[kind]
		if precededBy {
			fmt.Fprintln(out)
		}
		precededBy = true
		_, _ = cBold.Fprint(out, findingLabel(checkFinding{Kind: kind}))
		// A count only earns its place when there is more than one to count:
		// "[rekey] 1" invites the reader to compare a number against nothing.
		if len(group) > 1 {
			_, _ = cDim.Fprintf(out, "  %d", len(group))
		}
		fmt.Fprintln(out)

		// A single action shared by the whole group is stated once, after the
		// items. Twenty orphans carry twenty identical "jit vault orphans
		// --prune" strings; printing all twenty is the exact restatement
		// rule 5 forbids, and it buries the one line that matters.
		//
		// When the actions differ only by the path they name, the group falls
		// back to the templated form: five missing secrets would otherwise
		// alternate ✗/→ ten lines deep, restating one command shape five
		// times, when every path involved is already on the line above.
		shared := sharedAction(group)
		if shared == "" && len(group) > 1 {
			shared = templateAction(kind)
		}
		for _, f := range group {
			_, _ = c.Fprintf(out, "  %s ", glyph)
			wrapBody(out, findingIndent, body, hlCmds(formatFinding(f)))
			if shared == "" && f.Action != "" {
				writeActionLine(out, arrow, f.Action)
			}
		}
		if shared != "" {
			writeActionLine(out, arrow, shared)
		}
	}
	return true
}

// writeActionLine prints one cyan-arrow next step, and nothing else on the
// line (design/output-style.md, "The action line").
func writeActionLine(out io.Writer, arrow, action string) {
	fmt.Fprint(out, arrow)
	_, _ = cPath.Fprint(out, "→ ")
	wrapBody(out, findingIndent, arrow+"  ", hlCmds(action))
}

// templateAction is the group-level form of an action whose per-finding
// version differs only by the path it names — the placeholder stands in for
// the paths already listed immediately above. Empty for kinds whose findings
// can need genuinely different next steps (a [service] group can hold both a
// build mismatch and a stopped service), which keeps their per-item arrows.
func templateAction(kind checkKind) string {
	switch kind {
	case kindMissing:
		return "`jit vault set <path>` for each, or `jit migrate <path>` to convert the files they came from"
	case kindCorrupt:
		return "`jit vault history <path>` to see earlier versions, or `jit vault set <path>` to replace"
	default:
		return ""
	}
}

// sharedAction returns the action every finding in a group carries, or "" when
// they differ (or any lacks one) — in which case each states its own.
func sharedAction(group []checkFinding) string {
	first := group[0].Action
	if first == "" || len(group) == 1 {
		return first
	}
	for _, f := range group[1:] {
		if f.Action != first {
			return ""
		}
	}
	return first
}

// findingLabel is the bracketed kind tag. It heads a GROUP now rather than
// each line — twenty orphans get one `[orphan]  20`, not the tag twenty times
// (rule 1's header shape, and rule 5's state-it-once).
func findingLabel(f checkFinding) string {
	switch f.Kind {
	case kindParse:
		return "[parse]"
	case kindNotFound:
		return "[not found]"
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
	case kindWrapEnv:
		// Names why it isn't a failure, on the header, so the reader doesn't
		// have to infer it from the glyph — and so two wrap groups in one
		// report are distinguishable rather than the same word twice.
		return "[wrap: this shell]"
	case kindMount:
		return "[mount]"
	case kindVaultKey:
		return "[vault key]"
	case kindRekey:
		return "[rekey]"
	default:
		return ""
	}
}

// formatFinding renders one finding's BODY — no kind tag, since the group
// header above it carries that, and no remediation, since the action line
// below it carries that. What's left is purely what IS wrong, which is the
// whole job of a state line.
//
// Absolute paths go through shortHome: these details embed manifest and mount
// paths mid-sentence, and a 90-character /Users/... prefix pushed the part
// that identifies the file off the first line (rule 6).
func formatFinding(f checkFinding) string {
	switch f.Kind {
	case kindParse, kindNotFound, kindService, kindBackup, kindWrap, kindWrapEnv, kindMount, kindVaultKey, kindRekey:
		return shortHome(f.Detail)
	case kindMissing:
		return fmt.Sprintf("%s: %s → %s, not in the vault", profileRef(f), f.Variable, f.Path)
	case kindCorrupt:
		return fmt.Sprintf("%s: %s → %s: %s", profileRef(f), f.Variable, f.Path, shortHome(f.Detail))
	case kindVaultError:
		if f.Profile == "" {
			return shortHome(f.Detail)
		}
		return fmt.Sprintf("%s: %s → %s: %s", profileRef(f), f.Variable, f.Path, shortHome(f.Detail))
	case kindOrphan:
		return fmt.Sprintf("%s — %s", f.Path, f.Detail)
	case kindShadowed:
		return fmt.Sprintf("%s: %s", profileRef(f), f.Detail)
	default:
		return shortHome(f.Detail)
	}
}

// profileRef names the profile a finding belongs to, with its scope. The
// scope used to be dead weight on the line (project vs global rarely changes
// what you do) and is now load-bearing: a "mount" scope says the manifest
// lives somewhere the current directory can't see, which is the difference
// between an actionable finding and a mystery.
func profileRef(f checkFinding) string {
	if f.Scope == "" {
		return fmt.Sprintf("profile %q", f.Profile)
	}
	return fmt.Sprintf("profile %q (%s)", f.Profile, f.Scope)
}

func init() {
	doctorCmd.Flags().StringVar(&doctorProfile, "profile", "", "check only this profile, and skip the service/backup/wrap health sections")
	_ = doctorCmd.RegisterFlagCompletionFunc("profile", completeProfileNames)
	doctorCmd.Flags().StringVar(&doctorFormat, "format", "text", `output format: "text" (default) or "json"`)
	doctorCmd.Flags().BoolVar(&doctorVerbose, "verbose", false, "on success, list every variable→path reference that was checked")
	doctorCmd.Flags().BoolVar(&doctorOrphans, "orphans", false, "also warn about vault secrets no profile references (advisory, never a failure)")
	doctorCmd.Flags().BoolVar(&doctorWrap, "wrap", false, "check only the wrapped-tool shims, without opening the vault (replaces `jit wrap doctor`)")
	doctorCmd.MarkFlagsMutuallyExclusive("wrap", "profile")
	doctorCmd.MarkFlagsMutuallyExclusive("wrap", "orphans")
	rootCmd.AddCommand(doctorCmd)
}
