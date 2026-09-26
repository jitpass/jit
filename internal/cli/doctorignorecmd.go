// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// `jit doctor ignore` and `jit doctor unignore`: the only writers of
// ~/.jit/doctor-ignore.json (see doctorignore.go).

var (
	doctorShowIgnored    bool
	doctorIgnoreKind     string
	doctorIgnoreFormat   string
	doctorUnignoreKind   string
	doctorUnignoreFormat string
	doctorUnignoreAll    bool
)

var doctorIgnoreCmd = &cobra.Command{
	Use:   "ignore <name>...",
	Short: "Stop counting a doctor finding you have decided to leave as it is",
	Long: "Takes findings out of `jit doctor`'s counts: an ignored finding no longer\n" +
		"fails the run, flips ok or trips --strict, and the report folds it into one\n" +
		"[ignored] line at the end (--show-ignored lists them). Nothing is fixed: a\n" +
		"problem you ignore is still broken, doctor just stops counting it.\n\n" +
		"A name is what a row leads with: a profile (aws-dev, mcp-github), a file\n" +
		"(~/.clisso.yaml, ~/ or absolute), or, for a section whose rows have no\n" +
		"name of their own, the section (backup, orphan, storage-format). All of a\n" +
		"profile's rows in one section are one finding. A name in more than one\n" +
		"section needs --kind: the section, or its JSON kind (config-deleted or\n" +
		"config_deleted). `jit doctor --format json` gives every finding's kind\n" +
		"and name, and the argv that ignores it.\n\n" +
		"Each ignore remembers what the finding said. When that changes (its\n" +
		"~/.aws/config entry is edited, another secret goes missing) the finding\n" +
		"comes back and counts again, marked as changed, until you ignore it again.\n\n" +
		"Ignores are kept in ~/.jit/doctor-ignore.json. Only ignore and unignore\n" +
		"write it; doctor itself never does. With --format json it prints\n" +
		"{ignored, unignored, error}, with the same exit codes.",
	Example: "  jit doctor ignore aws-dev aws-admin\n" +
		"  jit doctor ignore --kind config-deleted mcp-github-server\n" +
		"  jit doctor ignore --format json backup",
	Args:         requireArgs(1, -1, "the name of a finding: the profile, file or section its row leads with"),
	SilenceUsage: true,
	RunE:         runDoctorIgnore,
}

var doctorUnignoreCmd = &cobra.Command{
	Use:   "unignore <name>... | --all",
	Short: "Count an ignored doctor finding again",
	Long: "Removes ignores `jit doctor ignore` recorded, so those findings show and\n" +
		"count again. A name removes every ignore by that name unless --kind\n" +
		"narrows it; --all removes them all. `jit doctor --show-ignored` lists what\n" +
		"is ignored. With --format json it prints {ignored, unignored, error}.",
	Example: "  jit doctor unignore aws-dev\n" +
		"  jit doctor unignore --all",
	Args: func(cmd *cobra.Command, args []string) error {
		if doctorUnignoreAll {
			if len(args) > 0 {
				return fmt.Errorf("%s: --all takes no names", cmd.CommandPath())
			}
			return nil
		}
		return requireArgs(1, -1, "the name of an ignored finding, or --all")(cmd, args)
	},
	SilenceUsage: true,
	RunE:         runDoctorUnignore,
}

// doctorIgnoreItem is one unit in the ignore/unignore JSON.
type doctorIgnoreItem struct {
	Kind checkKind `json:"kind"`
	Name string    `json:"name"`
}

// doctorIgnoreResult is `jit doctor ignore/unignore --format json`.
type doctorIgnoreResult struct {
	Ignored   []doctorIgnoreItem `json:"ignored"`
	Unignored []doctorIgnoreItem `json:"unignored"`
	Error     string             `json:"error,omitempty"`
}

// ignoreFail ends an ignore/unignore run that changed nothing: in JSON the
// error is printed as the result and exit 1 carries it; in text the error
// itself is the output.
func ignoreFail(cmd *cobra.Command, format string, err error) error {
	if format != "json" {
		return err
	}
	if werr := writeJSON(cmd.OutOrStdout(), doctorIgnoreResult{
		Ignored: []doctorIgnoreItem{}, Unignored: []doctorIgnoreItem{}, Error: err.Error(),
	}); werr != nil {
		return werr
	}
	return &ExitError{Code: 1, Msg: err.Error()}
}

func runDoctorIgnore(cmd *cobra.Command, args []string) error {
	if err := validateOutputFormat(doctorIgnoreFormat); err != nil {
		return fmt.Errorf("jit doctor ignore: %w", err)
	}
	fail := func(err error) error { return ignoreFail(cmd, doctorIgnoreFormat, err) }
	var kind checkKind
	if doctorIgnoreKind != "" {
		k, err := parseIgnoreKind(doctorIgnoreKind)
		if err != nil {
			return fail(fmt.Errorf("jit doctor ignore: %w", err))
		}
		kind = k
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fail(fmt.Errorf("jit doctor ignore: %w", err))
	}
	store, err := loadDoctorIgnores(home)
	if err != nil {
		return fail(fmt.Errorf("jit doctor ignore: %w", err))
	}
	// The full sweep, whatever flags doctor was last run with: a name is
	// resolved, and fingerprinted, against the same findings a plain
	// `jit doctor` reports. Never the --1password sweep, which costs a
	// Touch ID.
	outcome, err := gatherDoctorOutcome(io.Discard, "", false)
	if err != nil {
		return fail(fmt.Errorf("jit doctor ignore: %w", err))
	}
	picked, err := resolveIgnoreNames(doctorIgnoreUnits(outcome.Findings), args, kind)
	if err != nil {
		return fail(err)
	}

	today := doctorIgnoreNow().Format("2006-01-02")
	for _, u := range picked {
		entry := doctorIgnoreEntry{Kind: u.kind, Name: u.name, Fingerprint: u.fingerprint, Since: today}
		replaced := false
		for i, e := range store.Entries {
			if e.Kind == u.kind && e.Name == u.name {
				// Re-ignoring an unchanged finding keeps the date it was
				// first ignored; a changed one starts again today.
				if e.Fingerprint == u.fingerprint {
					entry.Since = e.Since
				}
				store.Entries[i] = entry
				replaced = true
			}
		}
		if !replaced {
			store.Entries = append(store.Entries, entry)
		}
	}
	if err := saveDoctorIgnores(home, store); err != nil {
		return fail(fmt.Errorf("jit doctor ignore: %w", err))
	}

	if doctorIgnoreFormat == "json" {
		res := doctorIgnoreResult{Ignored: []doctorIgnoreItem{}, Unignored: []doctorIgnoreItem{}}
		for _, u := range picked {
			res.Ignored = append(res.Ignored, doctorIgnoreItem{Kind: u.kind, Name: u.name})
		}
		return writeJSON(cmd.OutOrStdout(), res)
	}
	writeIgnoredReceipt(cmd.OutOrStdout(), picked, doctorIgnoreKind != "")
	return nil
}

// resolveIgnoreNames resolves each name to exactly one unit, or fails
// without anything written: an unknown name, or a name in more than one
// section with no --kind to choose.
func resolveIgnoreNames(units []*ignoreUnit, names []string, kind checkKind) ([]*ignoreUnit, error) {
	var picked []*ignoreUnit
	for _, name := range names {
		var matches []*ignoreUnit
		for _, u := range units {
			if (kind == "" || u.kind == kind) && ignoreNameMatches(u.kind, u.name, name) {
				matches = append(matches, u)
			}
		}
		switch len(matches) {
		case 0:
			where := "doctor reports"
			if kind != "" {
				where = "doctor reports under " + ignoreKindText(kind)
			}
			return nil, &hintedError{
				msg:  fmt.Sprintf("jit doctor ignore: nothing %s is named %s", where, name),
				cmd:  "jit doctor --format json",
				note: "each finding's ignore.name is the name to use",
			}
		case 1:
		default:
			var b strings.Builder
			fmt.Fprintf(&b, "jit doctor ignore: %s is in %d findings, pick one", name, len(matches))
			for _, m := range matches {
				fmt.Fprintf(&b, "\n  %s · %s", ignoreKindText(m.kind), ignoreUnitSummary(m))
			}
			// Suggest the advisory one: a warning is what a reader most
			// often means to set aside, and a problem stays one to fix.
			pick := matches[0]
			for _, m := range matches {
				if m.kind.warning() {
					pick = m
					break
				}
			}
			return nil, &hintedError{
				msg: b.String(),
				cmd: "jit doctor ignore --kind " + dashKind(pick.kind) + " " + shellQuoteArg(pick.name),
			}
		}
		if !containsUnit(picked, matches[0]) {
			picked = append(picked, matches[0])
		}
	}
	return picked, nil
}

func containsUnit(units []*ignoreUnit, u *ignoreUnit) bool {
	for _, x := range units {
		if x == u {
			return true
		}
	}
	return false
}

// writeIgnoredReceipt is what `jit doctor ignore` prints: each unit, the
// honest line for any problem among them, when the rest come back, and the
// command that undoes it.
func writeIgnoredReceipt(out io.Writer, picked []*ignoreUnit, withKind bool) {
	note := func(indent int, s string) {
		fmt.Fprint(out, strings.Repeat(" ", indent))
		wrapBody(out, indent, "    ", s)
	}
	var advisory []*ignoreUnit
	for _, u := range picked {
		_, _ = cOK.Fprint(out, glyphDone+" ")
		wrapBody(out, 2, "    ", fmt.Sprintf("ignored %s · %s", u.name, ignoreKindText(u.kind)))
		if u.kind.warning() {
			advisory = append(advisory, u)
		}
	}
	for _, u := range picked {
		if !u.kind.warning() {
			note(2, ignoreStillFails(u)+"; doctor just stops counting it")
		}
	}
	if len(advisory) > 0 {
		clause := ignoreComesBack(advisory[0])
		for _, u := range advisory[1:] {
			if ignoreComesBack(u) != clause {
				clause = "what it reports changes"
				break
			}
		}
		note(2, fmt.Sprintf("%s comes back if %s", pluralWord(len(advisory), "it", "each"), clause))
	}
	words := []string{"jit", "doctor", "unignore"}
	if withKind && len(picked) > 0 && allOneKind(picked) {
		words = append(words, "--kind", dashKind(picked[0].kind))
	}
	for _, u := range picked {
		words = append(words, shellQuoteArg(u.name))
	}
	fmt.Fprint(out, "  ")
	_, _ = cPath.Fprint(out, glyphAction+" ")
	wrapBody(out, 4, "    ", hlCmds("`"+strings.Join(words, " ")+"`"))
	note(4, fmt.Sprintf("to show %s again", pluralWord(len(picked), "it", "them")))
}

func allOneKind(units []*ignoreUnit) bool {
	for _, u := range units[1:] {
		if u.kind != units[0].kind {
			return false
		}
	}
	return true
}

func runDoctorUnignore(cmd *cobra.Command, args []string) error {
	if err := validateOutputFormat(doctorUnignoreFormat); err != nil {
		return fmt.Errorf("jit doctor unignore: %w", err)
	}
	fail := func(err error) error { return ignoreFail(cmd, doctorUnignoreFormat, err) }
	var kind checkKind
	if doctorUnignoreKind != "" {
		k, err := parseIgnoreKind(doctorUnignoreKind)
		if err != nil {
			return fail(fmt.Errorf("jit doctor unignore: %w", err))
		}
		kind = k
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fail(fmt.Errorf("jit doctor unignore: %w", err))
	}
	store, err := loadDoctorIgnores(home)
	if err != nil {
		return fail(fmt.Errorf("jit doctor unignore: %w", err))
	}

	drop := make([]bool, len(store.Entries))
	for i, e := range store.Entries {
		drop[i] = doctorUnignoreAll && (kind == "" || e.Kind == kind)
	}
	for _, name := range args {
		found := false
		for i, e := range store.Entries {
			if (kind == "" || e.Kind == kind) && ignoreNameMatches(e.Kind, e.Name, name) {
				drop[i] = true
				found = true
			}
		}
		if !found {
			return fail(&hintedError{
				msg: fmt.Sprintf("jit doctor unignore: nothing ignored is named %s", name),
				cmd: "jit doctor --show-ignored",
			})
		}
	}
	var removed, kept []doctorIgnoreEntry
	for i, e := range store.Entries {
		if drop[i] {
			removed = append(removed, e)
		} else {
			kept = append(kept, e)
		}
	}
	if len(removed) > 0 {
		store.Entries = kept
		if err := saveDoctorIgnores(home, store); err != nil {
			return fail(fmt.Errorf("jit doctor unignore: %w", err))
		}
	}

	if doctorUnignoreFormat == "json" {
		res := doctorIgnoreResult{Ignored: []doctorIgnoreItem{}, Unignored: []doctorIgnoreItem{}}
		for _, e := range removed {
			res.Unignored = append(res.Unignored, doctorIgnoreItem{Kind: e.Kind, Name: e.Name})
		}
		return writeJSON(cmd.OutOrStdout(), res)
	}
	out := cmd.OutOrStdout()
	if len(removed) == 0 {
		fmt.Fprintln(out, "nothing is ignored")
		return nil
	}
	for _, e := range removed {
		_, _ = cOK.Fprint(out, glyphDone+" ")
		wrapBody(out, 2, "    ", fmt.Sprintf("unignored %s · %s", e.Name, ignoreKindText(e.Kind)))
	}
	return nil
}

func init() {
	doctorCmd.Flags().BoolVar(&doctorShowIgnored, "show-ignored", false, "list each ignored finding in the [ignored] group, not just the count")

	doctorIgnoreCmd.Flags().StringVar(&doctorIgnoreKind, "kind", "", "the section the name is in, when it is in more than one (config-deleted, or the JSON kind)")
	doctorIgnoreCmd.Flags().StringVar(&doctorIgnoreFormat, "format", "text", `output format: "text" (default) or "json"`)
	_ = doctorIgnoreCmd.RegisterFlagCompletionFunc("format", completeOutputFormat)
	doctorUnignoreCmd.Flags().StringVar(&doctorUnignoreKind, "kind", "", "only the ignores of this kind (config-deleted, or the JSON kind)")
	doctorUnignoreCmd.Flags().StringVar(&doctorUnignoreFormat, "format", "text", `output format: "text" (default) or "json"`)
	doctorUnignoreCmd.Flags().BoolVar(&doctorUnignoreAll, "all", false, "remove every ignore")
	_ = doctorUnignoreCmd.RegisterFlagCompletionFunc("format", completeOutputFormat)
	doctorCmd.AddCommand(doctorIgnoreCmd, doctorUnignoreCmd)
}
