// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/audit"
)

// `jit review` and `jit unreview` keep the marks `jit scan` reads. They are
// their own commands, not `jit scan` subcommands, because `jit scan` never
// writes anything in any mode, and these write one file: jit's own list of
// marks. Neither ever touches a scanned file.

var (
	reviewList   bool
	reviewFormat string
	reviewOnly   []string
	unreviewIDs  []string
)

// reviewStorePath is where the marks live: beside the vault, in jit's own
// folder, never in anything a scan reads.
func reviewStorePath() (string, error) {
	root, err := vaultRootDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "scan-reviewed.json"), nil
}

// saveReviewStore writes the marks owner-only, through a temporary file
// so a crash never leaves half a list. This is the only write review does.
func saveReviewStore(store *audit.ReviewStore) error {
	data, err := store.Encode()
	if err != nil {
		return err
	}
	path := store.Path()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// loadScanReviews is the marks every scan applies (newAuditConfig). A
// store that cannot be read is said once on stderr and applies no marks:
// the scan then shows more, never less.
func loadScanReviews(stderr io.Writer) *audit.ReviewStore {
	path, err := reviewStorePath()
	if err != nil {
		return nil
	}
	store, err := audit.LoadReviewStore(path)
	if err != nil {
		fmt.Fprintf(stderr, "jit: review marks not applied: %v\n", err)
		return nil
	}
	return store
}

// reviewTarget is one FILE[:LINE] argument.
type reviewTarget struct {
	path string
	line *int
}

func splitReviewArg(arg string) (string, *int) {
	if i := strings.LastIndex(arg, ":"); i > 0 {
		if n, err := strconv.Atoi(arg[i+1:]); err == nil && n > 0 {
			return arg[:i], &n
		}
	}
	return arg, nil
}

func parseReviewTargets(args []string) ([]reviewTarget, error) {
	out := make([]reviewTarget, 0, len(args))
	for _, arg := range args {
		file, line := splitReviewArg(arg)
		abs, err := resolveScanTargets([]string{file})
		if err != nil {
			return nil, err
		}
		out = append(out, reviewTarget{path: abs[0], line: line})
	}
	return out, nil
}

// pathSpellings is every way a scan may have named the file: as given, made
// absolute, and fully resolved. `review` stores the scan's spelling, and a
// folder symlink (/tmp on macOS) makes the others differ from it.
func pathSpellings(file string) ([]string, error) {
	abs, err := filepath.Abs(file)
	if err != nil {
		return nil, err
	}
	out := []string{abs}
	if resolved, err := resolveScanTargets([]string{file}); err == nil && !slices.Contains(out, resolved[0]) {
		out = append(out, resolved[0])
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil && !slices.Contains(out, resolved) {
		out = append(out, resolved)
	}
	return out, nil
}

// onLine is whether f sits on line, or anywhere in the file when no line
// was given. A finding spanning lines (a PEM block) is on each of them.
func onLine(f audit.Finding, line *int) bool {
	if line == nil {
		return true
	}
	if f.Line == nil {
		return false
	}
	end := *f.Line
	if f.EndLine != nil {
		end = *f.EndLine
	}
	return *line >= *f.Line && *line <= end
}

// reviewLabel is what the finding is, in its evidence's first clause:
// "value matches AWS Access Key ID's known token format".
func reviewLabel(f audit.Finding) string {
	label := strings.SplitN(f.Evidence, " (", 2)[0]
	if label == "" {
		label = f.FindingType
	}
	return label
}

type reviewEntry struct {
	ID         string `json:"id"`
	Path       string `json:"path"`
	Line       *int   `json:"line,omitempty"`
	Type       string `json:"finding_type"`
	Label      string `json:"label"`
	ReviewedAt int64  `json:"reviewed_at"`
}

func reviewEntries(marks []audit.ReviewMark) []reviewEntry {
	out := make([]reviewEntry, 0, len(marks))
	for _, m := range marks {
		out = append(out, reviewEntry{ID: m.ID, Path: m.Path, Line: m.Line, Type: m.Type, Label: m.Label, ReviewedAt: m.ReviewedAt})
	}
	return out
}

type reviewResult struct {
	Reviewed   []reviewEntry `json:"reviewed,omitempty"`
	Unreviewed []reviewEntry `json:"unreviewed,omitempty"`
	// Skipped counts findings on a named line that a mark does not fit:
	// ones Protect or Redact fixes.
	Skipped int `json:"skipped,omitempty"`
	// Missed is each FILE[:LINE] the scan found nothing on any more, spelled
	// as review was given it (like Reviewed's paths): the line moved or the
	// value changed since the scan that listed it.
	Missed []string `json:"missed,omitempty"`
}

func writeReviewResult(w io.Writer, format, verb string, entries []reviewEntry, skipped int, missed ...string) error {
	if format == "json" {
		result := reviewResult{Skipped: skipped, Missed: missed}
		if verb == "unreviewed" {
			result.Unreviewed = entries
		} else {
			result.Reviewed = entries
		}
		// Always a list, never absent, so a reader can tell "none" from an
		// older jit.
		if result.Reviewed == nil && verb != "unreviewed" {
			result.Reviewed = []reviewEntry{}
		}
		if result.Unreviewed == nil && verb == "unreviewed" {
			result.Unreviewed = []reviewEntry{}
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}
	if len(entries) == 0 {
		if _, err := fmt.Fprintln(w, "Nothing "+verb+"."); err != nil {
			return err
		}
	}
	for _, e := range entries {
		where := shortPath(e.Path)
		if e.Line != nil {
			where += ":" + strconv.Itoa(*e.Line)
		}
		if _, err := fmt.Fprintf(w, "%s %s  %s\n", glyphDone, where, e.Label); err != nil {
			return err
		}
	}
	for _, m := range missed {
		if _, err := fmt.Fprintf(w, "Nothing to mark on %s any more: scan again.\n", shortTarget(m)); err != nil {
			return err
		}
	}
	if skipped > 0 {
		_, err := fmt.Fprintf(w, "%d more on those lines can't be marked: protect, redact or rotate them.\n", skipped)
		return err
	}
	return nil
}

// shortTarget is a FILE[:LINE] target for a person: the home folder as ~.
func shortTarget(target string) string {
	file, line := splitReviewArg(target)
	if line == nil {
		return shortPath(file)
	}
	return shortPath(file) + ":" + strconv.Itoa(*line)
}

func validateReviewFormat(format string) error {
	if format == "" || format == "text" || format == "json" {
		return nil
	}
	return fmt.Errorf("unknown --format %q (want \"text\" or \"json\")", format)
}

func openReviewStore() (*audit.ReviewStore, error) {
	path, err := reviewStorePath()
	if err != nil {
		return nil, err
	}
	return audit.LoadReviewStore(path)
}

var reviewCmd = &cobra.Command{
	GroupID: groupWorkflow,
	Use:     "review FILE[:LINE]...",
	Short:   "Mark scan findings you checked as not live, so scan stops reporting them",
	Long: "Mark scan findings you checked as not live: a real-looking key in a test file or a README. " +
		"The file is scanned again to find them, and the findings on LINE (or in the whole FILE) are marked; " +
		"--only narrows that to the findings with these record ids.\n\n" +
		"A mark matches what the finding is about, not its line: moving the line keeps the mark, and a changed " +
		"value is reported again. For a finding about a whole file, such as an env file's, that is every " +
		"credential it holds, or the file's content, so any change reports it again. A mark stores a keyed hash, " +
		"never a value, in jit's own folder (scan-reviewed.json). That file is the only thing this writes; " +
		"scanned files are never touched, and `jit scan` itself still writes nothing.\n\n" +
		"Findings jit can fix (Protect), and copies of secrets jit already holds (deep scan's vault copies, " +
		"AI agent caches), are not marked: protect, redact or rotate them. `jit scan --unfiltered` shows " +
		"marked findings again, tagged; `jit unreview` removes a mark.",
	Example: "  jit review ./tests/fixtures.json:12\n" +
		"  jit review docs/README.md\n" +
		"  jit review --list",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateReviewFormat(reviewFormat); err != nil {
			return fmt.Errorf("jit review: %w", err)
		}
		store, err := openReviewStore()
		if err != nil {
			return fmt.Errorf("jit review: %w", err)
		}
		if reviewList {
			return writeReviewResult(cmd.OutOrStdout(), reviewFormat, "reviewed", reviewEntries(store.Marks), 0)
		}
		if len(args) == 0 {
			return errors.New("jit review: name a FILE[:LINE], or --list")
		}
		targets, err := parseReviewTargets(args)
		if err != nil {
			return fmt.Errorf("jit review: %w", err)
		}
		cfg, err := newAuditConfig()
		if err != nil {
			return fmt.Errorf("jit review: %w", err)
		}
		// The findings to mark include ones already marked.
		cfg.Reviewed = nil
		now := time.Now()
		var marked []audit.ReviewMark
		var missed []string
		skipped := 0
		for _, t := range targets {
			findings, _, err := audit.TargetedScan(cfg, []string{t.path})
			if err != nil {
				return fmt.Errorf("jit review: %w", err)
			}
			matched := 0
			for _, f := range findings {
				if f.FilePath != t.path || !onLine(f, t.line) {
					continue
				}
				if len(reviewOnly) > 0 && !slices.Contains(reviewOnly, f.RecordID) {
					continue
				}
				matched++
				m, err := store.Mark(f, reviewLabel(f), now)
				if errors.Is(err, audit.ErrNotReviewable) {
					skipped++
					continue
				}
				if err != nil {
					return fmt.Errorf("jit review: %w", err)
				}
				if !slices.ContainsFunc(marked, func(x audit.ReviewMark) bool { return x.ID == m.ID }) {
					marked = append(marked, m)
				}
			}
			// One target that moved since the scan must not cost the rest
			// their marks: it is named in the result instead.
			if matched == 0 {
				where := t.path
				if t.line != nil {
					where += ":" + strconv.Itoa(*t.line)
				}
				missed = append(missed, where)
			}
		}
		if len(marked) == 0 {
			shown := make([]string, 0, len(missed))
			for _, m := range missed {
				shown = append(shown, shortTarget(m))
			}
			if skipped == 0 {
				return fmt.Errorf("jit review: scan finds nothing to mark on %s", strings.Join(shown, ", "))
			}
			msg := fmt.Sprintf("jit review: nothing there can be marked: protect, redact or rotate it (%d found)", skipped)
			if len(shown) > 0 {
				msg += "; nothing to mark on " + strings.Join(shown, ", ")
			}
			return errors.New(msg)
		}
		if err := saveReviewStore(store); err != nil {
			return fmt.Errorf("jit review: %w", err)
		}
		return writeReviewResult(cmd.OutOrStdout(), reviewFormat, "reviewed", reviewEntries(marked), skipped, missed...)
	},
}

var unreviewCmd = &cobra.Command{
	GroupID: groupWorkflow,
	Use:     "unreview [FILE[:LINE]...]",
	Short:   "Remove review marks, so scan reports those findings again",
	Long: "Remove review marks: the ones --id names (as `jit review --format json` and `--list` print them), " +
		"or every mark on FILE (on LINE, the line the finding was on when it was marked). " +
		"The next scan reports those findings again.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateReviewFormat(reviewFormat); err != nil {
			return fmt.Errorf("jit unreview: %w", err)
		}
		if len(args) == 0 && len(unreviewIDs) == 0 {
			return errors.New("jit unreview: name a FILE[:LINE], or --id")
		}
		store, err := openReviewStore()
		if err != nil {
			return fmt.Errorf("jit unreview: %w", err)
		}
		gone := store.UnmarkIDs(unreviewIDs)
		for _, arg := range args {
			file, line := splitReviewArg(arg)
			// The file may be gone by now: a mark on it is still removable.
			paths, err := pathSpellings(file)
			if err != nil {
				return fmt.Errorf("jit unreview: %w", err)
			}
			gone = append(gone, store.Unmark(paths, line)...)
		}
		if len(gone) > 0 {
			if err := saveReviewStore(store); err != nil {
				return fmt.Errorf("jit unreview: %w", err)
			}
		}
		return writeReviewResult(cmd.OutOrStdout(), reviewFormat, "unreviewed", reviewEntries(gone), 0)
	},
}

func init() {
	reviewCmd.Flags().BoolVar(&reviewList, "list", false, "list every mark: its id, file, line and what was found, never a value")
	reviewCmd.Flags().StringSliceVar(&reviewOnly, "only", nil, "mark only the findings with this record id (repeatable), as `jit scan --format ndjson` prints them")
	unreviewCmd.Flags().StringSliceVar(&unreviewIDs, "id", nil, "remove the mark with this id (repeatable)")
	for _, c := range []*cobra.Command{reviewCmd, unreviewCmd} {
		c.Flags().StringVar(&reviewFormat, "format", "text", `output format: "text" or "json"`)
		rootCmd.AddCommand(c)
	}
}
