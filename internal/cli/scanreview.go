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
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/audit"
)

var (
	scanReviewList   bool
	scanReviewFormat string
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
// so a crash never leaves half a list. This file is all review writes.
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

// loadScanReviews is the marks a scan applies. A store that cannot be read
// is said once on stderr and applies no marks: the scan then shows more,
// never less.
func loadScanReviews(cmd *cobra.Command) *audit.ReviewStore {
	path, err := reviewStorePath()
	if err != nil {
		return nil
	}
	store, err := audit.LoadReviewStore(path)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "jit scan: review marks not applied: %v\n", err)
		return nil
	}
	return store
}

// reviewTarget is one FILE[:LINE] argument.
type reviewTarget struct {
	path string
	line *int
}

func parseReviewTargets(args []string) ([]reviewTarget, error) {
	out := make([]reviewTarget, 0, len(args))
	for _, arg := range args {
		file, line := arg, (*int)(nil)
		if i := strings.LastIndex(arg, ":"); i > 0 {
			if n, err := strconv.Atoi(arg[i+1:]); err == nil && n > 0 {
				file, line = arg[:i], &n
			}
		}
		abs, err := resolveScanTargets([]string{file})
		if err != nil {
			return nil, err
		}
		out = append(out, reviewTarget{path: abs[0], line: line})
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
	Path       string `json:"path"`
	Line       *int   `json:"line,omitempty"`
	Type       string `json:"finding_type"`
	Label      string `json:"label"`
	ReviewedAt int64  `json:"reviewed_at"`
}

func reviewEntries(marks []audit.ReviewMark) []reviewEntry {
	out := make([]reviewEntry, 0, len(marks))
	for _, m := range marks {
		out = append(out, reviewEntry{Path: m.Path, Line: m.Line, Type: m.Type, Label: m.Label, ReviewedAt: m.ReviewedAt})
	}
	return out
}

func writeReviewResult(w io.Writer, format string, verb string, entries []reviewEntry) error {
	if format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string][]reviewEntry{verb: entries})
	}
	if len(entries) == 0 {
		_, err := fmt.Fprintln(w, "Nothing "+verb+".")
		return err
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
	return nil
}

func validateReviewFormat(format string) error {
	if format == "" || format == "text" || format == "json" {
		return nil
	}
	return fmt.Errorf("unknown --format %q (want \"text\" or \"json\")", format)
}

var scanReviewCmd = &cobra.Command{
	Use:   "review FILE[:LINE]...",
	Short: "Mark findings you checked as not live, so scan stops reporting them",
	Long: "Mark findings you checked as not live: a real-looking key in a test file or a README. " +
		"The file is scanned again to find them, and every finding on LINE (or in the whole FILE) is marked.\n\n" +
		"A mark matches the value in that file, not the line: moving the line keeps the mark, and a changed " +
		"value is reported again. It stores a keyed hash of the value, never the value, in jit's own folder " +
		"(scan-reviewed.json). That file is the only thing this writes; scanned files are never touched.\n\n" +
		"Copies of secrets jit already holds (deep scan's vault copies, AI agent caches) cannot be marked: " +
		"redact or rotate them. `jit scan --unfiltered` shows marked findings again, tagged; " +
		"`jit scan unreview` removes a mark.",
	Example: "  jit scan review ./tests/fixtures.json:12\n" +
		"  jit scan review docs/README.md\n" +
		"  jit scan review --list",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateReviewFormat(scanReviewFormat); err != nil {
			return fmt.Errorf("jit scan review: %w", err)
		}
		path, err := reviewStorePath()
		if err != nil {
			return fmt.Errorf("jit scan review: %w", err)
		}
		store, err := audit.LoadReviewStore(path)
		if err != nil {
			return fmt.Errorf("jit scan review: %w", err)
		}
		if scanReviewList {
			return writeReviewResult(cmd.OutOrStdout(), scanReviewFormat, "reviewed", reviewEntries(store.Marks))
		}
		if len(args) == 0 {
			return errors.New("jit scan review: name a FILE[:LINE], or --list")
		}
		targets, err := parseReviewTargets(args)
		if err != nil {
			return fmt.Errorf("jit scan review: %w", err)
		}
		cfg, err := newAuditConfig()
		if err != nil {
			return fmt.Errorf("jit scan review: %w", err)
		}
		now := time.Now()
		var added []audit.ReviewMark
		for _, t := range targets {
			findings, _, err := audit.TargetedScan(cfg, []string{t.path})
			if err != nil {
				return fmt.Errorf("jit scan review: %w", err)
			}
			matched := 0
			for _, f := range findings {
				if f.FilePath != t.path || !onLine(f, t.line) {
					continue
				}
				matched++
				isNew, err := store.Mark(f, reviewLabel(f), now)
				if err != nil {
					return fmt.Errorf("jit scan review: %w", err)
				}
				if isNew {
					added = append(added, store.Marks[len(store.Marks)-1])
				}
			}
			if matched == 0 {
				where := shortPath(t.path)
				if t.line != nil {
					where = fmt.Sprintf("line %d of %s", *t.line, where)
				}
				return fmt.Errorf("jit scan review: scan finds nothing on %s", where)
			}
		}
		if err := saveReviewStore(store); err != nil {
			return fmt.Errorf("jit scan review: %w", err)
		}
		return writeReviewResult(cmd.OutOrStdout(), scanReviewFormat, "reviewed", reviewEntries(added))
	},
}

var scanUnreviewCmd = &cobra.Command{
	Use:   "unreview FILE[:LINE]...",
	Short: "Remove review marks, so scan reports those findings again",
	Long: "Remove the review marks on FILE (on LINE, the line the finding was on when it was marked). " +
		"The next scan reports those findings again.",
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateReviewFormat(scanReviewFormat); err != nil {
			return fmt.Errorf("jit scan unreview: %w", err)
		}
		path, err := reviewStorePath()
		if err != nil {
			return fmt.Errorf("jit scan unreview: %w", err)
		}
		store, err := audit.LoadReviewStore(path)
		if err != nil {
			return fmt.Errorf("jit scan unreview: %w", err)
		}
		var gone []audit.ReviewMark
		for _, arg := range args {
			file, line := arg, (*int)(nil)
			if i := strings.LastIndex(arg, ":"); i > 0 {
				if n, convErr := strconv.Atoi(arg[i+1:]); convErr == nil && n > 0 {
					file, line = arg[:i], &n
				}
			}
			// The file may be gone by now: a mark on it is still removable.
			abs, absErr := filepath.Abs(file)
			if absErr != nil {
				return fmt.Errorf("jit scan unreview: %w", absErr)
			}
			if resolved, evalErr := filepath.EvalSymlinks(abs); evalErr == nil {
				abs = resolved
			}
			gone = append(gone, store.Unmark(abs, line)...)
		}
		if len(gone) > 0 {
			if err := saveReviewStore(store); err != nil {
				return fmt.Errorf("jit scan unreview: %w", err)
			}
		}
		return writeReviewResult(cmd.OutOrStdout(), scanReviewFormat, "unreviewed", reviewEntries(gone))
	},
}

func init() {
	scanReviewCmd.Flags().BoolVar(&scanReviewList, "list", false, "list every mark: file, line and what was found, never a value")
	for _, c := range []*cobra.Command{scanReviewCmd, scanUnreviewCmd} {
		c.Flags().StringVar(&scanReviewFormat, "format", "text", `output format: "text" or "json"`)
		scanCmd.AddCommand(c)
	}
}
