// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

// migrateReport is `jit migrate <path> --format json`'s one document: what
// the run changed and what it could not, in the terms a caller's own
// surface needs — the JitPass app's banner after a Protect reads "Protected
// ~/notion/.env · NOTION_TOKEN is in the vault · 8 cached copies removed ·
// 1 file left in Claude Code's transcripts" from exactly these fields,
// instead of parsing prose. Paths and variable names, never a value: the
// same contract as scan's ndjson (Finding.rawValue is never serialized,
// and neither is anything Vault.OnSet saw).
//
// The human text is not lost: `report` carries what the run would have
// printed, so a caller can show jit's own words on request without a
// second run (design/scan-and-protect.md, promise 3: Protect names
// everything it changes, and what it could not).
type migrateReport struct {
	// Targets are the paths named on the command line, resolved to
	// absolute paths, in the order given.
	Targets []string `json:"targets"`
	// Applied is whether the plan ran. False when there was nothing to
	// migrate in the targets (a plain file), or the run stopped before
	// touching anything.
	Applied bool `json:"applied"`
	// Vaulted are the variable names this run stored — "NOTION_TOKEN",
	// "github.com/oauth_token" — the last segment of each vault path,
	// once each. Names only.
	Vaulted []string `json:"vaulted"`
	// Caches is the agent-cache sweep's result: the files it rewrote and
	// the files it deliberately left alone, each with why.
	Caches migrateCacheReport `json:"caches"`
	// Errors is every error the run reported, in order; the rest of the
	// document is the partial result, which is real and undoable.
	Errors []string `json:"errors"`
	// Report is the text output the run would have printed.
	Report string `json:"report"`
}

type migrateCacheReport struct {
	Removed []cacheFileReport `json:"removed"`
	Left    []cacheFileReport `json:"left"`
}

// cacheFileReport is one cache file the sweep rewrote (Copies is the
// credential spans removed from it) or left in place (Kind is the
// migrate.SkipKind — live, binary, hardlink — and Reason the sentence
// the text output prints).
type cacheFileReport struct {
	Agent  string `json:"agent"`
	Area   string `json:"area"`
	Path   string `json:"path"`
	Copies int    `json:"copies,omitempty"`
	Kind   string `json:"kind,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// newMigrateReport starts a report whose slices are empty, not nil, so
// the JSON always carries `[]` rather than `null` for a consumer that
// indexes without checking.
func newMigrateReport() *migrateReport {
	return &migrateReport{
		Targets: []string{},
		Vaulted: []string{},
		Caches:  migrateCacheReport{Removed: []cacheFileReport{}, Left: []cacheFileReport{}},
		Errors:  []string{},
	}
}

// fill records the outcome applyMigrate handed off: the names it vaulted
// (from the same OnSet capture the cache sweep hunts with; only the Var
// half is kept) and the sweep's edits and skips.
func (r *migrateReport) fill(in cleanPhaseInputs) {
	seen := map[string]bool{}
	for _, s := range in.vaulted {
		if s.Var == "" || seen[s.Var] {
			continue
		}
		seen[s.Var] = true
		r.Vaulted = append(r.Vaulted, s.Var)
	}
	for _, e := range in.cleanup.Edited {
		r.Caches.Removed = append(r.Caches.Removed, cacheFileReport{
			Agent: e.Agent, Area: e.Area, Path: e.Path, Copies: e.Occurrences,
		})
	}
	for _, s := range in.cleanup.Skipped {
		r.Caches.Left = append(r.Caches.Left, cacheFileReport{
			Agent: s.Agent, Area: s.Area, Path: s.Path, Kind: string(s.Kind), Reason: s.Reason,
		})
	}
	if in.cleanErr != nil {
		r.Errors = append(r.Errors, "clearing AI agent caches: "+in.cleanErr.Error())
	}
}

// removedCopies totals the spans the sweep removed, for a one-line
// summary.
func (r *migrateReport) removedCopies() int {
	n := 0
	for _, e := range r.Caches.Removed {
		n += e.Copies
	}
	return n
}

// validateMigrateJSONFlags refuses the flags a JSON run cannot honour: the
// confirmation prompt and the --clean pass each need a person at the
// terminal, and a dry run has nothing to report as done.
func validateMigrateJSONFlags() error {
	switch {
	case !migrateYes:
		return errors.New("jit migrate: --format json needs --yes; a plan cannot be confirmed on a JSON stream")
	case migrateDryRun:
		return errors.New("jit migrate: --format json is for a real run; drop --dry-run")
	case migrateClean:
		return errors.New("jit migrate: --format json does not take --clean; its delete pass needs a person at the prompt")
	}
	return nil
}

// runMigratePathJSON runs the targeted migrate with its text output
// captured, and writes the one JSON document to the real stdout — after
// an error too, since the edits made before it are real and undoable and
// hiding them would strand the caller. The error still returns, so the
// exit status says the run did not finish.
func runMigratePathJSON(cmd *cobra.Command, targets []string) error {
	if err := validateMigrateJSONFlags(); err != nil {
		return err
	}
	stdout := cmd.OutOrStdout()
	var text bytes.Buffer
	cmd.SetOut(&text)
	defer cmd.SetOut(nil)

	report := newMigrateReport()
	runErr := migratePath(cmd, targets, report)
	if runErr != nil {
		report.Errors = append(report.Errors, runErr.Error())
	}
	report.Report = text.String()
	if err := writeJSON(stdout, report); err != nil {
		return fmt.Errorf("jit migrate: writing report: %w", err)
	}
	if runErr != nil {
		// The document above is the diagnosis; cobra would print the error
		// a second time on stderr, which is fine for a terminal and noise
		// for a program. Silence only the repeat.
		cmd.SilenceErrors = true
		defer func() { cmd.SilenceErrors = false }()
	}
	return runErr
}
