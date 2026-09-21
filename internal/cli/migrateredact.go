// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/migrate"
)

// migrateRedactCmd is `jit migrate redact`: replace the tokens jit scan found
// by their FORMAT in AI agent caches with a marker. The Protect verb for the
// scan's shape sweep (design/scan-and-protect.md: the "clean" verb of the
// exposed_secret-in-a-cache row), where `jit migrate caches` is the verb for
// copies of VAULTED values.
//
// No vault, no backup, no Touch ID (decided 2026-09-21): a backup would put
// an agent's whole transcript, token and all, in a vault the user never
// chose for it, and needing the vault is what would stop this from running
// unattended after a scheduled scan. The marker <jit:redacted:VENDOR> is the
// record of what was there. The change is one-way, and the plan says so.
var (
	migrateRedactFormat string
	migrateRedactLines  []int
)

var migrateRedactCmd = &cobra.Command{
	Use:   "redact [file...]",
	Short: "Replace tokens AI agents cached — found by their format — with a marker",
	Long: "jit migrate redact searches every AI coding agent's local cache — Claude\n" +
		"Code's transcripts, file-history and paste-cache, and the equivalents for\n" +
		"Cursor, Codex, Gemini and others — for credentials it recognises by their\n" +
		"format (the same vendor formats jit scan reports), and replaces each one in\n" +
		"place with a <jit:redacted:VENDOR> marker, the rest of the line untouched.\n\n" +
		"It is the fix for a token an agent cached that was never in your vault: a\n" +
		"key pasted into a prompt, a snapshot of a file you have since rotated.\n" +
		"`jit migrate caches` is the other half, for copies of vaulted secrets.\n\n" +
		"Only agent caches are rewritten, never a file of your own. There is no\n" +
		"backup and no Touch ID: the change is one-way, the marker says what was\n" +
		"there. A file an agent is writing at that moment is left alone and\n" +
		"reported; a binary store is reported, never rewritten. Name files to\n" +
		"limit the sweep to them; --line limits it to tokens on those lines.",
	Example: "  jit migrate redact                        # every agent cache\n" +
		"  jit migrate redact --dry-run              # show what would change, change nothing\n" +
		"  jit migrate redact ~/.claude/projects/x/s.jsonl --line 1046",
	Args: cobra.ArbitraryArgs,
	RunE: runMigrateRedact,
}

func init() {
	migrateRedactCmd.Flags().IntSliceVar(&migrateRedactLines, "line", nil, "only tokens on these 1-based lines of the named files (repeatable)")
	migrateRedactCmd.Flags().StringVar(&migrateRedactFormat, "format", "text", `output format: "text" (default), or "json": one document naming what was redacted and what was left; needs --yes`)
	_ = migrateRedactCmd.RegisterFlagCompletionFunc("format", completeOutputFormat)
	migrateCmd.AddCommand(migrateRedactCmd)
}

// redactReport is the --format json document: what was redacted, what was
// left and why, the errors, and the text the run would have printed. Paths
// and vendor names, never a value.
type redactReport struct {
	Files   []string           `json:"files"`
	Applied bool               `json:"applied"`
	Caches  migrateCacheReport `json:"caches"`
	Errors  []string           `json:"errors"`
	Report  string             `json:"report"`
}

func runMigrateRedact(cmd *cobra.Command, args []string) error {
	if err := validateOutputFormat(migrateRedactFormat); err != nil {
		return fmt.Errorf("jit migrate redact: %w", err)
	}
	if migrateRedactFormat != "json" {
		return migrateRedact(cmd, args, nil)
	}
	if !migrateYes {
		return errors.New("jit migrate redact: --format json needs --yes; a plan cannot be confirmed on a JSON stream")
	}
	if migrateDryRun {
		return errors.New("jit migrate redact: --format json is for a real run; drop --dry-run")
	}
	stdout := cmd.OutOrStdout()
	var text bytes.Buffer
	cmd.SetOut(&text)
	defer cmd.SetOut(nil)
	report := &redactReport{Files: []string{}, Caches: migrateCacheReport{Removed: []cacheFileReport{}, Left: []cacheFileReport{}}, Errors: []string{}}
	runErr := migrateRedact(cmd, args, report)
	if runErr != nil {
		report.Errors = append(report.Errors, runErr.Error())
	}
	report.Report = text.String()
	if err := writeJSON(stdout, report); err != nil {
		return fmt.Errorf("jit migrate redact: writing report: %w", err)
	}
	if runErr != nil {
		cmd.SilenceErrors = true
		defer func() { cmd.SilenceErrors = false }()
	}
	return runErr
}

func migrateRedact(cmd *cobra.Command, args []string, report *redactReport) error {
	out := cmd.OutOrStdout()
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("jit migrate redact: %w", err)
	}
	cwd, _ := os.Getwd()
	var files []string
	for _, a := range args {
		p := expandTilde(a, home)
		if !filepath.IsAbs(p) {
			p = filepath.Join(cwd, p)
		}
		p = filepath.Clean(p)
		if _, statErr := os.Lstat(p); statErr != nil {
			return fmt.Errorf("jit migrate redact: %s: %w", displayPath(home, p), statErr)
		}
		files = append(files, p)
	}
	if len(migrateRedactLines) > 0 && len(files) == 0 {
		return errors.New("jit migrate redact: --line needs the file it refers to")
	}
	if report != nil {
		report.Files = append(report.Files, files...)
	}

	plan, err := migrate.RedactAgentCacheShapes(home, files, migrateRedactLines, false)
	if err != nil {
		return fmt.Errorf("jit migrate redact: scanning agent caches: %w", err)
	}
	if len(plan.Edited) == 0 && len(plan.Skipped) == 0 {
		fmt.Fprintln(out, "No AI agent cache holds a token jit recognises by its format. Nothing to do.")
		return nil
	}
	if migrateDryRun {
		printDryRunBanner(out)
	}
	renderRedactPlan(out, home, plan)
	if migrateDryRun {
		printDryRunTrailer(out, migrateApplyCommand("jit migrate redact", args), false)
		return nil
	}
	if !migrateYes && !confirmPrompt(cmd, "Redact these tokens? This cannot be undone. [y/N] ") {
		fmt.Fprintln(out, "Aborted. Nothing was changed.")
		return nil
	}

	done, runErr := migrate.RedactAgentCacheShapes(home, files, migrateRedactLines, true)
	renderRedactResult(out, home, done)
	if report != nil {
		report.Applied = len(done.Edited) > 0
		for _, e := range done.Edited {
			report.Caches.Removed = append(report.Caches.Removed, cacheFileReport{Agent: e.Agent, Area: e.Area, Path: e.Path, Copies: e.Occurrences})
		}
		for _, s := range done.Skipped {
			report.Caches.Left = append(report.Caches.Left, cacheFileReport{Agent: s.Agent, Area: s.Area, Path: s.Path, Kind: string(s.Kind), Reason: s.Reason})
		}
	}
	if runErr != nil {
		fmt.Fprintf(out, "jit: stopped early: %v\n", runErr)
		return fmt.Errorf("jit migrate redact: %w", runErr)
	}
	return nil
}

// renderRedactPlan prints what the run WOULD do: tokens and files, grouped
// by agent and area, then what it would leave alone.
func renderRedactPlan(w io.Writer, home string, c migrate.AgentCacheCleanup) {
	if len(c.Edited) > 0 {
		_, _ = cBold.Fprintf(w, "AI agent caches\n")
		fmt.Fprintf(w, "  %s jit recognises by format sit in %s it will redact:\n",
			countWord(c.Occurrences(), "token", "tokens"), countWord(len(c.Edited), "file", "files"))
		renderRedactByAgent(w, c.Edited)
		fmt.Fprintln(w, "  each becomes a <jit:redacted:VENDOR> marker; the rest of the line stays.")
		fmt.Fprintln(w, "  No backup is taken: this cannot be undone. The marker says what was there.")
	}
	renderRedactSkips(w, home, c)
}

// renderRedactResult prints what the run DID.
func renderRedactResult(w io.Writer, home string, c migrate.AgentCacheCleanup) {
	if len(c.Edited) > 0 {
		_, _ = cOK.Fprintf(w, "%s ", glyphDone)
		_, _ = cBold.Fprintf(w, "Redacted %s in %s\n", countWord(c.Occurrences(), "token", "tokens"), countWord(len(c.Edited), "file", "files"))
		renderRedactByAgent(w, c.Edited)
	}
	renderRedactSkips(w, home, c)
}

func renderRedactByAgent(w io.Writer, edits []migrate.AgentCacheEdit) {
	byAgent := map[string]map[string]int{}
	for _, e := range edits {
		if byAgent[e.Agent] == nil {
			byAgent[e.Agent] = map[string]int{}
		}
		byAgent[e.Agent][e.Area] += e.Occurrences
	}
	agents := make([]string, 0, len(byAgent))
	for a := range byAgent {
		agents = append(agents, a)
	}
	sort.Strings(agents)
	for _, agent := range agents {
		areas := make([]string, 0, len(byAgent[agent]))
		for a := range byAgent[agent] {
			areas = append(areas, a)
		}
		sort.Strings(areas)
		parts := make([]string, 0, len(areas))
		for _, a := range areas {
			label := a
			if label == "" {
				label = "its cache"
			}
			parts = append(parts, fmt.Sprintf("%d in %s", byAgent[agent][a], label))
		}
		fmt.Fprintf(w, "    %-14s %s\n", agent, joinList(parts))
	}
}

func renderRedactSkips(w io.Writer, home string, c migrate.AgentCacheCleanup) {
	if len(c.Skipped) == 0 {
		return
	}
	_, _ = cWarn.Fprintf(w, "%s ", glyphWarn)
	_, _ = cBold.Fprintf(w, "%s left in place\n", countWord(len(c.Skipped), "file", "files"))
	for _, s := range c.Skipped {
		fmt.Fprintf(w, "    %s: %s\n", displayPath(home, s.Path), s.Reason)
	}
}
