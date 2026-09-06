// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/audit"
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/termtext"
)

// jit migrate --clean (design/migrate-clean.md): the CLI half of the delete
// pass. The plan category renders inside the one migrate plan (planExtras);
// this file owns the second consent, the fresh Touch ID gate, the apply
// call, and the mutation-log rendering. The mechanism (verify, backup,
// unlink) lives in internal/migrate/clean.go.

// migrateClean is the --clean flag: after the migrations, delete the files
// whose stated fix is deletion. Local to migrate/path like --mount —
// undo/remove/caches never delete scan findings, so inheriting it would
// advertise a no-op flag there.
var migrateClean bool

// cleanHasWork reports whether the --clean plan has anything to show — a
// candidate to delete, or a plan-time refusal the user must still see.
func cleanHasWork(p *migrate.CleanPlan) bool {
	return p != nil && (len(p.Candidates) > 0 || len(p.LeftAlone) > 0)
}

// dropCleanCandidates removes every planned deletion from the discovery's
// migration lists: under --clean a delete-class file routes to the delete
// pass INSTEAD of migration — vaulting a file the user already condemned
// would preserve what deletion is about to fix (the scan report's own
// stance on Trash findings). Only Candidates are dropped; a plan-time
// refusal leaves the file to whatever migration claims it, exactly as a
// run without --clean would.
func dropCleanCandidates(d *discovered, plan *migrate.CleanPlan) {
	if plan == nil || len(plan.Candidates) == 0 {
		return
	}
	claimed := make(map[string]bool, len(plan.Candidates))
	for _, c := range plan.Candidates {
		claimed[c.Path] = true
	}
	for _, list := range []*[]string{
		&d.envFiles, &d.tfvarsFiles, &d.k8sManifests, &d.shellConfigs,
		&d.historyFiles, &d.mcpConfigs, &d.gcpADCFiles, &d.sopsAgeFiles,
		&d.npmrcFiles, &d.netrcFiles, &d.pypircFiles, &d.streamlitFiles,
		&d.looseSecretFiles,
	} {
		kept := (*list)[:0]
		for _, p := range *list {
			if !claimed[p] {
				kept = append(kept, p)
			}
		}
		*list = kept
	}
}

// cleanClassDetail is the └ evidence line under one planned deletion: why
// THIS file is safe to automate, per class. The archived/agent lines state
// the vault check as a condition because at plan time it is one — the
// verification itself runs after consent and Touch ID (ApplyClean).
func cleanClassDetail(class audit.CleanClass) string {
	switch class {
	case audit.CleanTrash:
		return "in the Trash — finishing the deletion you started"
	case audit.CleanAgentLeftover:
		return "an AI agent cache leftover — deleted only after its secret is verified already in the vault"
	default:
		return "archived copy — deleted only after every secret in it is verified already in the vault"
	}
}

// printCleanPlanCategory renders the [deletions] plan category — rule-1
// header, the → outcome line, one bullet per file with its └ evidence line
// (the wrap-category shape: each class differs materially, so the reason
// rides the row it justifies). Plan-time refusals render right after
// through the same grouped-skip helper the results use, so a finding the
// scan showed never silently vanishes between scan and plan.
func printCleanPlanCategory(w io.Writer, home string, plan *migrate.CleanPlan) {
	if len(plan.Candidates) > 0 {
		fmt.Fprintf(w, "[deletions] %d\n", len(plan.Candidates))
		fmt.Fprint(w, "  "+glyphAction+" ")
		wrapBody(w, 4, "    ", hlCmds("files whose stated fix is deletion; each is backed up encrypted first, and `jit migrate undo` restores it"))
		for _, c := range plan.Candidates {
			fmt.Fprintf(w, "  "+glyphBullet+" %s\n", termtext.TruncMid(displayPath(home, c.Path), outputWidth()-4))
			fmt.Fprint(w, "    "+glyphBranch+" ")
			wrapBody(w, 6, "      ", cleanClassDetail(c.Class))
		}
		fmt.Fprintln(w)
	}
	printCleanSkips(w, home, plan.LeftAlone)
}

// cleanSkipHints maps a skip reason to the one next step worth printing
// under its group. Reasons without an entry are self-explanatory.
var cleanSkipHints = map[string]string{
	"whose secrets aren't all in the vault yet": "Migrate the live copy first (name it explicitly), then re-run with --clean.",
	"whose secret isn't in the vault":           "Rotate it at the provider, then delete the file by hand.",
}

// printCleanSkips renders the non-error left-alone rows in the standard
// skipped-findings shape, one group per distinct reason so an explanation
// is stated once (design/output-style.md's explain-once rule). Error rows
// are the caller's to report — they change the exit code.
func printCleanSkips(w io.Writer, home string, skips []migrate.CleanSkip) {
	var order []string
	byReason := map[string][]string{}
	for _, s := range skips {
		if s.Err {
			continue
		}
		if _, ok := byReason[s.Reason]; !ok {
			order = append(order, s.Reason)
		}
		byReason[s.Reason] = append(byReason[s.Reason], s.Path)
	}
	for _, reason := range order {
		paths := byReason[reason]
		printSkippedFindings(w, home, len(paths), reason, paths, cleanSkipHints[reason])
	}
}

// runCleanPhase executes the consented [deletions] category: its own [y/N]
// naming every path, then the fresh user-presence challenge, then
// ApplyClean, then the mutation log. Runs strictly AFTER the migrate phase
// (including wraps), so a value vaulted seconds ago already proves its
// archived copy redundant.
//
// The consent order is plan → [y/N] → fresh Touch ID (GAPS.md #17:
// declining never costs a prompt), and the challenge is forced explicitly
// even though the verification itself touches the KeyWrapper — the gate
// must not depend on that incidental fact (GAPS.md #60). --yes skips the
// typed prompt only, exactly like jit uninstall.
func runCleanPhase(cmd *cobra.Command, home string, plan *migrate.CleanPlan, runValues []migrate.AgentCacheSecret, swept map[string]bool) error {
	out := cmd.OutOrStdout()
	if len(plan.Candidates) == 0 {
		// Nothing deletable; the plan-time refusals were already printed
		// with the plan itself.
		return nil
	}

	if !migrateYes {
		var list strings.Builder
		for _, c := range plan.Candidates {
			list.WriteString("  " + termtext.TruncMid(displayPath(home, c.Path), outputWidth()-2) + "\n")
		}
		what := "this file"
		if n := len(plan.Candidates); n > 1 {
			what = fmt.Sprintf("these %d files", n)
		}
		prompt := fmt.Sprintf("Delete %s from disk? Encrypted copies are kept for jit migrate undo:\n%s[y/N] ",
			what, list.String())
		if !confirmPrompt(cmd, prompt) {
			fmt.Fprintln(out, "Deletions skipped. Nothing was deleted.")
			return nil
		}
	}

	// A fresh-auth vault, never the broker: deletion is the one
	// irreversible mutation migrate performs, and it gets remove's gate.
	v, err := openVaultFreshAuth()
	if err != nil {
		return fmt.Errorf("jit migrate --clean: %w", err)
	}
	reason := fmt.Sprintf("jit migrate --clean: delete %s", countWord(len(plan.Candidates), "flagged file", "flagged files"))
	if err := requireFreshUserPresence(v, reason); err != nil {
		return fmt.Errorf("jit migrate --clean: %w", err)
	}

	outcome, err := migrate.ApplyClean(v, *plan, runValues, swept)
	if err != nil {
		return fmt.Errorf("jit migrate --clean: %w", err)
	}

	fmt.Fprintln(out)
	if n := len(outcome.Deleted); n > 0 {
		printMigrateResultCategory(out, pluralWord(n, "file deleted", "files deleted"), n)
		var deleted []string
		for _, d := range outcome.Deleted {
			fmt.Fprintf(out, "  "+glyphBullet+" %s\n", termtext.TruncMid(displayPath(home, d.Path), outputWidth()-4))
			deleted = append(deleted, d.Path)
		}
		fmt.Fprint(out, "  ")
		wrapBody(out, 2, "  ", hlCmds("Restore any of them with `jit migrate undo <path>`."))
		fmt.Fprintln(out)
		wrapBody(out, 0, "", "Deleting a copy rotates nothing — rotate anything production these files held.")
		// The deletions happened under `jit migrate`'s name; the audit
		// trail must say which files, the same way the guard install is
		// recorded (recordSideEffect's contract).
		recordSideEffect("jit migrate --clean", append([]string{"migrate", "--clean"}, deleted...), "jit migrate")
	}
	// Reasons the pass declined are grouped like every skip note; failures
	// print one line each and fail the run, after the log above — the
	// deletions already made are real and must stay visible (the cache
	// sweep's partial-result rule).
	printCleanSkips(out, home, outcome.LeftAlone)
	failures := 0
	for _, s := range outcome.LeftAlone {
		if s.Err {
			failures++
			fmt.Fprintf(cmd.ErrOrStderr(), "jit migrate --clean: %s: %s\n", displayPath(home, s.Path), s.Reason)
		}
	}
	if failures > 0 {
		return fmt.Errorf("jit migrate --clean: %s failed; everything else above stands", countWord(failures, "deletion", "deletions"))
	}
	return nil
}
