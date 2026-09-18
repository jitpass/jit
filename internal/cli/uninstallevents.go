// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// uninstallRestoreFailedExitCode: a file could not be put back, so nothing
// was deleted. Not 1, for the reason doctorProblemsExitCode gives: exit 1 is
// what every unexpected error already returns, and a caller has to be able
// to tell "try again after fixing these files" from "something broke".
const uninstallRestoreFailedExitCode = 2

// uninstallEvents is the machine-readable side of `jit uninstall`, for a
// program driving it (the JitPass app's Remove flow). The progress tracker
// only animates on a TTY, so without this a caller sees nothing between the
// fingerprint and the exit code. One JSON object per line:
//
//	{"event":"step","step":"restore"}     a step began; the one before ended
//	{"event":"file","path":…,"ok":true}   one file put back (or "error":…)
//	{"event":"failed","failures":[…]}     restore failed; nothing was deleted
//	{"event":"done","ok":true}            finished ("problems":[…] when not ok)
//
// Steps, in order: auth, restore, stores, service, tools, vault. A nil
// *uninstallEvents is text mode; every method is a no-op on it.
type uninstallEvents struct {
	enc *json.Encoder
}

func newUninstallEvents(w io.Writer, format string) (*uninstallEvents, error) {
	switch format {
	case "", "text":
		return nil, nil
	case "json":
		if !uninstallDryRun {
			return nil, fmt.Errorf(`jit uninstall: --format json is the plan, so it needs --dry-run; a real run streams with --format ndjson`)
		}
	case "ndjson":
	default:
		return nil, fmt.Errorf("jit uninstall: unknown --format %q (text, json, ndjson)", format)
	}
	return &uninstallEvents{enc: json.NewEncoder(w)}, nil
}

func (e *uninstallEvents) emit(v any) {
	if e != nil {
		_ = e.enc.Encode(v)
	}
}

func (e *uninstallEvents) step(name string) {
	e.emit(map[string]string{"event": "step", "step": name})
}

func (e *uninstallEvents) file(path string, err error) {
	ev := map[string]any{"event": "file", "path": path, "ok": err == nil}
	if err != nil {
		ev["error"] = err.Error()
	}
	e.emit(ev)
}

func (e *uninstallEvents) failed(failures []restoreFailure) {
	e.emit(map[string]any{"event": "failed", "failures": failures})
}

func (e *uninstallEvents) done(problems []string) {
	ev := map[string]any{"event": "done", "ok": len(problems) == 0}
	if len(problems) > 0 {
		ev["problems"] = problems
	}
	e.emit(ev)
}

// uninstallPlanDoc is `jit uninstall --dry-run --format json`: everything
// the text plan says, for a window to draw. Read-only, and free of any
// prompt, like the plan it mirrors.
type uninstallPlanDoc struct {
	Restore      uninstallRestorePlan `json:"restore_plan"`
	Secrets      int                  `json:"secrets"`
	KeyPresent   bool                 `json:"key_present"`
	Shims        []string             `json:"shims"`
	Guard        bool                 `json:"guard"`
	Helpers      []string             `json:"helpers"`
	PathLineFile string               `json:"path_line_file,omitempty"`
	BinaryOwner  string               `json:"binary_owner,omitempty"`
}

func (e *uninstallEvents) plan(doc uninstallPlanDoc) error {
	return e.enc.Encode(doc)
}

// printUninstallRestorePlan is the text plan's first half: what comes back,
// what cannot, before "This will remove:" lists the rest.
func printUninstallRestorePlan(out io.Writer, home string, plan uninstallRestorePlan) {
	if len(plan.Restore) == 0 {
		fmt.Fprintln(out, "No migrated files are recorded, so there is nothing to put back.")
	} else {
		fmt.Fprintf(out, "This will put back %s, as plaintext:\n", countWord(len(plan.Restore), "file", "files"))
		for _, item := range plan.Restore {
			line := fmt.Sprintf("  - %s (%s)", displayPath(home, item.Path), restoreKindPhrase(item.Kind))
			if item.Drifted {
				line += "; changed since, today's version is kept beside it"
			}
			fmt.Fprintln(out, line)
		}
	}
	if n := len(plan.Unwired); n > 0 {
		fmt.Fprintf(out, "Left alone, jit's line is already gone from: %s\n", displayPaths(home, plan.Unwired))
	}
	if n := len(plan.Gone); n > 0 {
		fmt.Fprintf(out, "Not recreated: %s jit migrated that %s no longer there.\n", countWord(n, "file", "files"), pluralWord(n, "is", "are"))
	}
	if n := len(plan.KeptClean); n > 0 {
		fmt.Fprintf(out, "Left cleaned: %s of shell history and AI caches jit took tokens out of.\n", countWord(n, "file", "files"))
	}
	if n := len(plan.VaultOnly); n > 0 {
		fmt.Fprintf(out, "%s no file to go back to (%s) and will be lost:\n", countWord(n, "secret has", "secrets have"), classCounts(plan.VaultOnly))
		shown := plan.VaultOnly
		if len(shown) > 12 {
			shown = shown[:12]
		}
		for _, s := range shown {
			fmt.Fprintf(out, "  - %s\n", s.Path)
		}
		if extra := len(plan.VaultOnly) - len(shown); extra > 0 {
			fmt.Fprintf(out, "  - and %d more\n", extra)
		}
		fmt.Fprintln(out, hlCmds("`jit vault export <file>` first keeps them."))
	}
	if n := len(plan.ProjectStores); n > 0 {
		fmt.Fprintf(out, "Then .jit is removed from %s.\n", countWord(n, "project folder", "project folders"))
	}
	fmt.Fprintln(out)
}

// uninstallApplyCommand is the invocation a dry run's trailer names.
func uninstallApplyCommand() string {
	parts := []string{"jit uninstall"}
	switch {
	case uninstallRestore:
		parts = append(parts, "--restore")
	case uninstallPurge:
		parts = append(parts, "--purge")
	}
	if uninstallKeepBinary {
		parts = append(parts, "--keep-binary")
	}
	return strings.Join(parts, " ")
}
