// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const redactProbeToken = "ntn_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0"

func execMigrateRedact(t *testing.T, args ...string) (string, error) {
	t.Helper()
	migrateRedactFormat = "text"
	migrateRedactLines = nil
	return execMigrate(t, append([]string{"redact"}, args...)...)
}

func redactHome(t *testing.T) (home, transcript string) {
	t.Helper()
	home = withFixtureHome(t)
	withFixtureCwd(t)
	transcript = filepath.Join(home, ".claude", "projects", "p", "s.jsonl")
	if err := os.MkdirAll(filepath.Dir(transcript), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(transcript, []byte("{\"a\":1}\n{\"cmd\":\""+redactProbeToken+"\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return home, transcript
}

// The dry run names the marker and the one-way nature, and changes nothing.
func TestMigrateRedactDryRunSaysItCannotBeUndone(t *testing.T) {
	_, transcript := redactHome(t)
	out, err := execMigrateRedact(t, "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"1 token jit recognises by format", "Claude Code", "<jit:redacted:VENDOR>", "cannot be undone", "DRY RUN"} {
		if !strings.Contains(out, want) {
			t.Errorf("dry run lacks %q:\n%s", want, out)
		}
	}
	if raw, _ := os.ReadFile(transcript); !strings.Contains(string(raw), redactProbeToken) {
		t.Fatal("a dry run changed the file")
	}
	if strings.Contains(out, redactProbeToken) {
		t.Fatal("the token itself was printed")
	}
}

// Declined at the prompt (EOF on stdin): nothing changes.
func TestMigrateRedactDeclinedChangesNothing(t *testing.T) {
	_, transcript := redactHome(t)
	out, err := execMigrateRedact(t)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Aborted. Nothing was changed.") {
		t.Errorf("no abort line:\n%s", out)
	}
	if raw, _ := os.ReadFile(transcript); !strings.Contains(string(raw), redactProbeToken) {
		t.Fatal("a declined run changed the file")
	}
}

// --yes --format json: one document, the file rewritten, the marker in it.
func TestMigrateRedactJSONRewritesAndReports(t *testing.T) {
	_, transcript := redactHome(t)
	out, err := execMigrateRedact(t, "--yes", "--format", "json")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var report redactReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("not one JSON document: %v\n%s", err, out)
	}
	if !report.Applied || len(report.Caches.Removed) != 1 || report.Caches.Removed[0].Copies != 1 || report.Caches.Removed[0].Agent != "Claude Code" {
		t.Errorf("report = %+v", report)
	}
	if strings.Contains(out, redactProbeToken) {
		t.Fatal("the token reached the document")
	}
	raw, _ := os.ReadFile(transcript)
	if !strings.Contains(string(raw), "<jit:redacted:Notion Internal Integration Token>") || strings.Contains(string(raw), redactProbeToken) {
		t.Fatalf("file not redacted:\n%s", raw)
	}
}

func TestMigrateRedactRefusalsAndNothingToDo(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	if _, err := execMigrateRedact(t, "--format", "json"); err == nil || !strings.Contains(err.Error(), "needs --yes") {
		t.Errorf("json without --yes: %v", err)
	}
	if _, err := execMigrateRedact(t, "--line", "3"); err == nil || !strings.Contains(err.Error(), "needs the file") {
		t.Errorf("--line without a file: %v", err)
	}
	out, err := execMigrateRedact(t, "--yes")
	if err != nil || !strings.Contains(out, "Nothing to do") {
		t.Errorf("empty home: %v\n%s", err, out)
	}
	mine := filepath.Join(home, "notes.txt")
	if err := os.WriteFile(mine, []byte("x="+redactProbeToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err = execMigrateRedact(t, "--yes", mine)
	if err != nil || !strings.Contains(out, "Nothing to do") {
		t.Errorf("a file outside the caches must never be rewritten: %v\n%s", err, out)
	}
	if raw, _ := os.ReadFile(mine); !strings.Contains(string(raw), redactProbeToken) {
		t.Fatal("the user's own file was rewritten")
	}
}
