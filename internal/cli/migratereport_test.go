// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/keystore"
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/vault"
)

// `jit migrate <path> --format json` is one document a program can read:
// what was vaulted, what the sweep removed and left, the errors, and the
// text report. Never a value.

func TestMigrateFormatJSONNeedsYesAndRefusesDryRunAndClean(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	notes := filepath.Join(home, "notes.txt")
	if err := os.WriteFile(notes, []byte("just notes\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{notes, "--format", "json"}, "needs --yes"},
		{[]string{notes, "--format", "json", "--yes", "--dry-run"}, "drop --dry-run"},
		{[]string{notes, "--format", "json", "--yes", "--clean"}, "does not take --clean"},
		{[]string{notes, "--format", "yaml", "--yes"}, `unknown --format "yaml"`},
		{[]string{"--format", "json", "--yes"}, "is for `jit migrate <path>`"},
	} {
		_, err := execMigrate(t, tc.args...)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: want an error containing %q, got %v", tc.args, tc.want, err)
		}
	}
}

// A plain file has nothing to migrate: the document says so (applied
// false, no vaulted names) and carries the text the run would have printed,
// and NOTHING but the document reaches stdout.
func TestMigrateFormatJSONNothingToMigrateIsOneDocument(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	notes := filepath.Join(home, "notes.txt")
	if err := os.WriteFile(notes, []byte("just some notes, no secrets\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	out, err := execMigrate(t, notes, "--format", "json", "--yes")
	if err != nil {
		t.Fatalf("jit migrate <plain file> --format json --yes: %v", err)
	}
	var report migrateReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("stdout is not one JSON document: %v\n%s", err, out)
	}
	if !strings.HasPrefix(out, "{") {
		t.Errorf("text leaked ahead of the document:\n%s", out)
	}
	if got := report.Targets; len(got) != 1 || got[0] != notes {
		t.Errorf("targets = %v, want [%s]", got, notes)
	}
	if report.Applied {
		t.Error("applied = true for a file with nothing to migrate")
	}
	if len(report.Vaulted) != 0 || len(report.Errors) != 0 {
		t.Errorf("vaulted = %v, errors = %v; want both empty", report.Vaulted, report.Errors)
	}
	if !strings.Contains(report.Report, "none of the path(s) you named") {
		t.Errorf("report text does not carry the nothing-to-migrate line:\n%s", report.Report)
	}
	// Empty, not null: a consumer indexing `caches.removed` must not trip.
	for _, key := range []string{`"vaulted": []`, `"removed": []`, `"left": []`, `"errors": []`} {
		if !strings.Contains(out, key) {
			t.Errorf("document lacks %s:\n%s", key, out)
		}
	}
}

func TestMigrateReportFillNamesVarsAndTheSweepWithoutValues(t *testing.T) {
	report := newMigrateReport()
	report.fill(cleanPhaseInputs{
		vaulted: []migrate.AgentCacheSecret{
			{Var: "NOTION_TOKEN", Value: "ntn_secret_value_1"},
			{Var: "NOTION_TOKEN", Value: "ntn_secret_value_1"}, // a rotation re-set: once
			{Var: "STRIPE_KEY", Value: "sk_live_secret_value_2"},
		},
		cleanup: migrate.AgentCacheCleanup{
			Edited: []migrate.AgentCacheEdit{
				{Path: "/h/.claude/a.jsonl", Agent: "Claude Code", Area: "transcripts", Occurrences: 5},
				{Path: "/h/.claude/h", Agent: "Claude Code", Area: "edit history", Occurrences: 3},
			},
			Skipped: []migrate.AgentCacheSkip{
				{Path: "/h/.claude/live.jsonl", Agent: "Claude Code", Area: "transcripts", Kind: migrate.SkipLive, Reason: "the agent wrote to it while jit was working; left alone"},
			},
		},
		cleanErr: errors.New("boom"),
	})
	if got := report.Vaulted; strings.Join(got, ",") != "NOTION_TOKEN,STRIPE_KEY" {
		t.Errorf("vaulted = %v", got)
	}
	if report.removedCopies() != 8 || len(report.Caches.Removed) != 2 {
		t.Errorf("removed = %+v", report.Caches.Removed)
	}
	if len(report.Caches.Left) != 1 || report.Caches.Left[0].Kind != "live" || report.Caches.Left[0].Area != "transcripts" {
		t.Errorf("left = %+v", report.Caches.Left)
	}
	if len(report.Errors) != 1 || !strings.Contains(report.Errors[0], "boom") {
		t.Errorf("errors = %v", report.Errors)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"ntn_secret_value_1", "sk_live_secret_value_2"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("a vaulted value reached the report: %s", raw)
		}
	}
}

// `jit migrate caches --yes --format json` is the Findings banner's Clean
// AI agent caches: the migrate report's document, with the sweep under
// caches and nothing vaulted. Run end to end over a fixture home with the
// test key store: a vaulted token copied into Claude Code's edit history.
func TestMigrateCachesFormatJSON(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	origOpen := openKeyStore
	t.Cleanup(func() { openKeyStore = origOpen })
	key := countingKeychainKey{kw: newFakeKeyWrapper(), uses: new(int)}
	openKeyStore = func(r string) keystore.Store { return keystore.OpenTesting(r, key) }
	withFakeLaunchd(t)

	v, err := openVaultFreshAuth()
	if err != nil {
		t.Fatal(err)
	}
	// The migrate package's cache fixture; a value reading as a
	// placeholder is never hunted (audit.EligibleNeedle).
	token := "tok_51QzR7bWpKmT4vXnA9dLcE2hJ" // gitleaks:allow
	if err := v.SetWithMeta("acme/GH_TOKEN", []byte(token), vault.Meta{Class: vault.ClassDotenv}); err != nil {
		t.Fatal(err)
	}
	history := filepath.Join(home, ".claude", "file-history", "s1", "abc@v2")
	if err := os.MkdirAll(filepath.Dir(history), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(history, []byte("GH_TOKEN="+token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"caches", "--format", "json"}, "needs --yes"},
		{[]string{"caches", "--format", "json", "--yes", "--dry-run"}, "drop --dry-run"},
	} {
		if _, err := execMigrate(t, tc.args...); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: err = %v, want %q", tc.args, err, tc.want)
		}
	}

	out, err := execMigrate(t, "caches", "--yes", "--format", "json")
	if err != nil {
		t.Fatalf("jit migrate caches --yes --format json: %v\n%s", err, out)
	}
	if !strings.HasPrefix(out, "{") {
		t.Fatalf("text leaked ahead of the document:\n%s", out)
	}
	var report migrateReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("not one JSON document: %v\n%s", err, out)
	}
	if !report.Applied || len(report.Vaulted) != 0 || len(report.Errors) != 0 {
		t.Errorf("report = applied %v, vaulted %v, errors %v", report.Applied, report.Vaulted, report.Errors)
	}
	if len(report.Caches.Removed) != 1 || report.Caches.Removed[0].Agent != "Claude Code" || report.Caches.Removed[0].Copies != 1 {
		t.Errorf("removed = %+v, want one Claude Code file with one copy\n%s", report.Caches.Removed, report.Report)
	}
	if strings.Contains(out, token) {
		t.Error("the document carries the secret's value")
	}
	if b, _ := os.ReadFile(history); strings.Contains(string(b), token) {
		t.Error("the copy is still in the history file")
	}
	if report.Report == "" {
		t.Error("report text is empty; the sweep's own words belong in it")
	}
}
