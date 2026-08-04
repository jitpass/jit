// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// A named history file must route to the history category and NEVER fall
// through to the generic loose-secret classification — a zsh extended_history
// line reads as "embedded" content there, and the --mount offer it produces
// would turn the shell's own record into a FIFO no shell can append to.
func TestDiscoverFileTargetRoutesHistoryFiles(t *testing.T) {
	home := t.TempDir()
	token := "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
	path := filepath.Join(home, ".zsh_history")
	if err := os.WriteFile(path, []byte(": 1782826756:0;export GITHUB_TOKEN="+token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	d := &discovered{}
	if err := discoverFileTarget(d, home, path); err != nil {
		t.Fatalf("discoverFileTarget: %v", err)
	}
	if len(d.historyFiles) != 1 || d.historyFiles[0] != path {
		t.Errorf("historyFiles = %v, want the named file", d.historyFiles)
	}
	if len(d.looseSecretFiles) != 0 || len(d.looseEmbeddedSkipped) != 0 {
		t.Error("a history file leaked into the loose-secret categories")
	}
}

// A clean history file is routed (so it can never fall through) but yields
// nothing — the ordinary "nothing to migrate" outcome, not an error.
func TestDiscoverFileTargetCleanHistoryYieldsNothing(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".bash_history")
	if err := os.WriteFile(path, []byte("git status\nls -la\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	d := &discovered{}
	if err := discoverFileTarget(d, home, path); err != nil {
		t.Fatalf("discoverFileTarget: %v", err)
	}
	if got := d.total(); got != 0 {
		t.Errorf("total = %d, want 0", got)
	}
}

// A custom $HISTFILE has a name on no fixed list; the env var is what routes
// it — a user who moved their history has not thereby stopped having one.
func TestDiscoverFileTargetRoutesCustomHISTFILE(t *testing.T) {
	home := t.TempDir()
	token := "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
	path := filepath.Join(home, "myhist")
	if err := os.WriteFile(path, []byte(": 1782826756:0;export GITHUB_TOKEN="+token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HISTFILE", path)

	d := &discovered{}
	if err := discoverFileTarget(d, home, path); err != nil {
		t.Fatalf("discoverFileTarget: %v", err)
	}
	if len(d.historyFiles) != 1 {
		t.Errorf("historyFiles = %v, want the $HISTFILE target", d.historyFiles)
	}
}
