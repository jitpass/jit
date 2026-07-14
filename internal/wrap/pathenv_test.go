// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package wrap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRcFile(t *testing.T) {
	home := "/Users/alex"
	cases := map[string]string{
		"/bin/zsh":            filepath.Join(home, ".zshrc"),
		"":                    filepath.Join(home, ".zshrc"),
		"/opt/homebrew/bash":  filepath.Join(home, ".bashrc"),
		"/usr/local/bin/fish": filepath.Join(home, ".profile"),
	}
	for shell, want := range cases {
		if got := RcFile(home, shell); got != want {
			t.Errorf("RcFile(%q) = %q, want %q", shell, got, want)
		}
	}
}

func TestEnsurePathLineCreatesAndIsIdempotent(t *testing.T) {
	rc := filepath.Join(t.TempDir(), ".zshrc")

	changed, err := EnsurePathLine(rc)
	if err != nil || !changed {
		t.Fatalf("first EnsurePathLine = (%v, %v), want (true, nil)", changed, err)
	}
	data, err := os.ReadFile(rc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), pathLine) || !strings.Contains(string(data), pathLineComment) {
		t.Errorf("rc file missing the comment+export pair:\n%s", data)
	}

	changed, err = EnsurePathLine(rc)
	if err != nil || changed {
		t.Fatalf("second EnsurePathLine = (%v, %v), want (false, nil)", changed, err)
	}
	if again, _ := os.ReadFile(rc); strings.Count(string(again), pathLine) != 1 {
		t.Errorf("export line duplicated:\n%s", again)
	}
}

func TestEnsurePathLineRespectsExistingShimEntry(t *testing.T) {
	rc := filepath.Join(t.TempDir(), ".zshrc")
	custom := `export PATH="$HOME/.jit/shims:$HOME/bin:$PATH"` + "\n"
	if err := os.WriteFile(rc, []byte(custom), 0o644); err != nil { // #nosec G306 -- rc fixture, conventional mode
		t.Fatal(err)
	}
	changed, err := EnsurePathLine(rc)
	if err != nil || changed {
		t.Fatalf("EnsurePathLine over a hand-written shim entry = (%v, %v), want (false, nil)", changed, err)
	}
}

func TestEnsurePathLineAddsNewlineToUnterminatedFile(t *testing.T) {
	rc := filepath.Join(t.TempDir(), ".zshrc")
	if err := os.WriteFile(rc, []byte("alias ll='ls -l'"), 0o644); err != nil { // #nosec G306 -- rc fixture, conventional mode
		t.Fatal(err)
	}
	if _, err := EnsurePathLine(rc); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(rc)
	if strings.Contains(string(data), "ls -l'"+pathLineComment) {
		t.Errorf("comment glued onto the previous line:\n%s", data)
	}
	if !strings.Contains(string(data), "alias ll='ls -l'\n") {
		t.Errorf("original content damaged:\n%s", data)
	}
}

func TestRemovePathLineRemovesExactlyThePair(t *testing.T) {
	rc := filepath.Join(t.TempDir(), ".zshrc")
	before := "alias ll='ls -l'\n"
	after := "export EDITOR=vim\n"
	if err := os.WriteFile(rc, []byte(before), 0o644); err != nil { // #nosec G306 -- rc fixture, conventional mode
		t.Fatal(err)
	}
	if _, err := EnsurePathLine(rc); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(rc, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(after); err != nil {
		t.Fatal(err)
	}
	f.Close()

	changed, err := RemovePathLine(rc)
	if err != nil || !changed {
		t.Fatalf("RemovePathLine = (%v, %v), want (true, nil)", changed, err)
	}
	data, _ := os.ReadFile(rc)
	if strings.Contains(string(data), ".jit/shims") {
		t.Errorf("shim line still present:\n%s", data)
	}
	if !strings.Contains(string(data), before) || !strings.Contains(string(data), after) {
		t.Errorf("surrounding content damaged:\n%s", data)
	}

	changed, err = RemovePathLine(rc)
	if err != nil || changed {
		t.Fatalf("second RemovePathLine = (%v, %v), want (false, nil)", changed, err)
	}
	if _, err := RemovePathLine(filepath.Join(t.TempDir(), "missing")); err != nil {
		t.Errorf("RemovePathLine on a missing file: %v, want nil", err)
	}
}
