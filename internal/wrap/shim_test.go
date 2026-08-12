// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package wrap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGuardVar(t *testing.T) {
	cases := map[string]string{
		"gh":      "JIT_SHIM_GUARD_GH",
		"my-tool": "JIT_SHIM_GUARD_MY_TOOL",
		"doctl2":  "JIT_SHIM_GUARD_DOCTL2",
		"a.b_c":   "JIT_SHIM_GUARD_A_B_C",
		"STRIPE":  "JIT_SHIM_GUARD_STRIPE",
	}
	for tool, want := range cases {
		if got := guardVar(tool); got != want {
			t.Errorf("guardVar(%q) = %q, want %q", tool, got, want)
		}
	}
}

func TestShimArgv(t *testing.T) {
	// env-wrap: injects the profile.
	argv := shimArgv("gh", "/opt/homebrew/bin/gh", Entry{Profile: "wrap-gh"}, []string{"pr", "list", "--limit", "5"})
	want := []string{"jit", "run", "--profile", "wrap-gh", "--", "/opt/homebrew/bin/gh", "pr", "list", "--limit", "5"}
	if !equalArgv(argv, want) {
		t.Fatalf("env-wrap shimArgv = %v, want %v", argv, want)
	}

	// grant-wrap: grants the global mount by name.
	argv = shimArgv("gcloud", "/opt/homebrew/bin/gcloud", Entry{With: "gcp"}, []string{"storage", "ls"})
	want = []string{"jit", "run", "--with", "gcp", "--", "/opt/homebrew/bin/gcloud", "storage", "ls"}
	if !equalArgv(argv, want) {
		t.Fatalf("grant-wrap shimArgv = %v, want %v", argv, want)
	}

	// capture-wrap: routes through the tool's capture plumbing command.
	argv = shimArgv("clisso", "/opt/homebrew/bin/clisso", Entry{Capture: "clisso"}, []string{"get", "prod"})
	want = []string{"jit", "clisso-capture", "--real", "/opt/homebrew/bin/clisso", "--", "get", "prod"}
	if !equalArgv(argv, want) {
		t.Fatalf("capture-wrap shimArgv = %v, want %v", argv, want)
	}
}

func equalArgv(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// writeExecutable drops an executable file named tool into dir.
func writeExecutable(t *testing.T, dir, tool string) string {
	t.Helper()
	path := filepath.Join(dir, tool)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil { // #nosec G306 -- a test fixture that must be executable
		t.Fatal(err)
	}
	return path
}

func TestLookPathSkippingFindsRealBeyondShimDir(t *testing.T) {
	shims := t.TempDir()
	real := t.TempDir()
	writeExecutable(t, shims, "gh")
	realPath := writeExecutable(t, real, "gh")

	got, err := lookPathSkipping(shims+string(os.PathListSeparator)+real, "gh", shims)
	if err != nil {
		t.Fatalf("lookPathSkipping: %v", err)
	}
	if got != realPath {
		t.Errorf("resolved %q, want the real binary %q", got, realPath)
	}
}

func TestLookPathSkippingSeesThroughSymlinkedShimDir(t *testing.T) {
	shims := t.TempDir()
	real := t.TempDir()
	writeExecutable(t, shims, "gh")
	realPath := writeExecutable(t, real, "gh")

	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(shims, alias); err != nil {
		t.Fatal(err)
	}
	pathEnv := strings.Join([]string{shims, alias, real}, string(os.PathListSeparator))
	got, err := lookPathSkipping(pathEnv, "gh", shims)
	if err != nil {
		t.Fatalf("lookPathSkipping: %v", err)
	}
	if got != realPath {
		t.Errorf("resolved %q through a symlinked shim dir, want %q", got, realPath)
	}
}

func TestLookPathSkippingErrorsWhenOnlyShimExists(t *testing.T) {
	shims := t.TempDir()
	writeExecutable(t, shims, "gh")

	if _, err := lookPathSkipping(shims, "gh", shims); err == nil {
		t.Fatal("expected an error when the only PATH entry is the shim dir itself")
	}
}

func TestLookPathSkippingIgnoresNonExecutablesAndDirs(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "gh"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	if err := os.Mkdir(filepath.Join(other, "gh"), 0o755); err != nil {
		t.Fatal(err)
	}
	pathEnv := strings.Join([]string{dir, other}, string(os.PathListSeparator))
	if _, err := lookPathSkipping(pathEnv, "gh", t.TempDir()); err == nil {
		t.Fatal("expected an error, no executable gh exists on this PATH")
	}
}

// A completion invocation may be exec'd WITHOUT credential injection, so the
// classifier errs narrow: only the two markers that make the real tool itself
// enter completion mode. Anything looser would silently unwrap a real run.
func TestCompletionInvocation(t *testing.T) {
	t.Setenv("_ARGCOMPLETE", "")
	os.Unsetenv("_ARGCOMPLETE")
	cases := map[string]struct {
		args []string
		want bool
	}{
		"cobra completion":         {[]string{"__complete", "pr", "cre"}, true},
		"cobra no-desc completion": {[]string{"__completeNoDesc", "get", "po"}, true},
		"a real run":               {[]string{"pr", "create"}, false},
		"no args":                  {nil, false},
		"marker not first":         {[]string{"run", "__complete"}, false},
		// `gh completion zsh` GENERATES a script; it is a real, user-typed
		// command and must stay wrapped.
		"the completion subcommand": {[]string{"completion", "zsh"}, false},
	}
	for name, tc := range cases {
		if got := CompletionInvocation(tc.args); got != tc.want {
			t.Errorf("%s: CompletionInvocation(%v) = %v, want %v", name, tc.args, got, tc.want)
		}
	}

	// argcomplete tools signal completion mode via env, with a real-looking argv.
	t.Setenv("_ARGCOMPLETE", "1")
	if !CompletionInvocation([]string{"s3", "ls"}) {
		t.Error("_ARGCOMPLETE set: the real tool will answer a completion query, so this is one")
	}
}

// ShimExecReal resolves through the same skip-the-shim-dir lookup as the
// wrapped path, so its failure mode (and message) match ShimExec's.
func TestShimExecRealFailsLoudlyWhenOnlyTheShimExists(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	shimDir := ShimDir(home)
	if err := os.MkdirAll(shimDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shimDir, "ghost-tool"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shimDir)
	err := ShimExecReal("ghost-tool", []string{"__complete", ""})
	if err == nil {
		t.Fatal("ShimExecReal found a real tool where only the shim exists")
	}
	if !strings.Contains(err.Error(), "jit wrap undo ghost-tool") {
		t.Errorf("error %q does not name the way out", err)
	}
}
