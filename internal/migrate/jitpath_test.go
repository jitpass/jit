// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// jitPathRecorders are this package's files that rewrite an artifact to call
// back into jit, and therefore bake jit's absolute path into a file that
// outlives the process. Every one of them must ask the SAME question, in the
// same place, or they drift apart — which is exactly what happened before
// internal/selfpath existed.
var jitPathRecorders = []string{
	"mcpconfig.go",
	"kubeconfig.go",
	"awscreds.go",
	"dockercreds.go",
	"gitcreds.go",
	"terraform.go",
	"jitpathrefresh.go",
}

// TestEveryRecorderGoesThroughResolveJitExecutable is a source-level guard, in
// the spirit of internal/cli's TestBothServicePathsRepoint: it does not test
// behaviour, it stops a specific bug being reintroduced by a plausible edit.
//
// The bug: a category that needs jit's path reaches for os.Executable and
// filepath.EvalSymlinks directly, because that is the obvious way to get it
// and it works on the author's machine. It then records the fully resolved
// path — which on a Homebrew install is the version-numbered Caskroom copy
// `brew upgrade` deletes, silently breaking that artifact at the next
// upgrade with nothing to point at the cause. That is not hypothetical: it
// shipped, and every one of these six files carried it.
//
// resolveJitExecutable (selfpath.Durable) is the only correct answer, so this
// asserts nothing here rolls its own.
func TestEveryRecorderGoesThroughResolveJitExecutable(t *testing.T) {
	// Matches a direct resolution attempt while ignoring the word inside a
	// comment, which is how the rule gets explained in these same files.
	direct := regexp.MustCompile(`^[^/]*\b(os\.Executable|filepath\.EvalSymlinks)\(`)

	for _, file := range jitPathRecorders {
		data, err := os.ReadFile(file) // #nosec G304 -- this package's own sources
		if err != nil {
			t.Fatalf("reading %s: %v", file, err)
		}
		src := string(data)

		if !strings.Contains(src, "resolveJitExecutable()") {
			t.Errorf("%s is listed as recording jit's path but never calls "+
				"resolveJitExecutable(). Either it stopped doing that (drop it from "+
				"jitPathRecorders) or it found another way to get the path, which is "+
				"the bug this guard exists for.", file)
		}
		for i, line := range strings.Split(src, "\n") {
			if direct.MatchString(line) {
				t.Errorf("%s:%d resolves jit's own path directly:\n\t%s\n"+
					"A recorded path must come from resolveJitExecutable() "+
					"(internal/selfpath), which keeps Homebrew's stable bin symlink "+
					"instead of the version-numbered Caskroom copy `brew upgrade` deletes.",
					file, i+1, strings.TrimSpace(line))
			}
		}
	}
}

// TestJitPathRecordersExist keeps the list above honest: a renamed or deleted
// category would otherwise make the guard silently vacuous for that file.
func TestJitPathRecordersExist(t *testing.T) {
	for _, file := range jitPathRecorders {
		if _, err := os.Stat(filepath.Clean(file)); err != nil {
			t.Errorf("jitPathRecorders names %s, which is not in this package: %v", file, err)
		}
	}
}
