// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The drift guard for design/output-style.md, in the same spirit as
// plugins_doc_test.go: a rule nobody can grep for is a rule that decays.
//
// Both checks below started as one-off greps that found real drift after the
// output pass had supposedly finished — 29 print sites writing raw backticks
// and 26 hand-rolled color.New calls, across nine files, including some added
// the same afternoon by someone who had just fixed the identical thing
// elsewhere. Reviewing for this by eye does not work; the eye reads what the
// line says, not what colour it will be.
//
// Deliberately narrow. Both patterns are mechanical and false-positive free,
// so a failure here is always a real fix, never a judgement call to argue
// with. The rules that need judgement (is this amber reporting state or
// dressing up advice? is that glyph carrying meaning?) stay with the reviewer.

// printCall matches a call that writes user-facing output. fmt.Errorf is
// deliberately absent: an error is not styled output, it goes out through
// cobra's own error path, and backticks in one are plain text.
var printCall = regexp.MustCompile(`\b(?:Fprint|Fprintf|Fprintln|Print|Printf|Println)\(`)

// TestNoUnroutedCommandBackticks pins rule 5's sharpest edge: cyan is the
// only colour a command ever takes, and it gets there through hlCmds. A
// print call that writes a `backticked` command without it renders the
// backticks literally, in default weight, so the same sentence looks
// different depending on which command printed it.
func TestNoUnroutedCommandBackticks(t *testing.T) {
	for _, file := range styleCheckedFiles(t) {
		for i, line := range readLines(t, file) {
			if !strings.Contains(line, "`") || !printCall.MatchString(line) {
				continue
			}
			if strings.Contains(line, "hlCmds") {
				continue
			}
			t.Errorf("%s:%d writes a `backticked` command without hlCmds, so it renders "+
				"literal and uncolored. Wrap the message: hlCmds(fmt.Sprintf(...)).\n    %s",
				filepath.Base(file), i+1, strings.TrimSpace(line))
		}
	}
}

// TestNoHandRolledColors pins the palette seam: every colour decision goes
// through the semantic helpers in style.go (cDim, cBold, cPath, cOK, cWarn,
// cRisk, cPathBold, cOKBold), so changing a hue is a one-file edit and a
// call site says what it MEANS rather than which hue it picked.
//
// This catches the compound calls too (color.New(color.FgCyan, color.Bold)),
// which is where the sweep found hard-coded hues hiding after the simple
// ones had been cleaned up. Using color.Color as a TYPE is untouched and
// fine — doctor.go takes one as a parameter, which is plumbing, not a
// palette decision.
func TestNoHandRolledColors(t *testing.T) {
	for _, file := range styleCheckedFiles(t) {
		for i, line := range readLines(t, file) {
			if !strings.Contains(line, "color.New(") {
				continue
			}
			t.Errorf("%s:%d builds a color by hand. Use a semantic helper from style.go "+
				"(cDim, cBold, cPath, cOK, cWarn, cRisk, cPathBold, cOKBold) so a palette "+
				"change stays one edit.\n    %s",
				filepath.Base(file), i+1, strings.TrimSpace(line))
		}
	}
}

// TestDoctorsRenderNoLiteralBackticks is the guard the two lints above
// structurally cannot be: it checks rendered OUTPUT, not source.
//
// `jit wrap doctor` printed literal backticks in dim grey for as long as it
// existed, while `jit doctor` rendered the very same strings — wrap.Doctor's
// Detail fields — as cyan commands. One string, two appearances, depending on
// which command you typed: exactly the drift rule 5 names. Neither lint saw
// it, and neither could have. TestNoUnroutedCommandBackticks scans this
// package for print calls containing a backtick LITERAL, but the literals
// live in internal/wrap and reached the printer through a variable
// (`c.Detail`); TestNoHandRolledColors is about hues, not markup.
//
// So this asserts the property the lints are proxies for, on both surfaces at
// once: a rendered report never shows the reader a backtick. hlCmds strips
// them; anything that skips hlCmds leaves them in.
func TestDoctorsRenderNoLiteralBackticks(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)

	// A fixture broken in several ways at once, so both reports have plenty
	// of command-bearing findings to render.
	writeFixtureProfile(t, cwd, "app", "APP_KEY: app/key\n") // secret absent -> [missing]
	if err := os.MkdirAll(filepath.Join(home, ".jit"), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, ".jit", "wrap.json"),
		[]byte(`{"tools":{"kubectl":{"profile":"wrap-kubectl"}}}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"jit doctor", []string{"doctor"}},
		{"jit wrap doctor", []string{"wrap", "doctor"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			rootCmd.SetOut(&buf)
			rootCmd.SetArgs(tc.args)
			_ = rootCmd.Execute() // a failing health check is the point; the exit code isn't
			if got := buf.String(); strings.Contains(got, "`") {
				t.Errorf("%s rendered a literal backtick — a command that skipped hlCmds.\n%s", tc.name, got)
			}
		})
	}
}

// styleCheckedFiles lists this package's own non-test sources, minus
// style.go — which is where the palette is allowed to be built, and the one
// file both checks above exist to protect.
func styleCheckedFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading package dir: %v", err)
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") ||
			strings.HasSuffix(name, "_test.go") || name == "style.go" {
			continue
		}
		files = append(files, name)
	}
	if len(files) == 0 {
		t.Fatal("no source files found to check — the guard would pass vacuously")
	}
	return files
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- this package's own sources, listed by styleCheckedFiles
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return strings.Split(string(data), "\n")
}
