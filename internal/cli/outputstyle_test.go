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
// through the semantic helpers in style.go (cBold, cPath, cOK, cWarn,
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
				"(cBold, cPath, cOK, cWarn, cRisk, cPathBold, cOKBold) so a palette "+
				"change stays one edit.\n    %s",
				filepath.Base(file), i+1, strings.TrimSpace(line))
		}
	}
}

// TestPaletteIsCentralised keeps every ink in internal/style. The dim removal
// on 2026-08-06 is the case for this: the house style claimed one vocabulary,
// but internal/audit and internal/ui had quietly grown their own color.New
// calls, so a one-line palette change became a twelve-site hunt across three
// packages — and the sites the grep nearly missed were the ones rendering the
// report a user actually reads.
//
// Four known-drift lines in internal/audit/report.go are allowed by name until
// their preview decision lands: severity/risk Low in cyan (cyan is reserved
// for what the reader can type) and Info in FgWhite (a seventh ink). They are
// listed rather than pattern-matched so they cannot quietly multiply.
func TestPaletteIsCentralised(t *testing.T) {
	allowed := map[string]int{
		filepath.Join("..", "audit", "report.go"): 4,
		filepath.Join("..", "style", "style.go"):  100, // the definitions
	}
	found := map[string]int{}
	err := filepath.WalkDir("..", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "spike" || d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, readErr := os.ReadFile(path) // #nosec G304 -- walking the repo's own sources
		if readErr != nil {
			return readErr
		}
		for i, line := range strings.Split(string(data), "\n") {
			if !strings.Contains(line, "color.New(") {
				continue
			}
			found[path]++
			if found[path] <= allowed[path] {
				continue
			}
			t.Errorf("%s:%d builds a color by hand. Add it to internal/style and use "+
				"the semantic name, so a palette change stays one edit.\n    %s",
				path, i+1, strings.TrimSpace(line))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking internal: %v", err)
	}
	if found[filepath.Join("..", "style", "style.go")] == 0 {
		t.Fatal("no colors found in internal/style — the guard would pass vacuously")
	}
}

// TestNoFaintText keeps dim/faint text out of the whole binary, not just this
// package. jit rendered everything secondary with ESC[2m until 2026-08-06,
// which most terminals draw at around half opacity: on a dark theme that made
// the majority of a scan report — every manifest path, every address in the
// manual section, every count in `jit status` — genuinely hard to read.
// Secondary text is now written plain and inherits the terminal's own
// foreground; hierarchy comes from bold and semantic colour.
//
// The guard is repo-wide because the faint constructors were never centralised
// the way the hues are: internal/audit and internal/ui each built their own,
// so a style.go-only rule would have missed two thirds of them. It covers test
// files too — a test that asserts a faint escape is a test that would hold the
// old style in place.
func TestNoFaintText(t *testing.T) {
	roots := []string{"..", filepath.Join("..", "..", "cmd")}
	// The needle is assembled rather than written out so this file, which has
	// to name the thing it bans, does not trip its own check.
	needles := []string{"color." + "Faint", "\\x1b[2m", "\\033[2m", "\\e[2m"}
	checked := 0
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "spike" || d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || filepath.Base(path) == "outputstyle_test.go" {
				return nil
			}
			data, readErr := os.ReadFile(path) // #nosec G304 -- walking the repo's own sources
			if readErr != nil {
				return readErr
			}
			checked++
			for i, line := range strings.Split(string(data), "\n") {
				for _, needle := range needles {
					if strings.Contains(line, needle) {
						t.Errorf("%s:%d renders dim/faint text (%s). Secondary text is written "+
							"plain — see the palette table in design/output-style.md.\n    %s",
							path, i+1, needle, strings.TrimSpace(line))
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", root, err)
		}
	}
	if checked == 0 {
		t.Fatal("no source files walked — the guard would pass vacuously")
	}
}

// TestDoctorsRenderNoLiteralBackticks is the guard the two lints above
// structurally cannot be: it checks rendered OUTPUT, not source.
//
// The retired `jit wrap doctor` printed literal backticks in dim grey for as
// long as it existed, while `jit doctor` rendered the very same strings —
// wrap.Doctor's Detail fields, which both surfaces still share — as cyan
// commands. One string, two appearances, depending on which command you
// typed: exactly the drift rule 5 names. Neither lint saw it, and neither
// could have. TestNoUnroutedCommandBackticks scans this
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
		{"jit doctor --wrap", []string{"doctor", "--wrap"}},
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
