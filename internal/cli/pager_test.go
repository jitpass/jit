// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

func TestResolvePagerPrecedence(t *testing.T) {
	cases := []struct {
		name, jitPager, pager string
		setJit, setPager      bool
		want                  string
	}{
		{name: "default is less", want: "less"},
		{name: "PAGER honored", setPager: true, pager: "more", want: "more"},
		{name: "JIT_PAGER wins", setJit: true, jitPager: "bat", setPager: true, pager: "more", want: "bat"},
		{name: "cat disables", setPager: true, pager: "cat", want: ""},
		{name: "empty disables", setJit: true, jitPager: "", want: ""},
		{name: "value with flags kept verbatim", setPager: true, pager: "less -S", want: "less -S"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Unset both first: the test process inherits the developer's own
			// PAGER, and t.Setenv restores whatever was there afterwards.
			for _, k := range []string{"JIT_PAGER", "PAGER"} {
				t.Setenv(k, "")
				os.Unsetenv(k)
			}
			if tc.setJit {
				t.Setenv("JIT_PAGER", tc.jitPager)
			}
			if tc.setPager {
				t.Setenv("PAGER", tc.pager)
			}
			if got := resolvePager(); got != tc.want {
				t.Errorf("resolvePager() = %q, want %q", got, tc.want)
			}
		})
	}
}

// A command whose output was substituted (every test, and any caller writing
// to a buffer or file) must get its writer back untouched: the pager only
// ever fronts the process's real terminal.
func TestPageableOutputPassesNonStdoutThrough(t *testing.T) {
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	out, done := pageableOutput(cmd)
	done()
	if out != &buf {
		t.Fatalf("pageableOutput substituted a writer for a non-stdout output")
	}
}

func TestSimplePagerName(t *testing.T) {
	for cmdline, want := range map[string]string{
		"less":            "less",
		"less -S -+F":     "less",
		"more":            "more",
		"col -b | less":   "", // pipeline: the shell's business
		"$HOME/bin/pager": "", // variable: ditto
		"  ":              "",
	} {
		name, ok := simplePagerName(cmdline)
		if ok != (want != "") || name != want {
			t.Errorf("simplePagerName(%q) = %q, %v; want %q", cmdline, name, ok, want)
		}
	}
}

// A pager that spawns streams the report and delivers it whole once closed.
func TestPagerWriterStreamsThroughARealPager(t *testing.T) {
	path := filepath.Join(t.TempDir(), "paged")
	dst, err := os.Create(path) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()

	p := &pagerWriter{cmdline: "cat", dst: dst}
	if _, err := p.Write([]byte("first line\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Write([]byte("second line\n")); err != nil {
		t.Fatal(err)
	}
	p.close()

	got, err := os.ReadFile(path) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "first line\nsecond line\n" {
		t.Errorf("paged output = %q", got)
	}
}

// A pager that doesn't exist must cost nothing but a stderr note: the report
// itself falls through to the terminal.
func TestPagerWriterFallsBackWhenPagerMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "direct")
	dst, err := os.Create(path) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()

	p := &pagerWriter{cmdline: "definitely-not-a-pager-jit-test", dst: dst}
	if _, err := p.Write([]byte("the report\n")); err != nil {
		t.Fatal(err)
	}
	p.close()

	got, err := os.ReadFile(path) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "the report\n" {
		t.Errorf("fallback output = %q, want the report delivered directly", got)
	}
}
