// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package wrap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func doctorFailures(checks []DoctorCheck) []string {
	var fails []string
	for _, c := range checks {
		if !c.OK {
			fails = append(fails, c.Name+": "+c.Detail)
		}
	}
	return fails
}

func TestDoctorHealthyWrap(t *testing.T) {
	home := t.TempDir()
	real := t.TempDir()
	writeExecutable(t, real, "gh")
	res, err := Add(home, AddRequest{
		Tool:      "gh",
		Env:       map[string]string{"GH_TOKEN": "wrap-gh/GH_TOKEN"},
		Order:     []string{"GH_TOKEN"},
		JitBinary: "/usr/bin/true",
	})
	if err != nil {
		t.Fatal(err)
	}
	rc := RcFile(home, "/bin/zsh")
	if _, err := EnsurePathLine(rc); err != nil {
		t.Fatal(err)
	}

	pathEnv := ShimDir(home) + string(os.PathListSeparator) + real
	checks := Doctor(home, pathEnv, "/bin/zsh")
	if fails := doctorFailures(checks); len(fails) != 0 {
		t.Errorf("healthy wrap reported failures:\n%s\nshim=%s", strings.Join(fails, "\n"), res.ShimPath)
	}
}

func TestDoctorNoWrappedToolsIsClean(t *testing.T) {
	checks := Doctor(t.TempDir(), "/usr/bin", "/bin/zsh")
	if len(checks) != 1 || !checks[0].OK {
		t.Errorf("empty state should be one OK check, got %+v", checks)
	}
}

func TestDoctorFlagsBrokenPieces(t *testing.T) {
	home := t.TempDir()
	real := t.TempDir()
	writeExecutable(t, real, "gh")
	if _, err := Add(home, AddRequest{
		Tool:      "gh",
		Env:       map[string]string{"GH_TOKEN": "wrap-gh/GH_TOKEN"},
		Order:     []string{"GH_TOKEN"},
		JitBinary: "/usr/bin/true",
	}); err != nil {
		t.Fatal(err)
	}

	// Break everything: shim gone, profile gone, real tool off PATH, no rc line.
	if _, err := RemoveShim(home, "gh"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(home, ".jit", "profiles", "wrap-gh.yaml")); err != nil {
		t.Fatal(err)
	}

	checks := Doctor(home, "/usr/bin", "/bin/zsh")
	fails := strings.Join(doctorFailures(checks), "\n")
	for _, want := range []string{"PATH", "rc file", "tool gh"} {
		if !strings.Contains(fails, want) {
			t.Errorf("expected a %q failure, got:\n%s", want, fails)
		}
	}
}
