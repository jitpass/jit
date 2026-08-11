// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// plistFor builds a plist in the shape installAgentService writes, so these
// tests read the real document layout rather than a hand-simplified one — the
// Label is a <string> too, and it comes FIRST, which is the whole reason
// plistProgramPath cannot just take the document's first value.
func plistFor(program string) []byte {
	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>com.jitpass.agent</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>service</string>
		<string>run</string>
		<string>--ttl</string>
		<string>5m0s</string>
		<string>--consent</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>StandardOutPath</key>
	<string>/tmp/agent.log</string>
</dict>
</plist>
`, program))
}

func TestPlistProgramPath(t *testing.T) {
	t.Run("reads the program, not the label", func(t *testing.T) {
		got, ok := plistProgramPath(plistFor("/Users/x/.local/bin/jit"))
		if !ok {
			t.Fatal("plistProgramPath reported no program")
		}
		if got != "/Users/x/.local/bin/jit" {
			t.Errorf("got %q, want the ProgramArguments path (the Label sorts first in the document)", got)
		}
	})

	t.Run("a path with XML metacharacters survives", func(t *testing.T) {
		// Directory names really do contain "&" — installAgentService escapes
		// on the way in, so the value read back is the escaped form. What
		// matters here is that the reader returns the ProgramArguments entry
		// rather than stopping at the first entity.
		got, ok := plistProgramPath(plistFor("/Users/x/R&amp;D/jit"))
		if !ok || got != "/Users/x/R&amp;D/jit" {
			t.Errorf("got %q ok=%v, want the full escaped path", got, ok)
		}
	})

	t.Run("no ProgramArguments key", func(t *testing.T) {
		if _, ok := plistProgramPath([]byte("<plist><dict><key>Label</key><string>x</string></dict></plist>")); ok {
			t.Error("reported a program for a plist that has no ProgramArguments")
		}
	})

	t.Run("empty input", func(t *testing.T) {
		if _, ok := plistProgramPath(nil); ok {
			t.Error("reported a program for empty input")
		}
	})
}

// TestAgentPlistNeedsRepoint is the guard on the bug itself: `jit service
// restart` claimed "the service is now running the current binary" while only
// bootout/bootstrapping whatever plist was on disk. When that plist named a
// different binary — in the field, a build under /private/tmp that another
// process had installed — the claim was false and `jit service status`
// contradicted it immediately, while still advising the restart that could
// not fix it.
func TestAgentPlistNeedsRepoint(t *testing.T) {
	self, err := agentBinaryPath()
	if err != nil {
		t.Skipf("cannot resolve this test binary's path: %v", err)
	}

	t.Run("plist naming another binary needs a repoint", func(t *testing.T) {
		if !agentPlistNeedsRepoint(plistFor("/private/tmp/some-other-session/jit")) {
			t.Error("a plist pointing at a different binary should need repointing")
		}
	})

	t.Run("plist naming this binary does not", func(t *testing.T) {
		if agentPlistNeedsRepoint(plistFor(self)) {
			t.Error("a plist already pointing here should be reloaded in place, not rewritten")
		}
	})

	t.Run("unreadable plist keeps the old behaviour", func(t *testing.T) {
		// Uncertainty must not trigger a rewrite: reloading in place is what
		// restart did for its whole life, and a plist this cannot parse is not
		// evidence that anything is wrong with it.
		if agentPlistNeedsRepoint([]byte("not a plist")) {
			t.Error("an unparseable plist should not trigger a rewrite")
		}
	})
}

// TestAgentBinaryPathResolvesSymlinks pins why installAgentService resolves at
// all: launchd re-execs the recorded path at every login, so recording a
// symlink that a later upgrade replaces would leave the service pointing at
// nothing.
func TestAgentBinaryPathResolvesSymlinks(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real-jit")
	if err := os.WriteFile(real, []byte("#!/bin/sh\n"), 0o700); err != nil { // #nosec G306 -- a fake executable in a temp dir
		t.Fatal(err)
	}
	link := filepath.Join(dir, "jit")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	got, err := filepath.EvalSymlinks(link)
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("EvalSymlinks(%q) = %q, want %q", link, got, want)
	}
}

// TestBothServicePathsRepoint is a source-level guard, in the spirit of
// outputstyle_test.go: two commands move the service onto a new binary —
// `jit service restart` and `jit upgrade` — and both were written as a bare
// reload that silently kept the service on whatever binary the plist named.
// The bug was fixed in one place first; this makes sure a future edit cannot
// quietly restore the bare-reload version in either.
func TestBothServicePathsRepoint(t *testing.T) {
	for _, file := range []string{"agent.go", "upgrade.go"} {
		data, err := os.ReadFile(file) // #nosec G304 -- this package's own sources
		if err != nil {
			t.Fatalf("reading %s: %v", file, err)
		}
		if !strings.Contains(string(data), "agentPlistNeedsRepoint(") {
			t.Errorf("%s no longer checks agentPlistNeedsRepoint. A plain "+
				"reloadAgentService leaves the service running whatever binary the "+
				"plist names, which is the exact bug both call sites exist to avoid.", file)
		}
	}
}

// TestAgentPlistOrphaned pins the self-heal trigger in ensureAgentInstalled:
// only a plist whose program binary is definitely gone counts as orphaned —
// a healthy plist and a missing plist both answer false.
func TestAgentPlistOrphaned(t *testing.T) {
	home := shortFixtureHome(t)

	if agentPlistOrphaned() {
		t.Fatal("agentPlistOrphaned = true with no plist installed; want false")
	}

	dir := filepath.Join(home, "Library", "LaunchAgents")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	plistPath := filepath.Join(dir, agentPlistLabel+".plist")

	present := filepath.Join(home, "jit")
	if err := os.WriteFile(present, []byte("#!/bin/sh\n"), 0o755); err != nil { // #nosec G306 -- a fake executable in a test fixture
		t.Fatalf("WriteFile: %v", err)
	}
	plist := fmt.Sprintf(agentPlistTemplate, agentPlistLabel, present, (5 * time.Minute).String(), "", "/x/agent.log", "/x/agent.log")
	if err := os.WriteFile(plistPath, []byte(plist), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if agentPlistOrphaned() {
		t.Error("agentPlistOrphaned = true for a plist whose binary exists; want false")
	}

	gone := filepath.Join(home, "Caskroom", "jitpass", "0.80.1", "jit")
	plist = fmt.Sprintf(agentPlistTemplate, agentPlistLabel, gone, (5 * time.Minute).String(), "", "/x/agent.log", "/x/agent.log")
	if err := os.WriteFile(plistPath, []byte(plist), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if !agentPlistOrphaned() {
		t.Error("agentPlistOrphaned = false for a plist whose binary is gone; want true")
	}
}
