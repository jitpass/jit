// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// `jit scan` is read-only in EVERY mode, with no flag that makes it write.
// CLAUDE.md calls that "a stated guarantee, not an accident of layering", and
// internal/migrate exists as a separate command precisely to keep the boundary.
//
// Until now nothing enforced it. The guarantee held — one file-opening call in
// the whole package, O_RDONLY|O_NOFOLLOW|O_NONBLOCK — but it held by everyone
// remembering, and the way it would break is not a bug report: a scanner that
// writes a cache, touches an mtime, or "repairs" a malformed config would look
// like a feature, pass review, and quietly turn the one command users are told
// they can run on a machine they don't trust into one that modifies it.
//
// So this is a source-scanning guard, the same shape as TestNoFaintText and
// TestPaletteIsCentralised: it reads this package's own .go files rather than
// exercising behaviour, because the property is "this call never appears here",
// which no amount of black-box testing can establish.
//
// Scope note: it checks internal/audit only. That is the whole scan engine —
// internal/cli owns the command wiring and legitimately writes (its config
// root, the audit log), so widening this to cli would be a different, mostly
// false-positive test.
func TestAuditPackageNeverWrites(t *testing.T) {
	// Calls that create, modify, move or delete anything on disk. os.OpenFile
	// is handled separately below, since read-only is a legitimate use of it.
	forbidden := regexp.MustCompile(`\bos\.(Create|CreateTemp|WriteFile|Remove|RemoveAll|Rename|Mkdir|MkdirAll|Chmod|Chown|Chtimes|Truncate|Symlink|Link|Pipe)\(`)
	// A write through a *os.File or an io.Writer bound to one. The audit
	// package writes reports to an io.Writer the CALLER supplies, so
	// Fprintf/Fprintln are everywhere and legitimate; what must not appear is
	// a file handle this package opened for writing.
	openFileCall := regexp.MustCompile(`\bos\.OpenFile\(`)
	writeFlag := regexp.MustCompile(`os\.O_(WRONLY|RDWR|CREATE|APPEND|TRUNC|EXCL)`)

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading package dir: %v", err)
	}

	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		scanned++
		for i, line := range strings.Split(string(data), "\n") {
			loc := filepath.Join("internal/audit", name)
			if m := forbidden.FindString(line); m != "" {
				t.Errorf("%s:%d calls %s — `jit scan` is read-only in every mode; the fix path is internal/migrate",
					loc, i+1, strings.TrimSuffix(m, "("))
			}
			// The one legitimate open is read-only. Any write flag on it is
			// the same violation as os.Create, just spelled longer.
			if openFileCall.MatchString(line) && writeFlag.MatchString(line) {
				t.Errorf("%s:%d opens a file with a write flag — scan may only ever open O_RDONLY", loc, i+1)
			}
		}
	}

	// Without this the guard passes vacuously the day the package is split,
	// renamed, or this test is moved somewhere with no sources beside it.
	// TestNoFaintText and the outputstyle guards all end this way for the same
	// reason, and it is the failure mode a source-scanning test has that a
	// behavioural one does not.
	if scanned < 20 {
		t.Fatalf("scanned only %d non-test .go files in internal/audit — the guard would pass vacuously", scanned)
	}
}
