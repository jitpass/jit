// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package vault

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestReservedNamespaceClassification(t *testing.T) {
	cases := []struct {
		path            string
		backup, history bool
	}{
		{"_backups/Users_x_app_.env.jit-bak-1", true, false},
		{"_history/stripe/live-key/1234.enc", false, true},
		{"stripe/live-key", false, false},
		// Neither prefix may match a path that merely CONTAINS the name, or a
		// user's own "backups/…" group would vanish from their vault listing.
		{"backups/thing", false, false},
		{"app/_backups/thing", false, false},
		{"_backupsomething/thing", false, false},
		{"", false, false},
	}
	for _, c := range cases {
		if got := IsBackupPath(c.path); got != c.backup {
			t.Errorf("IsBackupPath(%q) = %v, want %v", c.path, got, c.backup)
		}
		if got := IsHistoryPath(c.path); got != c.history {
			t.Errorf("IsHistoryPath(%q) = %v, want %v", c.path, got, c.history)
		}
		if got, want := IsReservedPath(c.path), c.backup || c.history; got != want {
			t.Errorf("IsReservedPath(%q) = %v, want %v", c.path, got, want)
		}
	}
}

// TestNoRawReservedPrefixOutsideThisFile is the guard that gives the namespaces
// an owner rather than ten copies.
//
// Both prefixes were string literals at ten call sites across internal/cli,
// internal/migrate and this package — and vault itself, the owner, used the
// same bare literal every borrower did. Renaming one fails silently in the
// worst direction: a missed site stops EXCLUDING, so `jit migrate`'s encrypted
// backup copies of credentials start appearing wherever that site feeds.
//
// Walks the whole tree, not just this package: the borrowers are the point.
func TestNoRawReservedPrefixOutsideThisFile(t *testing.T) {
	root := ".."
	var offenders []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		// Test files are exempt ON PURPOSE. A fixture path SHOULD be the
		// literal "_backups/…": building it from the constant under test makes
		// both sides of the comparison move together, which is how an
		// assertion stops being able to fail. Same reasoning that took
		// shortVersion() out of internal/cli's status expectations.
		if strings.HasSuffix(path, "_test.go") || filepath.Base(path) == "namespace.go" {
			return nil
		}
		data, readErr := os.ReadFile(path) // #nosec G304 -- walking jit's own source tree
		if readErr != nil {
			return nil
		}
		for i, line := range strings.Split(string(data), "\n") {
			code := line
			if idx := strings.Index(code, "//"); idx >= 0 {
				code = code[:idx] // prose may name the namespace freely
			}
			// Any occurrence in code, not just a quote-adjacent one: the
			// namespace also appears mid-string in help text, and help that
			// names a directory the vault no longer uses is the same drift
			// with a user on the other end of it.
			if strings.Contains(code, BackupPathPrefix) || strings.Contains(code, HistoryPathPrefix) {
				offenders = append(offenders, filepath.ToSlash(path)+":"+strconv.Itoa(i+1))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree: %v", err)
	}
	if len(offenders) > 0 {
		t.Errorf("reserved namespace spelled out in code rather than using vault's constants:\n  %s\n"+
			"use BackupPathPrefix/HistoryPathPrefix or IsBackupPath/IsHistoryPath/IsReservedPath",
			strings.Join(offenders, "\n  "))
	}
}
