// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package migrate

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/vault"
)

// TestEnvFileMigrationStampsSharedProvenance proves the wiring end to end:
// every secret pulled from one .env lands with class=dotenv, the SAME group
// id (so "these all came from one file" is a durable fact, not a path
// inference), and an origin that points back at the source. A second file's
// secrets get a DIFFERENT group id.
func TestEnvFileMigrationStampsSharedProvenance(t *testing.T) {
	root := t.TempDir()
	v := newTestVault(t)

	pathA := filepath.Join(root, "svc-a", ".env")
	writeFile(t, pathA, "API_KEY=aaa\nDB_URL=bbb\nDEBUG=ccc\n")
	if _, err := ApplyEnvFile(v, root, pathA); err != nil {
		t.Fatalf("ApplyEnvFile A: %v", err)
	}

	pathB := filepath.Join(root, "svc-b", ".env")
	writeFile(t, pathB, "TOKEN=zzz\n")
	if _, err := ApplyEnvFile(v, root, pathB); err != nil {
		t.Fatalf("ApplyEnvFile B: %v", err)
	}

	paths, err := v.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	var groupA string
	seenB := false
	for _, p := range paths {
		// _backups/... are jit's own encrypted file backups (bare Set, no
		// provenance by design), not user secrets — the list rendering keeps
		// them separate too.
		if strings.HasPrefix(p, "_backups/") {
			continue
		}
		info, err := v.Info(p)
		if err != nil {
			t.Fatalf("Info %s: %v", p, err)
		}
		if info.Class != vault.ClassDotenv {
			t.Errorf("%s class = %q, want %q", p, info.Class, vault.ClassDotenv)
		}
		if info.GroupID == "" {
			t.Errorf("%s has no group id", p)
		}
		if info.Origin == "" {
			t.Errorf("%s has no origin", p)
		}

		switch {
		case containsPathSegment(info.Origin, "svc-a"):
			if groupA == "" {
				groupA = info.GroupID
			} else if info.GroupID != groupA {
				t.Errorf("%s: svc-a secrets have differing group ids %q vs %q, want one shared id", p, info.GroupID, groupA)
			}
		case containsPathSegment(info.Origin, "svc-b"):
			seenB = true
			if groupA != "" && info.GroupID == groupA {
				t.Errorf("%s: svc-b secret shares svc-a's group id %q, want a distinct group per source file", p, groupA)
			}
		}
	}
	if groupA == "" {
		t.Fatal("no svc-a secrets found")
	}
	if !seenB {
		t.Fatal("no svc-b secret found")
	}
}

func containsPathSegment(origin, seg string) bool {
	return filepath.Base(filepath.Dir(origin)) == seg
}
