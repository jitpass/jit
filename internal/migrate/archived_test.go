// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package migrate

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/jitpass/jit/internal/audit"
)

func TestLooksArchived(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/Users/alex/Documents/archive/ai_security_workspace/.env", true},
		{"/Users/alex/Documents/Archive/ai_security_workspace/.env", true}, // case-insensitive
		{"/Users/alex/Documents/archived/old-project/.env", true},
		{"/Users/alex/.Trash/some-project/.env", true},
		{"/Users/alex/backups/2024/.env", true},
		{"/Users/alex/Documents/myapp/.env", false},
		{"/Users/alex/Documents/archive-service/.env", false}, // "archive-service" is not the exact component "archive"
	}
	for _, c := range cases {
		if got := LooksArchived(c.path); got != c.want {
			t.Errorf("LooksArchived(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestFilterArchived(t *testing.T) {
	paths := []string{
		"/Users/alex/Documents/myapp/.env",
		"/Users/alex/Documents/archive/old/.env",
		"/Users/alex/Repos/service/.env",
		"/Users/alex/.Trash/thing/.env",
	}
	kept, skipped := FilterArchived(paths)

	wantKept := []string{"/Users/alex/Documents/myapp/.env", "/Users/alex/Repos/service/.env"}
	wantSkipped := []string{"/Users/alex/Documents/archive/old/.env", "/Users/alex/.Trash/thing/.env"}
	if !reflect.DeepEqual(kept, wantKept) {
		t.Errorf("kept = %v, want %v", kept, wantKept)
	}
	if !reflect.DeepEqual(skipped, wantSkipped) {
		t.Errorf("skipped = %v, want %v", skipped, wantSkipped)
	}
}

func TestFilterArchivedNoMatches(t *testing.T) {
	paths := []string{"/Users/alex/Documents/myapp/.env"}
	kept, skipped := FilterArchived(paths)
	if !reflect.DeepEqual(kept, paths) {
		t.Errorf("kept = %v, want %v", kept, paths)
	}
	if skipped != nil {
		t.Errorf("skipped = %v, want nil", skipped)
	}
}

// TestFilterPlayground pins the whole-machine sweep's playground
// exclusion: a finding inside a .jitpass-playground-marked checkout is
// synthetic bait audit already excludes from its score, and migrate must
// skip (not vault) it — while everything else passes through untouched.
func TestFilterPlayground(t *testing.T) {
	home := t.TempDir()
	playground := filepath.Join(home, "jitpass-playground")
	if err := os.MkdirAll(playground, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(playground, audit.PlaygroundMarkerFile), nil, 0o600); err != nil {
		t.Fatalf("WriteFile marker: %v", err)
	}
	for _, p := range []string{
		filepath.Join(playground, "api", ".env"),
		filepath.Join(home, "myapp", ".env"),
	} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(p, []byte("A=1\n"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	paths := []string{
		filepath.Join(home, "myapp", ".env"),
		filepath.Join(playground, "api", ".env"),
	}
	kept, skipped := FilterPlayground(home, paths)
	wantKept := []string{filepath.Join(home, "myapp", ".env")}
	wantSkipped := []string{filepath.Join(playground, "api", ".env")}
	if !reflect.DeepEqual(kept, wantKept) {
		t.Errorf("kept = %v, want %v", kept, wantKept)
	}
	if !reflect.DeepEqual(skipped, wantSkipped) {
		t.Errorf("skipped = %v, want %v", skipped, wantSkipped)
	}

	// Rooted inside the playground itself (the first-run tour's `jit
	// migrate local` practice path), nothing is synthetic: the filter
	// must keep everything.
	kept, skipped = FilterPlayground(playground, wantSkipped)
	if !reflect.DeepEqual(kept, wantSkipped) || skipped != nil {
		t.Errorf("home-in-playground: kept = %v, skipped = %v, want everything kept", kept, skipped)
	}
}
