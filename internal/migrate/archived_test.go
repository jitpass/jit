// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"reflect"
	"testing"
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
