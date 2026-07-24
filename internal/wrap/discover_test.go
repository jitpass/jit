// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package wrap

import "testing"

func TestDiscoverTokenPrefersSourcesInOrder(t *testing.T) {
	gh, _ := Lookup("gh")
	home := fixtureHomeFor(t, gh.Sources[0], "gh/hosts.yml")

	d, found, err := DiscoverToken(home, gh)
	if err != nil || !found {
		t.Fatalf("DiscoverToken = (found=%v, err=%v)", found, err)
	}
	if d.Source == nil || d.Source.Path != gh.Sources[0].Path {
		t.Errorf("expected the file source to win, got %+v", d.Source)
	}
	if d.Value != "gho_FIXTUREtoken1234567890abcdefFIXTURE" {
		t.Errorf("wrong value: %q", d.Value)
	}
}

func TestDiscoverTokenFallsBackToTokenCommand(t *testing.T) {
	entry := CatalogEntry{
		Tool:         "faketool",
		Kind:         KindShim,
		EnvVars:      map[string]string{"T": "T"},
		Order:        []string{"T"},
		Sources:      []TokenSource{{Path: "~/nonexistent.yml", Format: "yaml", Selector: "token"}},
		TokenCommand: []string{"echo", "token-from-command"},
	}
	d, found, err := DiscoverToken(t.TempDir(), entry)
	if err != nil || !found {
		t.Fatalf("DiscoverToken = (found=%v, err=%v)", found, err)
	}
	if d.Value != "token-from-command" || d.Source != nil {
		t.Errorf("expected the command fallback with nil Source, got %+v", d)
	}
}

func TestDiscoverTokenNotFoundIsCalm(t *testing.T) {
	entry := CatalogEntry{
		Tool:    "faketool",
		Kind:    KindShim,
		EnvVars: map[string]string{"T": "T"},
		Order:   []string{"T"},
		Sources: []TokenSource{{Path: "~/nonexistent.yml", Format: "yaml", Selector: "token"}},
	}
	_, found, err := DiscoverToken(t.TempDir(), entry)
	if err != nil || found {
		t.Fatalf("want (found=false, err=nil), got (%v, %v)", found, err)
	}
}
