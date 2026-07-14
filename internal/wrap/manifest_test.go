// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package wrap

import (
	"os"
	"testing"
	"time"
)

func TestLoadManifestMissingFileIsEmptyAndUsable(t *testing.T) {
	m, err := LoadManifest(t.TempDir())
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if len(m.Tools) != 0 {
		t.Errorf("expected no tools, got %v", m.Tools)
	}
	m.Tools["gh"] = Entry{Profile: "wrap-gh"} // must not panic on a nil map
}

func TestManifestRoundTrip(t *testing.T) {
	home := t.TempDir()
	m := Manifest{Tools: map[string]Entry{
		"gh": {Profile: "wrap-gh", Vars: []string{"GH_TOKEN"}, AddedAt: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)},
	}}
	if err := m.Save(home); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(ManifestPath(home))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("manifest mode = %o, want 0600", perm)
	}

	got, err := LoadManifest(home)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	entry, ok := got.Tools["gh"]
	if !ok {
		t.Fatalf("gh missing after round trip: %v", got.Tools)
	}
	if entry.Profile != "wrap-gh" || len(entry.Vars) != 1 || entry.Vars[0] != "GH_TOKEN" {
		t.Errorf("entry mangled: %+v", entry)
	}
	if !entry.AddedAt.Equal(m.Tools["gh"].AddedAt) {
		t.Errorf("AddedAt = %v, want %v", entry.AddedAt, m.Tools["gh"].AddedAt)
	}
}

func TestLoadManifestCorruptFileErrors(t *testing.T) {
	home := t.TempDir()
	if err := (Manifest{}).Save(home); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ManifestPath(home), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManifest(home); err == nil {
		t.Error("expected an error for a corrupt manifest")
	}
}
