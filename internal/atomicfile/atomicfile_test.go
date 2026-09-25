// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package atomicfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The result is a regular 0600 file with the new contents, a symlink planted
// where a temp file might go is never written through, and no temp is left.
func TestWriteFile(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "state.json")
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{dest + ".tmp", filepath.Join(dir, ".tmp-")} {
		if err := os.Symlink(victim, name); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(dest, []byte("old"), 0o644); err != nil { // #nosec G306 -- a test file, made loose on purpose
		t.Fatal(err)
	}
	if err := WriteFile(dest, []byte("new")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		t.Errorf("dest is %v, want a regular file, 0600", fi.Mode())
	}
	if b, _ := os.ReadFile(dest); string(b) != "new" {
		t.Errorf("dest holds %q, want %q", b, "new")
	}
	if b, _ := os.ReadFile(victim); string(b) != "untouched" {
		t.Errorf("the write went through a planted symlink: victim now %q", b)
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".tmp-") && e.Name() != ".tmp-" {
			t.Errorf("a temp file survived the write: %s", e.Name())
		}
	}
}
