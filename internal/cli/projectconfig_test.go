// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadAsFilePinned(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	proj := filepath.Join(home, "code", "app")
	if err := os.MkdirAll(filepath.Join(proj, ".jit"), 0o755); err != nil {
		t.Fatal(err)
	}

	// No config -> not pinned.
	if readAsFilePinned(proj) {
		t.Error("no config should not pin live")
	}

	// read_as_file: true -> pinned, and inherited by a subdirectory.
	if err := os.WriteFile(filepath.Join(proj, ".jit", "config.yaml"), []byte("read_as_file: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !readAsFilePinned(proj) {
		t.Error("read_as_file: true should pin live")
	}
	sub := filepath.Join(proj, "services", "api")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if !readAsFilePinned(sub) {
		t.Error("read_as_file should be inherited walking up from a subdir")
	}

	// read_as_file: false -> not pinned.
	if err := os.WriteFile(filepath.Join(proj, ".jit", "config.yaml"), []byte("read_as_file: false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if readAsFilePinned(proj) {
		t.Error("read_as_file: false should not pin live")
	}

	// Malformed config -> not pinned (fails safe to swap).
	if err := os.WriteFile(filepath.Join(proj, ".jit", "config.yaml"), []byte("read_as_file: [not a bool\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if readAsFilePinned(proj) {
		t.Error("a malformed config must fail safe (not pinned)")
	}
}
