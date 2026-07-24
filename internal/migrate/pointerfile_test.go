// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/profile"
)

func TestPointerFilePath(t *testing.T) {
	got := PointerFilePath("/Users/alex/code/myapp/.env")
	want := "/Users/alex/code/myapp/.env.pointers"
	if got != want {
		t.Errorf("PointerFilePath = %q, want %q", got, want)
	}
}

func TestWritePointerFileNeverContainsRealValues(t *testing.T) {
	dir := t.TempDir()
	mountPath := filepath.Join(dir, ".env")
	vars := profile.Profile{
		"DATABASE_URL":   "myapp/DATABASE_URL",
		"STRIPE_API_KEY": "myapp/STRIPE_API_KEY",
	}

	if err := WritePointerFile(mountPath, vars, nil); err != nil {
		t.Fatalf("WritePointerFile: %v", err)
	}

	data, err := os.ReadFile(PointerFilePath(mountPath))
	if err != nil {
		t.Fatalf("reading pointer file: %v", err)
	}
	content := string(data)

	for name, path := range vars {
		wantLine := name + "=jit://vault/" + path
		if !strings.Contains(content, wantLine) {
			t.Errorf("expected pointer file to contain %q, got:\n%s", wantLine, content)
		}
	}
	// The whole point: never a real secret value, only vault paths. Since
	// this test has no real value to check against directly, assert the
	// shape instead — every non-comment line must contain the jit://
	// pointer scheme, never a bare assignment.
	for _, line := range strings.Split(strings.TrimSpace(content), "\n") {
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if !strings.Contains(line, "=jit://vault/") {
			t.Errorf("expected every variable line to use the jit://vault/ pointer scheme, got: %q", line)
		}
	}
}

func TestWritePointerFileIsSortedAndDeterministic(t *testing.T) {
	dir := t.TempDir()
	mountPath := filepath.Join(dir, ".env")
	vars := profile.Profile{
		"ZEBRA": "myapp/ZEBRA",
		"APPLE": "myapp/APPLE",
	}

	if err := WritePointerFile(mountPath, vars, nil); err != nil {
		t.Fatalf("WritePointerFile: %v", err)
	}
	data, err := os.ReadFile(PointerFilePath(mountPath))
	if err != nil {
		t.Fatalf("reading pointer file: %v", err)
	}

	appleIdx := strings.Index(string(data), "APPLE=")
	zebraIdx := strings.Index(string(data), "ZEBRA=")
	if appleIdx == -1 || zebraIdx == -1 || appleIdx > zebraIdx {
		t.Errorf("expected APPLE before ZEBRA (sorted), got:\n%s", data)
	}
}

func TestWritePointerFileNeverCreatesAFIFO(t *testing.T) {
	dir := t.TempDir()
	mountPath := filepath.Join(dir, ".env")
	if err := WritePointerFile(mountPath, profile.Profile{"A": "myapp/A"}, nil); err != nil {
		t.Fatalf("WritePointerFile: %v", err)
	}

	info, err := os.Lstat(PointerFilePath(mountPath))
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	if info.Mode()&os.ModeNamedPipe != 0 {
		t.Error("pointer file must never be a FIFO, the whole point is it's safe to stat/mmap/peek casually")
	}
	if !info.Mode().IsRegular() {
		t.Errorf("pointer file mode = %v, want a regular file", info.Mode())
	}
}
