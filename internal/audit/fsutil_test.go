// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func walkAndCollect(t *testing.T, root string) []string {
	t.Helper()
	var found []string
	err := walkHomeDir(root, func(path string, d fs.DirEntry) error {
		found = append(found, path)
		return nil
	})
	if err != nil {
		t.Fatalf("walkHomeDir: %v", err)
	}
	return found
}

func contains(paths []string, want string) bool {
	for _, p := range paths {
		if p == want {
			return true
		}
	}
	return false
}

// TestWalkHomeDirSkipsGoModCache locks in a real-world dogfooding finding
// (2026-07-06): the Go module cache holds third-party package source and
// testdata, never the user's own files, and was showing up as false
// positives (including this project's own gosec dependency).
func TestWalkHomeDirSkipsGoModCache(t *testing.T) {
	home := t.TempDir()
	noise := filepath.Join(home, "go", "pkg", "mod", "github.com", "example", "pkg@v1.0.0", ".env.example")
	mkdirAll(t, filepath.Dir(noise))
	writeFile(t, noise, "SOME_VAR=placeholder\n")

	real := filepath.Join(home, "code", "myproject", ".env")
	mkdirAll(t, filepath.Dir(real))
	writeFile(t, real, "SOME_VAR=placeholder\n")

	found := walkAndCollect(t, home)
	if contains(found, noise) {
		t.Errorf("walkHomeDir must skip the Go module cache, but found %q", noise)
	}
	if !contains(found, real) {
		t.Errorf("walkHomeDir should still find the user's own project file %q", real)
	}
}

// TestWalkHomeDirSkipsVSCodeExtensionsButNotProjectVSCode locks in the
// other real-world finding: installed VS Code extensions ship bundled
// example content that isn't the user's own, but a project-local .vscode
// directory (e.g. its own .vscode/mcp.json) must still be scanned.
func TestWalkHomeDirSkipsVSCodeExtensionsButNotProjectVSCode(t *testing.T) {
	home := t.TempDir()
	extensionNoise := filepath.Join(home, ".vscode", "extensions", "some.extension-1.0.0", "snippets", "secret.yaml")
	mkdirAll(t, filepath.Dir(extensionNoise))
	writeFile(t, extensionNoise, "kind: Secret\n")

	projectFile := filepath.Join(home, "code", "myproject", ".vscode", "mcp.json")
	mkdirAll(t, filepath.Dir(projectFile))
	writeFile(t, projectFile, `{"servers":{}}`)

	found := walkAndCollect(t, home)
	if contains(found, extensionNoise) {
		t.Errorf("walkHomeDir must skip ~/.vscode/extensions, but found %q", extensionNoise)
	}
	if !contains(found, projectFile) {
		t.Errorf("walkHomeDir should still find a project-local .vscode file %q", projectFile)
	}
}

// A FIFO at a fixed-path credential store must not hang the scan.
//
// The fixed-path scanners are checked outside walkHomeDir's regular-file
// guard, and several opened their path with no guard of their own. `mkfifo
// ~/.kube/config` therefore parked `jit scan` in open(2) indefinitely — no
// output, no error, nothing to indicate why. jit's own migrate creates FIFOs
// for a living, so this is jit's shape of file, not an exotic one.
func TestScanDoesNotHangOnFIFOAtFixedPath(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, ".kube"))
	fifo := filepath.Join(home, ".kube", "config")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, _, err := Scan(Config{HomeDir: home, RunID: "test", ScannerVersion: "test"})
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Scan blocked on a FIFO at ~/.kube/config: it is waiting in open(2) for a writer that will never come")
	}
}

// openFile must not follow a symlink out of the scanned tree.
//
// privatekey.go read through one and reported the target's contents under the
// LINK's path — a finding naming a file whose content lives somewhere else,
// and a silent widening of the scan past $HOME. walkHomeDir already refused to
// follow symlinks; the fixed-path and ReadDir-driven scanners did not.
func TestOpenFileRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "outside-secret")
	writeFile(t, target, "-----BEGIN OPENSSH PRIVATE KEY-----\n")
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	if _, err := openFile(link); err == nil {
		t.Error("openFile followed a symlink; a finding would be reported at the link's path, not where the content lives")
	}
	if _, err := readFile(link); err == nil {
		t.Error("readFile followed a symlink")
	}
	// The real file itself must still open normally.
	f, err := openFile(target)
	if err != nil {
		t.Fatalf("openFile refused an ordinary regular file: %v", err)
	}
	_ = f.Close()
}
