// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"io/fs"
	"path/filepath"
	"testing"
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
