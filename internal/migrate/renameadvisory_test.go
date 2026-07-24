// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"os"
	"path/filepath"
	"testing"
)

// writePointer drops a pointer companion (<envName>.pointers) under dir whose
// lines reference the given namespace, mimicking what WritePointerFile leaves
// behind for a migrated env file.
func writePointer(t *testing.T, dir, envName, ns string) {
	t.Helper()
	content := pointerFileHeaderPrefix + ", no secret values here, only vault paths.\n" +
		"API_KEY=jit://vault/" + ns + "/API_KEY\n" +
		"DB_URL=jit://vault/" + ns + "/DB_URL\n"
	writeFile(t, filepath.Join(dir, envName+".pointers"), content)
}

func TestDetectRenamedRootProject(t *testing.T) {
	tests := []struct {
		name        string
		folderName  string
		setup       func(t *testing.T, root string)
		wantOK      bool
		wantOldName string
	}{
		{
			name:       "root .env migrated then folder renamed",
			folderName: "notion-app",
			setup: func(t *testing.T, root string) {
				writePointer(t, root, ".env", "notion")
			},
			wantOK:      true,
			wantOldName: "notion",
		},
		{
			name:       "folder name still matches namespace",
			folderName: "notion",
			setup: func(t *testing.T, root string) {
				writePointer(t, root, ".env", "notion")
			},
			wantOK: false,
		},
		{
			name:       "variant suffix compares folder stem, not qualified namespace",
			folderName: "notion-app",
			setup: func(t *testing.T, root string) {
				writePointer(t, root, ".env.local", "notion-local")
			},
			wantOK:      true,
			wantOldName: "notion",
		},
		{
			name:       "variant suffix, unrenamed folder is silent",
			folderName: "notion",
			setup: func(t *testing.T, root string) {
				writePointer(t, root, ".env.local", "notion-local")
			},
			wantOK: false,
		},
		{
			name:       "case-only rename is not flagged",
			folderName: "Notion",
			setup: func(t *testing.T, root string) {
				writePointer(t, root, ".env", "notion")
			},
			wantOK: false,
		},
		{
			name:       "subfolder pointer never reaches the root check",
			folderName: "notion-app",
			setup: func(t *testing.T, root string) {
				sub := filepath.Join(root, "services", "api")
				if err := os.MkdirAll(sub, 0o755); err != nil {
					t.Fatal(err)
				}
				// A subfolder migration's pointer lives under the subdir and
				// records a non-basename namespace; it must not be read here.
				writePointer(t, sub, ".env", "services-api")
			},
			wantOK: false,
		},
		{
			name:       "no pointer companions at all",
			folderName: "notion-app",
			setup:      func(t *testing.T, root string) {},
			wantOK:     false,
		},
		{
			name:       "a real (unmigrated) .env is not a pointer and is ignored",
			folderName: "notion-app",
			setup: func(t *testing.T, root string) {
				writeFile(t, filepath.Join(root, ".env"), "API_KEY=real-value\n")
			},
			wantOK: false,
		},
		{
			name:       "empty pointer file is ignored",
			folderName: "notion-app",
			setup: func(t *testing.T, root string) {
				writeFile(t, filepath.Join(root, ".env.pointers"), "")
			},
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Build the project under a parent so filepath.Base(root) is the
			// folder name under test.
			parent := t.TempDir()
			root := filepath.Join(parent, tc.folderName)
			if err := os.MkdirAll(root, 0o755); err != nil {
				t.Fatal(err)
			}
			tc.setup(t, root)

			oldName, newName, ok := DetectRenamedRootProject(root)
			if ok != tc.wantOK {
				t.Fatalf("DetectRenamedRootProject ok = %v, want %v (old=%q new=%q)", ok, tc.wantOK, oldName, newName)
			}
			if !ok {
				return
			}
			if oldName != tc.wantOldName {
				t.Fatalf("oldName = %q, want %q", oldName, tc.wantOldName)
			}
			if newName != tc.folderName {
				t.Fatalf("newName = %q, want %q", newName, tc.folderName)
			}
		})
	}
}
