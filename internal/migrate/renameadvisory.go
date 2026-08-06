// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/jitpass/jit/internal/pointerfile"
)

// pointerVaultPrefix is the token every pointer-file line puts before a
// secret's vault path (pointerfile.go writes "VAR=jit://vault/<ns>/<VAR>").
// The namespace is the single path segment right after it.
const pointerVaultPrefix = pointerfile.ValuePrefix

// DetectRenamedRootProject reports whether the project at root was migrated
// under a different folder name than root's current basename — the common
// "I renamed my project folder after jit migrate" case, which leaves the
// vault still labeling this project's secrets under the OLD folder name.
//
// The signal is deliberately narrow to stay false-positive-free: it reads
// ONLY the pointer companions (<root>/.env.pointers and .env.<variant>.pointers)
// that a root .env migration leaves behind. Those are plain regular files
// that travel with the folder on a rename, so the namespace they record
// (jit://vault/<ns>/...) is exactly the name the vault still uses. A
// subfolder migration (services/api/.env -> profile "services-api") writes
// its pointer under that subdirectory, never at root, so it can never
// reach this check — which is why the check needs no way to tell a renamed
// root from a legitimately non-basename subfolder profile.
//
// Returns (oldName, newName, true) when a root pointer's namespace stem
// differs from root's current basename. ok is false — never an error — when
// nothing conclusive is found (no pointer companions, unreadable files, or
// the name already matches); this is an advisory, so a best-effort miss must
// stay silent rather than fail a command.
func DetectRenamedRootProject(root string) (oldName, newName string, ok bool) {
	newName = filepath.Base(root)
	if newName == "" || newName == "." || newName == string(filepath.Separator) {
		return "", "", false
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		return "", "", false
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		envName, isCompanion := pointerfile.TrimCompanionSuffix(name)
		if !isCompanion {
			continue
		}
		if !envFileNamePattern.MatchString(envName) {
			continue
		}
		ns := readPointerNamespace(filepath.Join(root, name))
		if ns == "" {
			continue
		}
		// Strip the file's own variant suffix (.env.local -> "local") so we
		// compare the FOLDER stem, not the variant-qualified namespace:
		// ".env.local.pointers" records namespace "notion-local" for a
		// folder that was named "notion".
		stem := ns
		if variant := envFileVariantSuffix(envName); variant != "" {
			stem = strings.TrimSuffix(ns, "-"+variant)
		}
		// EqualFold, not ==: a case-only rename (notion -> Notion) on the
		// default case-insensitive macOS filesystem is not a rename worth
		// flagging — the vault path still resolves and the label reads the
		// same to a human.
		if stem != "" && !strings.EqualFold(stem, newName) {
			return stem, newName, true
		}
	}
	return "", "", false
}

// readPointerNamespace returns the vault namespace recorded in a pointer
// file's first "VAR=jit://vault/<ns>/<VAR>" line, or "" if the file has no
// such line (unreadable, empty, or not actually a pointer file). The
// namespace is the one path segment between the prefix and the next slash.
func readPointerNamespace(path string) string {
	f, err := os.Open(path) // #nosec G304 -- a *.pointers companion under the project root, jit's own regular file
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		i := strings.Index(line, pointerVaultPrefix)
		if i < 0 {
			continue
		}
		rest := line[i+len(pointerVaultPrefix):]
		slash := strings.IndexByte(rest, '/')
		if slash <= 0 {
			continue
		}
		return rest[:slash]
	}
	return ""
}
