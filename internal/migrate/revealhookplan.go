// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// This file is the read-only side of the reveal-hook layer (issue #3):
// InstallRevealHook used to be the plan's blind spot — `jit migrate
// --dry-run` promised "the full plan" while the package.json/.envrc rewrite
// it implied never appeared in any list or count, and `jit migrate undo`
// reversed the hook without ever naming the file. PlanRevealHook predicts
// what InstallRevealHook would edit; RevealHookFiles reports what
// UninstallRevealHook would touch. Both share the installers' own decision
// helpers (missingRevealLines, applyNpmRevealEntries) so prediction and
// mutation can't drift apart.

// missingRevealLines returns the reveal command lines for mountPaths not
// already present in a hook file's lines — the direnv installer's
// per-path idempotency check, shared with PlanRevealHook.
func missingRevealLines(lines []string, jitPath string, mountPaths []string) []string {
	var missing []string
	for _, mountPath := range mountPaths {
		revealLine := revealHookCommand(jitPath, mountPath)
		present := false
		for _, l := range lines {
			if strings.Contains(l, revealLine) {
				present = true
				break
			}
		}
		if !present {
			missing = append(missing, revealLine)
		}
	}
	return missing
}

// applyNpmRevealEntries returns entries with jit's reveal command wired
// into a "pre<name>" script for each npmRevealHookScripts target present,
// and whether anything actually changed. Per-path idempotent, same as the
// direnv installer: only commands not already present get prepended,
// joined into ONE combined prefix so all of a directory's mounts land in a
// single edit of the pre-script. Shared by installNpmRevealHook (which
// writes the result) and PlanRevealHook (which only wants `changed`).
func applyNpmRevealEntries(entries []scriptEntry, jitPath string, mountPaths []string) ([]scriptEntry, bool) {
	changed := false
	for _, target := range npmRevealHookScripts {
		targetIdx := indexOfScript(entries, target)
		if targetIdx < 0 {
			continue
		}
		preKey := "pre" + target
		preIdx := indexOfScript(entries, preKey)
		existing := ""
		if preIdx >= 0 {
			existing = entries[preIdx].value
		}
		missing := missingRevealLines([]string{existing}, jitPath, mountPaths)
		if len(missing) == 0 {
			continue // already installed by an earlier migrate run
		}
		combined := strings.Join(missing, " && ")
		if existing != "" {
			combined = combined + " && " + existing
		}
		if preIdx >= 0 {
			entries[preIdx].value = combined
		} else {
			// npm runs "predev" before "dev" wherever the key sits;
			// inserting it right above its target keeps the diff adjacent
			// to the script it guards.
			entries = slices.Insert(entries, targetIdx, scriptEntry{key: preKey, value: combined})
		}
		changed = true
	}
	return entries, changed
}

// PlanRevealHook reports which hook file InstallRevealHook would edit for
// dir's mounts — "" and RevealHookNone when it would change nothing (no
// hook point exists, or every reveal command is already wired). Same
// candidate order as the installer: an existing .envrc always wins, and a
// fully-wired .envrc means no edit at all (the installer returns early
// there, never falling through to package.json).
func PlanRevealHook(dir string, mountPaths ...string) (hookPath string, kind RevealHookKind, err error) {
	if len(mountPaths) == 0 {
		return "", RevealHookNone, nil
	}
	jitPath, err := resolveJitExecutable()
	if err != nil {
		return "", RevealHookNone, err
	}

	envrcPath := filepath.Join(dir, ".envrc")
	if info, statErr := os.Stat(envrcPath); statErr == nil && !info.IsDir() {
		lines, err := readLines(envrcPath)
		if err != nil {
			return "", RevealHookNone, err
		}
		if len(missingRevealLines(lines, jitPath, mountPaths)) > 0 {
			return envrcPath, RevealHookDirenv, nil
		}
		return "", RevealHookNone, nil
	}

	pkgPath := filepath.Join(dir, "package.json")
	data, readErr := os.ReadFile(pkgPath) // #nosec G304 -- dir is the mount's own directory joined with a fixed literal filename
	if readErr != nil {
		return "", RevealHookNone, nil
	}
	var pkg map[string]json.RawMessage
	if err := json.Unmarshal(data, &pkg); err != nil {
		return "", RevealHookNone, nil
	}
	scriptsRaw, ok := pkg["scripts"]
	if !ok {
		return "", RevealHookNone, nil
	}
	entries, ok := parseScriptEntries(scriptsRaw)
	if !ok {
		return "", RevealHookNone, nil
	}
	if _, changed := applyNpmRevealEntries(entries, jitPath, mountPaths); changed {
		return pkgPath, RevealHookNpm, nil
	}
	return "", RevealHookNone, nil
}

// RevealHookFiles reports which of dir's hook files (.envrc, package.json)
// currently carry jit's reveal command for any of mountPaths — the files
// UninstallRevealHook would edit. Display-only (the uninstaller re-parses
// properly); a marker match on the raw bytes is exactly the presence test
// the uninstallers themselves use per line/segment.
func RevealHookFiles(dir string, mountPaths ...string) []string {
	if len(mountPaths) == 0 {
		return nil
	}
	markers := make([]string, len(mountPaths))
	for i, mp := range mountPaths {
		markers[i] = revealHookMarker(mp)
	}
	var files []string
	for _, name := range []string{".envrc", "package.json"} {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path) // #nosec G304 -- dir is the mount's own directory joined with a fixed literal filename
		if err != nil {
			continue
		}
		if lineHasAnyMarker(string(data), markers) {
			files = append(files, path)
		}
	}
	return files
}
