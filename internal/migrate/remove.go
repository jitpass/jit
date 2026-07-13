// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/vault"
)

// This file holds `jit migrate remove`'s package-side helpers (GAPS.md
// #59): everything needed to take jit back OUT of a project completely —
// the piece `jit migrate undo` deliberately never does (undo reverses
// files and keeps the vault; remove restores files AND deletes the
// project's vault secrets, profiles, backups, and hooks). The CLI
// orchestration (plan → confirm → fresh auth → execute) lives in
// internal/cli/migrateremove.go, same division of labor as runMigrate.

// pointerFileHeader is the first line WritePointerFile/ReplaceWithPointerFile
// emit — IsPointerFile's detection anchor. Keep the two in sync.
const pointerFileHeader = "# jit pointer file"

// pointerValuePrefix is the value scheme every pointer line uses.
const pointerValuePrefix = "jit://vault/"

// IsPointerFile reports whether path is a regular file jit itself wrote in
// the pointer format (never a live mount's FIFO — those are checked by
// mode before this ever opens anything, since opening a pipe for read
// blocks on a writer).
func IsPointerFile(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	f, err := os.Open(path) // #nosec G304 -- callers pass paths from jit's own filesystem walk, and the read is capped to one header-sized line
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, len(pointerFileHeader))
	n, err := f.Read(buf)
	if err != nil || n < len(pointerFileHeader) {
		return false
	}
	return string(buf) == pointerFileHeader
}

// RestorePointerFile rewrites an in-place pointer file (a backup-suffixed
// .env-family file ReplaceWithPointerFile converted, GAPS.md #34) back
// into a plain dotenv file by resolving each KEY=jit://vault/<path> line
// against v. Returns the restored variable names, sorted. Lines that
// aren't pointer lines (the header comments) are dropped — the output is
// a regenerated dotenv file, matching UnmountFile's own "content comes
// from the vault, not the file" contract.
func RestorePointerFile(v *vault.Vault, path string) ([]string, error) {
	lines, err := readLines(path)
	if err != nil {
		return nil, fmt.Errorf("reading pointer file %s: %w", path, err)
	}
	values := map[string]string{}
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		name, ref, ok := strings.Cut(trimmed, "=")
		if !ok || !strings.HasPrefix(ref, pointerValuePrefix) {
			return nil, fmt.Errorf("%s line %d isn't a jit pointer line — refusing to restore a file jit doesn't fully understand", path, i+1)
		}
		secret, err := v.Get(strings.TrimPrefix(ref, pointerValuePrefix))
		if err != nil {
			return nil, fmt.Errorf("resolving %s (%s): %w", name, ref, err)
		}
		values[name] = string(secret)
	}
	if err := os.WriteFile(path, mount.FormatDotenv(values), 0o600); err != nil {
		return nil, fmt.Errorf("writing %s: %w", path, err)
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

// DiscoverPointerArtifacts walks root's tree for the two pointer-file forms
// jit migrate leaves behind: ".pointers" companions written alongside a
// live mount (safe to just delete — the mount itself is handled
// separately), and in-place pointer files (a backup-suffixed .env-family
// file replaced by ReplaceWithPointerFile — these need RestorePointerFile,
// since the pointer content replaced the original file itself). Same walk
// tolerances as DiscoverEnvFiles: a permission error under the tree skips
// that path, never aborts the scan.
func DiscoverPointerArtifacts(root string) (companions, inPlace []string, err error) {
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path == root {
				return err
			}
			return filepath.SkipDir
		}
		if d.IsDir() {
			if skipDiscoveryDir(path, d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(d.Name(), jitPointerFileSuffix) {
			companions = append(companions, path)
			return nil
		}
		if envFileNamePattern.MatchString(d.Name()) && IsPointerFile(path) {
			inPlace = append(inPlace, path)
		}
		return nil
	})
	if walkErr != nil {
		return nil, nil, fmt.Errorf("walking %s: %w", root, walkErr)
	}
	sort.Strings(companions)
	sort.Strings(inPlace)
	return companions, inPlace, nil
}

// DropBackupRecords rewrites the undo index without drop's records,
// matched by VaultPath — unique per record, since backupSecretFile bumps
// its timestamp until the vault path is free. Deleting the corresponding
// _backups/ vault entries is the caller's job (it holds the authed vault;
// this only edits bookkeeping).
func DropBackupRecords(root string, drop []BackupRecord) error {
	if len(drop) == 0 {
		return nil
	}
	path := BackupIndexPath(root)
	idx, err := loadBackupIndex(path)
	if err != nil {
		return err
	}
	dropSet := make(map[string]bool, len(drop))
	for _, r := range drop {
		dropSet[r.VaultPath] = true
	}
	kept := idx.Backups[:0:0]
	for _, r := range idx.Backups {
		if !dropSet[r.VaultPath] {
			kept = append(kept, r)
		}
	}
	if len(kept) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("removing emptied undo index: %w", err)
		}
		return nil
	}
	data, err := yaml.Marshal(backupIndexFile{Backups: kept})
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// isRevealHookCommand reports whether one shell command (an .envrc line, or
// one "&&"-separated segment of an npm pre-script) is jit's own injected
// reveal call — matched on revealHookCommand's two invariant fragments
// rather than the full string, since the embedded jit executable path
// changes across installs/rebuilds.
func isRevealHookCommand(s string) bool {
	return strings.Contains(s, " agent reveal ") && strings.Contains(s, "--quiet 2>/dev/null || true")
}

// RemoveRevealHooks strips every reveal call InstallRevealHook ever wired
// into dir's .envrc and package.json pre-scripts, returning the files it
// actually edited. The inverse of InstallRevealHook, with the same
// tolerance: a missing/malformed file is "nothing to remove," never an
// error. No backups are taken — this runs on `jit migrate remove`'s
// leave-nothing-behind path, and the only lines touched are jit's own
// injected ones (hooks never hold a secret).
func RemoveRevealHooks(dir string) ([]string, error) {
	var edited []string
	envrcPath, err := removeDirenvRevealHooks(dir)
	if err != nil {
		return nil, err
	}
	if envrcPath != "" {
		edited = append(edited, envrcPath)
	}
	pkgPath, err := removeNpmRevealHooks(dir)
	if err != nil {
		return nil, err
	}
	if pkgPath != "" {
		edited = append(edited, pkgPath)
	}
	return edited, nil
}

func removeDirenvRevealHooks(dir string) (string, error) {
	envrcPath := filepath.Join(dir, ".envrc")
	info, err := os.Stat(envrcPath)
	if err != nil || info.IsDir() {
		return "", nil
	}
	lines, err := readLines(envrcPath)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", envrcPath, err)
	}
	kept := lines[:0:0]
	changed := false
	for _, l := range lines {
		if isRevealHookCommand(l) {
			changed = true
			continue
		}
		kept = append(kept, l)
	}
	if !changed {
		return "", nil
	}
	newContent := strings.Join(kept, "\n")
	if err := os.WriteFile(envrcPath, []byte(newContent), 0o600); err != nil {
		return "", fmt.Errorf("writing %s: %w", envrcPath, err)
	}
	// Leave-nothing-behind: with no jit command left in the file, its
	// .jit-bak siblings have nothing left to back up.
	if err := cleanupHookBackupsIfClean(envrcPath, newContent); err != nil {
		return "", err
	}
	return envrcPath, nil
}

func removeNpmRevealHooks(dir string) (string, error) {
	pkgPath := filepath.Join(dir, "package.json")
	data, err := os.ReadFile(pkgPath) // #nosec G304 -- dir comes from jit's own registry/walk, joined with a fixed literal filename
	if err != nil {
		return "", nil
	}
	var pkg map[string]json.RawMessage
	if err := json.Unmarshal(data, &pkg); err != nil {
		return "", nil
	}
	scriptsRaw, ok := pkg["scripts"]
	if !ok {
		return "", nil
	}
	var scripts map[string]string
	if err := json.Unmarshal(scriptsRaw, &scripts); err != nil {
		return "", nil
	}

	changed := false
	for _, target := range npmRevealHookScripts {
		preKey := "pre" + target
		existing, ok := scripts[preKey]
		if !ok {
			continue
		}
		segments := strings.Split(existing, " && ")
		kept := segments[:0:0]
		for _, s := range segments {
			if isRevealHookCommand(s) {
				changed = true
				continue
			}
			kept = append(kept, s)
		}
		if len(kept) == 0 {
			// The whole pre-script was jit's — InstallRevealHook created it,
			// so removing the key entirely restores the original file shape.
			delete(scripts, preKey)
		} else {
			scripts[preKey] = strings.Join(kept, " && ")
		}
	}
	if !changed {
		return "", nil
	}

	scriptsJSON, err := marshalJSONNoEscape(scripts, "")
	if err != nil {
		return "", err
	}
	pkg["scripts"] = scriptsJSON
	out, err := marshalJSONNoEscape(pkg, "  ")
	if err != nil {
		return "", err
	}
	// Same byte-fidelity rule as UninstallRevealHook: restore the exact
	// pre-install bytes when removing the hooks reproduces them, then clean
	// the now-pointless .jit-bak siblings — remove's whole promise is
	// leave-nothing-behind, and the hook file never held a secret.
	written, err := writeNpmHookFile(pkgPath, out, data)
	if err != nil {
		return "", fmt.Errorf("writing %s: %w", pkgPath, err)
	}
	if err := cleanupHookBackupsIfClean(pkgPath, string(written)); err != nil {
		return "", err
	}
	return pkgPath, nil
}
