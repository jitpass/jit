// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package migrate

import (
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
	var order []string
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		name, ref, ok := strings.Cut(trimmed, "=")
		if !ok || !strings.HasPrefix(ref, pointerValuePrefix) {
			return nil, fmt.Errorf("%s line %d isn't a jit pointer line, refusing to restore a file jit doesn't fully understand", path, i+1)
		}
		secret, err := v.Get(strings.TrimPrefix(ref, pointerValuePrefix))
		if err != nil {
			return nil, fmt.Errorf("resolving %s (%s): %w", name, ref, err)
		}
		if _, dup := values[name]; !dup {
			order = append(order, name)
		}
		values[name] = string(secret)
	}
	if err := os.WriteFile(path, mount.FormatDotenv(values, order), 0o600); err != nil {
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
			if skipDiscoveryDir(root, path, d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		// Regular files only, same rule as audit's walk (fsutil.go): a
		// live mount's FIFO is not a pointer artifact, and IsPointerFile
		// below must never open one (its read would block forever).
		if !d.Type().IsRegular() {
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
