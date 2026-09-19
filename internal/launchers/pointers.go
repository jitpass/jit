// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package launchers

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/pointerfile"
)

// readPointers reads every pointer file jit can enumerate: in-place pointer
// files from the undo index (every one was backed up before it was written)
// and the home walk, then ~/.clisso.yaml. Their `.pointers` companions are
// not users: jit never reads them, and the mount they sit beside is already
// counted through its profile.
//
// A file jit knows it rewrote (the undo index says so) must read, or it is
// an error. A walk candidate that can't be opened can't be told apart from
// any other unreadable .env file, so it is skipped.
func (d *discovery) readPointers(root string, walked []string) {
	done := map[string]bool{}
	read := func(file string, mustRead bool) {
		file = filepath.Clean(file)
		if done[file] {
			return
		}
		done[file] = true
		paths, err := readPointerFile(file, mustRead)
		if err != nil {
			d.fail(SourcePointers, file, err)
			return
		}
		for _, p := range paths {
			d.m.Pointers = append(d.m.Pointers, Launcher{Kind: KindPointerFile, File: file, VaultPath: p})
		}
	}

	clissoPath := migrate.ClissoConfigPath(d.home)
	if root != "" {
		recs, err := migrate.LoadBackupRecords(root)
		if err != nil {
			d.fail(SourcePointers, "", fmt.Errorf("reading the undo index: %w", err))
		}
		for _, rec := range recs {
			if rec.OriginalPath == "" || filepath.Clean(rec.OriginalPath) == clissoPath {
				continue
			}
			read(rec.OriginalPath, true)
		}
	}
	for _, f := range walked {
		read(f, false)
	}

	clisso, err := migrate.ClissoPointerPaths(d.home)
	if err != nil {
		d.fail(SourcePointers, clissoPath, fmt.Errorf("reading %s: %w", clissoPath, err))
		return
	}
	for _, p := range clisso {
		d.m.Pointers = append(d.m.Pointers, Launcher{Kind: KindPointerFile, File: clissoPath, VaultPath: p})
	}
}

// readCompanions reads the `.pointers` companions the walk found, into
// Companions rather than Pointers.
//
// A companion is not a user — readPointers says why, and that stays true:
// nothing here reaches usage, so no secret becomes "referenced" because a
// companion names it, and `vault orphans --prune` deletes exactly what it
// did before. What this adds is the ability to CHECK the names, which the
// old skip made impossible. The assumption the skip rests on — "the mount
// it sits beside is already counted through its profile" — holds on a
// machine that still has the mount and the profile. A vault restored onto
// a new Mac has neither, and then the companion is the only surviving
// record of what that mount served, naming secrets nothing else mentions.
//
// Unreadable is a skip, never an error: a companion is documentation jit
// wrote for a human, and no deletion decision is taken on it.
func (d *discovery) readCompanions(files []string) {
	done := map[string]bool{}
	for _, file := range files {
		file = filepath.Clean(file)
		if done[file] {
			continue
		}
		done[file] = true
		paths, err := readPointerFile(file, false)
		if err != nil {
			continue
		}
		for _, p := range paths {
			d.m.Companions = append(d.m.Companions, Launcher{Kind: KindPointerFile, File: file, VaultPath: p})
		}
	}
}

// readPointerFile returns the vault paths a jit pointer file names, or
// nothing for a file that isn't one (or no longer exists). Only a regular
// file is ever opened: a path in the undo index may be a live mount's FIFO
// by now, and opening one for read blocks on a writer.
func readPointerFile(file string, mustRead bool) ([]string, error) {
	info, err := os.Lstat(file)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		if mustRead {
			return nil, fmt.Errorf("reading pointer file %s: %w", file, err)
		}
		return nil, nil
	}
	if !info.Mode().IsRegular() {
		return nil, nil
	}
	data, err := os.ReadFile(file) // #nosec G304 -- a path from jit's own undo index or its home walk, confirmed a regular file above
	if err != nil {
		if mustRead {
			return nil, fmt.Errorf("reading pointer file %s: %w", file, err)
		}
		return nil, nil
	}
	if !pointerfile.HasHeader(data) {
		return nil, nil
	}
	var paths []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		if p, ok := pointerfile.VaultPath(value); ok && p != "" {
			paths = append(paths, p)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading pointer file %s: %w", file, err)
	}
	return paths, nil
}
