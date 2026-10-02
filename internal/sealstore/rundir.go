// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package sealstore

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// prepareBase makes base (0700) and refuses one that is a symlink or not
// owner-only: the run dirs below it hold a plaintext store while a tool
// runs.
func prepareBase(base string) error {
	if err := os.MkdirAll(base, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(base)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s: not a plain directory", base)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s: mode %#o, want owner-only", base, info.Mode().Perm())
	}
	return nil
}

// NewRunDir makes a fresh owner-only directory under base for one run,
// named for its owner (pid and fork time, so Sweep can tell a live owner
// from a recycled pid).
func NewRunDir(base string, pid int, startMicro int64) (string, error) {
	if err := prepareBase(base); err != nil {
		return "", err
	}
	return os.MkdirTemp(base, fmt.Sprintf("%d-%d-", pid, startMicro))
}

// Owner parses a run dir's name back into its owner. ok is false for a
// name NewRunDir did not make.
func Owner(dir string) (pid int, startMicro int64, ok bool) {
	parts := strings.SplitN(filepath.Base(dir), "-", 3)
	if len(parts) != 3 || parts[2] == "" {
		return 0, 0, false
	}
	p, err1 := strconv.Atoi(parts[0])
	s, err2 := strconv.ParseInt(parts[1], 10, 64)
	if err1 != nil || err2 != nil || p <= 0 {
		return 0, 0, false
	}
	return p, s, true
}

// Sweep removes the run dirs under base whose owner is no longer alive:
// what a run killed before its cleanup left behind. Entries NewRunDir did
// not name are left alone. A missing base is nothing to sweep.
func Sweep(base string, alive func(pid int, startMicro int64) bool) (removed []string, err error) {
	entries, err := os.ReadDir(base)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var errs []error
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, start, ok := Owner(e.Name())
		if !ok || alive(pid, start) {
			continue
		}
		dir := filepath.Join(base, e.Name())
		if err := os.RemoveAll(dir); err != nil {
			errs = append(errs, err)
			continue
		}
		removed = append(removed, dir)
	}
	return removed, errors.Join(errs...)
}
