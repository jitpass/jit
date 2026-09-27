// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// Package settings stores the plain values a protected .env keeps beside its
// secrets: URLs, IDs, file names, flags. They live next to the vault, not in
// it, and not in the profile manifest either, which is documented as safe to
// commit and so must never carry a value (design/secrets-only-vault.md, D7).
//
// A manifest entry names a setting by a pointer, jit://setting/<path>, where
// <path> has the vault's own grammar ("billing-sync/BILLING_URL"). A vault
// path can never contain ':', so a pointer is never mistaken for one.
//
// Plain files, deliberately: a setting is exactly as readable as the .env
// line it came from, and reading one needs no Touch ID. That is the point.
package settings

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jitpass/jit/internal/atomicfile"
)

// PointerPrefix starts every manifest entry that names a setting.
const PointerPrefix = "jit://setting/"

// Dir is the store's directory under the vault's root.
const Dir = "settings"

// ErrNotFound reports a pointer whose setting file is missing.
var ErrNotFound = errors.New("setting not found")

// Pointer returns the manifest value naming the setting at path.
func Pointer(path string) string { return PointerPrefix + path }

// PathOf returns the setting path a manifest value names, and false for any
// value that is not a setting pointer (a vault path).
func PathOf(entry string) (string, bool) {
	return strings.CutPrefix(entry, PointerPrefix)
}

// IsPointer reports whether a manifest value names a setting.
func IsPointer(entry string) bool {
	_, ok := PathOf(entry)
	return ok
}

// Store is the settings directory under one vault root.
type Store struct {
	root string
}

// New returns the store under vaultRoot (the directory holding the vault).
func New(vaultRoot string) *Store {
	return &Store{root: filepath.Join(vaultRoot, Dir)}
}

// pathPattern is internal/vault's secretPathPattern, repeated because this
// package sits below internal/vault: the service (internal/agent), which must
// not import the vault, reads settings too. TestPathPatternMatchesVault keeps
// the two identical.
var pathPattern = regexp.MustCompile(`^[A-Za-z0-9_.\-]+(/[A-Za-z0-9_.\-]+)*$`)

// ValidatePath reports whether path is a legal setting path: the vault's
// grammar, no "." or ".." segment.
func ValidatePath(path string) error {
	if !pathPattern.MatchString(path) {
		return fmt.Errorf("setting path %q must be slash-separated segments of letters, digits, '.', '_', '-'", path)
	}
	for _, seg := range strings.Split(path, "/") {
		if seg == "." || seg == ".." {
			return fmt.Errorf("setting path %q must not contain %q segments", path, seg)
		}
	}
	return nil
}

// file maps a setting path to its file: the vault's grammar, and never
// outside the store.
func (s *Store) file(path string) (string, error) {
	if err := ValidatePath(path); err != nil {
		return "", err
	}
	full := filepath.Join(s.root, filepath.FromSlash(path))
	if !strings.HasPrefix(full, s.root+string(filepath.Separator)) {
		return "", fmt.Errorf("setting path %q escapes the store", path)
	}
	return full, nil
}

// File returns the file holding the setting at path, for a caller that
// fingerprints it (an AI job, design/secrets-only-vault.md D8).
func (s *Store) File(path string) (string, error) { return s.file(path) }

// Get returns the setting at path.
func (s *Store) Get(path string) ([]byte, error) {
	f, err := s.file(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(f) // #nosec G304 -- f is validated and confined to the store above
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", path, ErrNotFound)
	}
	return data, err
}

// Set writes the setting at path, replacing any value there.
func (s *Store) Set(path string, value []byte) error {
	f, err := s.file(path)
	if err != nil {
		return err
	}
	// 0600 file, 0700 folders (atomicfile.WriteFile): as private as the
	// .env the value came from, and no more.
	if err := atomicfile.WriteFile(f, value); err != nil {
		return fmt.Errorf("writing setting %s: %w", path, err)
	}
	return nil
}

// Exists reports whether a setting is stored at path.
func (s *Store) Exists(path string) (bool, error) {
	f, err := s.file(path)
	if err != nil {
		return false, err
	}
	_, err = os.Stat(f)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// Remove deletes the setting at path. A missing one is not an error: the
// caller wanted it gone.
func (s *Store) Remove(path string) error {
	f, err := s.file(path)
	if err != nil {
		return err
	}
	if err := os.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing setting %s: %w", path, err)
	}
	return nil
}
