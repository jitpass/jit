// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// Package pointerfile owns the on-disk format `jit migrate` leaves in place
// of a credential: the header that marks a file as jit's own, the `jit://`
// value that names a vault path instead of holding a secret, and the suffix
// of the git-safe companion written beside a live mount.
//
// It exists because the format had three components and thirteen spellings,
// in four packages, with no owner. internal/migrate WRITES it, internal/audit
// READS it to avoid re-reporting an already-migrated file as an exposed
// secret, internal/cli and internal/mount both test for it — and each declared
// its own const, under three different names for the same string
// (pointerFileHeader / pointerFileHeaderPrefix, pointerValuePrefix /
// pointerVaultPrefix / clissoPointerPrefix), plus four inline literals.
//
// The failure that shape produces is documented in both packages' comments as
// a real incident (GAPS.md #30). Change the header wording in the writer and
// audit stops recognising its own output, so `jit scan` reports every
// already-migrated file as an exposed secret — the re-discovery incident where
// a second project-scoped `jit migrate` run parsed a `.pointers` companion's
// `KEY=jit://vault/...` lines as if they were real credentials and converted
// the git-safe companion itself into a live mount.
//
// Deliberately a leaf: no imports beyond the standard library, so it can sit
// below internal/audit, internal/migrate, internal/cli and internal/mount
// without adding an edge between any of them — the same shape internal/style
// has for the output vocabulary.
package pointerfile

import "strings"

const (
	// Header is the first line of a file jit rewrote in place. Matched as a
	// PREFIX: the written header continues with guidance for whoever opens
	// the file, and only this much is the marker.
	Header = "# jit pointer file"

	// ValuePrefix introduces a vault path where a credential used to be, in
	// `KEY=jit://vault/<path>` form. Its whole job is to be recognisable:
	// anything reading a config must be able to tell "this is a reference"
	// from "this is a secret", and a value that fails that test gets stored
	// in the vault a second time as though it were a credential.
	ValuePrefix = "jit://vault/"

	// CompanionSuffix names the git-safe file written ALONGSIDE a live mount
	// (`.env` -> `.env.pointers`), listing which vault path each variable
	// resolves to. Committable and IDE-peekable, holding no secret.
	CompanionSuffix = ".pointers"
)

// Value renders vaultPath as a pointer value.
func Value(vaultPath string) string { return ValuePrefix + vaultPath }

// IsValue reports whether s is a pointer rather than a real credential.
func IsValue(s string) bool { return strings.HasPrefix(s, ValuePrefix) }

// VaultPath returns the vault path a pointer value names, and whether s was a
// pointer at all. Callers that only need the yes/no want IsValue.
func VaultPath(s string) (string, bool) {
	rest, ok := strings.CutPrefix(s, ValuePrefix)
	return rest, ok
}

// HasHeader reports whether content begins with the pointer-file marker.
func HasHeader(content []byte) bool {
	return strings.HasPrefix(string(content), Header)
}

// CompanionPath returns the companion file written beside path.
func CompanionPath(path string) string { return path + CompanionSuffix }

// TrimCompanionSuffix returns the file a companion belongs to, and whether
// name was a companion at all.
func TrimCompanionSuffix(name string) (string, bool) {
	return strings.CutSuffix(name, CompanionSuffix)
}

// IsCompanion reports whether name is one of jit's `.pointers` companions.
func IsCompanion(name string) bool { return strings.HasSuffix(name, CompanionSuffix) }
