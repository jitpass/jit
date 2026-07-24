// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/jitpass/jit/internal/vault"
)

// newProvenance builds the vault.Meta every migrator stamps onto the secrets
// it pulls from a single source file: the semantic class, a freshly minted
// group id, and the normalized origin path. Mint ONCE per Apply call and pass
// the same Meta to every SetWithMeta, so "these all came from ~/x/.env" is one
// durable group id shared across the batch — not an inference from vault path
// prefixes that a later folder rename or file move would silently break.
//
// SetWithMeta only honors this on a new secret; a re-migrate that rotates an
// existing value keeps that value's original group and origin, so a fresh id
// per run never fractures a group that already exists.
func newProvenance(class, sourcePath string) (vault.Meta, error) {
	gid, err := vault.NewGroupID()
	if err != nil {
		return vault.Meta{}, err
	}
	return vault.Meta{Class: class, GroupID: gid, Origin: normalizeOrigin(sourcePath)}, nil
}

// normalizeOrigin canonicalizes a source path for storage as a secret's
// Origin: absolute, with the user's home directory collapsed to "~" so the
// label is portable and readable. Best effort — a path that can't be made
// absolute is stored as given rather than dropped.
func normalizeOrigin(path string) string {
	if path == "" {
		return "" // no source to record (e.g. a live credential-helper store)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		if abs == home {
			return "~"
		}
		if strings.HasPrefix(abs, home+string(filepath.Separator)) {
			return "~" + abs[len(home):]
		}
	}
	return abs
}
