// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// secretPathPattern allows slash-separated segments of letters, digits,
// underscore, hyphen, and dot — enough for "stripe/dev-key" or
// "aws/s3-access-key" (RFC.md Pillar I's own examples) without ever
// admitting ".." or an absolute path, since this becomes part of a real
// filesystem path below the vault root.
var secretPathPattern = regexp.MustCompile(`^[A-Za-z0-9_.\-]+(/[A-Za-z0-9_.\-]+)*$`)

// sanitizeSecretPath validates a user-supplied secret path and returns the
// absolute file path it maps to under vaultDir. Rejecting anything outside
// secretPathPattern up front, then re-checking the resulting path still
// falls under vaultDir after filepath.Clean, is deliberate defense in
// depth: the regexp should already make traversal impossible, but a
// filesystem path derived from user input is exactly the kind of place a
// single missed edge case turns into a real path-traversal bug.
//
// Beyond traversal, the path must map to its file WITHOUT normalization:
// a v2 payload's AAD is bound to the path exactly as given (envelopeAAD),
// so any input the filesystem resolves to a different name than the AAD
// records decrypts never — and fails with the "corrupted/tampered" error,
// the one message that makes a user fear a healthy vault is gone. Two
// real cases are rejected here for exactly that reason: "." segments
// (collapsed by filepath.Join, so "a/./b" stored at a/b.enc with an AAD
// of "a/./b") and letter-case variants of an existing entry (the default
// macOS filesystem is case-insensitive, so "stripe/dev-key" opens
// Dev-Key.enc while the AAD says otherwise — see rejectCaseVariant).
func sanitizeSecretPath(vaultDir, path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("secret path must not be empty")
	}
	if strings.Contains(path, "..") {
		return "", fmt.Errorf("secret path %q must not contain \"..\"", path)
	}
	if !secretPathPattern.MatchString(path) {
		return "", fmt.Errorf("secret path %q must be slash-separated segments of letters, digits, '.', '_', '-' (e.g. \"stripe/dev-key\")", path)
	}
	for _, seg := range strings.Split(path, "/") {
		if seg == "." {
			return "", fmt.Errorf("secret path %q must not contain \".\" segments", path)
		}
	}

	full := filepath.Join(vaultDir, path+".enc")
	cleanVaultDir := filepath.Clean(vaultDir)
	if full != cleanVaultDir && !strings.HasPrefix(full, cleanVaultDir+string(filepath.Separator)) {
		return "", fmt.Errorf("secret path %q escapes the vault directory", path)
	}
	if err := rejectCaseVariant(vaultDir, path); err != nil {
		return "", err
	}
	return full, nil
}

// rejectCaseVariant errors when path names no existing entry exactly but
// a stored entry differs from it only by letter case. On the default
// (case-insensitive) macOS filesystem such a path would silently resolve
// to the case-variant file and fail its AAD check as if tampered with;
// on a case-sensitive filesystem it would report not-found while `jit
// vault list` shows a near-identical name. Both deserve the same honest
// answer: the stored spelling. Walks one directory level per segment,
// stopping at the first level where nothing matches (a genuinely new
// subtree can't collide with anything).
func rejectCaseVariant(vaultDir, path string) error {
	dir := vaultDir
	segs := strings.Split(path, "/")
	for i, seg := range segs {
		name := seg
		if i == len(segs)-1 {
			name += ".enc"
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil // level doesn't exist yet (or is unreadable — later ops will surface that)
		}
		exact, variant := false, ""
		for _, e := range entries {
			if e.Name() == name {
				exact = true
				break
			}
			if strings.EqualFold(e.Name(), name) {
				variant = e.Name()
			}
		}
		if exact {
			dir = filepath.Join(dir, name)
			continue
		}
		if variant != "" {
			stored := strings.Join(append(append([]string{}, segs[:i]...), strings.TrimSuffix(variant, ".enc")), "/")
			return fmt.Errorf("secret path %q differs from stored %q only by letter case; use the stored spelling (case-variant paths collide on case-insensitive filesystems, so the vault never allows two)", path, stored)
		}
		return nil // nothing at this level: new subtree, nothing below to collide with
	}
	return nil
}
