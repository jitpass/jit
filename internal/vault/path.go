// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"fmt"
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

	full := filepath.Join(vaultDir, path+".enc")
	cleanVaultDir := filepath.Clean(vaultDir)
	if full != cleanVaultDir && !strings.HasPrefix(full, cleanVaultDir+string(filepath.Separator)) {
		return "", fmt.Errorf("secret path %q escapes the vault directory", path)
	}
	return full, nil
}
