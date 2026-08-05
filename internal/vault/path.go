// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package vault

import (
	"errors"
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

// ErrInvalidPath marks every rejection in sanitizeSecretPath as "the PATH you
// asked for is not a legal secret path" — a caller's own input, fixable by
// editing it — as opposed to the store being unreadable. The two arrive at a
// caller through the same return and used to be indistinguishable, so `jit
// doctor` filed a typo'd path in a profile manifest under [vault error], the
// kind it documents as "an unexpected error while checking the vault (a
// permissions problem on the store, say)". A CI check paging on vault_error
// for storage health got woken by a typo.
var ErrInvalidPath = errors.New("invalid secret path")

// invalidPathError carries ErrInvalidPath's identity without its words. A
// plain fmt.Errorf("…: %w", ErrInvalidPath) would append "invalid secret
// path" to messages that already say precisely what is wrong and have been
// user-visible for a long time; Unwrap gives errors.Is the same answer while
// Error() stays byte-identical to what these call sites always returned.
type invalidPathError struct{ msg string }

func (e *invalidPathError) Error() string { return e.msg }
func (e *invalidPathError) Unwrap() error { return ErrInvalidPath }

func invalidPath(format string, a ...any) error {
	return &invalidPathError{msg: fmt.Sprintf(format, a...)}
}

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
//
// Every rejection here wraps ErrInvalidPath, so a caller can tell a bad path
// from a bad store.
// ValidatePath reports whether path is a legal secret path, using only the
// checks that need nothing from the filesystem: shape, traversal segments,
// and the reserved history namespace.
//
// Split out of sanitizeSecretPath so a caller can reject a bad path BEFORE
// doing anything expensive or irreversible with it. `jit vault rm` is the
// motivating one: it used to prompt for a fingerprint and only then discover
// the path was malformed, demanding an approval for an operation it was
// always going to refuse.
func ValidatePath(path string) error {
	if path == "" {
		return invalidPath("secret path must not be empty")
	}
	if !secretPathPattern.MatchString(path) {
		return invalidPath("secret path %q must be slash-separated segments of letters, digits, '.', '_', '-' (e.g. \"stripe/dev-key\")", path)
	}
	// Traversal is a property of a SEGMENT, not of the string. This used to
	// reject any path merely containing "..", which turned an ordinary name
	// like "db..old/key" into an accusation of path traversal — a confusing
	// error for something harmless. ".." and "." are refused as whole
	// segments, which is the actual hazard (and the regexp above already
	// forbids a leading slash, so the joined path cannot escape either way —
	// sanitizeSecretPath's post-Join prefix check is the third layer).
	for _, seg := range strings.Split(path, "/") {
		if seg == "." || seg == ".." {
			return invalidPath("secret path %q must not contain %q segments", path, seg)
		}
	}
	// _history/ is the version-history tree (history.go), written only by
	// the archive machinery itself — unlike _backups/, which jit migrate
	// legitimately writes through Set. A user secret planted there would
	// read as an archived version of whatever path it names, and Restore
	// would rename it over the real secret. EqualFold, not ==: on the
	// default case-insensitive macOS filesystem, "_History" IS "_history".
	if first := strings.SplitN(path, "/", 2)[0]; strings.EqualFold(first, historyDirName) {
		return invalidPath("secret path %q is reserved for jit's own version history (%s/)", path, historyDirName)
	}
	return nil
}

func sanitizeSecretPath(vaultDir, path string) (string, error) {
	if err := ValidatePath(path); err != nil {
		return "", err
	}
	// Traversal is a property of a SEGMENT, not of the string. This used to
	// reject any path merely containing "..", which turned an ordinary name
	// like "db..old/key" into an accusation of path traversal — a confusing
	// error for something harmless. ".." and "." are refused as whole segments,
	// which is the actual hazard (and the regexp above already forbids a
	// leading slash, so the joined path cannot escape either way — the
	// post-Join prefix check below is the third layer).

	// _history/ is the version-history tree (history.go), written only by
	// the archive machinery itself — unlike _backups/, which jit migrate
	// legitimately writes through Set. A user secret planted there would
	// read as an archived version of whatever path it names, and Restore
	// would rename it over the real secret. EqualFold, not ==: on the
	// default case-insensitive macOS filesystem, "_History" IS "_history".
	full := filepath.Join(vaultDir, path+".enc")
	cleanVaultDir := filepath.Clean(vaultDir)
	if full != cleanVaultDir && !strings.HasPrefix(full, cleanVaultDir+string(filepath.Separator)) {
		return "", invalidPath("secret path %q escapes the vault directory", path)
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
			return invalidPath("secret path %q differs from stored %q only by letter case; use the stored spelling (case-variant paths collide on case-insensitive filesystems, so the vault never allows two)", path, stored)
		}
		return nil // nothing at this level: new subtree, nothing below to collide with
	}
	return nil
}
