// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/jitpass/jit/internal/vault"
)

// A profile's .source sidecar is its OWNER LIST (design/doctor-repair.md,
// Phase 2): one owning config per line, most often exactly one. A single
// line is the format every jit before the list wrote, so every existing
// sidecar reads unchanged, and a sidecar this package writes with one owner
// is byte-identical to the old one ("<source>\n").
//
// An owner is a block-scoped source as mcpSourceScope builds it: the config
// file path, suffixed "#<projectDir>" for a server inside ~/.claude.json's
// projects map. OwnerFile strips that scope for callers asking "which file".
//
// Several owners mean one profile several configs launch with the SAME
// values: no copies, so a rotation happens once. Different values still get
// separate profiles (claimMCPNamespace bumps). An owner whose file is gone
// does not count (LiveProfileOwners).
//
// An older jit reads the whole multi-line sidecar as one string, sees a
// mismatch with its own source and bumps to a fresh namespace. It copies and
// never overwrites, so a downgrade stays safe.

// parseOwnerLines splits sidecar content into its owners: trimmed, blank
// lines dropped, duplicates dropped, first occurrence's order kept.
func parseOwnerLines(data []byte) []string {
	var owners []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || seen[line] {
			continue
		}
		seen[line] = true
		owners = append(owners, line)
	}
	return owners
}

// formatOwnerLines is parseOwnerLines' inverse: one owner per line, each
// newline-terminated. Owners are trimmed and deduplicated on the way out,
// so a caller can append without checking first.
func formatOwnerLines(owners []string) string {
	var b strings.Builder
	seen := map[string]bool{}
	for _, o := range owners {
		o = strings.TrimSpace(o)
		if o == "" || seen[o] {
			continue
		}
		seen[o] = true
		b.WriteString(o)
		b.WriteByte('\n')
	}
	return b.String()
}

// ownersInclude reports whether owners lists source, compared exactly (the
// block-scoped form, which is what claimMCPNamespace compares).
func ownersInclude(owners []string, source string) bool {
	for _, o := range owners {
		if o == source {
			return true
		}
	}
	return false
}

// ProfileSourcePath is the .source sidecar path for a profile manifest.
func ProfileSourcePath(profilePath string) string {
	return profileSourceSidecarPath(profilePath)
}

// ReadProfileOwners is ProfileOwners for a caller that must tell "no owner"
// from "can't tell": a missing sidecar is (nil, nil), an unreadable one is
// an error.
func ReadProfileOwners(profilePath string) ([]string, error) {
	data, err := os.ReadFile(profileSourceSidecarPath(profilePath)) // #nosec G304 -- a fixed-suffix sibling of jit's own profile manifest
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return parseOwnerLines(data), nil
}

// ProfileOwners returns every owner a profile's .source sidecar records, in
// file order, trimmed and deduplicated, each in its block-scoped form (see
// OwnerFile). nil when there is no sidecar or it can't be read.
func ProfileOwners(profilePath string) []string {
	owners, _ := ReadProfileOwners(profilePath)
	return owners
}

// OwnerFile is the config file an owner names, its block scope stripped.
func OwnerFile(owner string) string {
	return mcpSourceFile(owner)
}

// LiveProfileOwners is ProfileOwners minus every owner whose config file no
// longer exists. A gone owner launches nothing and must not keep a profile
// alive; that is the whole of design/doctor-repair.md's config_deleted case.
// Only a definite "does not exist" drops an owner: a file that can't be
// stat'ed for another reason (a privacy-denied folder) is kept, since
// "can't tell" must not read as "gone".
func LiveProfileOwners(profilePath string) []string {
	return liveOwners(ProfileOwners(profilePath))
}

// liveOwners is LiveProfileOwners over a list already in hand, for a caller
// reading the sidecar some other way (claimMCPNamespace reads it through the
// run's pending writes).
func liveOwners(owners []string) []string {
	var live []string
	for _, o := range owners {
		if _, err := os.Stat(OwnerFile(o)); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		live = append(live, o)
	}
	return live
}

// WriteProfileOwners replaces a profile's owner list, atomically and at the
// sidecar's usual 0600. An empty list removes the sidecar, which leaves the
// profile unstamped (claimMCPNamespace's legacy rules), never stamped with
// nobody.
func WriteProfileOwners(profilePath string, owners []string) error {
	path := profileSourceSidecarPath(profilePath)
	content := formatOwnerLines(owners)
	if content == "" {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("removing %s: %w", path, err)
		}
		return nil
	}
	if err := vault.AtomicWriteFile(path, []byte(content)); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}
