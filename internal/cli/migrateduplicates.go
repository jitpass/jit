// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"crypto/sha256"
	"fmt"
	"io"
	"sort"

	"github.com/jitpass/jit/internal/vault"
)

// Migrate-time duplicate disclosure: when a migration stores a value the
// vault already holds under another group, say so on the spot — the moment
// the copy is born, not months later in a listing. Disclosure only, by the
// annotate-never-collapse decision: the file still migrates normally into
// its own profile (collapsing copies would change who breaks when one is
// later removed), and the note routes to `jit vault duplicates` for the
// full comparison and remedy.

// buildVaultValueIndex digests every secret ALREADY stored before this run
// writes anything, mapping value digest -> the first vault path holding it.
// Values are hashed as read and never kept. Best-effort: an unreadable
// envelope is skipped, and a nil index (a listing failure) simply disables
// the notes — disclosure must never fail a migration.
func buildVaultValueIndex(v *vault.Vault) map[string]string {
	paths, err := v.List()
	if err != nil {
		return nil
	}
	secrets, _ := splitBackupPaths(paths)
	idx := make(map[string]string, len(secrets))
	for _, p := range secrets {
		value, err := v.Get(p)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(value)
		key := fmt.Sprintf("%x", sum)
		if _, ok := idx[key]; !ok {
			idx[key] = p
		}
	}
	return idx
}

// minDuplicateValueLen keeps trivially-coincidental values ("true", a port
// number) from reading as duplicates; a real credential or endpoint is
// comfortably longer.
const minDuplicateValueLen = 6

// noteDuplicateValues prints one note under a migrated file's result line
// when values just stored under profileName duplicate what other groups
// already held. Key names that look like plain configuration are skipped on
// sharedCredentialFindings' reasoning (two scripts sharing OUTPUT_FILE is
// not a duplicate credential), as are very short values.
func noteDuplicateValues(out io.Writer, v *vault.Vault, idx map[string]string, profileName string, vars []string) {
	if len(idx) == 0 {
		return
	}
	dupCount := 0
	groupSet := map[string]bool{}
	for _, name := range vars {
		if looksLikeConfig(name) {
			continue
		}
		value, err := v.Get(profileName + "/" + name)
		if err != nil || len(value) < minDuplicateValueLen {
			continue
		}
		sum := sha256.Sum256(value)
		existing, ok := idx[fmt.Sprintf("%x", sum)]
		if !ok {
			continue
		}
		if g := groupPrefix(existing); g != profileName {
			dupCount++
			groupSet[g] = true
		}
	}
	if dupCount == 0 {
		return
	}
	groups := make([]string, 0, len(groupSet))
	for g := range groupSet {
		groups = append(groups, g)
	}
	sort.Strings(groups)
	fmt.Fprint(out, hlCmds(fmt.Sprintf("    note: %s already stored under %s, see `jit vault duplicates`\n",
		countWord(dupCount, "value is", "values are"), truncateList(groups, 3))))
}

// dupIndexOnce builds the value index lazily, once per migrate run, and
// only when a category that discloses duplicates actually applied a file.
type dupIndexOnce struct {
	v     *vault.Vault
	built bool
	idx   map[string]string
}

func (d *dupIndexOnce) get() map[string]string {
	if !d.built {
		d.built = true
		d.idx = buildVaultValueIndex(d.v)
	}
	return d.idx
}
