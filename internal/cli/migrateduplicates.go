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

// buildVaultValueIndex digests every stored secret, mapping value digest ->
// every vault path holding it. Values are hashed as read and never kept.
// Best-effort: an unreadable envelope is skipped, and a nil index (a listing
// failure) simply disables the notes — disclosure must never fail a
// migration.
//
// It reads what is STORED, never what a linked secret resolves to: a
// 1Password-linked entry is keyed by its reference, so two links to the
// same field read as duplicates of each other and a link never equals a
// literal copy of the same value. Resolving would cost one `op read` exec
// per linked secret on every migrate run — and, with the app locked, one
// unlock dialog each — for a disclosure note.
//
// It maps a digest to EVERY path holding it, not just the first. The index
// is built lazily, which means it is built AFTER the run's first file has
// already been stored, so a value's own freshly-written path is in here
// too — and with a single-path map the lookup could return that path
// instead of the older copy, see itself, and stay silent about a real
// duplicate. Keeping every path lets the lookup skip the migrating
// profile's own and still find the older one. (Found by migrating a copied
// folder on a real machine: the note never appeared, because
// "ws-copy/CAIDO_URL" sorts before "ws/CAIDO_URL" and won the map slot.)
func buildVaultValueIndex(v *vault.Vault) map[string][]string {
	paths, err := v.List()
	if err != nil {
		return nil
	}
	secrets, _ := splitBackupPaths(paths)
	idx := make(map[string][]string, len(secrets))
	for _, p := range secrets {
		key, _, ok := storedDigest(v, p)
		if !ok {
			continue
		}
		idx[key] = append(idx[key], p)
	}
	return idx
}

// storedDigest keys one vault entry for the duplicate index: the digest of
// its stored bytes, prefixed by storage kind so a reference and a literal
// can never collide. Returns the stored length too, for the floor below.
func storedDigest(v *vault.Vault, path string) (key string, n int, ok bool) {
	payload, storage, err := v.GetStored(path)
	if err != nil {
		return "", 0, false
	}
	sum := sha256.Sum256(payload)
	key = fmt.Sprintf("%x", sum)
	if storage != "" {
		key = storage + ":" + key
	}
	return key, len(payload), true
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
func noteDuplicateValues(out io.Writer, v *vault.Vault, idx map[string][]string, profileName string, vars []string) {
	if len(idx) == 0 {
		return
	}
	dupCount := 0
	groupSet := map[string]bool{}
	for _, name := range vars {
		if looksLikeConfig(name) {
			continue
		}
		key, n, ok := storedDigest(v, profileName+"/"+name)
		if !ok || n < minDuplicateValueLen {
			continue
		}
		counted := false
		for _, existing := range idx[key] {
			// Skip the value's own group, including the copy this very
			// migration just wrote (the index is built after the store).
			g := groupPrefix(existing)
			if g == profileName {
				continue
			}
			groupSet[g] = true
			if !counted {
				dupCount++
				counted = true
			}
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
	idx   map[string][]string
}

func (d *dupIndexOnce) get() map[string][]string {
	if !d.built {
		d.built = true
		d.idx = buildVaultValueIndex(d.v)
	}
	return d.idx
}
