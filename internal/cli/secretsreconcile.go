// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"sort"
	"strings"

	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

// secretState classifies one stored secret (or a whole group of them) by who
// references it, seen from the current directory. It is the distinction `jit
// profile list` never drew: a secret existing in the vault says nothing about
// whether THIS project uses it.
type secretState int

const (
	// stateWiredHere: referenced by a project-local profile (a
	// .jit/profiles/*.yaml under cwd). This project actively uses it.
	stateWiredHere secretState = iota
	// stateManagedElsewhere: referenced only by a global profile or by a
	// registered mount's profile, not by any project-local one. Stored and
	// reachable, just not by this project's local config.
	stateManagedElsewhere
	// stateUnreferenced: referenced by no profile jit can see from here. A
	// candidate orphan — it may belong to a different project, or be genuinely
	// dead (a re-migration leftover, a stale backup group).
	stateUnreferenced
)

// secretMember is one stored secret within a group: its full vault path, its
// key (the path with the "group/" prefix stripped, matching `jit vault list`),
// and its own state.
type secretMember struct {
	Path  string      `json:"path"`
	Key   string      `json:"key"`
	State secretState `json:"-"`
}

// secretGroup is a first-path-segment grouping (the same grouping `jit vault
// list` and `jit vault orphans` use), classified by a single dominant state.
// Wired wins over elsewhere wins over unreferenced, so a group holding even one
// wired secret reads as wired; Mixed flags when its members don't all agree,
// which a re-migration that split a group can produce.
type secretGroup struct {
	Name    string         `json:"name"`
	Members []secretMember `json:"members"`
	State   secretState    `json:"-"`
	Mixed   bool           `json:"mixed,omitempty"`
	// DuplicateOf names a still-referenced group holding exactly the same
	// key names as this one, set only on unreferenced groups. It is the
	// fingerprint of a re-migration that renamed a group (custom_scripts-wiz
	// -> wiz) and left the original copy behind: the same keys, nothing
	// pointing at them any more. Compared by KEY NAME only — status never
	// decrypts, so it cannot and does not claim the values match.
	DuplicateOf string `json:"duplicate_of,omitempty"`
}

// secretsReconciliation is the whole vault<->profile picture from cwd: every
// stored secret grouped and classified, plus the project-local profile tallies
// (how many profiles wire secrets here, how many references they make, how many
// of those references point at a secret that isn't actually stored). It is what
// `jit status`'s Secrets section and `jit status --secrets` both render, so the
// glance and the detail can never disagree.
type secretsReconciliation struct {
	Groups []secretGroup

	TotalSecrets int
	TotalGroups  int

	WiredGroups        int
	ElsewhereGroups    int
	UnreferencedGroups int

	UnreferencedSecrets int

	// UnreferencedInMixed counts unreferenced secrets sitting inside groups
	// whose DOMINANT state is wired or elsewhere — members the group-level
	// bucketing above can't count without hiding an actively-used group in
	// the unreferenced pile. `jit vault orphans` keys on individual paths, so
	// these are exactly the secrets it would list that UnreferencedSecrets
	// doesn't; surfacing the number keeps the two commands from appearing to
	// disagree.
	UnreferencedInMixed int

	// DuplicateGroups/DuplicateSecrets count the unreferenced groups that
	// carry the same key names as a group still in use — the re-migration
	// leftovers described on secretGroup.DuplicateOf. They are a SUBSET of
	// the Unreferenced totals, not an additional bucket.
	DuplicateGroups  int
	DuplicateSecrets int

	// Project-local profile tallies, for the "Wired here: N groups via P
	// profiles (R references)" line. WiredProblems counts project-local
	// references whose secret isn't in the vault at all (a wired-but-broken
	// reference) — the same existence failure `jit doctor` reports, scoped to
	// the wired set.
	WiredProfiles int
	WiredRefs     int
	WiredProblems int

	// ParseFailures counts profile manifests jit could see but couldn't load.
	// Their references don't count toward any set, so a directory with an
	// unreadable profile degrades gracefully rather than mislabeling secrets as
	// unreferenced.
	ParseFailures int
}

// groupPrefix returns a vault path's group: everything before the first '/', or
// the whole path when it has none. Matches printOrphanGroups and `jit vault
// list`.
func groupPrefix(path string) string {
	if i := strings.IndexByte(path, '/'); i >= 0 {
		return path[:i]
	}
	return path
}

// reconcileSecrets is the shared engine behind the Secrets section. It walks the
// profiles jit can see from cwd (project-local, global, and every registered
// mount's), records which vault paths each set references, then walks the stored
// secrets and classifies each by the strongest referencer.
//
// It is deliberately TOLERANT where collectReferencedPaths (which backs the
// deleting `jit vault orphans --prune`) is strict: a profile that won't parse is
// counted and skipped, not fatal, because `jit status` must stay a safe,
// always-runnable overview. It never touches the vault's KeyWrapper (List/Exists
// are auth-free), so it triggers no Touch ID prompt and reveals no value.
func reconcileSecrets(root, cwd string, v *vault.Vault) (secretsReconciliation, error) {
	var rec secretsReconciliation

	projectRefs := map[string]bool{}
	elsewhereRefs := map[string]bool{}

	infos, err := profile.ListAll(cwd)
	if err != nil {
		return secretsReconciliation{}, err
	}
	for _, info := range infos {
		p, err := profile.LoadFile(info.Path)
		if err != nil {
			rec.ParseFailures++
			continue
		}
		target := elsewhereRefs
		if info.Scope == profile.ScopeProject {
			target = projectRefs
			rec.WiredProfiles++
			rec.WiredRefs += len(p)
		}
		for _, vaultPath := range p {
			target[vaultPath] = true
		}
	}

	// A registered mount's profile may live in another project's tree; jit is
	// still actively serving it, so it counts as "managed elsewhere", not
	// orphaned. Tolerant here too: a mount whose manifest vanished shouldn't
	// break the overview.
	if entries, err := mount.LoadRegistry(mount.RegistryPath(root)); err == nil {
		for _, e := range entries {
			p, err := profile.LoadFile(e.ProfilePath)
			if err != nil {
				continue
			}
			for _, vaultPath := range p {
				elsewhereRefs[vaultPath] = true
			}
		}
	}

	paths, err := v.List()
	if err != nil {
		return secretsReconciliation{}, err
	}
	stored, _ := splitBackupPaths(paths)
	storedSet := make(map[string]bool, len(stored))
	for _, p := range stored {
		storedSet[p] = true
	}

	// A project-local reference to a path that isn't stored is a wired-but-broken
	// reference — the same "missing secret" jit doctor flags, scoped to the
	// wired set. It won't appear as a stored group below, so count it here.
	for p := range projectRefs {
		if !storedSet[p] {
			rec.WiredProblems++
		}
	}

	classify := func(path string) secretState {
		switch {
		case projectRefs[path]:
			return stateWiredHere
		case elsewhereRefs[path]:
			return stateManagedElsewhere
		default:
			return stateUnreferenced
		}
	}

	byGroup := map[string]*secretGroup{}
	var order []string
	for _, p := range stored {
		name := groupPrefix(p)
		g, ok := byGroup[name]
		if !ok {
			g = &secretGroup{Name: name}
			byGroup[name] = g
			order = append(order, name)
		}
		g.Members = append(g.Members, secretMember{
			Path:  p,
			Key:   strings.TrimPrefix(p, name+"/"),
			State: classify(p),
		})
	}

	rec.TotalSecrets = len(stored)
	rec.TotalGroups = len(order)
	sort.Strings(order)
	rec.Groups = make([]secretGroup, 0, len(order))
	for _, name := range order {
		g := byGroup[name]
		// Dominant state: wired beats elsewhere beats unreferenced, so a group
		// with any active use never hides in the unreferenced bucket.
		dominant := stateUnreferenced
		mixed := false
		for i, m := range g.Members {
			if i > 0 && m.State != g.Members[0].State {
				mixed = true
			}
			if m.State < dominant {
				dominant = m.State
			}
		}
		g.State = dominant
		g.Mixed = mixed
		switch dominant {
		case stateWiredHere:
			rec.WiredGroups++
		case stateManagedElsewhere:
			rec.ElsewhereGroups++
		default:
			rec.UnreferencedGroups++
			rec.UnreferencedSecrets += len(g.Members)
		}
		if dominant != stateUnreferenced {
			for _, m := range g.Members {
				if m.State == stateUnreferenced {
					rec.UnreferencedInMixed++
				}
			}
		}
		rec.Groups = append(rec.Groups, *g)
	}

	markDuplicateGroups(&rec)

	return rec, nil
}

// keySignature fingerprints a group by its key names alone, sorted so member
// order can't affect it. Key names, never values: status is auth-free by
// contract (no KeyWrapper, no Touch ID), so comparing the actual secrets is
// not available to it — and the rendering says so rather than implying the
// copies are byte-identical.
func keySignature(g secretGroup) string {
	keys := make([]string, len(g.Members))
	for i, m := range g.Members {
		keys[i] = m.Key
	}
	sort.Strings(keys)
	return strings.Join(keys, "\x00")
}

// markDuplicateGroups links each unreferenced group to a still-referenced one
// holding the same key names, and tallies how many there are. This is what
// turns "35 unreferenced secrets" — an undifferentiated pile the reader has to
// audit by hand — into "31 of them are copies of groups you're still using",
// which is a decision they can actually make.
//
// A one-secret group is deliberately NOT matched: single-key groups collide on
// generic names (API_KEY, OUTPUT_FILE) constantly, and a false "this is just a
// leftover" on the one secret that isn't would be the expensive mistake here.
func markDuplicateGroups(rec *secretsReconciliation) {
	referenced := map[string]string{}
	for _, g := range rec.Groups {
		if g.State == stateUnreferenced || len(g.Members) < 2 {
			continue
		}
		sig := keySignature(g)
		// Groups are already sorted by name, so first-wins is deterministic
		// and names the alphabetically-first live group.
		if _, seen := referenced[sig]; !seen {
			referenced[sig] = g.Name
		}
	}
	for i := range rec.Groups {
		g := &rec.Groups[i]
		if g.State != stateUnreferenced || len(g.Members) < 2 {
			continue
		}
		if live, ok := referenced[keySignature(*g)]; ok {
			g.DuplicateOf = live
			rec.DuplicateGroups++
			rec.DuplicateSecrets += len(g.Members)
		}
	}
}
