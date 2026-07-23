// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

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
		rec.Groups = append(rec.Groups, *g)
	}

	return rec, nil
}
