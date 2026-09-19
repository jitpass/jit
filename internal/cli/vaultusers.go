// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"fmt"
	"path/filepath"
	"slices"
	"sort"

	"github.com/jitpass/jit/internal/launchers"
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/profile"
)

// secretUse is one thing that uses a stored secret: a profile that names it
// (from any store jit can find, possibly served through a mount), or a
// pointer file holding a jit://vault reference to it. Exactly one of
// ProfilePath and PointerFile is set.
type secretUse struct {
	ProfileName string
	ProfilePath string        // the manifest file, the identity uses dedupe on
	Scope       profile.Scope // global or project
	Project     string        // the project root, for a project-scope profile
	MountPath   string        // a registered mount this profile feeds, "" when none
	OwnerConfig string        // the profile's recorded source config (.source sidecar)
	PointerFile string        // a pointer file naming the secret, for a pointer use
	// LaunchedBy lists the MCP configs whose entries start this profile, in
	// any wrapper layer. Display evidence only (attachLaunchers): an MCP
	// config that fails to parse is skipped there, so an empty list means
	// "no known launcher", never "unused".
	LaunchedBy []string
	// Tools names the MCP servers behind LaunchedBy, each with the config
	// that starts it, in config then server order. Same provenance and
	// caveats as LaunchedBy.
	Tools []toolUse
}

// toolUse is one tool (an MCP server, by name) that uses a profile, and
// the config that starts it.
type toolUse struct {
	Name   string `json:"name"`
	Config string `json:"config"`
}

// toolsIn returns the names of u's tools that config starts, in order.
func (u secretUse) toolsIn(config string) []string {
	var names []string
	for _, t := range u.Tools {
		if t.Config == config && !containsString(names, t.Name) {
			names = append(names, t.Name)
		}
	}
	return names
}

// scopeLabel renders the profile's store the way the rm warnings show it:
// "global", or "project ~/proj".
func (u secretUse) scopeLabel() string {
	if u.Scope == profile.ScopeProject && u.Project != "" {
		return "project " + shortPath(u.Project)
	}
	return string(u.Scope)
}

// vaultUsage is collectVaultUsers' answer: every vault path something uses,
// with each user, plus the registered mounts whose profile manifest is gone.
// launchers is the map it was built from, kept for attachLaunchers.
type vaultUsage struct {
	byPath      map[string][]secretUse
	staleMounts []mount.Entry
	launchers   *launchers.Map
}

// usesOf returns the uses of the given paths only, keyed by path.
func (u vaultUsage) usesOf(paths []string) map[string][]secretUse {
	out := map[string][]secretUse{}
	for _, p := range paths {
		if list := u.byPath[p]; len(list) > 0 {
			out[p] = list
		}
	}
	return out
}

// collectVaultUsers is the one STRICT answer to "what uses this secret",
// for every caller that deletes on the answer (`jit vault rm`, `vault
// orphans --prune`, `vault duplicates`, `jit migrate remove`). It is the
// launcher map (internal/launchers) flattened by vault path, so this and
// every other "what launches it" answer read the same files the same way:
//
//   - profiles in cwd's store, the global store (always, even when cwd is
//     home) and every project store under home. A project store is found by
//     walking home for .jit directories. The walk used to be missing, and
//     every check ran from cwd alone, so a project's secrets looked unused
//     from anywhere else. That is how "Delete All" in the app was one click
//     from removing a project's secrets.
//   - the mount registry. A registered mount whose manifest is gone names
//     nothing and comes back as a stale mount instead (GAPS.md #67).
//   - pointer files: jit's own in-place pointer files (header-marked), found
//     through the undo index and the home walk, plus ~/.clisso.yaml.
//
// STRICT means an unreadable or unparseable manifest, registry, undo index
// or pointer file is an ERROR, never a skip: a skipped file would make its
// secrets look unused, which is exactly the verdict a deleting caller must
// never reach by accident. It is strict about exactly those sources. The
// map's other sources (MCP configs, AWS, kubeconfig, rc files) only ever
// add launchers to a profile that already counts as a user, so one of them
// failing cannot make a secret look unused, and a hand-broken mcp.json
// somewhere under home must not disable deletion everywhere. A directory
// the walk can't enter is skipped, as every home walk in jit does.
func collectVaultUsers(root, cwd string) (vaultUsage, error) {
	usage := vaultUsage{byPath: map[string][]secretUse{}}
	home, err := profile.GlobalRoot()
	if err != nil {
		return usage, fmt.Errorf("finding the global profile store: %w", err)
	}
	m, err := launchers.Discover(launchers.Options{Home: home, Root: root, Cwd: cwd})
	if err != nil {
		return usage, err
	}
	if err := m.Err(launchers.SourceProfiles, launchers.SourceMounts, launchers.SourcePointers); err != nil {
		return usage, err
	}
	return vaultUsageFromMap(m), nil
}

// vaultUsageFromMap flattens an already-discovered launcher map by vault
// path. collectVaultUsers is its strict front door; `jit profile rm`
// discovers strictly itself (it needs the launchers as well) and flattens
// the same map, so the two can never disagree about a secret's users.
func vaultUsageFromMap(m *launchers.Map) vaultUsage {
	usage := vaultUsage{byPath: map[string][]secretUse{}}
	usage.launchers = m
	usage.staleMounts = m.StaleMounts

	for _, p := range m.Profiles {
		u := secretUse{
			ProfileName: p.Name,
			ProfilePath: p.Path,
			Scope:       p.Scope,
			Project:     p.Project,
			OwnerConfig: migrate.ProfileOwnerConfig(p.Path),
		}
		if len(p.Mounts) > 0 {
			u.MountPath = p.Mounts[0]
		}
		for _, vaultPath := range uniqueValues(p.Values) {
			usage.byPath[vaultPath] = append(usage.byPath[vaultPath], u)
		}
	}
	for _, pl := range m.Pointers {
		usage.byPath[pl.VaultPath] = append(usage.byPath[pl.VaultPath], secretUse{PointerFile: pl.File})
	}

	for p, list := range usage.byPath {
		sort.SliceStable(list, func(i, j int) bool { return useSortKey(list[i]) < useSortKey(list[j]) })
		usage.byPath[p] = list
	}
	return usage
}

// collectReferencedPaths is collectVaultUsers flattened to the set of used
// paths, for `jit vault orphans`, which only asks "is anything using it".
// Same strict contract, same stale-mount exception.
func collectReferencedPaths(root, cwd string) (map[string]bool, []mount.Entry, error) {
	usage, err := collectVaultUsers(root, cwd)
	if err != nil {
		return nil, nil, err
	}
	referenced := make(map[string]bool, len(usage.byPath))
	for p := range usage.byPath {
		referenced[p] = true
	}
	return referenced, usage.staleMounts, nil
}

func useSortKey(u secretUse) string {
	if u.PointerFile != "" {
		return "1\x00" + u.PointerFile
	}
	return "0\x00" + u.ProfileName + "\x00" + u.ProfilePath
}

// uniqueValues returns a profile's vault paths, each once: two variables
// naming one secret are one use of it.
func uniqueValues(p profile.Profile) []string {
	set := map[string]bool{}
	for _, v := range p {
		set[v] = true
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// canonicalPath resolves symlinks for comparison, falling back to the
// cleaned path when it can't (the file vanished mid-read).
func canonicalPath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return filepath.Clean(p)
}

// attachLaunchers fills LaunchedBy and Tools on the given uses from the MCP launchers
// in the map collectVaultUsers built: which configs start each profile,
// counting every wrapper layer of a nested entry and discovered from home.
// Display only, and lenient: an MCP config that failed to parse adds
// nothing, which reads as "no known launcher", never as "unused". The map
// attributes a launcher the way `jit run` resolves a profile NAME, project
// first: a global profile takes every launcher naming it, a project one
// only launchers inside its own project.
//
// MCP only, deliberately: the other launcher kinds are in the map, and
// widening what `vault rm` and `vault duplicates` print is a separate,
// previewed change.
func (usage vaultUsage) attachLaunchers(uses map[string][]secretUse) {
	if len(uses) == 0 || usage.launchers == nil {
		return
	}
	for p, list := range uses {
		for i := range list {
			u := &list[i]
			if u.ProfilePath == "" {
				continue
			}
			lp := usage.launchers.ProfileAt(u.ProfilePath)
			if lp == nil {
				continue
			}
			for _, l := range lp.LaunchersOf(launchers.KindMCP) {
				if !containsString(u.LaunchedBy, l.File) {
					u.LaunchedBy = append(u.LaunchedBy, l.File)
				}
				t := toolUse{Name: l.Detail, Config: l.File}
				if l.Detail != "" && !slices.Contains(u.Tools, t) {
					u.Tools = append(u.Tools, t)
				}
			}
			sort.Strings(u.LaunchedBy)
			sort.SliceStable(u.Tools, func(i, j int) bool {
				if u.Tools[i].Config != u.Tools[j].Config {
					return u.Tools[i].Config < u.Tools[j].Config
				}
				return u.Tools[i].Name < u.Tools[j].Name
			})
		}
		uses[p] = list
	}
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
