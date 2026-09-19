// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/profile"
)

// secretReference is one thing that points at a stored secret: a profile
// (by name and store), possibly served live through a registered mount.
type secretReference struct {
	ProfileName string
	Scope       profile.Scope
	MountPath   string // the mounted file this profile feeds, "" when none
	// OwnerConfig is the config file the referencing profile records as its
	// source (migrate.ProfileOwnerConfig). It is the ONLY provenance a
	// pre-provenance (v1/v2) secret has: those envelopes carry no Origin
	// field at all, so anything keying on Origin alone is blind to every
	// secret migrated before provenance shipped. `jit vault get`'s
	// "migrated from" footer has always read this rather than Origin.
	OwnerConfig string
}

// referencesForPaths maps each requested vault path to the profiles jit can
// see from cwd pointing at it: the project-local (cwd) and global stores,
// plus the profile behind every registered mount. LENIENT (an unloadable
// profile is skipped) and narrow (no walk of home, no pointer files),
// because its callers only DISPLAY: `jit vault list`'s used_by and its
// provenance fallback, which run on every listing and must stay cheap.
//
// Nothing that deletes may use it. Every deleting caller goes through
// collectVaultUsers, the strict collector: this one once decided what
// `vault rm`, `duplicates --prune` and `migrate remove` treated as unused,
// and missed every project store outside cwd and every pointer file.
func referencesForPaths(root, cwd string, paths []string) map[string][]secretReference {
	wanted := map[string]bool{}
	for _, p := range paths {
		wanted[p] = true
	}
	refs := map[string][]secretReference{}
	seen := map[string]bool{}    // profile file path -> already consumed
	owner := map[string]string{} // profile file path -> its recorded source config
	add := func(profilePath, name string, scope profile.Scope, mountPath string) {
		if seen[profilePath] {
			// A mount whose profile was already listed still needs its
			// MountPath attached to that profile's references.
			if mountPath == "" {
				return
			}
			for vaultPath, list := range refs {
				if !wanted[vaultPath] {
					continue
				}
				for i := range list {
					if list[i].ProfileName == name && list[i].MountPath == "" {
						list[i].MountPath = mountPath
					}
				}
			}
			return
		}
		seen[profilePath] = true
		entries, err := profile.LoadFile(profilePath)
		if err != nil {
			return
		}
		src, ok := owner[profilePath]
		if !ok {
			src = migrate.ProfileOwnerConfig(profilePath)
			owner[profilePath] = src
		}
		for _, vaultPath := range entries {
			if wanted[vaultPath] {
				refs[vaultPath] = append(refs[vaultPath], secretReference{
					ProfileName: name, Scope: scope, MountPath: mountPath,
					OwnerConfig: src,
				})
			}
		}
	}
	if infos, err := profile.ListAll(cwd); err == nil {
		for _, info := range infos {
			add(info.Path, info.Name, info.Scope, "")
		}
	}
	if entries, err := mount.LoadRegistry(mount.RegistryPath(root)); err == nil {
		for _, e := range entries {
			name := strings.TrimSuffix(filepath.Base(e.ProfilePath), filepath.Ext(e.ProfilePath))
			add(e.ProfilePath, name, profile.ScopeGlobal, e.MountPath)
		}
	}
	for _, list := range refs {
		sort.Slice(list, func(i, j int) bool { return list[i].ProfileName < list[j].ProfileName })
	}
	return refs
}
