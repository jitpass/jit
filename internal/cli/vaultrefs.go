// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/profile"
)

// secretReference is one thing that points at a stored secret: a profile
// (by name and store), possibly served live through a registered mount.
type secretReference struct {
	ProfileName string
	Scope       profile.Scope
	MountPath   string // the mounted file this profile feeds, "" when none
}

// referencesForPaths maps each requested vault path to whatever jit can see
// pointing at it: profiles in the project-local (cwd) and global stores,
// plus the profile behind every registered mount. The mirror image of
// collectReferencedPaths with the opposite failure contract — that one is
// STRICT because its caller deletes what looks unreferenced, this one is
// LENIENT (an unloadable profile is skipped) because its callers only WARN:
// a parse failure must not block `jit vault rm`, and a missed warning is
// the pre-existing behavior, not a new hazard.
func referencesForPaths(root, cwd string, paths []string) map[string][]secretReference {
	wanted := map[string]bool{}
	for _, p := range paths {
		wanted[p] = true
	}
	refs := map[string][]secretReference{}
	seen := map[string]bool{} // profile file path -> already consumed
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
		for _, vaultPath := range entries {
			if wanted[vaultPath] {
				refs[vaultPath] = append(refs[vaultPath], secretReference{
					ProfileName: name, Scope: scope, MountPath: mountPath,
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

// printRmReferenceWarnings tells the user, BEFORE the delete-confirmation,
// which of the doomed paths something still points at — the gap that made
// "rm the stale copy" advice dangerous: rm deletes only the envelope file,
// so a wired secret's profile keeps naming it and its mount keeps serving a
// FIFO no writer can fill. Purely advisory (the [y/N] and the fingerprint
// still decide); the remedy routes to `jit migrate remove`, the command
// that takes the file, the profile and the secrets down together.
func printRmReferenceWarnings(out io.Writer, refs map[string][]secretReference) {
	if len(refs) == 0 {
		return
	}
	paths := make([]string, 0, len(refs))
	for p := range refs {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	mounts := map[string]bool{}
	var mountOrder []string
	for _, p := range paths {
		for _, r := range refs[p] {
			_, _ = cWarnBold.Fprintf(out, "%s ", glyphMark)
			fmt.Fprintf(out, "%s is wired to profile ", p)
			_, _ = cBold.Fprint(out, r.ProfileName)
			fmt.Fprintf(out, " (%s)\n", r.Scope)
			if r.MountPath != "" && !mounts[r.MountPath] {
				mounts[r.MountPath] = true
				mountOrder = append(mountOrder, r.MountPath)
				fmt.Fprintf(out, "  %s served by the mount at %s\n", glyphBranch, shortPath(r.MountPath))
			}
		}
	}
	if len(mountOrder) > 0 {
		which := "that mount"
		if len(mountOrder) > 1 {
			which = "those mounts"
		}
		fmt.Fprintf(out, "  deleting only the secret leaves %s broken; to remove file,\n", which)
		fmt.Fprintln(out, "  profile and secret together:")
		for _, m := range mountOrder {
			_, _ = cPath.Fprintf(out, "  %s jit migrate remove %s\n", glyphAction, shortPath(m))
		}
	}
}
